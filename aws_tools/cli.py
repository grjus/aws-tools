from __future__ import annotations

import argparse
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console

from aws_tools.aws import create_context
from aws_tools.cleanup import CleanupError, apply_findings
from aws_tools.cloudformation import deployed_stack_inventory, stack_details
from aws_tools.config import load_config
from aws_tools.costs import get_cost_details
from aws_tools.filtering import apply_report_filters
from aws_tools.logs_tail import LogTailError, resolve_log_group, tail_log_group
from aws_tools.render import (
    render_cost_details,
    render_report,
    render_stack_details,
    render_stack_inventory,
)
from aws_tools.reports import default_report_path
from aws_tools.scanners import cost_risk, logs_retention, orphaned, tag_compliance


console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 1
    try:
        return args.handler(args)
    except (BotoCoreError, ClientError) as exc:
        console.print(f"[red]AWS request failed:[/red] {exc}")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-tools",
        description="AWS resource reporting and guarded cleanup tools.",
    )
    parser.add_argument("--profile", help="AWS profile override.")
    parser.add_argument(
        "--regions",
        help="Comma-separated AWS regions override.",
    )
    parser.add_argument(
        "--read-only-role-arn",
        help="Read-only IAM role ARN to assume for scan commands.",
    )
    subparsers = parser.add_subparsers(dest="command")

    _add_scan_command(subparsers, "orphaned", _handle_orphaned_scan)
    _add_scan_command(subparsers, "logs-retention", _handle_logs_scan)
    _add_scan_command(subparsers, "cost-risk", _handle_cost_scan)
    _add_scan_command(subparsers, "tag-compliance", _handle_tag_scan)
    _add_cost_command(subparsers)
    _add_stacks_command(subparsers)
    _add_logs_command(subparsers)
    _add_cleanup_command(subparsers)
    _add_roadmap_command(subparsers)
    return parser


def _add_scan_command(subparsers, name: str, handler) -> None:
    parser = subparsers.add_parser(name)
    nested = parser.add_subparsers(dest="action")
    scan = nested.add_parser("scan")
    scan.add_argument("--output", type=Path, help="JSON report output path.")
    scan.add_argument(
        "--no-save",
        action="store_true",
        help="Render results without writing a report file.",
    )
    scan.add_argument(
        "--filter",
        action="append",
        help=(
            "Filter findings by service or service:resource-type. "
            "Can be repeated or comma-separated."
        ),
    )
    if name == "orphaned":
        scan.add_argument(
            "--include-managed",
            action="store_true",
            help="Include resources classified as managed or excluded.",
        )
    scan.set_defaults(handler=handler)


def _add_logs_command(subparsers) -> None:
    parser = subparsers.add_parser("logs")
    nested = parser.add_subparsers(dest="action")
    tail = nested.add_parser("tail")
    tail.add_argument(
        "partial_name",
        help="Partial log group name (substring match).",
    )
    tail.add_argument(
        "--interval",
        type=_positive_float,
        default=5.0,
        help="Refresh interval in seconds between polls. Default: 5.",
    )
    tail.add_argument(
        "--lookback",
        type=_non_negative_int,
        default=60,
        help="Initial lookback window in seconds. Default: 60.",
    )
    tail.add_argument(
        "--region",
        help="Restrict log group search to a single AWS region.",
    )
    tail.set_defaults(handler=_handle_logs_tail)


def _handle_logs_tail(args) -> int:
    config, context = _context(args)
    regions = [args.region] if args.region else None
    try:
        region, log_group_name = resolve_log_group(context, args.partial_name, regions)
    except LogTailError as exc:
        console.print(f"[red]Log tail error:[/red] {exc}")
        return 2
    return tail_log_group(
        context,
        log_group_name,
        region,
        interval=args.interval,
        lookback_seconds=args.lookback,
    )


def _add_cleanup_command(subparsers) -> None:
    parser = subparsers.add_parser("cleanup")
    nested = parser.add_subparsers(dest="action")
    apply_parser = nested.add_parser("apply")
    apply_parser.add_argument("--report", type=Path, required=True)
    apply_parser.add_argument(
        "--ids",
        required=True,
        help="Comma-separated finding IDs, or ALL for every cleanup-eligible finding.",
    )
    apply_parser.add_argument(
        "--execute",
        action="store_true",
        help="Apply actions. Omit for dry-run.",
    )
    apply_parser.set_defaults(handler=_handle_cleanup_apply)


def _add_cost_command(subparsers) -> None:
    parser = subparsers.add_parser("cost")
    nested = parser.add_subparsers(dest="action")
    details = nested.add_parser("details")
    details.add_argument(
        "--past-months",
        type=_non_negative_int,
        default=3,
        help="Number of completed months to include before the current month.",
    )
    details.add_argument(
        "--output",
        type=Path,
        help="Write cost details JSON to this path.",
    )
    details.set_defaults(handler=_handle_cost_details)


def _add_stacks_command(subparsers) -> None:
    parser = subparsers.add_parser("stacks")
    nested = parser.add_subparsers(dest="action")
    list_parser = nested.add_parser("list")
    list_parser.add_argument(
        "--output",
        type=Path,
        help="Write detailed stack inventory JSON to this path.",
    )
    list_parser.set_defaults(handler=_handle_stacks_list)
    details_parser = nested.add_parser("details")
    details_parser.add_argument("stack_name", help="CloudFormation stack name or ID.")
    details_parser.add_argument(
        "--output",
        type=Path,
        help="Write detailed stack resources JSON to this path.",
    )
    details_parser.set_defaults(handler=_handle_stacks_details)


def _add_roadmap_command(subparsers) -> None:
    parser = subparsers.add_parser("roadmap")
    parser.set_defaults(handler=_handle_roadmap)


def _handle_orphaned_scan(args) -> int:
    config, context = _context(args)
    report = orphaned.scan(
        context,
        config,
        include_managed=args.include_managed,
    )
    return _finish_scan(config, report, args)


def _handle_logs_scan(args) -> int:
    config, context = _context(args)
    report = logs_retention.scan(context, config)
    return _finish_scan(config, report, args)


def _handle_cost_scan(args) -> int:
    config, context = _context(args)
    report = cost_risk.scan(context)
    return _finish_scan(config, report, args)


def _handle_tag_scan(args) -> int:
    config, context = _context(args)
    report = tag_compliance.scan(context, config)
    return _finish_scan(config, report, args)


def _handle_cost_details(args) -> int:
    _, context = _context(args)
    details = get_cost_details(context, past_months=args.past_months)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(details.model_dump_json(indent=2), encoding="utf-8")
    render_cost_details(details, args.output)
    return 0


def _handle_cleanup_apply(args) -> int:
    finding_ids = [item.strip() for item in args.ids.split(",") if item.strip()]
    context = None
    if args.execute:
        _, context = _context(args, assume_read_only_role=False)
    try:
        messages = apply_findings(
            context=context,
            report_path=args.report,
            finding_ids=finding_ids,
            execute=args.execute,
        )
    except CleanupError as exc:
        console.print(f"[red]Cleanup failed:[/red] {exc}")
        return 2
    for message in messages:
        console.print(message)
    return 0


def _handle_stacks_list(args) -> int:
    _, context = _context(args)
    inventory = deployed_stack_inventory(context)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(inventory.model_dump_json(indent=2), encoding="utf-8")
    render_stack_inventory(inventory, args.output)
    return 1 if inventory.scan_errors else 0


def _handle_stacks_details(args) -> int:
    _, context = _context(args)
    details = stack_details(context, args.stack_name)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(details.model_dump_json(indent=2), encoding="utf-8")
    if not details.stacks:
        console.print(f"[red]Stack not found:[/red] {args.stack_name}")
        if details.scan_errors:
            render_stack_details(details, args.output)
        return 1
    render_stack_details(details, args.output)
    return 1 if details.scan_errors else 0


def _handle_roadmap(args) -> int:
    del args
    console.print("[bold]Planned tools[/bold]")
    for item in [
        "orphaned scan",
        "logs-retention scan/apply",
        "cost-risk scan",
        "tag-compliance scan",
        "cost details",
        "security group cleanup",
        "s3 hygiene",
        "iam access key audit",
        "ami and snapshot cleanup",
        "vpc networking audit",
        "cloudformation stack health",
    ]:
        console.print(f"- {item}")
    return 0


def _finish_scan(config, report, args) -> int:
    report = apply_report_filters(report, args.filter)
    path = None
    if not args.no_save:
        path = args.output or default_report_path(config, report.tool)
        report.write_json(path)
    render_report(report, path)
    return 0


def _context(args, assume_read_only_role: bool = True):
    regions = None
    if args.regions:
        regions = [
            region.strip() for region in args.regions.split(",") if region.strip()
        ]
    config = load_config(
        profile=args.profile,
        regions=regions,
        read_only_role_arn=args.read_only_role_arn,
    )
    return config, create_context(
        config,
        assume_read_only_role=assume_read_only_role,
    )


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
