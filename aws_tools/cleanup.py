from __future__ import annotations

from pathlib import Path

from aws_tools.aws import AwsContext, client
from aws_tools.models import Finding
from aws_tools.reports import load_report


class CleanupError(RuntimeError):
    pass


def apply_findings(
    context: AwsContext | None,
    report_path: Path,
    finding_ids: list[str],
    execute: bool,
) -> list[str]:
    report = load_report(report_path)
    messages: list[str] = []

    for finding in _select_findings(report.findings, finding_ids):
        messages.append(_apply_finding(context, finding, execute))

    return messages


def _select_findings(
    findings: list[Finding],
    finding_ids: list[str],
) -> list[Finding]:
    normalized = [finding_id.upper() for finding_id in finding_ids]
    if "ALL" in normalized:
        if len(finding_ids) != 1:
            raise CleanupError("Use --ids ALL by itself, not mixed with IDs")
        selected = [
            finding
            for finding in findings
            if finding.cleanup_eligible and finding.cleanup_action is not None
        ]
        if not selected:
            raise CleanupError("Report has no cleanup-eligible findings")
        return selected

    by_id = {finding.id: finding for finding in findings}
    selected = []
    for finding_id in finding_ids:
        finding = by_id.get(finding_id)
        if finding is None:
            raise CleanupError(f"Finding not found in report: {finding_id}")
        if not finding.cleanup_eligible or finding.cleanup_action is None:
            raise CleanupError(f"Finding is not cleanup eligible: {finding_id}")
        selected.append(finding)
    return selected


def _apply_finding(
    context: AwsContext | None,
    finding: Finding,
    execute: bool,
) -> str:
    action = finding.cleanup_action
    if action is None:
        raise CleanupError(f"Missing cleanup action for {finding.id}")

    if action.name == "logs.put_retention_policy":
        params = action.parameters
        if not execute:
            return (
                f"DRY-RUN {finding.id}: set retention on "
                f"{params['log_group_name']} to {params['retention_days']} days"
            )
        if context is None:
            raise CleanupError("AWS context is required when --execute is set")
        logs = client(context, "logs", finding.region)
        _require_log_group(logs, params["log_group_name"])
        logs.put_retention_policy(
            logGroupName=params["log_group_name"],
            retentionInDays=int(params["retention_days"]),
        )
        return f"APPLIED {finding.id}: retention policy updated"

    raise CleanupError(f"Unsupported cleanup action: {action.name}")


def _require_log_group(logs, name: str) -> None:
    response = logs.describe_log_groups(logGroupNamePrefix=name, limit=50)
    for group in response.get("logGroups", []):
        if group.get("logGroupName") == name:
            return
    raise CleanupError(f"Log group no longer exists: {name}")
