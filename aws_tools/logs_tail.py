from __future__ import annotations

import time
from datetime import datetime

from botocore.exceptions import ClientError
from rich.console import Console

from aws_tools.aws import AwsContext, client


class LogTailError(RuntimeError):
    """Raised when a log group cannot be uniquely resolved or tailed."""


def resolve_log_group(
    context: AwsContext,
    partial_name: str,
    regions: list[str] | None = None,
) -> tuple[str, str]:
    """Return ``(region, logGroupName)`` for the single log group whose name
    contains ``partial_name`` across the given regions.

    Raises :class:`LogTailError` when zero or more than one log group matches.
    """
    search_regions = regions or context.regions
    if not search_regions:
        raise LogTailError(
            "No AWS regions configured. Set AWS_REGIONS or pass --regions."
        )
    matches: list[tuple[str, str]] = []
    for region in search_regions:
        logs = client(context, "logs", region)
        try:
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for group in page.get("logGroups", []):
                    name = group.get("logGroupName")
                    if name and partial_name in name:
                        matches.append((region, name))
        except ClientError as exc:
            raise LogTailError(f"Failed to list log groups in {region}: {exc}") from exc

    if not matches:
        searched = ", ".join(search_regions)
        raise LogTailError(
            f"No log group matching '{partial_name}' found in: {searched}"
        )
    if len(matches) > 1:
        listing = "\n".join(f"  - {region}: {name}" for region, name in matches)
        raise LogTailError(
            f"Multiple log groups match '{partial_name}' "
            f"({len(matches)} found). Narrow the partial name or pass --region:\n"
            f"{listing}"
        )
    return matches[0]


def tail_log_group(
    context: AwsContext,
    log_group_name: str,
    region: str,
    *,
    interval: float = 5.0,
    lookback_seconds: int = 60,
    console: Console | None = None,
    sleep=time.sleep,
    now=time.time,
    max_iterations: int | None = None,
) -> int:
    """Continuously tail ``log_group_name`` in ``region``.

    Polls CloudWatch Logs ``filter_log_events`` every ``interval`` seconds and
    prints newly seen events. Returns 0 on normal exit (KeyboardInterrupt or
    after ``max_iterations`` polls for tests). ``sleep`` and ``now`` are
    injectable for testing.
    """
    if interval <= 0:
        raise LogTailError("--interval must be greater than 0 seconds")
    if lookback_seconds < 0:
        raise LogTailError("--lookback must be 0 or greater")

    logs = client(context, "logs", region)
    console = console or Console()
    console.print(
        f"[bold]Tailing[/bold] {log_group_name} [{region}] "
        f"every {interval:g}s (lookback {lookback_seconds}s) - Ctrl+C to stop."
    )

    start_from_ms = int((now() - lookback_seconds) * 1000)
    last_timestamp_ms = start_from_ms
    seen: set[str] = set()
    iterations = 0

    try:
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            next_token: str | None = None
            printed_any = False
            while True:
                kwargs: dict = {
                    "logGroupName": log_group_name,
                    "startTime": last_timestamp_ms,
                }
                if next_token:
                    kwargs["nextToken"] = next_token
                response = logs.filter_log_events(**kwargs)
                for event in response.get("events", []):
                    event_id = event.get("eventId")
                    if event_id and event_id in seen:
                        continue
                    if event_id:
                        seen.add(event_id)
                    _render_event(event, console)
                    ts = event.get("timestamp") or 0
                    if ts > last_timestamp_ms:
                        last_timestamp_ms = ts
                    printed_any = True
                next_token = response.get("nextToken")
                if not next_token:
                    break
            # Advance past the last seen event so we do not rescan old events.
            if printed_any:
                last_timestamp_ms += 1
            if max_iterations is None or iterations < max_iterations:
                sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")
    return 0


def _render_event(event: dict, console: Console) -> None:
    timestamp = event.get("timestamp")
    stream = event.get("logStreamName") or "-"
    message = event.get("message") or ""
    if message.endswith("\n"):
        message = message[:-1]
    when = (
        datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
        if timestamp
        else "?"
    )
    console.print(f"[dim]{when}[/dim]  [cyan]{stream}[/cyan]  {message}")
