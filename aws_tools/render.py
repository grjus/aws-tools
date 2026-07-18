from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from aws_tools.models import Report


console = Console()


def render_report(report: Report, path: Path | None = None) -> None:
    console.print(f"[bold]{report.tool}[/bold] findings: {len(report.findings)}")
    if path is not None:
        console.print(f"Report: {path}")
    if report.scan_errors:
        console.print(f"[yellow]Scan errors: {len(report.scan_errors)}[/yellow]")
        for error in report.scan_errors:
            console.print(
                f"- {error.service}.{error.operation} "
                f"[{error.region}]: {error.code or 'unknown'} "
                f"{error.message}"
            )

    by_risk = Counter(finding.risk for finding in report.findings)
    if by_risk:
        console.print(
            "Risk: "
            + ", ".join(f"{risk.value}={count}" for risk, count in by_risk.items())
        )

    table = Table(show_lines=False)
    table.add_column("ID")
    table.add_column("Risk")
    table.add_column("Service")
    table.add_column("Region")
    table.add_column("Resource")
    table.add_column("Recommendation")

    for finding in report.findings:
        table.add_row(
            finding.id,
            finding.risk.value,
            finding.service,
            finding.region,
            finding.resource_id,
            finding.recommendation,
        )

    if report.findings:
        console.print(table)
