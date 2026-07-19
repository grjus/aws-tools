from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from aws_tools.cloudformation import StackDetails, StackInventory
from aws_tools.costs import CostDetails
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
    table.add_column("Stack")
    table.add_column("Recommendation")

    for finding in report.findings:
        table.add_row(
            finding.id,
            finding.risk.value,
            finding.service,
            finding.region,
            finding.resource_id,
            finding.stack_name or "-",
            finding.recommendation,
        )

    if report.findings:
        console.print(table)


def render_stack_inventory(inventory: StackInventory, path: Path | None = None) -> None:
    console.print(
        f"[bold]cloudformation stacks[/bold]: {len(inventory.stacks)} "
        f"across {len(inventory.regions)} region(s)"
    )
    if path is not None:
        console.print(f"Inventory: {path}")
    if inventory.scan_errors:
        console.print(f"[yellow]Scan errors: {len(inventory.scan_errors)}[/yellow]")
        for error in inventory.scan_errors:
            console.print(
                f"- {error.service}.{error.operation} "
                f"[{error.region}]: {error.code or 'unknown'} "
                f"{error.message}"
            )

    table = Table(show_lines=False)
    table.add_column("Region")
    table.add_column("Stack")
    table.add_column("Status")
    table.add_column("Created")
    table.add_column("Modified")
    table.add_column("Resources", justify="right")
    table.add_column("Drift")
    table.add_column("Protection")

    for stack in inventory.stacks:
        table.add_row(
            stack.region,
            stack.stack_name,
            stack.stack_status,
            stack.creation_time.isoformat(),
            stack.last_updated_time.isoformat() if stack.last_updated_time else "-",
            str(stack.resource_count),
            stack.drift_status or "-",
            _format_bool(stack.termination_protection_enabled),
        )

    if inventory.stacks:
        console.print(table)


def render_stack_details(details: StackDetails, path: Path | None = None) -> None:
    console.print(
        f"[bold]cloudformation stack details[/bold]: {details.stack_name} "
        f"({len(details.stacks)} match(es))"
    )
    if path is not None:
        console.print(f"Details: {path}")
    if details.scan_errors:
        console.print(f"[yellow]Scan errors: {len(details.scan_errors)}[/yellow]")
        for error in details.scan_errors:
            console.print(
                f"- {error.service}.{error.operation} "
                f"[{error.region}]: {error.code or 'unknown'} "
                f"{error.message}"
            )

    for stack in details.stacks:
        console.print(
            f"[bold]{stack.stack_name}[/bold] [{stack.region}] "
            f"{stack.stack_status}, resources={stack.resource_count}, "
            f"created={stack.creation_time.isoformat()}, "
            f"modified={stack.last_updated_time.isoformat() if stack.last_updated_time else '-'}"
        )
        resources = details.resources.get(stack.stack_id, [])
        table = Table(show_lines=False)
        table.add_column("Logical ID")
        table.add_column("Type")
        table.add_column("Physical ID")
        table.add_column("Status")
        table.add_column("Updated")
        table.add_column("Drift")

        for resource in resources:
            table.add_row(
                resource.logical_resource_id,
                resource.resource_type,
                resource.physical_resource_id or "-",
                resource.resource_status or "-",
                (
                    resource.last_updated_time.isoformat()
                    if resource.last_updated_time
                    else "-"
                ),
                resource.drift_status or "-",
            )
        console.print(table)


def render_cost_details(details: CostDetails, path: Path | None = None) -> None:
    console.print(
        f"[bold]cost details[/bold]: {details.current_start_date.isoformat()} "
        f"through {details.as_of_date.isoformat()}"
    )
    if path is not None:
        console.print(f"Details: {path}")

    summary = Table(show_header=False, show_lines=False)
    summary.add_column("Metric")
    summary.add_column("Amount", justify="right")
    summary.add_row(
        "Current month-to-date",
        _format_money(details.current_amount, details.unit),
    )
    summary.add_row(
        "Estimated rest of month",
        _format_money(details.estimated_remaining_amount, details.unit),
    )
    summary.add_row(
        "Estimated month-end total",
        _format_money(details.estimated_month_end_amount, details.unit),
    )
    console.print(summary)

    if details.past_periods:
        past = Table(title="Past costs", show_lines=False)
        past.add_column("Period")
        past.add_column("Amount", justify="right")
        for period in details.past_periods:
            past.add_row(
                period.start_date.strftime("%Y-%m"),
                _format_money(period.amount, period.unit),
            )
        console.print(past)

    if details.services:
        services = Table(
            title="Current and estimated cost by service", show_lines=False
        )
        services.add_column("Service")
        services.add_column("Current", justify="right")
        services.add_column("Estimated rest", justify="right")
        services.add_column("Estimated month-end", justify="right")
        for service in details.services:
            services.add_row(
                service.service,
                _format_money(service.current_amount, service.unit),
                _format_money(service.estimated_remaining_amount, service.unit),
                _format_money(service.estimated_month_end_amount, service.unit),
            )
        console.print(services)


def _format_bool(value: bool | None) -> str:
    if value is None:
        return "-"
    return "yes" if value else "no"


def _format_money(amount: float, unit: str) -> str:
    return f"{amount:,.2f} {unit}"
