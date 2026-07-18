from __future__ import annotations

from aws_tools.models import FindingFilter, Report


def parse_filters(values: list[str] | None) -> list[FindingFilter]:
    filters = []
    for value in _split_values(values):
        parts = value.split(":", 1)
        if len(parts) == 2:
            filters.append(FindingFilter(service=parts[0], resource_type=parts[1]))
        else:
            filters.append(FindingFilter(service=parts[0]))
    return filters


def apply_report_filters(report: Report, values: list[str] | None) -> Report:
    filters = parse_filters(values)
    if not filters:
        return report
    report.filters = _split_values(values)
    report.findings = [
        finding
        for finding in report.findings
        if any(finding_filter.matches(finding) for finding_filter in filters)
    ]
    return report


def _split_values(values: list[str] | None) -> list[str]:
    result = []
    for value in values or []:
        result.extend(item.strip() for item in value.split(",") if item.strip())
    return result
