from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from aws_tools.aws import AwsContext, client


TOOL = "cost-details"
METRIC = "UnblendedCost"


class PastCostPeriod(BaseModel):
    start_date: date
    end_date_exclusive: date
    amount: float
    unit: str = "USD"


class ServiceCostEstimate(BaseModel):
    service: str
    current_amount: float
    estimated_remaining_amount: float
    estimated_month_end_amount: float
    unit: str = "USD"


class CostDetails(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    tool: Literal["cost-details"] = TOOL
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    profile: str | None = None
    account_ids: list[str] = Field(default_factory=list)
    as_of_date: date
    current_start_date: date
    current_end_date_exclusive: date
    days_elapsed: int
    days_in_month: int
    current_amount: float
    estimated_remaining_amount: float
    estimated_month_end_amount: float
    unit: str = "USD"
    past_periods: list[PastCostPeriod] = Field(default_factory=list)
    services: list[ServiceCostEstimate] = Field(default_factory=list)

    def write_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path


def get_cost_details(
    context: AwsContext,
    past_months: int = 3,
    as_of: date | None = None,
) -> CostDetails:
    if past_months < 0:
        raise ValueError("past_months must be 0 or greater")

    as_of = as_of or date.today()
    month_start = as_of.replace(day=1)
    current_end = as_of + timedelta(days=1)
    days_elapsed = max((current_end - month_start).days, 1)
    days_in_month = monthrange(as_of.year, as_of.month)[1]

    cost_client = client(context, "ce", "us-east-1")
    past_periods = _past_cost_periods(cost_client, month_start, past_months)
    service_costs = _current_service_costs(cost_client, month_start, current_end)
    current_amount = round(sum(item.current_amount for item in service_costs), 2)
    estimated_month_end = _project_month_end(
        current_amount,
        days_elapsed,
        days_in_month,
    )
    estimated_remaining = round(max(estimated_month_end - current_amount, 0.0), 2)

    return CostDetails(
        profile=context.profile,
        account_ids=[context.account_id],
        as_of_date=as_of,
        current_start_date=month_start,
        current_end_date_exclusive=current_end,
        days_elapsed=days_elapsed,
        days_in_month=days_in_month,
        current_amount=current_amount,
        estimated_remaining_amount=estimated_remaining,
        estimated_month_end_amount=estimated_month_end,
        unit=_cost_unit(service_costs, past_periods),
        past_periods=past_periods,
        services=service_costs,
    )


def _past_cost_periods(
    cost_client,
    current_month_start: date,
    past_months: int,
) -> list[PastCostPeriod]:
    if past_months == 0:
        return []
    start = _add_months(current_month_start, -past_months)
    results = _get_cost_and_usage(
        cost_client,
        start,
        current_month_start,
        granularity="MONTHLY",
    )
    periods: list[PastCostPeriod] = []
    for result in results:
        total = result.get("Total", {}).get(METRIC, {})
        periods.append(
            PastCostPeriod(
                start_date=date.fromisoformat(result["TimePeriod"]["Start"]),
                end_date_exclusive=date.fromisoformat(result["TimePeriod"]["End"]),
                amount=round(float(total.get("Amount", 0.0)), 2),
                unit=total.get("Unit", "USD"),
            )
        )
    return periods


def _current_service_costs(
    cost_client,
    start: date,
    end: date,
) -> list[ServiceCostEstimate]:
    days_elapsed = max((end - start).days, 1)
    days_in_month = monthrange(start.year, start.month)[1]
    service_amounts: dict[str, tuple[float, str]] = {}
    results = _get_cost_and_usage(
        cost_client,
        start,
        end,
        granularity="MONTHLY",
        group_by=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    for result in results:
        for group in result.get("Groups", []):
            service = group.get("Keys", ["Unknown"])[0]
            metric = group.get("Metrics", {}).get(METRIC, {})
            amount = float(metric.get("Amount", 0.0))
            unit = metric.get("Unit", "USD")
            current, _ = service_amounts.get(service, (0.0, unit))
            service_amounts[service] = (current + amount, unit)

    services = [
        ServiceCostEstimate(
            service=service,
            current_amount=round(amount, 2),
            estimated_remaining_amount=round(
                max(
                    _project_month_end(amount, days_elapsed, days_in_month) - amount, 0
                ),
                2,
            ),
            estimated_month_end_amount=_project_month_end(
                amount,
                days_elapsed,
                days_in_month,
            ),
            unit=unit,
        )
        for service, (amount, unit) in service_amounts.items()
    ]
    return sorted(
        services, key=lambda item: item.estimated_month_end_amount, reverse=True
    )


def _get_cost_and_usage(
    cost_client,
    start: date,
    end: date,
    granularity: str,
    group_by: list[dict[str, str]] | None = None,
) -> list[dict]:
    request = {
        "TimePeriod": {
            "Start": start.isoformat(),
            "End": end.isoformat(),
        },
        "Granularity": granularity,
        "Metrics": [METRIC],
    }
    if group_by:
        request["GroupBy"] = group_by

    results: list[dict] = []
    while True:
        response = cost_client.get_cost_and_usage(**request)
        results.extend(response.get("ResultsByTime", []))
        token = response.get("NextPageToken")
        if not token:
            return results
        request["NextPageToken"] = token


def _project_month_end(amount: float, days_elapsed: int, days_in_month: int) -> float:
    if amount <= 0:
        return 0.0
    return round((amount / days_elapsed) * days_in_month, 2)


def _add_months(value: date, months: int) -> date:
    month_index = value.year * 12 + value.month - 1 + months
    year, month_zero_based = divmod(month_index, 12)
    month = month_zero_based + 1
    day = min(value.day, monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _cost_unit(
    services: list[ServiceCostEstimate],
    past_periods: list[PastCostPeriod],
) -> str:
    if services:
        return services[0].unit
    if past_periods:
        return past_periods[0].unit
    return "USD"
