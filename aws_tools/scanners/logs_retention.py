from __future__ import annotations

from botocore.exceptions import ClientError

from aws_tools.aws import AwsContext, client
from aws_tools.cloudformation import StackOwnership, stack_resource_ownership
from aws_tools.config import AppConfig
from aws_tools.models import (
    CleanupAction,
    Confidence,
    Finding,
    Report,
    Risk,
    stable_finding_id,
)
from aws_tools.scanners.common import stack_fields, stack_owner_for


TOOL = "logs-retention"


def scan(context: AwsContext, config: AppConfig) -> Report:
    findings: list[Finding] = []
    for region in context.regions:
        findings.extend(_region_findings(context, config, region))
    return Report(
        tool=TOOL,
        profile=context.profile,
        account_ids=[context.account_id],
        regions=context.regions,
        findings=findings,
    )


def _region_findings(
    context: AwsContext,
    config: AppConfig,
    region: str,
) -> list[Finding]:
    logs = client(context, "logs", region)
    ownership = stack_resource_ownership(context, region)
    findings: list[Finding] = []
    try:
        for page in logs.get_paginator("describe_log_groups").paginate():
            for group in page.get("logGroups", []):
                retention = group.get("retentionInDays")
                if retention is not None and retention <= config.log_retention_days:
                    continue
                findings.append(
                    _finding(context, config, region, group, retention, ownership)
                )
    except ClientError:
        return findings
    return findings


def _finding(
    context: AwsContext,
    config: AppConfig,
    region: str,
    group: dict,
    retention: int | None,
    ownership: dict[str, StackOwnership],
) -> Finding:
    name = group["logGroupName"]
    owner = stack_owner_for(ownership, name, group.get("arn"))
    evidence = (
        ["No retention policy set"]
        if retention is None
        else [f"Retention is {retention} days"]
    )
    return Finding(
        id=stable_finding_id(
            TOOL, context.account_id, region, "logs", "log-group", name
        ),
        tool=TOOL,
        account_id=context.account_id,
        region=region,
        service="logs",
        resource_type="log-group",
        resource_id=name,
        arn=group.get("arn"),
        **stack_fields(owner),
        evidence=evidence,
        risk=Risk.LOW,
        confidence=Confidence.HIGH,
        cleanup_eligible=True,
        cleanup_action=CleanupAction(
            name="logs.put_retention_policy",
            parameters={
                "log_group_name": name,
                "retention_days": config.log_retention_days,
            },
        ),
        recommendation=f"Set retention to {config.log_retention_days} days",
    )
