from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from aws_tools.aws import AwsContext, client
from aws_tools.cloudformation import StackOwnership, stack_resource_ownership
from aws_tools.models import Confidence, Finding, Report, Risk, stable_finding_id
from aws_tools.scanners.common import stack_fields, stack_owner_for, tag_dict


TOOL = "cost-risk"


def scan(context: AwsContext) -> Report:
    findings: list[Finding] = []
    for region in context.regions:
        ownership = stack_resource_ownership(context, region)
        findings.extend(_ec2_cost_findings(context, region, ownership))
        findings.extend(_logs_cost_findings(context, region, ownership))
    return Report(
        tool=TOOL,
        profile=context.profile,
        account_ids=[context.account_id],
        regions=context.regions,
        findings=findings,
    )


def _ec2_cost_findings(
    context: AwsContext,
    region: str,
    ownership: dict[str, StackOwnership] | None = None,
) -> list[Finding]:
    ec2 = client(context, "ec2", region)
    ownership = ownership or {}
    findings: list[Finding] = []
    try:
        for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for volume in page.get("Volumes", []):
                volume_id = volume["VolumeId"]
                findings.append(
                    _finding(
                        context,
                        region,
                        "ec2",
                        "volume",
                        volume_id,
                        "Unattached EBS volume",
                        Risk.MEDIUM,
                        tags=tag_dict(volume.get("Tags")),
                        ownership=ownership,
                    )
                )
        for address in ec2.describe_addresses().get("Addresses", []):
            if address.get("AssociationId"):
                continue
            allocation_id = address.get("AllocationId")
            if allocation_id:
                findings.append(
                    _finding(
                        context,
                        region,
                        "ec2",
                        "elastic-ip",
                        allocation_id,
                        "Elastic IP is not associated",
                        Risk.MEDIUM,
                        ownership=ownership,
                        owner_identifiers=[address.get("PublicIp")],
                    )
                )
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    findings.append(
                        _finding(
                            context,
                            region,
                            "ec2",
                            "instance",
                            instance["InstanceId"],
                            "Stopped EC2 instance may still carry storage cost",
                            Risk.LOW,
                            tags=tag_dict(instance.get("Tags")),
                            ownership=ownership,
                        )
                    )
    except ClientError:
        return findings
    return findings


def _logs_cost_findings(
    context: AwsContext,
    region: str,
    ownership: dict[str, StackOwnership] | None = None,
) -> list[Finding]:
    logs = client(context, "logs", region)
    ownership = ownership or {}
    findings: list[Finding] = []
    try:
        for page in logs.get_paginator("describe_log_groups").paginate():
            for group in page.get("logGroups", []):
                if group.get("retentionInDays") is None:
                    findings.append(
                        _finding(
                            context,
                            region,
                            "logs",
                            "log-group",
                            group["logGroupName"],
                            "CloudWatch log group has no retention policy",
                            Risk.LOW,
                            arn=group.get("arn"),
                            ownership=ownership,
                        )
                    )
    except ClientError:
        return findings
    return findings


def _finding(
    context: AwsContext,
    region: str,
    service: str,
    resource_type: str,
    resource_id: str,
    evidence: str,
    risk: Risk,
    arn: str | None = None,
    tags: dict[str, str] | None = None,
    ownership: dict[str, StackOwnership] | None = None,
    owner_identifiers: list[str | None] | None = None,
) -> Finding:
    owner = stack_owner_for(
        ownership or {},
        resource_id,
        arn,
        *(owner_identifiers or []),
    )
    return Finding(
        id=stable_finding_id(
            TOOL,
            context.account_id,
            region,
            service,
            resource_type,
            resource_id,
        ),
        tool=TOOL,
        account_id=context.account_id,
        region=region,
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        arn=arn,
        **stack_fields(owner),
        tags=tags or {},
        evidence=[evidence, f"Detected at {datetime.now(timezone.utc).isoformat()}"],
        risk=risk,
        confidence=Confidence.HIGH,
        recommendation="Review and clean up if no longer needed",
    )
