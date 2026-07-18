from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from aws_tools.aws import AwsContext, client
from aws_tools.models import Confidence, Finding, Report, Risk, stable_finding_id
from aws_tools.scanners.common import tag_dict


TOOL = "cost-risk"


def scan(context: AwsContext) -> Report:
    findings: list[Finding] = []
    for region in context.regions:
        findings.extend(_ec2_cost_findings(context, region))
        findings.extend(_logs_cost_findings(context, region))
    return Report(
        tool=TOOL,
        profile=context.profile,
        account_ids=[context.account_id],
        regions=context.regions,
        findings=findings,
    )


def _ec2_cost_findings(context: AwsContext, region: str) -> list[Finding]:
    ec2 = client(context, "ec2", region)
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
                        )
                    )
    except ClientError:
        return findings
    return findings


def _logs_cost_findings(context: AwsContext, region: str) -> list[Finding]:
    logs = client(context, "logs", region)
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
) -> Finding:
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
        tags=tags or {},
        evidence=[evidence, f"Detected at {datetime.now(timezone.utc).isoformat()}"],
        risk=risk,
        confidence=Confidence.HIGH,
        recommendation="Review and clean up if no longer needed",
    )
