from __future__ import annotations

from botocore.exceptions import ClientError

from aws_tools.aws import AwsContext, client
from aws_tools.cloudformation import StackOwnership, stack_resource_ownership
from aws_tools.config import AppConfig
from aws_tools.models import Confidence, Finding, Report, Risk, stable_finding_id
from aws_tools.scanners.common import stack_fields, stack_owner_for


TOOL = "tag-compliance"


def scan(context: AwsContext, config: AppConfig) -> Report:
    findings: list[Finding] = []
    for region in context.regions:
        tagging = client(context, "resourcegroupstaggingapi", region)
        ownership = stack_resource_ownership(context, region)
        findings.extend(_region_findings(context, config, region, tagging, ownership))
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
    tagging,
    ownership: dict[str, StackOwnership],
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        for page in tagging.get_paginator("get_resources").paginate():
            for resource in page.get("ResourceTagMappingList", []):
                tags = {tag["Key"]: tag["Value"] for tag in resource.get("Tags", [])}
                missing = [tag for tag in config.required_tags if tag not in tags]
                if not missing:
                    continue
                arn = resource["ResourceARN"]
                owner = stack_owner_for(ownership, arn)
                findings.append(
                    Finding(
                        id=stable_finding_id(
                            TOOL,
                            context.account_id,
                            region,
                            "tagging",
                            "resource",
                            arn,
                        ),
                        tool=TOOL,
                        account_id=context.account_id,
                        region=region,
                        service="tagging",
                        resource_type="resource",
                        resource_id=arn,
                        arn=arn,
                        **stack_fields(owner),
                        tags=tags,
                        evidence=[f"Missing required tags: {', '.join(missing)}"],
                        risk=Risk.LOW,
                        confidence=Confidence.HIGH,
                        recommendation="Add the missing required tags",
                    )
                )
    except ClientError:
        return findings
    return findings
