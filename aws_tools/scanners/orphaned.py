from __future__ import annotations

from botocore.exceptions import ClientError

from aws_tools.aws import AwsContext, client
from aws_tools.cloudformation import (
    StackOwnership,
    has_stack_tag,
    stack_resource_ownership,
)
from aws_tools.config import AppConfig, ResourceIdentity
from aws_tools.models import (
    Confidence,
    Finding,
    Report,
    Risk,
    ScanError,
    stable_finding_id,
)
from aws_tools.scanners.common import tag_dict


TOOL = "orphaned"


def scan(
    context: AwsContext,
    config: AppConfig,
    include_managed: bool = False,
) -> Report:
    findings: list[Finding] = []
    scan_errors: list[ScanError] = []
    all_ownership: dict[str, StackOwnership] = {}
    for region in context.regions:
        ownership = stack_resource_ownership(context, region)
        all_ownership.update(ownership)
        findings.extend(
            _regional_findings(
                context,
                config,
                region,
                ownership,
                include_managed,
            )
        )

    findings.extend(_s3_findings(context, config, all_ownership, include_managed))
    findings.extend(
        _cloudfront_findings(
            context,
            config,
            all_ownership,
            include_managed,
            scan_errors,
        )
    )
    return Report(
        tool=TOOL,
        profile=context.profile,
        account_ids=[context.account_id],
        regions=context.regions,
        findings=findings,
        scan_errors=scan_errors,
    )


def _regional_findings(
    context: AwsContext,
    config: AppConfig,
    region: str,
    ownership: dict[str, StackOwnership],
    include_managed: bool,
) -> list[Finding]:
    resources = []
    resources.extend(_ec2_resources(context, region))
    resources.extend(_elb_resources(context, region))
    resources.extend(_rds_resources(context, region))
    resources.extend(_lambda_resources(context, region))
    resources.extend(_logs_resources(context, region))
    return [
        _finding(context, config, region, resource, ownership)
        for resource in resources
        if include_managed or _is_orphan_candidate(resource, ownership, config)
    ]


def _is_orphan_candidate(
    resource: ResourceIdentity,
    ownership: dict[str, StackOwnership],
    config: AppConfig,
) -> bool:
    if resource.resource_id in ownership or has_stack_tag(resource.tags):
        return False
    return config.is_excluded(resource) is None


def _finding(
    context: AwsContext,
    config: AppConfig,
    region: str,
    resource: ResourceIdentity,
    ownership: dict[str, StackOwnership],
) -> Finding:
    evidence, risk, confidence, recommendation = _classification(
        resource,
        ownership,
        config,
    )
    return Finding(
        id=stable_finding_id(
            TOOL,
            context.account_id,
            region,
            resource.service,
            resource.resource_type,
            resource.resource_id,
        ),
        tool=TOOL,
        account_id=context.account_id,
        region=region,
        service=resource.service,
        resource_type=resource.resource_type,
        resource_id=resource.resource_id,
        arn=resource.arn,
        name=resource.name,
        tags=resource.tags,
        evidence=evidence,
        risk=risk,
        confidence=confidence,
        recommendation=recommendation,
    )


def _classification(
    resource: ResourceIdentity,
    ownership: dict[str, StackOwnership],
    config: AppConfig,
) -> tuple[list[str], Risk, Confidence, str]:
    owner = ownership.get(resource.resource_id)
    if owner:
        return (
            [
                "CloudFormation physical resource ID found",
                (f"Stack: {owner.stack_name} ({owner.stack_id})"),
                f"Logical resource: {owner.logical_resource_id}",
                f"CloudFormation resource type: {owner.resource_type}",
                f"Stack region: {owner.region}",
            ],
            Risk.LOW,
            Confidence.HIGH,
            "Managed by CloudFormation; no cleanup recommended",
        )
    if has_stack_tag(resource.tags):
        return (
            ["CloudFormation stack tag found"],
            Risk.LOW,
            Confidence.HIGH,
            "Managed by CloudFormation; no cleanup recommended",
        )
    excluded = config.is_excluded(resource)
    if excluded:
        return (
            [f"Excluded by rule: {excluded}"],
            Risk.LOW,
            Confidence.HIGH,
            "Excluded by configuration; no cleanup recommended",
        )
    return (
        ["No CloudFormation physical resource ID or stack tag found"],
        Risk.MEDIUM,
        Confidence.MEDIUM,
        "Review ownership before cleanup",
    )


def _ec2_resources(context: AwsContext, region: str) -> list[ResourceIdentity]:
    ec2 = client(context, "ec2", region)
    resources: list[ResourceIdentity] = []
    try:
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    resources.append(
                        ResourceIdentity(
                            service="ec2",
                            resource_type="instance",
                            resource_id=instance["InstanceId"],
                            tags=tag_dict(instance.get("Tags")),
                        )
                    )
        for page in ec2.get_paginator("describe_volumes").paginate():
            for volume in page.get("Volumes", []):
                resources.append(
                    ResourceIdentity(
                        service="ec2",
                        resource_type="volume",
                        resource_id=volume["VolumeId"],
                        tags=tag_dict(volume.get("Tags")),
                    )
                )
        for address in ec2.describe_addresses().get("Addresses", []):
            allocation_id = address.get("AllocationId")
            if allocation_id:
                resources.append(
                    ResourceIdentity(
                        service="ec2",
                        resource_type="elastic-ip",
                        resource_id=allocation_id,
                        tags=tag_dict(address.get("Tags")),
                    )
                )
        for page in ec2.get_paginator("describe_nat_gateways").paginate():
            for gateway in page.get("NatGateways", []):
                resources.append(
                    ResourceIdentity(
                        service="ec2",
                        resource_type="nat-gateway",
                        resource_id=gateway["NatGatewayId"],
                        tags=tag_dict(gateway.get("Tags")),
                    )
                )
    except ClientError:
        return resources
    return resources


def _elb_resources(context: AwsContext, region: str) -> list[ResourceIdentity]:
    elbv2 = client(context, "elbv2", region)
    resources: list[ResourceIdentity] = []
    try:
        for page in elbv2.get_paginator("describe_load_balancers").paginate():
            for lb in page.get("LoadBalancers", []):
                arn = lb["LoadBalancerArn"]
                resources.append(
                    ResourceIdentity(
                        service="elasticloadbalancing",
                        resource_type="load-balancer",
                        resource_id=arn,
                        arn=arn,
                        name=lb.get("LoadBalancerName"),
                    )
                )
        for page in elbv2.get_paginator("describe_target_groups").paginate():
            for tg in page.get("TargetGroups", []):
                arn = tg["TargetGroupArn"]
                resources.append(
                    ResourceIdentity(
                        service="elasticloadbalancing",
                        resource_type="target-group",
                        resource_id=arn,
                        arn=arn,
                        name=tg.get("TargetGroupName"),
                    )
                )
    except ClientError:
        return resources
    return resources


def _rds_resources(context: AwsContext, region: str) -> list[ResourceIdentity]:
    rds = client(context, "rds", region)
    resources: list[ResourceIdentity] = []
    try:
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                resources.append(
                    ResourceIdentity(
                        service="rds",
                        resource_type="db-instance",
                        resource_id=db["DBInstanceIdentifier"],
                        arn=db.get("DBInstanceArn"),
                    )
                )
        for page in rds.get_paginator("describe_db_clusters").paginate():
            for cluster in page.get("DBClusters", []):
                resources.append(
                    ResourceIdentity(
                        service="rds",
                        resource_type="db-cluster",
                        resource_id=cluster["DBClusterIdentifier"],
                        arn=cluster.get("DBClusterArn"),
                    )
                )
    except ClientError:
        return resources
    return resources


def _lambda_resources(context: AwsContext, region: str) -> list[ResourceIdentity]:
    lamb = client(context, "lambda", region)
    resources: list[ResourceIdentity] = []
    try:
        for page in lamb.get_paginator("list_functions").paginate():
            for function in page.get("Functions", []):
                resources.append(
                    ResourceIdentity(
                        service="lambda",
                        resource_type="function",
                        resource_id=function["FunctionName"],
                        arn=function.get("FunctionArn"),
                    )
                )
    except ClientError:
        return resources
    return resources


def _logs_resources(context: AwsContext, region: str) -> list[ResourceIdentity]:
    logs = client(context, "logs", region)
    resources: list[ResourceIdentity] = []
    try:
        for page in logs.get_paginator("describe_log_groups").paginate():
            for group in page.get("logGroups", []):
                resources.append(
                    ResourceIdentity(
                        service="logs",
                        resource_type="log-group",
                        resource_id=group["logGroupName"],
                        arn=group.get("arn"),
                    )
                )
    except ClientError:
        return resources
    return resources


def _s3_findings(
    context: AwsContext,
    config: AppConfig,
    ownership: dict[str, StackOwnership],
    include_managed: bool,
) -> list[Finding]:
    s3 = client(context, "s3")
    findings: list[Finding] = []
    try:
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            tags = _s3_bucket_tags(s3, name)
            resource = ResourceIdentity(
                service="s3",
                resource_type="bucket",
                resource_id=name,
                arn=f"arn:aws:s3:::{name}",
                name=name,
                tags=tags,
            )
            if include_managed or _is_orphan_candidate(
                resource,
                ownership,
                config,
            ):
                findings.append(
                    _finding(context, config, "global", resource, ownership)
                )
    except ClientError:
        return findings
    return findings


def _cloudfront_findings(
    context: AwsContext,
    config: AppConfig,
    ownership: dict[str, StackOwnership],
    include_managed: bool,
    scan_errors: list[ScanError],
) -> list[Finding]:
    cloudfront = client(context, "cloudfront")
    findings: list[Finding] = []
    try:
        paginator = cloudfront.get_paginator("list_distributions")
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            for distribution in items:
                arn = distribution["ARN"]
                resource = ResourceIdentity(
                    service="cloudfront",
                    resource_type="distribution",
                    resource_id=distribution["Id"],
                    arn=arn,
                    name=distribution.get("DomainName"),
                    tags=_cloudfront_tags(cloudfront, arn),
                )
                if include_managed or _is_orphan_candidate(
                    resource,
                    ownership,
                    config,
                ):
                    findings.append(
                        _finding(
                            context,
                            config,
                            "global",
                            resource,
                            ownership,
                        )
                    )
    except ClientError as exc:
        scan_errors.append(_scan_error("cloudfront", "list_distributions", exc))
        return findings
    return findings


def _s3_bucket_tags(s3, bucket_name: str) -> dict[str, str]:
    try:
        response = s3.get_bucket_tagging(Bucket=bucket_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"NoSuchTagSet", "NoSuchBucket"}:
            return {}
        raise
    return tag_dict(response.get("TagSet"))


def _cloudfront_tags(cloudfront, arn: str) -> dict[str, str]:
    try:
        response = cloudfront.list_tags_for_resource(Resource=arn)
    except ClientError:
        return {}
    return tag_dict(response.get("Tags", {}).get("Items"))


def _scan_error(service: str, operation: str, exc: ClientError) -> ScanError:
    error = exc.response.get("Error", {})
    return ScanError(
        service=service,
        operation=operation,
        region="global",
        code=error.get("Code"),
        message=error.get("Message", str(exc)),
    )
