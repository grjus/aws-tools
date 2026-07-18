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
    CleanupAction,
    Finding,
    Report,
    Risk,
    ScanError,
    stable_finding_id,
)
from aws_tools.scanners.common import stack_fields, stack_owner_for, tag_dict


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
    resources.extend(_dynamodb_resources(context, region))
    resources.extend(_opensearch_serverless_resources(context, region))
    resources.extend(_bedrock_resources(context, region))
    resources.extend(_sagemaker_resources(context, region))
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
    cleanup_action = _cleanup_action(resource, ownership, config)
    owner = stack_owner_for(ownership, resource.resource_id, resource.arn, resource.name)
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
        **stack_fields(owner),
        tags=resource.tags,
        evidence=evidence,
        risk=risk,
        confidence=confidence,
        cleanup_eligible=cleanup_action is not None,
        cleanup_action=cleanup_action,
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
        _orphan_risk(resource),
        Confidence.MEDIUM,
        _orphan_recommendation(resource),
    )


def _cleanup_action(
    resource: ResourceIdentity,
    ownership: dict[str, StackOwnership],
    config: AppConfig,
) -> CleanupAction | None:
    if not _is_orphan_candidate(resource, ownership, config):
        return None
    if resource.service == "logs" and resource.resource_type == "log-group":
        return CleanupAction(
            name="logs.delete_log_group",
            parameters={"log_group_name": resource.resource_id},
        )
    if resource.service == "s3" and resource.resource_type == "bucket":
        return CleanupAction(
            name="s3.empty_and_delete_bucket",
            parameters={"bucket_name": resource.resource_id},
        )
    return None


def _orphan_risk(resource: ResourceIdentity) -> Risk:
    if resource.service == "logs":
        return Risk.LOW
    if resource.service == "s3":
        return Risk.HIGH
    return Risk.MEDIUM


def _orphan_recommendation(resource: ResourceIdentity) -> str:
    if resource.service == "logs":
        return "Delete orphaned log group if logs are no longer needed"
    if resource.service == "s3":
        return "Empty and delete after bucket state checks pass"
    return "Review ownership before cleanup"


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


def _dynamodb_resources(
    context: AwsContext,
    region: str,
) -> list[ResourceIdentity]:
    dynamodb = client(context, "dynamodb", region)
    resources: list[ResourceIdentity] = []
    try:
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                table = dynamodb.describe_table(TableName=table_name)["Table"]
                resources.append(
                    ResourceIdentity(
                        service="dynamodb",
                        resource_type="table",
                        resource_id=table_name,
                        arn=table.get("TableArn"),
                        name=table_name,
                    )
                )
    except ClientError:
        return resources
    return resources


def _opensearch_serverless_resources(
    context: AwsContext,
    region: str,
) -> list[ResourceIdentity]:
    aoss = client(context, "opensearchserverless", region)
    resources: list[ResourceIdentity] = []
    try:
        for collection in aoss.list_collections().get("collectionSummaries", []):
            resources.append(
                ResourceIdentity(
                    service="opensearchserverless",
                    resource_type="collection",
                    resource_id=collection["id"],
                    arn=collection.get("arn"),
                    name=collection.get("name"),
                )
            )
    except ClientError:
        return resources
    return resources


def _bedrock_resources(context: AwsContext, region: str) -> list[ResourceIdentity]:
    bedrock = client(context, "bedrock-agent", region)
    resources: list[ResourceIdentity] = []
    try:
        paginator = bedrock.get_paginator("list_knowledge_bases")
        for page in paginator.paginate():
            for kb in page.get("knowledgeBaseSummaries", []):
                resources.append(
                    ResourceIdentity(
                        service="bedrock-agent",
                        resource_type="knowledge-base",
                        resource_id=kb["knowledgeBaseId"],
                        name=kb.get("name"),
                    )
                )
    except ClientError:
        return resources
    return resources


def _sagemaker_resources(
    context: AwsContext,
    region: str,
) -> list[ResourceIdentity]:
    sagemaker = client(context, "sagemaker", region)
    resources: list[ResourceIdentity] = []
    try:
        for resource_type in _SAGEMAKER_LIST_OPERATIONS:
            resources.extend(_sagemaker_named_resources(sagemaker, resource_type))
    except ClientError:
        return resources
    return resources


def _sagemaker_named_resources(sagemaker, resource_type: str) -> list[ResourceIdentity]:
    operation, key, id_key, arn_key = _SAGEMAKER_LIST_OPERATIONS[resource_type]
    resources: list[ResourceIdentity] = []
    paginator = sagemaker.get_paginator(operation)
    for page in paginator.paginate():
        for item in page.get(key, []):
            resource_id = item[id_key]
            resources.append(
                ResourceIdentity(
                    service="sagemaker",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    arn=item.get(arn_key),
                    name=resource_id,
                )
            )
    return resources


_SAGEMAKER_LIST_OPERATIONS = {
    "notebook-instance": (
        "list_notebook_instances",
        "NotebookInstances",
        "NotebookInstanceName",
        "NotebookInstanceArn",
    ),
    "endpoint": ("list_endpoints", "Endpoints", "EndpointName", "EndpointArn"),
    "model": ("list_models", "Models", "ModelName", "ModelArn"),
    "training-job": (
        "list_training_jobs",
        "TrainingJobSummaries",
        "TrainingJobName",
        "TrainingJobArn",
    ),
    "processing-job": (
        "list_processing_jobs",
        "ProcessingJobSummaries",
        "ProcessingJobName",
        "ProcessingJobArn",
    ),
    "transform-job": (
        "list_transform_jobs",
        "TransformJobSummaries",
        "TransformJobName",
        "TransformJobArn",
    ),
    "domain": ("list_domains", "Domains", "DomainId", "DomainArn"),
    "app": ("list_apps", "Apps", "AppName", "AppArn"),
    "feature-group": (
        "list_feature_groups",
        "FeatureGroupSummaries",
        "FeatureGroupName",
        "FeatureGroupArn",
    ),
    "workteam": ("list_workteams", "Workteams", "WorkteamName", "WorkteamArn"),
}


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
