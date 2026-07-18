from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from botocore.exceptions import ClientError
from pydantic import BaseModel, Field

from aws_tools.aws import AwsContext, client
from aws_tools.models import ScanError


ACTIVE_STACK_STATUSES = [
    "CREATE_COMPLETE",
    "CREATE_IN_PROGRESS",
    "DELETE_FAILED",
    "IMPORT_COMPLETE",
    "IMPORT_IN_PROGRESS",
    "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
    "IMPORT_ROLLBACK_IN_PROGRESS",
    "REVIEW_IN_PROGRESS",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "ROLLBACK_IN_PROGRESS",
    "UPDATE_COMPLETE",
    "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
    "UPDATE_IN_PROGRESS",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
    "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_IN_PROGRESS",
]


class StackOwnership(BaseModel):
    stack_id: str
    stack_name: str
    logical_resource_id: str
    resource_type: str
    region: str


class StackInventoryItem(BaseModel):
    account_id: str
    region: str
    stack_id: str
    stack_name: str
    stack_status: str
    creation_time: datetime
    last_updated_time: datetime | None = None
    description: str | None = None
    drift_status: str | None = None
    drift_last_checked_at: datetime | None = None
    termination_protection_enabled: bool | None = None
    parent_id: str | None = None
    root_id: str | None = None
    role_arn: str | None = None
    timeout_minutes: int | None = None
    notification_arns: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    resource_count: int = 0
    resource_types: dict[str, int] = Field(default_factory=dict)
    parameter_keys: list[str] = Field(default_factory=list)
    output_keys: list[str] = Field(default_factory=list)
    tag_keys: list[str] = Field(default_factory=list)


class StackInventory(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    account_id: str
    profile: str | None = None
    regions: list[str] = Field(default_factory=list)
    stacks: list[StackInventoryItem] = Field(default_factory=list)
    scan_errors: list[ScanError] = Field(default_factory=list)


class StackResource(BaseModel):
    logical_resource_id: str
    physical_resource_id: str | None = None
    resource_type: str
    resource_status: str | None = None
    resource_status_reason: str | None = None
    last_updated_time: datetime | None = None
    drift_status: str | None = None
    module_info: dict[str, str] = Field(default_factory=dict)


class StackDetails(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    account_id: str
    profile: str | None = None
    regions: list[str] = Field(default_factory=list)
    stack_name: str
    stacks: list[StackInventoryItem] = Field(default_factory=list)
    resources: dict[str, list[StackResource]] = Field(default_factory=dict)
    scan_errors: list[ScanError] = Field(default_factory=list)


def deployed_stack_inventory(context: AwsContext) -> StackInventory:
    stacks: list[StackInventoryItem] = []
    errors: list[ScanError] = []
    for region in context.regions:
        cfn = client(context, "cloudformation", region)
        try:
            paginator = cfn.get_paginator("list_stacks")
            for page in paginator.paginate(StackStatusFilter=ACTIVE_STACK_STATUSES):
                for summary in page.get("StackSummaries", []):
                    try:
                        stacks.append(
                            _stack_inventory_item(
                                context=context,
                                cfn=cfn,
                                region=region,
                                stack_id=summary["StackId"],
                            )
                        )
                    except ClientError as exc:
                        errors.append(_scan_error("describe_stacks", region, exc))
        except ClientError as exc:
            errors.append(_scan_error("list_stacks", region, exc))
    stacks.sort(key=lambda item: (item.region, item.stack_name.lower()))
    return StackInventory(
        account_id=context.account_id,
        profile=context.profile,
        regions=context.regions,
        stacks=stacks,
        scan_errors=errors,
    )


def stack_details(context: AwsContext, stack_name: str) -> StackDetails:
    stacks: list[StackInventoryItem] = []
    resources: dict[str, list[StackResource]] = {}
    errors: list[ScanError] = []
    for region in context.regions:
        cfn = client(context, "cloudformation", region)
        try:
            stack = _stack_inventory_item(
                context=context,
                cfn=cfn,
                region=region,
                stack_id=stack_name,
            )
        except ClientError as exc:
            if _client_error_code(exc) != "ValidationError":
                errors.append(_scan_error("describe_stacks", region, exc))
            continue
        stacks.append(stack)
        try:
            resources[stack.stack_id] = _stack_resources(cfn, stack.stack_id)
        except ClientError as exc:
            errors.append(_scan_error("list_stack_resources", region, exc))
            resources[stack.stack_id] = []
    stacks.sort(key=lambda item: (item.region, item.stack_name.lower()))
    return StackDetails(
        account_id=context.account_id,
        profile=context.profile,
        regions=context.regions,
        stack_name=stack_name,
        stacks=stacks,
        resources=resources,
        scan_errors=errors,
    )


def stack_resource_ownership(
    context: AwsContext,
    region: str,
) -> dict[str, StackOwnership]:
    cfn = client(context, "cloudformation", region)
    resources: dict[str, StackOwnership] = {}
    try:
        paginator = cfn.get_paginator("list_stacks")
        for page in paginator.paginate(StackStatusFilter=ACTIVE_STACK_STATUSES):
            for summary in page.get("StackSummaries", []):
                resources.update(
                    _resources_for_stack(
                        cfn,
                        summary["StackId"],
                        summary["StackName"],
                        region,
                    )
                )
    except ClientError:
        return resources
    return resources


def stack_resource_ids(context: AwsContext, region: str) -> set[str]:
    return set(stack_resource_ownership(context, region))


def has_stack_tag(tags: dict[str, str]) -> bool:
    return any(key.startswith("aws:cloudformation:") for key in tags)


def _stack_inventory_item(
    context: AwsContext,
    cfn,
    region: str,
    stack_id: str,
) -> StackInventoryItem:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    resources = _resource_type_counts(cfn, stack_id)
    drift = stack.get("DriftInformation", {})
    return StackInventoryItem(
        account_id=context.account_id,
        region=region,
        stack_id=stack["StackId"],
        stack_name=stack["StackName"],
        stack_status=stack["StackStatus"],
        creation_time=stack["CreationTime"],
        last_updated_time=stack.get("LastUpdatedTime"),
        description=stack.get("Description"),
        drift_status=drift.get("StackDriftStatus"),
        drift_last_checked_at=drift.get("LastCheckTimestamp"),
        termination_protection_enabled=stack.get("EnableTerminationProtection"),
        parent_id=stack.get("ParentId"),
        root_id=stack.get("RootId"),
        role_arn=stack.get("RoleARN"),
        timeout_minutes=stack.get("TimeoutInMinutes"),
        notification_arns=stack.get("NotificationARNs", []),
        capabilities=stack.get("Capabilities", []),
        resource_count=sum(resources.values()),
        resource_types=dict(sorted(resources.items())),
        parameter_keys=sorted(
            parameter["ParameterKey"] for parameter in stack.get("Parameters", [])
        ),
        output_keys=sorted(output["OutputKey"] for output in stack.get("Outputs", [])),
        tag_keys=sorted(tag["Key"] for tag in stack.get("Tags", [])),
    )


def _resources_for_stack(
    cfn,
    stack_id: str,
    stack_name: str,
    region: str,
) -> dict[str, StackOwnership]:
    resources: dict[str, StackOwnership] = {}
    paginator = cfn.get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=stack_id):
        for resource in page.get("StackResourceSummaries", []):
            physical_id = resource.get("PhysicalResourceId")
            if physical_id:
                resources[physical_id] = StackOwnership(
                    stack_id=stack_id,
                    stack_name=stack_name,
                    logical_resource_id=resource["LogicalResourceId"],
                    resource_type=resource["ResourceType"],
                    region=region,
                )
    return resources


def _stack_resources(cfn, stack_id: str) -> list[StackResource]:
    resources: list[StackResource] = []
    paginator = cfn.get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=stack_id):
        for resource in page.get("StackResourceSummaries", []):
            drift = resource.get("DriftInformation", {})
            module = resource.get("ModuleInfo", {})
            resources.append(
                StackResource(
                    logical_resource_id=resource["LogicalResourceId"],
                    physical_resource_id=resource.get("PhysicalResourceId"),
                    resource_type=resource["ResourceType"],
                    resource_status=resource.get("ResourceStatus"),
                    resource_status_reason=resource.get("ResourceStatusReason"),
                    last_updated_time=resource.get("LastUpdatedTimestamp"),
                    drift_status=drift.get("StackResourceDriftStatus"),
                    module_info={
                        key: value
                        for key, value in {
                            "type_hierarchy": module.get("TypeHierarchy"),
                            "logical_id_hierarchy": module.get("LogicalIdHierarchy"),
                        }.items()
                        if value
                    },
                )
            )
    resources.sort(key=lambda item: (item.resource_type, item.logical_resource_id))
    return resources


def _resource_type_counts(cfn, stack_id: str) -> Counter[str]:
    resources: Counter[str] = Counter()
    paginator = cfn.get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=stack_id):
        for resource in page.get("StackResourceSummaries", []):
            resources[resource["ResourceType"]] += 1
    return resources


def _client_error_code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")


def _scan_error(operation: str, region: str, exc: ClientError) -> ScanError:
    error = exc.response.get("Error", {})
    return ScanError(
        service="cloudformation",
        operation=operation,
        region=region,
        code=error.get("Code"),
        message=error.get("Message", str(exc)),
    )
