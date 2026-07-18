from __future__ import annotations

from botocore.exceptions import ClientError
from pydantic import BaseModel

from aws_tools.aws import AwsContext, client


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
