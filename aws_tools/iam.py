from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, Field

from aws_tools.aws import AwsContext, AssumedRoleCredentials, assume_role_credentials
from aws_tools.aws import client as aws_client


class RoleSummary(BaseModel):
    role_name: str
    arn: str
    path: str = "/"
    created_at: datetime
    description: str | None = None
    max_session_duration: int | None = None


class RoleSearchResult(BaseModel):
    name_regex: str
    account_id: str
    profile: str | None = None
    roles: list[RoleSummary] = Field(default_factory=list)


def list_roles_matching(context: AwsContext, name_regex: str) -> RoleSearchResult:
    pattern = re.compile(name_regex)
    iam = aws_client(context, "iam")
    roles: list[RoleSummary] = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            if not pattern.search(role_name):
                continue
            roles.append(
                RoleSummary(
                    role_name=role_name,
                    arn=role["Arn"],
                    path=role.get("Path", "/"),
                    created_at=role["CreateDate"],
                    description=role.get("Description"),
                    max_session_duration=role.get("MaxSessionDuration"),
                )
            )
    roles.sort(key=lambda role: role.role_name.lower())
    return RoleSearchResult(
        name_regex=name_regex,
        account_id=context.account_id,
        profile=context.profile,
        roles=roles,
    )


def assume_role(
    context: AwsContext,
    role_arn: str,
    session_name: str,
    duration_seconds: int | None = None,
) -> AssumedRoleCredentials:
    return assume_role_credentials(
        source_session=context.session,
        role_arn=role_arn,
        session_name=session_name,
        duration_seconds=duration_seconds,
    )
