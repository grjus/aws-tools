from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import boto3

from aws_tools.config import AppConfig


@dataclass(frozen=True)
class AwsContext:
    session: boto3.Session
    account_id: str
    profile: str | None
    regions: list[str]
    assumed_role_arn: str | None = None


@dataclass(frozen=True)
class AssumedRoleCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    role_arn: str
    session_name: str


def create_context(
    config: AppConfig,
    assume_read_only_role: bool = True,
    require_regions: bool = True,
) -> AwsContext:
    session = boto3.Session(profile_name=config.profile)
    regions = config.regions or _context_regions(session, require_regions)
    assumed_role_arn = None
    if assume_read_only_role and config.read_only_role_arn:
        session = _assume_role_session(
            source_session=session,
            role_arn=config.read_only_role_arn,
            session_name=config.role_session_name,
        )
        assumed_role_arn = config.read_only_role_arn
    account_id = session.client("sts").get_caller_identity()["Account"]
    return AwsContext(
        session=session,
        account_id=account_id,
        profile=config.profile,
        regions=regions,
        assumed_role_arn=assumed_role_arn,
    )


def client(context: AwsContext, service: str, region: str | None = None):
    return context.session.client(service, region_name=region)


def _default_region(session: boto3.Session) -> str:
    region = session.region_name
    if not region:
        raise ValueError(
            "No AWS region configured. Set AWS_REGIONS in .env or pass --regions."
        )
    return region


def _context_regions(session: boto3.Session, require_regions: bool) -> list[str]:
    if session.region_name:
        return [session.region_name]
    if require_regions:
        return [_default_region(session)]
    return []


def _assume_role_session(
    source_session: boto3.Session,
    role_arn: str,
    session_name: str,
) -> boto3.Session:
    credentials = assume_role_credentials(
        source_session=source_session,
        role_arn=role_arn,
        session_name=session_name,
    )
    return boto3.Session(
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
        aws_session_token=credentials.session_token,
        region_name=source_session.region_name,
    )


def assume_role_credentials(
    source_session: boto3.Session,
    role_arn: str,
    session_name: str,
    duration_seconds: int | None = None,
) -> AssumedRoleCredentials:
    request = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
    }
    if duration_seconds is not None:
        request["DurationSeconds"] = duration_seconds
    credentials = source_session.client("sts").assume_role(**request)["Credentials"]
    return AssumedRoleCredentials(
        access_key_id=credentials["AccessKeyId"],
        secret_access_key=credentials["SecretAccessKey"],
        session_token=credentials["SessionToken"],
        expiration=credentials["Expiration"],
        role_arn=role_arn,
        session_name=session_name,
    )
