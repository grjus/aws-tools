from __future__ import annotations

from dataclasses import dataclass

import boto3

from aws_tools.config import AppConfig


@dataclass(frozen=True)
class AwsContext:
    session: boto3.Session
    account_id: str
    profile: str | None
    regions: list[str]
    assumed_role_arn: str | None = None


def create_context(
    config: AppConfig,
    assume_read_only_role: bool = True,
) -> AwsContext:
    session = boto3.Session(profile_name=config.profile)
    regions = config.regions or [_default_region(session)]
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


def _assume_role_session(
    source_session: boto3.Session,
    role_arn: str,
    session_name: str,
) -> boto3.Session:
    credentials = source_session.client("sts").assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=source_session.region_name,
    )
