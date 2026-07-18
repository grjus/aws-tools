from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator


class ExclusionRule(BaseModel):
    service: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    arn: str | None = None
    name_pattern: str | None = None
    tag_key: str | None = None
    tag_value: str | None = None
    reason: str = "Configured exclusion"

    @model_validator(mode="after")
    def require_match_field(self) -> "ExclusionRule":
        fields = [
            self.service,
            self.resource_type,
            self.resource_id,
            self.arn,
            self.name_pattern,
            self.tag_key,
        ]
        if not any(value is not None for value in fields):
            raise ValueError("Exclusion rule must define at least one matcher")
        return self

    def matches(self, resource: "ResourceIdentity") -> bool:
        checks = [
            self.service is None or self.service == resource.service,
            self.resource_type is None or self.resource_type == resource.resource_type,
            self.resource_id is None or self.resource_id == resource.resource_id,
            self.arn is None or self.arn == resource.arn,
            self.name_pattern is None
            or fnmatch(resource.name or "", self.name_pattern),
        ]
        if self.tag_key is not None:
            value = resource.tags.get(self.tag_key)
            checks.append(value is not None)
            if self.tag_value is not None:
                checks.append(value == self.tag_value)
        return all(checks)


class ResourceIdentity(BaseModel):
    service: str
    resource_type: str
    resource_id: str
    arn: str | None = None
    name: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class AppConfig(BaseModel):
    profile: str | None = None
    regions: list[str] = Field(default_factory=list)
    read_only_role_arn: str | None = None
    role_session_name: str = "aws-tools-read-only"
    reports_dir: Path = Path(".aws-tools/reports")
    exclusions: list[ExclusionRule] = Field(default_factory=list)
    required_tags: list[str] = Field(
        default_factory=lambda: ["Owner", "Environment", "CostCenter"]
    )
    log_retention_days: int = 30

    @field_validator("log_retention_days")
    @classmethod
    def validate_log_retention_days(cls, value: int) -> int:
        allowed = {
            1,
            3,
            5,
            7,
            14,
            30,
            60,
            90,
            120,
            150,
            180,
            365,
            400,
            545,
            731,
            1096,
            1827,
            2192,
            2557,
            2922,
            3288,
            3653,
        }
        if value not in allowed:
            raise ValueError("Invalid CloudWatch Logs retention day value")
        return value

    def is_excluded(self, resource: ResourceIdentity) -> str | None:
        for rule in built_in_exclusions() + self.exclusions:
            if rule.matches(resource):
                return rule.reason
        return None


def built_in_exclusions() -> list[ExclusionRule]:
    return [
        ExclusionRule(
            service="s3",
            name_pattern="cdk-*-assets-*",
            reason="CDK bootstrap assets bucket",
        ),
        ExclusionRule(
            name_pattern="CDKToolkit",
            reason="CDK bootstrap stack resource",
        ),
        ExclusionRule(
            name_pattern="hnb659fds-*",
            reason="CDK bootstrap qualifier resource",
        ),
    ]


def load_config(
    profile: str | None = None,
    regions: list[str] | None = None,
    read_only_role_arn: str | None = None,
    config_path: Path = Path(".aws-tools/config.yaml"),
) -> AppConfig:
    load_dotenv()
    file_values = {}
    if config_path.exists():
        file_values = yaml.safe_load(config_path.read_text("utf-8")) or {}

    env_regions = _split_regions(os.getenv("AWS_REGIONS"))
    config = AppConfig.model_validate(file_values)
    config.profile = profile or os.getenv("AWS_PROFILE") or config.profile
    config.regions = regions or env_regions or config.regions
    config.read_only_role_arn = (
        read_only_role_arn
        or os.getenv("AWS_READ_ONLY_ROLE_ARN")
        or config.read_only_role_arn
    )
    return config


def _split_regions(value: str | None) -> list[str]:
    if not value:
        return []
    return [region.strip() for region in value.split(",") if region.strip()]
