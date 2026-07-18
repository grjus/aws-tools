from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CleanupAction(BaseModel):
    name: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    tool: str
    account_id: str
    region: str
    service: str
    resource_type: str
    resource_id: str
    arn: str | None = None
    name: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    risk: Risk = Risk.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    cleanup_eligible: bool = False
    cleanup_action: CleanupAction | None = None
    recommendation: str


class ScanError(BaseModel):
    service: str
    operation: str
    region: str
    code: str | None = None
    message: str


class FindingFilter(BaseModel):
    service: str | None = None
    resource_type: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.service and self.service != finding.service:
            return False
        if self.resource_type and self.resource_type != finding.resource_type:
            return False
        return True


class Report(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    tool: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    profile: str | None = None
    account_ids: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    filters: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    scan_errors: list[ScanError] = Field(default_factory=list)

    def write_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path


def stable_finding_id(
    tool: str,
    account_id: str,
    region: str,
    service: str,
    resource_type: str,
    resource_id: str,
) -> str:
    raw = ":".join([tool, account_id, region, service, resource_type, resource_id])
    digest = sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{tool}-{digest}"
