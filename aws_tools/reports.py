from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import TypeAdapter

from aws_tools.config import AppConfig
from aws_tools.models import Report


def default_report_path(config: AppConfig, tool: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return config.reports_dir / f"{timestamp}-{tool}.json"


def load_report(path: Path) -> Report:
    adapter = TypeAdapter(Report)
    return adapter.validate_json(path.read_text(encoding="utf-8"))
