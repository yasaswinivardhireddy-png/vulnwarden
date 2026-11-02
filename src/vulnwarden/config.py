"""Configuration loaded from vulnwarden.yaml (all fields optional)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

DEFAULT_EXCLUDES = [
    ".git",
    ".hg",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    ".vulnwarden",
]


class MonitorConfig(BaseModel):
    label: str = "security-remediation"
    remind_after_hours: float = 24.0
    escalate_after_hours: float = 72.0
    repeat_every_hours: float = 24.0


class NotifyConfig(BaseModel):
    channels: list[str] = Field(default_factory=lambda: ["console"])
    email_to: list[str] = Field(default_factory=list)
    escalation_email_to: list[str] = Field(default_factory=list)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_sender: str = "vulnwarden@localhost"
    smtp_username_env: str = "VULNWARDEN_SMTP_USERNAME"
    smtp_password_env: str = "VULNWARDEN_SMTP_PASSWORD"  # noqa: S105 - environment variable name, not a secret
    slack_webhook_env: str = "VULNWARDEN_SLACK_WEBHOOK"
    teams_webhook_env: str = "VULNWARDEN_TEAMS_WEBHOOK"


class RemediationConfig(BaseModel):
    test_command: list[str] = Field(default_factory=lambda: ["{python}", "-m", "pytest", "-q"])
    test_timeout_seconds: int = 900
    max_fixes: int = 25
    max_priority: str = "P3"
    branch_prefix: str = "vulnwarden/remediation"


class LLMConfig(BaseModel):
    provider: str = "none"
    model: str = "gemini-3.5-flash"
    min_confidence: float = 0.6
    context_lines: int = 8


class Config(BaseModel):
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    exposure: str = "internal"
    sla_hours: dict[str, int] = Field(default_factory=lambda: {"P1": 72, "P2": 168, "P3": 720, "P4": 2160})
    owners: list[str] = Field(default_factory=list)
    escalation_contacts: list[str] = Field(default_factory=list)
    crypto_policy: str | None = None
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)


def load_config(path: str | Path | None = None, repo: str | Path | None = None) -> Config:
    """Load config from an explicit path, else <repo>/vulnwarden.yaml, else defaults."""
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    elif repo:
        candidates.append(Path(repo) / "vulnwarden.yaml")
    for candidate in candidates:
        if candidate.is_file():
            data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            config = Config.model_validate(data)
            for name in DEFAULT_EXCLUDES:
                if name not in config.exclude:
                    config.exclude.append(name)
            return config
        if path:
            raise FileNotFoundError(f"Config file not found: {candidate}")
    return Config()
