"""Core data models shared by scanners, triage, remediation and reporting."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @property
    def default_score(self) -> float:
        return _DEFAULT_SCORE[self.value]

    @classmethod
    def from_score(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def parse(cls, value: str | None, default: Severity | None = None) -> Severity:
        text = (value or "").strip().lower()
        mapped = _ALIASES.get(text)
        if mapped is not None:
            return cls(mapped)
        return default if default is not None else cls.MEDIUM


_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_DEFAULT_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
_ALIASES = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "important": "high",
    "moderate": "medium",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "note": "low",
    "negligible": "info",
    "info": "info",
    "informational": "info",
    "none": "info",
}


class Category(StrEnum):
    CODE = "code"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    CRYPTO = "crypto"
    API = "api"


_WS = re.compile(r"\s+")


class Finding(BaseModel):
    """A single security issue, normalized across every scanner and import format."""

    rule_id: str
    title: str
    category: Category
    severity: Severity
    source: str
    path: str
    line: int | None = None
    message: str = ""
    snippet: str = ""
    cwe: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    package: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    fix_hint: str = ""
    occurrence: int = 0
    # Triage enrichment
    epss: float | None = None
    in_kev: bool = False
    reachable: bool | None = None
    risk_score: float | None = None
    priority: str | None = None
    sla_hours: int | None = None
    status: str = "open"
    sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def vuln_id(self) -> str | None:
        """Canonical vulnerability id: the first CVE alias, else the first advisory id."""
        cves = sorted(a for a in self.aliases if a.upper().startswith("CVE-"))
        if cves:
            return cves[0].upper()
        return sorted(self.aliases)[0] if self.aliases else None

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication, tracking and reconciliation.

        Dependency findings ignore the installed version so an upgrade that is still
        vulnerable keeps the same identity. Code findings use the normalized flagged
        line instead of the line number so unrelated edits do not create new findings.
        """
        if self.package:
            key = "|".join(
                [
                    self.category.value,
                    (self.ecosystem or "").lower(),
                    normalize_package(self.package, self.ecosystem),
                    self.vuln_id or self.rule_id,
                ]
            )
        else:
            anchor = _WS.sub(" ", self.snippet).strip() or str(self.line or 0)
            key = f"{self.rule_id}|{self.path}|{anchor}|{self.occurrence}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    @property
    def is_open(self) -> bool:
        return self.status == "open"


def normalize_package(name: str, ecosystem: str | None = None) -> str:
    if (ecosystem or "").lower() in {"pypi", "pip", ""}:
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def assign_occurrences(findings: list[Finding]) -> list[Finding]:
    """Disambiguate identical flagged lines within the same file so each keeps its own identity."""
    seen: dict[tuple[str, str, str], int] = {}
    for finding in sorted(findings, key=lambda f: (f.path, f.line or 0)):
        if finding.package:
            continue
        key = (finding.rule_id, finding.path, _WS.sub(" ", finding.snippet).strip())
        finding.occurrence = seen.get(key, 0)
        seen[key] = finding.occurrence + 1
    return findings


class CryptoAsset(BaseModel):
    """An inventoried cryptographic asset (algorithm, certificate, protocol, key or library)."""

    asset_type: str
    name: str
    path: str
    line: int | None = None
    primitive: str | None = None
    key_size: int | None = None
    mode: str | None = None
    evidence: str = ""
    quantum_vulnerable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    repo: str
    findings: list[Finding] = Field(default_factory=list)
    crypto_assets: list[CryptoAsset] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_open]
