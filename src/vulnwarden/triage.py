"""Triage: correlate findings across scanners, detect stale reports, reclassify severity and prioritize."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .config import Config
from .files import read_text
from .intel import Intel
from .models import Category, Finding, Severity, normalize_package
from .scanners.dependencies import version_key

IMPORT_NAMES = {
    "pyyaml": ["yaml"],
    "pycrypto": ["Crypto"],
    "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"],
    "pyjwt": ["jwt"],
    "pyopenssl": ["OpenSSL"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"],
    "python-dateutil": ["dateutil"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "protobuf": ["google"],
    "python-jose": ["jose"],
    "pynacl": ["nacl"],
    "m2crypto": ["M2Crypto"],
    "attrs": ["attr", "attrs"],
}
PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
_WS = re.compile(r"\s+")


def import_names(package: str) -> list[str]:
    key = normalize_package(package)
    return IMPORT_NAMES.get(key, [key.replace("-", "_")])


def _version(value: str | None) -> Version | None:
    try:
        return Version(value) if value else None
    except InvalidVersion:
        return None


def _prefer(finding: Finding) -> tuple[int, int, int]:
    first_party = finding.source.startswith(("vulnwarden", "osv"))
    return (int(first_party), int(finding.cvss_vector is not None), finding.severity.rank)


def correlate(findings: list[Finding], root: Path, manifest: list[dict[str, Any]]) -> dict[str, int]:
    """Merge duplicates, flag stale/discrepant reports and reconcile severities. Mutates findings."""
    stats: Counter[str] = Counter()

    for finding in findings:
        if finding.cvss_score is None:
            continue
        computed = Severity.from_score(finding.cvss_score)
        if computed != finding.severity:
            finding.details["reported_severity"] = finding.severity.value
            finding.notes.append(
                f"Severity reclassified from {finding.severity.value} ({finding.source}) to {computed.value} "
                f"(CVSS base {finding.cvss_score:.1f})."
            )
            finding.severity = computed
            stats["reclassified"] += 1

    groups: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.package and finding.is_open and finding.vuln_id:
            key = (
                (finding.ecosystem or "").lower(),
                normalize_package(finding.package, finding.ecosystem),
                finding.vuln_id,
            )
            groups[key].append(finding)
    for group in groups.values():
        if len(group) < 2:
            continue
        primary = max(group, key=_prefer)
        for other in group:
            if other is primary:
                continue
            other.status = "duplicate"
            other.notes.append(f"Duplicate of the {primary.source} finding for {primary.vuln_id}.")
            primary.sources = sorted(set(primary.sources) | set(other.sources))
            primary.aliases = sorted(set(primary.aliases) | set(other.aliases))
            if other.source == primary.source:
                stats["duplicate_advisories"] += 1  # e.g. the same CVE published as both GHSA and PYSEC
                continue
            stats["duplicates"] += 1
            reported = other.details.get("reported_severity", other.severity.value)
            if reported != primary.severity.value:
                primary.notes.append(
                    f"Severity reclassified: {other.source} reported {reported}, "
                    f"{primary.source} data gives {primary.severity.value}."
                )
                if "reported_severity" not in other.details:
                    stats["reclassified"] += 1

    by_path: dict[str, list[Finding]] = defaultdict(list)
    for finding in sorted((f for f in findings if not f.package and f.is_open), key=_prefer, reverse=True):
        kept = by_path[finding.path]
        match = next(
            (
                k
                for k in kept
                if k.source != finding.source
                and abs((k.line or 0) - (finding.line or 0)) <= 1
                and (set(k.cwe) & set(finding.cwe))
            ),
            None,
        )
        if match is None:
            kept.append(finding)
            continue
        finding.status = "duplicate"
        finding.notes.append(f"Duplicate of {match.rule_id} at {match.path}:{match.line} ({match.source}).")
        match.sources = sorted(set(match.sources) | set(finding.sources))
        stats["duplicates"] += 1

    declared: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dep in manifest:
        declared[normalize_package(dep["name"], dep["ecosystem"])].append(dep)
    file_cache: dict[str, str | None] = {}
    for finding in findings:
        if not finding.is_open:
            continue
        if finding.package and finding.category == Category.DEPENDENCY and finding.source != "osv":
            entries = declared.get(normalize_package(finding.package, finding.ecosystem), [])
            same_file = [d for d in entries if d["path"] == finding.path] or entries
            if not same_file:
                _stale(finding, "Package is no longer declared in any manifest.", stats)
                continue
            current = _version(same_file[0].get("version"))
            reported = _version(finding.installed_version)
            fixes = sorted((v for v in map(_version, finding.fixed_versions) if v), key=str)
            if current and reported and current != reported and fixes and current >= min(fixes):
                _stale(
                    finding,
                    f"Reporting discrepancy: manifest pins {current}, at or above the fixed "
                    f"{min(fixes)} (scanner saw {reported}).",
                    stats,
                )
        elif not finding.package and finding.source.startswith("sarif:"):
            if finding.path not in file_cache:
                file = root / finding.path
                file_cache[finding.path] = read_text(file) if file.is_file() else None
            text = file_cache[finding.path]
            if text is None:
                _stale(finding, "Flagged file no longer exists.", stats)
            elif finding.snippet and _WS.sub(" ", finding.snippet).strip() not in _WS.sub(" ", text):
                _stale(finding, "Flagged code is no longer present.", stats)
    return dict(stats)


def _stale(finding: Finding, reason: str, stats: Counter[str]) -> None:
    finding.status = "stale"
    finding.notes.append(reason)
    stats["stale"] += 1


def risk_score(finding: Finding, exposure: str) -> tuple[float, list[str]]:
    base = finding.cvss_score if finding.cvss_score is not None else finding.severity.default_score
    reasons = [f"{'CVSS' if finding.cvss_score is not None else 'severity'} base {base:.1f}"]
    score = base
    if finding.in_kev:
        score += 2.0
        reasons.append("listed in CISA KEV (+2.0)")
    if finding.epss is not None and finding.epss >= 0.01:
        bump = round(2.0 * finding.epss, 2)
        score += bump
        reasons.append(f"EPSS {finding.epss:.3f} (+{bump})")
    if exposure == "internet-facing" and finding.category in {
        Category.CODE,
        Category.API,
        Category.DEPENDENCY,
        Category.CONTAINER,
    }:
        score += 0.5
        reasons.append("internet-facing service (+0.5)")
    if finding.reachable is False:
        score -= 1.0
        reasons.append("package not imported by first-party code (-1.0)")
    elif finding.reachable:
        reasons.append("package imported by first-party code")
    return max(0.0, min(10.0, score)), reasons


def priority_for(finding: Finding, score: float) -> str:
    if finding.in_kev or score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.0:
        return "P3"
    return "P4"


def prioritize(findings: list[Finding], intel: Intel, config: Config, imported_modules: set[str]) -> None:
    """Enrich open findings with EPSS/KEV/reachability, then score, prioritize and sort in place."""
    open_findings = [f for f in findings if f.is_open]
    cves = {a.upper() for f in open_findings for a in f.aliases if a.upper().startswith("CVE-")}
    epss = intel.epss(cves) if cves else {}
    kev = intel.kev() if cves else set()
    for finding in open_findings:
        ids = [a.upper() for a in finding.aliases if a.upper().startswith("CVE-")]
        scores = [epss[c] for c in ids if c in epss]
        finding.epss = max(scores) if scores else None
        finding.in_kev = any(c in kev for c in ids)
        if finding.package and (finding.ecosystem or "").lower() == "pypi" and imported_modules:
            finding.reachable = any(name in imported_modules for name in import_names(finding.package))
        score, reasons = risk_score(finding, config.exposure)
        finding.risk_score = round(score, 2)
        finding.priority = priority_for(finding, score)
        finding.sla_hours = config.sla_hours.get(finding.priority)
        finding.details["risk_factors"] = reasons
    findings.sort(
        key=lambda f: (
            0 if f.is_open else 1,
            PRIORITY_RANK.get(f.priority or "P4", 4),
            -(f.risk_score or 0.0),
            f.path,
            f.line or 0,
        )
    )


def summarize(findings: list[Finding]) -> dict[str, Any]:
    open_findings = [f for f in findings if f.is_open]
    return {
        "open": len(open_findings),
        "by_severity": dict(Counter(f.severity.value for f in open_findings)),
        "by_priority": dict(sorted(Counter(f.priority or "P4" for f in open_findings).items())),
        "by_category": dict(Counter(f.category.value for f in open_findings)),
        "duplicates": sum(1 for f in findings if f.status == "duplicate"),
        "stale": sum(1 for f in findings if f.status == "stale"),
        "kev": sum(1 for f in open_findings if f.in_kev),
    }


__all__ = ["correlate", "prioritize", "summarize", "risk_score", "priority_for", "import_names", "version_key"]
