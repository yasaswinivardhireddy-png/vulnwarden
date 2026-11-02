"""Software composition analysis: parse manifests and match pinned versions against OSV."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from ..files import iter_files, read_text, rel
from ..intel import Intel, best_cvss
from ..models import Category, Finding, Severity, normalize_package


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    path: str
    line: int
    spec: str


REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<op>===|==|~=|>=|<=|!=|>|<)?\s*(?P<version>[A-Za-z0-9._*+!-]+)?"
)
REQUIREMENTS_FILE = re.compile(r"^requirements[\w.-]*\.txt$", re.I)


def parse_requirements(text: str, path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:")):
            continue
        match = REQ_LINE.match(line)
        if not match:
            continue
        version = match["version"] if match["op"] in {"==", "==="} else None
        if version and "*" in version:
            version = None
        deps.append(Dependency(match["name"], version, "PyPI", path, number, raw.strip()))
    return deps


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def parse_package_lock(text: str, path: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found: dict[tuple[str, str], Dependency] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            version = meta.get("version")
            if version:
                dep = Dependency(name, version, "npm", path, _line_of(text, f'"{key}"'), f"{name}@{version}")
                found.setdefault((name, version), dep)
    elif isinstance(data.get("dependencies"), dict):
        for name, meta in data["dependencies"].items():
            version = meta.get("version") if isinstance(meta, dict) else None
            if version:
                dep = Dependency(name, version, "npm", path, _line_of(text, f'"{name}"'), f"{name}@{version}")
                found.setdefault((name, version), dep)
    return list(found.values())


def find_dependencies(root: Path, exclude: list[str]) -> list[Dependency]:
    deps: list[Dependency] = []
    for file in iter_files(root, exclude):
        name = file.name
        if not (REQUIREMENTS_FILE.match(name) or name == "package-lock.json"):
            continue
        text = read_text(file)
        if text is None:
            continue
        if name == "package-lock.json":
            deps.extend(parse_package_lock(text, rel(root, file)))
        else:
            deps.extend(parse_requirements(text, rel(root, file)))
    return deps


def _version(value: str | None) -> Version | None:
    if not value:
        return None
    try:
        return Version(value)
    except InvalidVersion:
        return None


def version_key(value: str) -> tuple[int, Version | str]:
    parsed = _version(value)
    return (0, parsed) if parsed is not None else (1, value)


def fixed_versions_for(vuln: dict[str, Any], name: str, ecosystem: str, installed: str | None) -> list[str]:
    """Fixed releases for the affected range that contains the installed version."""
    target = normalize_package(name, ecosystem)
    current = _version(installed)
    candidates: set[str] = set()
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if normalize_package(package.get("name", ""), ecosystem) != target:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            introduced: str | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                    fixed_v, intro_v = _version(fixed), _version(introduced)
                    in_range = current is None or (
                        fixed_v is not None
                        and current < fixed_v
                        and (introduced in {None, "0"} or (intro_v is not None and intro_v <= current))
                    )
                    if in_range:
                        candidates.add(fixed)
                    introduced = None
    return sorted(candidates, key=version_key)


def finding_from_osv(dep: Dependency, vuln: dict[str, Any]) -> Finding:
    aliases = sorted({vuln["id"], *vuln.get("aliases", [])})
    vector, score = best_cvss(vuln.get("severity", []))
    database = vuln.get("database_specific") or {}
    severity = Severity.from_score(score) if score is not None else Severity.parse(database.get("severity"))
    fixes = fixed_versions_for(vuln, dep.name, dep.ecosystem, dep.version)
    summary = vuln.get("summary") or (vuln.get("details") or vuln["id"]).strip().splitlines()[0][:120]
    cves = sorted(a for a in aliases if a.upper().startswith("CVE-"))
    hint = (
        f"Upgrade {dep.name} to {fixes[0]} or later."
        if fixes
        else f"No fixed release of {dep.name} is published for this range; replace or mitigate."
    )
    return Finding(
        rule_id=cves[0] if cves else vuln["id"],
        title=f"{dep.name} {dep.version}: {summary}",
        category=Category.DEPENDENCY,
        severity=severity,
        source="osv",
        path=dep.path,
        line=dep.line,
        snippet=dep.spec,
        cwe=list(database.get("cwe_ids") or []),
        aliases=aliases,
        package=dep.name,
        ecosystem=dep.ecosystem,
        installed_version=dep.version,
        fixed_versions=fixes,
        cvss_vector=vector,
        cvss_score=score,
        fix_hint=hint,
        sources=["osv"],
        details={"osv_id": vuln["id"], "published": vuln.get("published")},
    )


def dependency_findings(deps: list[Dependency], intel: Intel) -> list[Finding]:
    pinned = [d for d in deps if d.version]
    if not pinned:
        return []
    ids_per_dep = intel.osv_query([(d.ecosystem, d.name, d.version or "") for d in pinned])
    findings: list[Finding] = []
    for dep, vuln_ids in zip(pinned, ids_per_dep, strict=True):
        for vuln_id in vuln_ids:
            vuln = intel.osv_vuln(vuln_id)
            if vuln and not vuln.get("withdrawn"):
                findings.append(finding_from_osv(dep, vuln))
    return findings


def remaining_vulns(intel: Intel, ecosystem: str, name: str, version: str) -> list[dict[str, Any]]:
    """Advisories that still affect a candidate version (used to validate upgrades)."""
    ids = intel.osv_query([(ecosystem, name, version)])[0]
    advisories = [intel.osv_vuln(i) for i in ids]
    return [a for a in advisories if a and not a.get("withdrawn")]
