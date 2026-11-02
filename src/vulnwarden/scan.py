"""Run every scanner over a repository and return one normalized result."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, date, datetime
from pathlib import Path

from . import crypto
from .config import Config
from .files import iter_files, read_text, rel
from .intel import Intel
from .models import ScanResult, assign_occurrences
from .pyast import ImportMap
from .scanners.containers import load_trivy, scan_dockerfile
from .scanners.dependencies import dependency_findings, find_dependencies
from .scanners.openapi import scan_openapi
from .scanners.python_sast import scan_python_source
from .scanners.sarif import load_sarif


def _is_dockerfile(name: str) -> bool:
    lowered = name.lower()
    return lowered == "dockerfile" or lowered.startswith("dockerfile.") or lowered.endswith(".dockerfile")


def scan_repository(
    root: str | Path,
    config: Config,
    intel: Intel,
    *,
    sarif: Iterable[str | Path] = (),
    trivy: Iterable[str | Path] = (),
    now: datetime | None = None,
    policy: crypto.CryptoPolicy | None = None,
) -> ScanResult:
    root = Path(root).resolve()
    now = now or datetime.now(UTC)
    today: date = now.date()
    result = ScanResult(repo=str(root))
    imported: set[str] = set()
    scanned = 0

    for file in iter_files(root, config.exclude):
        path = rel(root, file)
        suffix = file.suffix.lower()
        is_docker = _is_dockerfile(file.name)
        if suffix not in {".py", ".yaml", ".yml", ".json"} and not is_docker:
            continue
        text = read_text(file)
        if text is None:
            continue
        scanned += 1
        if suffix == ".py":
            findings, tree = scan_python_source(text, path)
            if tree is None:
                result.warnings.append(f"Skipped {path}: not valid Python")
                continue
            result.findings.extend(findings)
            imported |= ImportMap(tree).modules
        elif is_docker:
            result.findings.extend(scan_dockerfile(text, path, today))
        elif "openapi" in text[:2000] or "swagger" in text[:2000]:
            result.findings.extend(scan_openapi(text, path))

    deps = find_dependencies(root, config.exclude)
    result.findings.extend(dependency_findings(deps, intel))
    for report in sarif:
        result.findings.extend(load_sarif(Path(report)))
    for report in trivy:
        result.findings.extend(load_trivy(Path(report)))

    if policy is None:
        policy_path = config.crypto_policy
        if policy_path and not Path(policy_path).is_absolute():
            policy_path = str(root / policy_path)
        policy = crypto.load_policy(policy_path)
    assets = crypto.discover(root, config.exclude, deps)
    ages = crypto.key_ages(root, assets, now)
    result.crypto_assets = assets
    result.findings.extend(crypto.evaluate(assets, policy, now, ages))

    assign_occurrences(result.findings)
    result.warnings.extend(dict.fromkeys(intel.errors))
    result.stats = {
        "files_scanned": scanned,
        "dependencies": len(deps),
        "pinned_dependencies": sum(1 for d in deps if d.version),
        "crypto_assets": len(assets),
        "imported_modules": sorted(imported),
        "lifecycle": crypto.lifecycle(assets, policy, now, ages),
        "policy": policy.name,
    }
    result.stats["dependency_manifest"] = [
        {"name": d.name, "version": d.version, "ecosystem": d.ecosystem, "path": d.path, "line": d.line} for d in deps
    ]
    return result
