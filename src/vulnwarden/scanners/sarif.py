"""Import SARIF 2.1.0 results from any static analyzer (CodeQL, Semgrep, Bandit, ...)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import Category, Finding, Severity

CWE_TAG = re.compile(r"cwe[-/:_ ]?0*(\d+)", re.I)


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
    props = {**rule.get("properties", {}), **result.get("properties", {})}
    security_severity = props.get("security-severity")
    if security_severity is not None:
        try:
            return Severity.from_score(float(security_severity))
        except (TypeError, ValueError):
            pass
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return Severity.parse(level)


def load_sarif(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "sarif")
        rules_list = driver.get("rules", [])
        rules = {r.get("id"): r for r in rules_list if r.get("id")}
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            if rule_id is None and isinstance(result.get("ruleIndex"), int) and result["ruleIndex"] < len(rules_list):
                rule_id = rules_list[result["ruleIndex"]].get("id")
            rule_id = rule_id or "unknown"
            rule = rules.get(rule_id, {})
            tags = [*rule.get("properties", {}).get("tags", []), *result.get("properties", {}).get("tags", [])]
            cwe = sorted({f"CWE-{m.group(1)}" for tag in tags for m in CWE_TAG.finditer(str(tag))})
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = location.get("artifactLocation", {}).get("uri", "")
            uri = re.sub(r"^file://", "", uri).lstrip("./") if uri.startswith(("file://", "./")) else uri
            region = location.get("region", {})
            message = result.get("message", {}).get("text", "")
            title = (rule.get("shortDescription") or {}).get("text") or message[:120] or rule_id
            findings.append(
                Finding(
                    rule_id=f"{tool}:{rule_id}",
                    title=title,
                    category=Category.CODE,
                    severity=_severity(result, rule),
                    source=f"sarif:{tool}",
                    path=uri,
                    line=region.get("startLine"),
                    message=message,
                    snippet=(region.get("snippet") or {}).get("text", "").strip(),
                    cwe=cwe,
                    fix_hint=(rule.get("help") or {}).get("text", "")[:300],
                    sources=[f"sarif:{tool}"],
                )
            )
    return findings
