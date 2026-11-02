"""Markdown, HTML and JSON reporting, plus the remediation pull-request description."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from .models import Finding, ScanResult
from .remediation import FixResult, TestRun

STATUS_LABEL = {
    "applied": "✅ Applied",
    "reverted": "↩️ Reverted",
    "rejected": "⛔ Rejected",
    "skipped": "➖ Skipped",
    "manual": "👤 Needs owner",
    "already-resolved": "✅ Resolved by another fix",
}


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def findings_table(findings: list[Finding], limit: int = 40) -> str:
    rows = ["| Priority | Severity | Risk | Finding | Location | Signals |", "|---|---|---|---|---|---|"]
    for finding in [f for f in findings if f.is_open][:limit]:
        signals = []
        if finding.in_kev:
            signals.append("KEV")
        if finding.epss is not None:
            signals.append(f"EPSS {finding.epss:.2f}")
        if finding.reachable is False:
            signals.append("not imported")
        if len(finding.sources) > 1:
            signals.append(f"{len(finding.sources)} sources")
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        rows.append(
            f"| {finding.priority or '-'} | {finding.severity.value} | {finding.risk_score or 0:.1f} | "
            f"{_cell(finding.rule_id)}: {_cell(finding.title)[:90]} | `{_cell(location)}` | "
            f"{', '.join(signals) or '-'} |"
        )
    return "\n".join(rows)


def results_table(results: list[FixResult]) -> str:
    rows = ["| Status | Fix | Kind | Priority | Detail |", "|---|---|---|---|---|"]
    for result in results:
        detail = result.reason or result.plan.reason
        if result.guardrail_violations:
            detail = "; ".join(result.guardrail_violations)
        rows.append(
            f"| {STATUS_LABEL.get(result.status, result.status)} | {_cell(result.plan.title)[:80]} | "
            f"{result.plan.kind} | {result.plan.priority or '-'} | {_cell(detail)[:120] or '-'} |"
        )
    return "\n".join(rows)


def lifecycle_section(lifecycle: dict[str, Any]) -> str:
    lines = ["## Cryptographic lifecycle", ""]
    certificates = lifecycle.get("certificates", [])
    if certificates:
        lines += ["| Certificate | Path | Expires | Days left | Status |", "|---|---|---|---|---|"]
        lines += [
            f"| {_cell(c['name'])} | `{c['path']}` | {c['not_after']} | {c['days_left']} | {c['status']} |"
            for c in certificates
        ]
    deprecated = lifecycle.get("deprecated_algorithms", {})
    if deprecated:
        lines += ["", "Deprecated algorithms in use: " + ", ".join(f"{k} ({v})" for k, v in deprecated.items())]
    pqc = lifecycle.get("pqc_candidates", {})
    if pqc.get("count"):
        lines += [
            "",
            f"Post-quantum migration candidates: {pqc['count']} assets "
            f"({', '.join(f'{k}: {v}' for k, v in pqc['by_algorithm'].items())}). {pqc['recommendation']}",
        ]
    return "\n".join(lines)


def markdown_report(
    scan: ScanResult,
    summary: dict[str, Any],
    correlation: dict[str, int] | None = None,
    sync: dict[str, Any] | None = None,
    results: list[FixResult] | None = None,
    pull_request: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    correlation = correlation or {}
    lines = [
        "# VulnWarden security report",
        "",
        f"Repository: `{scan.repo}` | Generated: {now} | Policy: {scan.stats.get('policy', '-')}",
        "",
        f"**{summary['open']} open findings** - by priority: "
        + ", ".join(f"{k} {v}" for k, v in summary["by_priority"].items())
        + " | by severity: "
        + ", ".join(f"{k} {v}" for k, v in sorted(summary["by_severity"].items())),
        "",
        f"Correlation: {correlation.get('duplicates', 0)} cross-scanner duplicates and "
        f"{correlation.get('duplicate_advisories', 0)} duplicate advisories merged, "
        f"{correlation.get('stale', 0)} stale reports flagged, "
        f"{correlation.get('reclassified', 0)} severities reclassified. "
        f"{summary.get('kev', 0)} findings are in CISA KEV.",
    ]
    if sync:
        lines += [
            "",
            f"Since last scan: {len(sync.get('new', []))} new, {len(sync.get('resolved', []))} resolved "
            f"(verified by rescan), {len(sync.get('reopened', []))} reopened, "
            f"{len(sync.get('reclassified', []))} reclassified.",
        ]
    if scan.warnings:
        lines += ["", "> **Warning:** results may be incomplete: " + "; ".join(scan.warnings[:5])]
    lines += ["", "## Prioritized findings", "", findings_table(scan.findings)]
    if results:
        lines += ["", "## Remediation", "", results_table(results)]
    if pull_request:
        lines += ["", f"Pull request: {pull_request.get('url')}"]
    lines += ["", lifecycle_section(scan.stats.get("lifecycle", {}))]
    return "\n".join(lines) + "\n"


def pr_body(results: list[FixResult], scan: ScanResult | None, tests: TestRun | None) -> str:
    applied = [r for r in results if r.status == "applied"]
    other = [r for r in results if r.status != "applied"]
    lines = [
        "## VulnWarden security remediation",
        "",
        "Generated by an AI-assisted agent. **A human must review and approve before merge.** "
        "Every fix below was applied one at a time and kept only if the full test suite passed and a security "
        "rescan showed the target finding resolved with no new findings.",
        "",
        "| Fix | Priority | Resolves | Commit |",
        "|---|---|---|---|",
    ]
    for result in applied:
        flag = " ⚠️ major version" if result.plan.major_upgrade else ""
        lines.append(
            f"| {_cell(result.plan.title)}{flag} | {result.plan.priority or '-'} | "
            f"{_cell(', '.join(result.plan.rule_ids))[:80]} | {(result.commit or '')[:8]} |"
        )
    if tests is not None:
        lines += [
            "",
            f"Baseline tests: {'passed' if tests.passed else 'failed'} in {tests.duration_seconds}s"
            + (" (no tests found; validation relied on rescans)" if tests.no_tests else "")
            + ".",
        ]
    if any(r.explanation for r in applied):
        lines += ["", "<details><summary>Model explanations</summary>", ""]
        lines += [f"- **{_cell(r.plan.title)}**: {_cell(r.explanation)}" for r in applied if r.explanation]
        lines += ["", "</details>"]
    if other:
        lines += ["", "### Not changed in this PR", "", results_table(other)]
    if scan is not None:
        counts = Counter(f.priority for f in scan.open_findings())
        lines += ["", "Open findings before this PR: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))]
    return "\n".join(lines) + "\n"


def json_report(scan: ScanResult, summary: dict[str, Any], **extra: Any) -> str:
    payload = {"summary": summary, "scan": scan.model_dump(mode="json"), **extra}
    return json.dumps(payload, indent=2, default=str)


def html_dashboard(
    scan: ScanResult,
    summary: dict[str, Any],
    trend: list[dict[str, Any]] | None = None,
    results: list[FixResult] | None = None,
) -> str:
    """Self-contained HTML dashboard (no JavaScript, no external assets)."""

    def esc(value: Any) -> str:
        return html.escape(str(value))

    cards = "".join(
        f"<div class='card'><div class='n'>{esc(v)}</div><div>{esc(k)}</div></div>"
        for k, v in [
            ("Open findings", summary["open"]),
            *summary["by_priority"].items(),
            ("In CISA KEV", summary.get("kev", 0)),
            ("Duplicates merged", summary.get("duplicates", 0)),
            ("Stale reports", summary.get("stale", 0)),
        ]
    )
    sparkline = ""
    if trend and len(trend) > 1:
        peak = max(t["open"] for t in trend) or 1
        step = 300 / (len(trend) - 1)
        points = " ".join(f"{i * step:.0f},{60 - 55 * t['open'] / peak:.0f}" for i, t in enumerate(trend))
        sparkline = (
            f"<h2>Open findings trend</h2><svg width='300' height='60' role='img' "
            f"aria-label='Open findings over the last {len(trend)} runs'><polyline fill='none' "
            f"stroke='#1f6feb' stroke-width='2' points='{points}'/></svg>"
            f"<p>{' → '.join(str(t['open']) for t in trend)}</p>"
        )
    rows = "".join(
        f"<tr><td>{esc(f.priority)}</td><td>{esc(f.severity.value)}</td><td>{f.risk_score or 0:.1f}</td>"
        f"<td>{esc(f.rule_id)}</td><td>{esc(f.title)}</td><td><code>{esc(f.path)}:{esc(f.line or '')}</code></td>"
        f"<td>{esc(f.sla_hours or '')}</td></tr>"
        for f in scan.open_findings()[:200]
    )
    fixes = ""
    if results:
        fixes = (
            "<h2>Remediation</h2><table><tr><th>Status</th><th>Fix</th><th>Kind</th><th>Detail</th></tr>"
            + "".join(
                f"<tr><td>{esc(STATUS_LABEL.get(r.status, r.status))}</td><td>{esc(r.plan.title)}</td>"
                f"<td>{esc(r.plan.kind)}</td><td>{esc(r.reason or r.plan.reason)}</td></tr>"
                for r in results
            )
            + "</table>"
        )
    certificates = "".join(
        f"<tr><td>{esc(c['name'])}</td><td>{esc(c['path'])}</td><td>{esc(c['not_after'])}</td>"
        f"<td>{esc(c['days_left'])}</td><td>{esc(c['status'])}</td></tr>"
        for c in scan.stats.get("lifecycle", {}).get("certificates", [])
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>VulnWarden dashboard</title>
<style>{DASHBOARD_CSS}</style>
</head><body><h1>VulnWarden security dashboard</h1><p>{esc(scan.repo)}</p><div class="cards">{cards}</div>{sparkline}
<h2>Prioritized open findings</h2><table><tr><th>Priority</th><th>Severity</th><th>Risk</th><th>Rule</th>
<th>Title</th><th>Location</th><th>SLA (h)</th></tr>{rows}</table>{fixes}
<h2>Certificates</h2><table><tr><th>Name</th><th>Path</th><th>Expires</th><th>Days left</th><th>Status</th></tr>
{certificates}</table>
</body></html>
"""


DASHBOARD_CSS = " ".join(
    [
        "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2328}",
        ".cards{display:flex;gap:12px;flex-wrap:wrap}",
        ".card{border:1px solid #d0d7de;border-radius:8px;padding:12px 16px;min-width:110px}",
        ".n{font-size:28px;font-weight:600}",
        "table{border-collapse:collapse;margin-top:8px;font-size:13px}",
        "td,th{border:1px solid #d0d7de;padding:4px 8px;text-align:left}",
    ]
)


__all__ = ["html_dashboard", "json_report", "markdown_report", "pr_body"]
