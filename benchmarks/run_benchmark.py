"""Reproducible end-to-end benchmark on the seeded demo service (examples/vulnerable-shop).

Steps: copy the demo into a temporary git repo, generate throwaway certificates, scan with the
sample Trivy and SARIF reports, run the LangGraph agent with auto-approval and no LLM, then
rescan the remediation branch and re-run the tests. Intelligence comes from the recorded cache
in benchmarks/intel-cache, so results are reproducible offline. Use --live to refresh it.

    uv run python benchmarks/run_benchmark.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from vulnwarden.agent import AgentContext, build_graph, run_scan
from vulnwarden.config import load_config
from vulnwarden.intel import Intel
from vulnwarden.models import Finding
from vulnwarden.remediation import FixResult, run_tests
from vulnwarden.store import Store

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "vulnerable-shop"
CACHE = ROOT / "benchmarks" / "intel-cache"
OUT = ROOT / "benchmarks"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def prepare(workdir: Path) -> Path:
    repo = workdir / "vulnerable-shop"
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns("certs", ".vulnwarden", "__pycache__", ".pytest_cache"))
    subprocess.run([sys.executable, "make_certs.py"], cwd=repo, check=True, capture_output=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(
        repo,
        "-c",
        "user.name=bench",
        "-c",
        "user.email=bench@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "Seed vulnerable shop",
    )
    return repo


def detection(findings: list[Finding], expected: dict[str, Any]) -> dict[str, Any]:
    found = Counter((f.rule_id, f.path) for f in findings if f.source.startswith("vulnwarden"))
    detected = planted = 0
    rows = []
    for item in expected["planted"]:
        need = item.get("count", 1)
        got = found[(item["rule"], item["path"])]
        detected += min(got, need)
        planted += need
        rows.append({"rule": item["rule"], "path": item["path"], "expected": need, "found": got})
    keys = {(i["rule"], i["path"]) for i in expected["planted"]}
    unexpected = sorted(f"{rule} {path}" for rule, path in found if (rule, path) not in keys)
    return {"detected": detected, "planted": planted, "rows": rows, "unexpected": unexpected}


def first_party_open(findings: list[Finding]) -> Counter[str]:
    return Counter(f.severity.value for f in findings if f.is_open)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Refresh OSV/EPSS/KEV data from the network")
    args = parser.parse_args()
    expected = yaml.safe_load((OUT / "expected.yaml").read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        repo = prepare(Path(tmp))
        config = load_config(None, repo)
        store = Store(Path(tmp) / "state.db")
        with Intel(cache_dir=CACHE, offline=not args.live, max_age_hours=None) as intel:
            ctx = AgentContext(
                repo=repo,
                config=config,
                intel=intel,
                store=store,
                auto_approve=True,
                sarif=[str(repo / "reports" / "semgrep.sarif")],
                trivy=[str(repo / "reports" / "trivy-image.json")],
            )
            start = time.perf_counter()
            scan = run_scan(ctx)
            scan_seconds = time.perf_counter() - start
            before = run_scan(ctx, include_imports=False)

            start = time.perf_counter()
            state = build_graph(ctx).invoke({}, {"configurable": {"thread_id": "benchmark"}})
            agent_seconds = time.perf_counter() - start

            results = [FixResult.model_validate(r) for r in state.get("results", [])]
            branch = state.get("branch")
            if branch:
                git(repo, "switch", "-q", branch)
            after = run_scan(ctx, include_imports=False)
            tests_after = run_tests(repo, config.remediation.test_command, 600)
            commits = int(git(repo, "rev-list", "--count", f"main..{branch}")) if branch else 0
        audit_ok, _ = store.verify_audit()
        audit_entries = len(store.audit_entries())
        store.close()

    det = detection(scan.findings, expected)
    advisories = [f for f in scan.findings if f.source == "osv" and f.is_open]
    correlation = scan.stats.get("correlation", {})
    statuses = Counter(r.status for r in results)
    kinds_applied = Counter(r.plan.kind for r in results if r.status == "applied")
    fixable = sum(1 for r in results if r.plan.kind != "manual")
    resolved_fps = {fp for r in results if r.status in {"applied", "already-resolved"} for fp in r.plan.fingerprints}
    before_open, after_open = first_party_open(before.findings), first_party_open(after.findings)
    summary = {
        "generated": datetime.now(UTC).strftime("%Y-%m-%d"),
        "intel": "live" if args.live else "recorded cache",
        "planted_detected": det["detected"],
        "planted_total": det["planted"],
        "unexpected_findings": det["unexpected"],
        "dependency_advisories": len(advisories),
        "vulnerable_packages": len({f.package for f in advisories}),
        "unique_cves": len({f.vuln_id for f in advisories if (f.vuln_id or "").startswith("CVE-")}),
        "kev_findings": sum(1 for f in scan.findings if f.is_open and f.in_kev),
        "correlation": correlation,
        "crypto_assets": len(scan.crypto_assets),
        "plans_total": len(results),
        "plans_auto": fixable,
        "results": dict(statuses),
        "applied_by_kind": dict(kinds_applied),
        "findings_resolved_by_fixes": len(resolved_fps),
        "validated_commits": commits,
        "open_before": sum(before_open.values()),
        "open_after": sum(after_open.values()),
        "open_before_by_severity": dict(before_open),
        "open_after_by_severity": dict(after_open),
        "tests_after_fixes_passed": tests_after.passed,
        "audit_entries": audit_entries,
        "audit_chain_intact": audit_ok,
        "scan_seconds": round(scan_seconds, 2),
        "agent_seconds": round(agent_seconds, 2),
        "reverted": [{"fix": r.plan.title, "reason": r.reason} for r in results if r.status == "reverted"],
    }
    (OUT / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_markdown(summary, det, results)
    print(json.dumps({k: v for k, v in summary.items() if k != "reverted"}, indent=2))
    ok = det["detected"] == det["planted"] and tests_after.passed and audit_ok
    return 0 if ok else 1


def write_markdown(summary: dict[str, Any], det: dict[str, Any], results: list[FixResult]) -> None:
    c = summary["correlation"]
    lines = [
        "# Benchmark results",
        "",
        f"Generated {summary['generated']} by `benchmarks/run_benchmark.py` on `examples/vulnerable-shop` "
        f"(intel: {summary['intel']}, no LLM, auto-approval).",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Planted issues detected | **{summary['planted_detected']}/{summary['planted_total']}** |",
        f"| Findings outside the planted list | {len(summary['unexpected_findings'])} |",
        f"| Dependency advisories (OSV) | {summary['dependency_advisories']} across "
        f"{summary['vulnerable_packages']} packages ({summary['unique_cves']} unique CVEs) |",
        f"| Cross-scanner duplicates merged | {c.get('duplicates', 0)} |",
        f"| Duplicate advisories merged (GHSA/PYSEC) | {c.get('duplicate_advisories', 0)} |",
        f"| Stale or discrepant reports flagged | {c.get('stale', 0)} |",
        f"| Severities reclassified | {c.get('reclassified', 0)} |",
        f"| Cryptographic assets inventoried | {summary['crypto_assets']} |",
        f"| Fix plans (auto / total) | {summary['plans_auto']} / {summary['plans_total']} |",
        f"| Fixes applied after tests + rescan | {summary['results'].get('applied', 0)} "
        f"({', '.join(f'{k}: {v}' for k, v in summary['applied_by_kind'].items())}) |",
        f"| Fixes rolled back by validation | {summary['results'].get('reverted', 0)} |",
        f"| Findings resolved by validated fixes | {summary['findings_resolved_by_fixes']} |",
        f"| Open first-party findings before -> after | {summary['open_before']} -> {summary['open_after']} |",
        f"| Tests pass on the remediation branch | {'yes' if summary['tests_after_fixes_passed'] else 'no'} |",
        f"| Audit log entries / hash chain | {summary['audit_entries']} / "
        f"{'intact' if summary['audit_chain_intact'] else 'BROKEN'} |",
        f"| Scan time / agent run time | {summary['scan_seconds']} s / {summary['agent_seconds']} s |",
        "",
        "## Detection",
        "",
        "| Rule | Path | Expected | Found |",
        "|---|---|---|---|",
    ]
    lines += [f"| {r['rule']} | `{r['path']}` | {r['expected']} | {r['found']} |" for r in det["rows"]]
    lines += ["", "## Remediation outcomes", "", "| Status | Fix | Kind | Detail |", "|---|---|---|---|"]
    for r in results:
        if r.plan.kind == "manual" and r.status == "manual":
            continue
        lines.append(f"| {r.status} | {r.plan.title} | {r.plan.kind} | {(r.reason or '-').replace('|', '/')} |")
    manual = [r for r in results if r.status == "manual"]
    lines += [
        "",
        f"{len(manual)} findings were routed to owners (no safe automatic fix, below the auto-fix "
        "threshold, or no fixed release).",
    ]
    (OUT / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
