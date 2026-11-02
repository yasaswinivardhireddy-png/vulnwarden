"""Command-line interface: scan, crypto, remediate, monitor, reconcile and audit."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from langgraph.types import Command

from . import __version__, crypto
from .agent import AgentContext, build_graph, run_scan
from .config import load_config
from .github import GitHubClient
from .intel import Intel
from .llm import LLMConfigError, PatchModel, create_chat_model
from .models import ScanResult, Severity
from .monitor import run_monitor
from .notify import Notifier
from .remediation import FixResult
from .report import html_dashboard, json_report, markdown_report
from .store import Store
from .triage import summarize


def _write(path: str | None, content: str) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8")
        print(f"Wrote {path}")


def _intel(args: argparse.Namespace, repo: Path | None) -> Intel:
    cache = args.intel_cache or (repo / ".vulnwarden" / "intel-cache" if repo else None)
    return Intel(cache_dir=cache, offline=args.offline, max_age_hours=None if args.offline else 24.0)


def _store(args: argparse.Namespace, repo: Path | None) -> Store:
    return Store(args.db or ((repo or Path.cwd()) / ".vulnwarden" / "state.db"))


def _github(repo_slug: str | None) -> GitHubClient | None:
    if not repo_slug:
        return None
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise SystemExit("Set GITHUB_TOKEN (fine-grained: Contents and Pull requests read/write on this repo).")
    return GitHubClient(repo_slug, token)


def _print_summary(scan: ScanResult, summary: dict[str, Any]) -> None:
    correlation = scan.stats.get("correlation", {})
    print(
        f"Open findings: {summary['open']}  by priority: {summary['by_priority']}  by severity: "
        f"{summary['by_severity']}"
    )
    print(
        f"Correlation: {correlation.get('duplicates', 0)} cross-scanner duplicates, "
        f"{correlation.get('duplicate_advisories', 0)} duplicate advisories, {correlation.get('stale', 0)} stale, "
        f"{correlation.get('reclassified', 0)} reclassified; crypto assets: {len(scan.crypto_assets)}"
    )
    for finding in scan.open_findings()[:15]:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        print(
            f"  {finding.priority} {finding.severity.value:<8} {finding.risk_score or 0:>4.1f}  "
            f"{finding.rule_id:<26} {location}"
        )
    for warning in scan.warnings[:5]:
        print(f"  warning: {warning}")


def cmd_scan(args: argparse.Namespace) -> int:
    repo = Path(args.path).resolve()
    config = load_config(args.config, repo)
    with _intel(args, repo) as intel:
        ctx = AgentContext(
            repo=repo,
            config=config,
            intel=intel,
            store=_store(args, repo),
            sarif=args.sarif or [],
            trivy=args.trivy or [],
        )
        scan = run_scan(ctx)
        sync = ctx.store.sync_findings(scan.findings, str(repo))
        trend = ctx.store.trend()
    summary = summarize(scan.findings)
    _print_summary(scan, summary)
    _write(args.markdown, markdown_report(scan, summary, scan.stats.get("correlation"), sync.model_dump()))
    _write(args.json, json_report(scan, summary, sync=sync.model_dump()))
    _write(args.html, html_dashboard(scan, summary, trend))
    if args.cbom:
        _write(args.cbom, json.dumps(crypto.to_cbom(scan.crypto_assets, repo.name), indent=2))
    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        blocking = [f for f in scan.open_findings() if f.severity.rank >= threshold]
        if blocking:
            print(f"Failing: {len(blocking)} open findings at or above {args.fail_on}.")
            return 2
    return 0


def cmd_crypto(args: argparse.Namespace) -> int:
    repo = Path(args.path).resolve()
    config = load_config(args.config, repo)
    policy = crypto.load_policy(args.policy or config.crypto_policy)
    from .scanners.dependencies import find_dependencies

    assets = crypto.discover(repo, config.exclude, find_dependencies(repo, config.exclude))
    ages = crypto.key_ages(repo, assets)
    findings = crypto.evaluate(assets, policy, ages=ages)
    lifecycle = crypto.lifecycle(assets, policy, ages=ages)
    print(f"Crypto assets: {len(assets)}  policy violations: {len(findings)}  policy: {policy.name}")
    for finding in findings:
        location = f"{finding.path}:{finding.line or ''}"
        print(f"  {finding.severity.value:<8} {finding.rule_id:<28} {location}  {finding.message}")
    for cert in lifecycle["certificates"]:
        print(f"  certificate {cert['name']} expires {cert['not_after']} ({cert['days_left']} days, {cert['status']})")
    print(f"  PQC migration candidates: {lifecycle['pqc_candidates']['count']}")
    if args.cbom:
        _write(args.cbom, json.dumps(crypto.to_cbom(assets, repo.name), indent=2))
    _write(
        args.json,
        json.dumps(
            {
                "assets": [a.model_dump(mode="json") for a in assets],
                "findings": [f.model_dump(mode="json") for f in findings],
                "lifecycle": lifecycle,
            },
            indent=2,
            default=str,
        ),
    )
    return 0


def _ask(payload: dict[str, Any]) -> str:
    print("\nProposed fixes:")
    for plan in payload["plans"]:
        flag = "  [major upgrade]" if plan.get("major_upgrade") else ""
        print(f"  {plan['id']:<52} {plan['priority'] or '-':<3} {plan['kind']:<10} {plan['title']}{flag}")
    if not sys.stdin.isatty():
        print("No interactive terminal: declining. Re-run with --yes to approve all fixes.")
        return "none"
    return input(f"{payload['question']}\n> ").strip() or "none"


def cmd_remediate(args: argparse.Namespace) -> int:
    repo = Path(args.path).resolve()
    config = load_config(args.config, repo)
    if args.llm:
        config.llm.provider = args.llm
    try:
        chat_model = create_chat_model(config.llm.provider, config.llm.model)
    except LLMConfigError as exc:
        print(f"LLM disabled: {exc}")
        chat_model = None
    with _intel(args, repo) as intel:
        ctx = AgentContext(
            repo=repo,
            config=config,
            intel=intel,
            store=_store(args, repo),
            sarif=args.sarif or [],
            trivy=args.trivy or [],
            llm=PatchModel(chat_model, config.llm.context_lines) if chat_model else None,
            github=_github(args.github),
            auto_approve=args.yes,
        )
        graph = build_graph(ctx)
        thread = {"configurable": {"thread_id": f"run-{uuid.uuid4().hex[:8]}"}}
        state = graph.invoke({}, thread)
        while "__interrupt__" in state:
            state = graph.invoke(Command(resume=_ask(state["__interrupt__"][0].value)), thread)
    scan = ctx.last_scan
    assert scan is not None
    summary = summarize(scan.findings)
    _print_summary(scan, summary)
    results = [FixResult.model_validate(r) for r in state.get("results", [])]
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    print(f"Remediation: {counts or 'no fixes attempted'}")
    if state.get("branch"):
        print(f"Validated fixes are on local branch {state['branch']}")
    if state.get("pull_request"):
        print(f"Pull request: {state['pull_request']['url']}")
    for error in state.get("errors", []):
        print(f"error: {error}")
    _write(
        args.report,
        markdown_report(scan, summary, state.get("correlation"), state.get("sync"), results, state.get("pull_request")),
    )
    _write(
        args.json,
        json_report(
            scan,
            summary,
            results=[r.model_dump(mode="json") for r in results],
            pull_request=state.get("pull_request"),
            branch=state.get("branch"),
        ),
    )
    return 1 if state.get("errors") else 0


def cmd_monitor(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    github = _github(args.github)
    assert github is not None
    store = _store(args, None)
    notifier = Notifier(config.notify, dry_run=args.dry_run)
    actions = run_monitor(github, store, notifier, config, comment_on_pr=not args.no_comment)
    for action in actions:
        print(
            f"PR #{action.pr_number}: {action.kind} -> {', '.join(action.recipients) or 'owners'} "
            f"({action.reason}) delivered={action.delivered} errors={action.errors}"
        )
    if not actions:
        print("No remediation PRs need follow-up.")
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    """Rescan after merges and close the loop: verified fixes, reopened findings and merged PR status."""
    repo = Path(args.path).resolve()
    config = load_config(args.config, repo)
    store = _store(args, repo)
    with _intel(args, repo) as intel:
        ctx = AgentContext(repo=repo, config=config, intel=intel, store=store)
        scan = run_scan(ctx, include_imports=False)
    sync = store.sync_findings(scan.findings, str(repo))
    github = _github(args.github) if args.github else None
    verified, ineffective = [], []
    for pull in store.pulls("open"):
        if github is not None:
            remote = github.get_pull(pull["number"])
            if remote.get("merged_at"):
                store.update_pull(pull["number"], "merged", remote["merged_at"])
            elif remote.get("state") == "closed":
                store.update_pull(pull["number"], "closed")
                continue
            else:
                continue
        still_open = [fp for fp in pull["fingerprints"] if store.finding_status(fp) == "open"]
        (ineffective if still_open else verified).append(pull["number"])
    store.audit(
        "vulnwarden",
        "reconcile",
        {
            "resolved": len(sync.resolved),
            "reopened": len(sync.reopened),
            "verified_pulls": verified,
            "ineffective_pulls": ineffective,
        },
    )
    print(
        f"Resolved since last scan (verified by rescan): {len(sync.resolved)}; reopened: {len(sync.reopened)}; "
        f"new: {len(sync.new)}; open: {sync.still_open}"
    )
    print(f"Merged PRs verified closed: {verified}; PRs whose findings are still open: {ineffective}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    store = _store(args, Path(args.path).resolve() if args.path else None)
    ok, bad = store.verify_audit()
    entries = store.audit_entries()
    print(f"Audit log: {len(entries)} entries, chain {'intact' if ok else f'BROKEN at entry {bad}'}")
    return 0 if ok else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnwarden", description=__doc__)
    parser.add_argument("--version", action="version", version=f"vulnwarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, path: bool = True) -> None:
        if path:
            p.add_argument("path", help="Repository to analyze")
        p.add_argument("--config", help="Path to vulnwarden.yaml")
        p.add_argument("--db", help="SQLite state database (default: <repo>/.vulnwarden/state.db)")
        p.add_argument("--offline", action="store_true", help="Use only the intel cache (no network)")
        p.add_argument("--intel-cache", help="Directory for cached OSV/EPSS/KEV responses")

    scan = sub.add_parser("scan", help="Scan, correlate and prioritize")
    common(scan)
    scan.add_argument("--sarif", action="append", help="Import a SARIF report (repeatable)")
    scan.add_argument("--trivy", action="append", help="Import a Trivy JSON report (repeatable)")
    scan.add_argument("--markdown")
    scan.add_argument("--json")
    scan.add_argument("--html")
    scan.add_argument("--cbom", help="Write a CycloneDX 1.6 CBOM")
    scan.add_argument("--fail-on", choices=[s.value for s in Severity], help="Exit 2 if open findings reach this")
    scan.set_defaults(func=cmd_scan)

    cr = sub.add_parser("crypto", help="Cryptographic inventory, policy check and lifecycle")
    common(cr)
    cr.add_argument("--policy", help="Crypto policy YAML")
    cr.add_argument("--cbom")
    cr.add_argument("--json")
    cr.set_defaults(func=cmd_crypto)

    rem = sub.add_parser("remediate", help="Run the agent: fix, validate and open a pull request")
    common(rem)
    rem.add_argument("--sarif", action="append")
    rem.add_argument("--trivy", action="append")
    rem.add_argument("--github", help="owner/name; opens a PR (token from GITHUB_TOKEN)")
    rem.add_argument("--llm", choices=["none", "gemini"], help="Model provider for fixes without a codemod")
    rem.add_argument("--yes", action="store_true", help="Approve all proposed fixes (non-interactive)")
    rem.add_argument("--report", help="Write a Markdown report")
    rem.add_argument("--json")
    rem.set_defaults(func=cmd_remediate)

    mon = sub.add_parser("monitor", help="Remind/escalate on idle remediation PRs")
    common(mon, path=False)
    mon.add_argument("--github", required=True)
    mon.add_argument("--dry-run", action="store_true")
    mon.add_argument("--no-comment", action="store_true", help="Do not comment on the PR")
    mon.set_defaults(func=cmd_monitor)

    rec = sub.add_parser("reconcile", help="Verify closure after merges")
    common(rec)
    rec.add_argument("--github")
    rec.set_defaults(func=cmd_reconcile)

    aud = sub.add_parser("audit", help="Verify the hash-chained audit log")
    aud.add_argument("path", nargs="?")
    aud.add_argument("--db")
    aud.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
