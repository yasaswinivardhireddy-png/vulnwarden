"""The remediation agent: a LangGraph state machine with a human-approval interrupt.

scan -> plan -> approve (interrupt) -> remediate -> publish -> report
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .config import Config
from .github import GitHubClient
from .intel import Intel
from .llm import PatchModel
from .models import Finding, ScanResult
from .remediation import FixPlan, FixResult, GitError, Remediator, TestRun, git, plan_fixes
from .report import pr_body
from .scan import scan_repository
from .store import Store
from .triage import correlate, prioritize, summarize


class AgentState(TypedDict, total=False):
    findings: list[dict[str, Any]]
    summary: dict[str, Any]
    correlation: dict[str, int]
    sync: dict[str, Any]
    plans: list[dict[str, Any]]
    approved: list[str]
    results: list[dict[str, Any]]
    baseline_tests: dict[str, Any] | None
    branch: str | None
    base_sha: str | None
    pull_request: dict[str, Any] | None
    errors: list[str]


@dataclass
class AgentContext:
    repo: Path
    config: Config
    intel: Intel
    store: Store
    sarif: list[str] = field(default_factory=list)
    trivy: list[str] = field(default_factory=list)
    llm: PatchModel | None = None
    github: GitHubClient | None = None
    auto_approve: bool = False
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    last_scan: ScanResult | None = None


class PublishError(RuntimeError):
    pass


def run_scan(ctx: AgentContext, include_imports: bool = True) -> ScanResult:
    """Scan + correlate + prioritize. Validation rescans skip imported reports, which describe the past."""
    result = scan_repository(
        ctx.repo,
        ctx.config,
        ctx.intel,
        sarif=ctx.sarif if include_imports else (),
        trivy=ctx.trivy if include_imports else (),
        now=ctx.now(),
    )
    result.stats["correlation"] = correlate(result.findings, ctx.repo, result.stats["dependency_manifest"])
    prioritize(result.findings, ctx.intel, ctx.config, set(result.stats["imported_modules"]))
    return result


def parse_decision(decision: Any, plan_ids: list[str]) -> list[str]:
    if decision is True or (isinstance(decision, str) and decision.strip().lower() in {"all", "yes", "y"}):
        return list(plan_ids)
    if isinstance(decision, (list, tuple, set)):
        chosen = {str(d) for d in decision}
    elif isinstance(decision, str):
        chosen = {d.strip() for d in decision.replace(";", ",").split(",") if d.strip()}
    else:
        chosen = set()
    return [pid for pid in plan_ids if pid in chosen]


def _git_show(repo: Path, ref: str) -> str:
    return subprocess.run(["git", "show", ref], cwd=repo, capture_output=True, check=True, timeout=60).stdout.decode(
        "utf-8"
    )


def publish(ctx: AgentContext, state: AgentState) -> dict[str, Any]:
    """Replay the validated local commits onto a new GitHub branch and open a pull request."""
    github = ctx.github
    assert github is not None
    base = github.default_branch()
    remote_base = github.branch_sha(base)
    if remote_base != state.get("base_sha"):
        raise PublishError(
            f"Local base {str(state.get('base_sha'))[:8]} differs from {base} on GitHub "
            f"({remote_base[:8]}); pull the latest {base} and re-run."
        )
    branch = state["branch"] or ""
    github.create_branch(branch, remote_base)
    parent = remote_base
    commits = git(ctx.repo, "rev-list", "--reverse", f"{state['base_sha']}..{branch}").split()
    for sha in commits:
        paths = git(ctx.repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha).splitlines()
        files = {path: _git_show(ctx.repo, f"{sha}:{path}") for path in paths}
        parent = github.commit_files(branch, parent, files, git(ctx.repo, "log", "-1", "--format=%B", sha))
    results = [FixResult.model_validate(r) for r in state.get("results", [])]
    applied = [r for r in results if r.status == "applied"]
    tests = TestRun.model_validate(state["baseline_tests"]) if state.get("baseline_tests") else None
    pull = github.open_pull_request(
        branch, base, f"VulnWarden: {len(applied)} validated security fixes", pr_body(results, ctx.last_scan, tests)
    )
    labels = [ctx.config.monitor.label, "security"]
    if any(r.plan.major_upgrade for r in applied):
        labels.append("breaking-change-risk")
    github.add_labels(pull["number"], labels)
    github.request_reviewers(pull["number"], ctx.config.owners)
    fingerprints = sorted({fp for r in applied for fp in r.plan.fingerprints})
    ctx.store.record_pull(pull["number"], github.repo, pull["html_url"], branch, fingerprints, pull.get("created_at"))
    return {"number": pull["number"], "url": pull["html_url"], "branch": branch, "labels": labels}


def build_graph(ctx: AgentContext, checkpointer: Any = None) -> Any:
    def audit(action: str, details: dict[str, Any], actor: str = "vulnwarden") -> None:
        ctx.store.audit(actor, action, details, ctx.now())

    def scan_node(state: AgentState) -> AgentState:
        result = run_scan(ctx)
        ctx.last_scan = result
        sync = ctx.store.sync_findings(result.findings, str(ctx.repo), ctx.now())
        summary = summarize(result.findings)
        audit(
            "scan",
            {
                "open": summary["open"],
                "by_priority": summary["by_priority"],
                "correlation": result.stats["correlation"],
                "warnings": result.warnings[:5],
            },
        )
        return {
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "summary": summary,
            "correlation": result.stats["correlation"],
            "sync": sync.model_dump(),
            "errors": [],
        }

    def plan_node(state: AgentState) -> AgentState:
        findings = [Finding.model_validate(f) for f in state["findings"]]
        plans = plan_fixes(findings, ctx.config, llm_available=ctx.llm is not None)
        audit(
            "plan",
            {"actionable": sum(p.kind != "manual" for p in plans), "manual": sum(p.kind == "manual" for p in plans)},
        )
        return {"plans": [p.model_dump(mode="json") for p in plans]}

    def approve_node(state: AgentState) -> AgentState:
        actionable = [p for p in state["plans"] if p["kind"] != "manual"]
        ids = [p["id"] for p in actionable]
        if ctx.auto_approve:
            approved, actor = ids, "policy:auto-approve"
        else:
            decision = interrupt(
                {
                    "question": "Approve these fixes? Reply 'all', 'none' or a comma-separated list of plan ids.",
                    "plans": [
                        {k: p.get(k) for k in ("id", "kind", "title", "priority", "path", "major_upgrade")}
                        for p in actionable
                    ],
                }
            )
            approved, actor = parse_decision(decision, ids), "human"
        audit("approval", {"approved": approved, "declined": [i for i in ids if i not in approved]}, actor)
        return {"approved": approved}

    def remediate_node(state: AgentState) -> AgentState:
        plans = [FixPlan.model_validate(p) for p in state["plans"]]
        approved = set(state.get("approved", []))
        for plan in plans:
            if plan.kind != "manual" and plan.id not in approved:
                plan.kind, plan.reason = "manual", "Not approved by a reviewer."
        try:
            if git(ctx.repo, "status", "--porcelain", "--untracked-files=no"):
                raise GitError("Working tree has uncommitted changes; commit or stash them first.")
            original = git(ctx.repo, "rev-parse", "--abbrev-ref", "HEAD")
            base_sha = git(ctx.repo, "rev-parse", "HEAD")
        except (GitError, OSError) as exc:
            return {"errors": [*state.get("errors", []), str(exc)], "results": [], "branch": None}
        branch = f"{ctx.config.remediation.branch_prefix}-{ctx.now():%Y%m%d-%H%M%S}"
        git(ctx.repo, "switch", "-q", "-c", branch)
        try:
            baseline = run_scan(ctx, include_imports=False)
            remediator = Remediator(
                ctx.repo,
                ctx.config,
                ctx.intel,
                lambda: run_scan(ctx, include_imports=False),
                llm=ctx.llm,
                audit=lambda action, details: audit(action, details),
            )
            results, tests = remediator.run(plans, baseline)
        finally:
            git(ctx.repo, "switch", "-q", original)
        applied = [r for r in results if r.status == "applied"]
        if not applied:
            git(ctx.repo, "branch", "-q", "-D", branch)
        return {
            "results": [r.model_dump(mode="json") for r in results],
            "baseline_tests": tests.model_dump(),
            "branch": branch if applied else None,
            "base_sha": base_sha,
        }

    def publish_node(state: AgentState) -> AgentState:
        if not state.get("branch") or ctx.github is None:
            return {"pull_request": None}
        try:
            pull = publish(ctx, state)
        except Exception as exc:
            audit("publish_failed", {"error": str(exc)})
            return {"pull_request": None, "errors": [*state.get("errors", []), f"Publishing failed: {exc}"]}
        audit("pull_request_opened", pull)
        return {"pull_request": pull}

    def report_node(state: AgentState) -> AgentState:
        audit(
            "run_complete",
            {
                "applied": sum(r["status"] == "applied" for r in state.get("results", [])),
                "pull_request": (state.get("pull_request") or {}).get("url"),
            },
        )
        return {}

    graph = StateGraph(AgentState)
    for name, node in [
        ("scan", scan_node),
        ("plan", plan_node),
        ("approve", approve_node),
        ("remediate", remediate_node),
        ("publish", publish_node),
        ("report", report_node),
    ]:
        graph.add_node(name, node)
    graph.add_edge(START, "scan")
    graph.add_edge("scan", "plan")
    graph.add_conditional_edges(
        "plan",
        lambda s: "approve" if any(p["kind"] != "manual" for p in s["plans"]) else "report",
        {"approve": "approve", "report": "report"},
    )
    graph.add_conditional_edges(
        "approve",
        lambda s: "remediate" if s.get("approved") else "report",
        {"remediate": "remediate", "report": "report"},
    )
    graph.add_edge("remediate", "publish")
    graph.add_edge("publish", "report")
    graph.add_edge("report", END)
    return graph.compile(checkpointer=checkpointer or InMemorySaver())
