"""Plan, apply and validate fixes. Every change must pass the test suite and a security rescan."""

from __future__ import annotations

import difflib
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from .codemods import apply_codemod, codemod_for
from .config import Config
from .guardrails import check_proposal
from .intel import Intel
from .llm import PatchModel
from .models import Category, Finding, ScanResult, normalize_package
from .scanners.dependencies import fixed_versions_for, remaining_vulns, version_key

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
NEVER_SEND_TO_LLM = {"VW-PY-HARDCODED-SECRET", "VW-CRYPTO-PRIVATE-KEY", "VW-DOCKER-SECRET"}
SENSITIVE_ENV = re.compile(r"(?i)(token|secret|password|passwd|api_?key|credential|private_?key|webhook)")
BOT_NAME = "VulnWarden Bot"
BOT_EMAIL = "vulnwarden-bot@users.noreply.github.com"


class FixPlan(BaseModel):
    id: str
    kind: str  # dependency | codemod | llm | manual
    title: str
    path: str
    line: int | None = None
    fingerprints: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    priority: str | None = None
    risk_score: float | None = None
    package: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    major_upgrade: bool = False
    reason: str = ""


class TestRun(BaseModel):
    passed: bool
    returncode: int
    duration_seconds: float
    output_tail: str = ""
    no_tests: bool = False


class FixResult(BaseModel):
    plan: FixPlan
    status: str  # applied | reverted | rejected | skipped | manual | already-resolved
    reason: str = ""
    commit: str | None = None
    tests_passed: bool | None = None
    introduced: list[str] = Field(default_factory=list)
    guardrail_violations: list[str] = Field(default_factory=list)
    explanation: str = ""
    diff: str = ""


# ------------------------------------------------------------------ planning
def _plan_id(prefix: str, *parts: Any) -> str:
    text = "-".join(str(p) for p in parts if p)
    return f"{prefix}-{re.sub(r'[^A-Za-z0-9]+', '-', text).strip('-').lower()[:48]}"


def _major(old: str | None, new: str | None) -> bool:
    try:
        return bool(old and new and Version(new).major > Version(old).major)
    except InvalidVersion:
        return False


def plan_fixes(findings: list[Finding], config: Config, llm_available: bool = False) -> list[FixPlan]:
    open_findings = [f for f in findings if f.is_open]
    max_rank = PRIORITY_RANK.get(config.remediation.max_priority, 3)
    plans: list[FixPlan] = []

    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in open_findings:
        if finding.category == Category.DEPENDENCY and finding.package and finding.source == "osv":
            groups[(finding.path, normalize_package(finding.package, finding.ecosystem))].append(finding)
    for (path, package), group in groups.items():
        head = min(group, key=lambda f: (PRIORITY_RANK.get(f.priority or "P4", 4), -(f.risk_score or 0)))
        fixable = [f for f in group if f.fixed_versions]
        common = {
            "path": path,
            "line": head.line,
            "priority": head.priority,
            "risk_score": head.risk_score,
            "package": head.package,
            "from_version": head.installed_version,
        }
        if fixable and head.ecosystem == "PyPI" and path.endswith(".txt"):
            target = max((f.fixed_versions[0] for f in fixable), key=version_key)
            plans.append(
                FixPlan(
                    id=_plan_id("dep", package, target),
                    kind="dependency",
                    title=f"Upgrade {head.package} {head.installed_version} -> {target}",
                    fingerprints=[f.fingerprint for f in fixable],
                    rule_ids=sorted({f.rule_id for f in fixable}),
                    to_version=target,
                    major_upgrade=_major(head.installed_version, target),
                    **common,
                )
            )
        unfixable = [f for f in group if f not in fixable or not (head.ecosystem == "PyPI" and path.endswith(".txt"))]
        if unfixable:
            reason = (
                "No fixed release is published; replace the package or apply a mitigation."
                if not any(f.fixed_versions for f in unfixable)
                else "Lockfile upgrades for this ecosystem are not automated yet."
            )
            plans.append(
                FixPlan(
                    id=_plan_id("manual", package),
                    kind="manual",
                    title=f"Review {head.package} {head.installed_version}",
                    fingerprints=[f.fingerprint for f in unfixable],
                    rule_ids=sorted({f.rule_id for f in unfixable}),
                    reason=reason,
                    **common,
                )
            )

    for finding in open_findings:
        if finding.category == Category.DEPENDENCY and finding.source == "osv":
            continue
        kind, reason = "manual", finding.fix_hint
        if finding.package:
            reason = "Rebuild on a patched base image or upgrade the package in the image."
        elif codemod_for(finding) is not None:
            kind = "codemod"
        elif (
            llm_available and finding.path.endswith(".py") and finding.line and finding.rule_id not in NEVER_SEND_TO_LLM
        ):
            kind = "llm"
        plans.append(
            FixPlan(
                id=_plan_id(kind, finding.rule_id, finding.path, finding.line),
                kind=kind,
                title=finding.title,
                path=finding.path,
                line=finding.line,
                fingerprints=[finding.fingerprint],
                rule_ids=[finding.rule_id],
                priority=finding.priority,
                risk_score=finding.risk_score,
                reason=reason,
            )
        )

    actionable = 0
    for plan in sorted(plans, key=lambda p: (PRIORITY_RANK.get(p.priority or "P4", 4), -(p.risk_score or 0))):
        if plan.kind == "manual":
            continue
        if PRIORITY_RANK.get(plan.priority or "P4", 4) > max_rank:
            plan.kind, plan.reason = "manual", f"Below the auto-fix threshold ({config.remediation.max_priority})."
        elif actionable >= config.remediation.max_fixes:
            plan.kind, plan.reason = "manual", "Deferred: max_fixes per run reached."
        else:
            actionable += 1
    order = {"dependency": 0, "codemod": 1, "llm": 2, "manual": 3}
    return sorted(plans, key=lambda p: (order[p.kind], PRIORITY_RANK.get(p.priority or "P4", 4), -(p.risk_score or 0)))


def upgrade_requirement(text: str, line: int | None, package: str, version: str) -> str | None:
    lines = text.splitlines(keepends=True)
    index = (line or 0) - 1
    if not 0 <= index < len(lines):
        return None
    name = r"[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", package))
    match = re.match(rf"^(\s*{name}\s*(?:\[[^\]]*\])?\s*)(===|==)\s*([A-Za-z0-9._*+!-]+)", lines[index], re.I)
    if not match:
        return None
    lines[index] = lines[index][: match.start(2)] + "==" + version + lines[index][match.end(3) :]
    return "".join(lines)


# ---------------------------------------------------------------- execution
def sanitized_env() -> dict[str, str]:
    """Environment for running untrusted repository tests: no tokens, keys or webhooks."""
    env = {k: v for k, v in os.environ.items() if not SENSITIVE_ENV.search(k)}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_tests(repo: Path, command: list[str], timeout: int) -> TestRun:
    argv = [sys.executable if part == "{python}" else part for part in command]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv, cwd=repo, env=sanitized_env(), capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return TestRun(passed=False, returncode=127, duration_seconds=0.0, output_tail=f"Not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        return TestRun(
            passed=False,
            returncode=-1,
            duration_seconds=float(timeout),
            output_tail=f"Tests timed out after {timeout}s",
        )
    output = (proc.stdout or "") + (proc.stderr or "")
    return TestRun(
        passed=proc.returncode in {0, 5},
        returncode=proc.returncode,
        duration_seconds=round(time.monotonic() - start, 2),
        output_tail=output[-1500:],
        no_tests=proc.returncode == 5,
    )


class GitError(RuntimeError):
    pass


def git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, timeout=120, check=False)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def commit_files(repo: Path, paths: list[str], message: str) -> str:
    git(repo, "add", "--", *paths)
    git(
        repo,
        "-c",
        f"user.name={BOT_NAME}",
        "-c",
        f"user.email={BOT_EMAIL}",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        message,
    )
    return git(repo, "rev-parse", "HEAD")


def unified_diff(before: str, after: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile=f"a/{path}", tofile=f"b/{path}"
        )
    )


class Remediator:
    def __init__(
        self,
        repo: Path,
        config: Config,
        intel: Intel,
        scan: Callable[[], ScanResult],
        llm: PatchModel | None = None,
        audit: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.repo = repo
        self.config = config
        self.intel = intel
        self.scan = scan
        self.llm = llm
        self.audit = audit or (lambda action, details: None)

    def run(self, plans: list[FixPlan], baseline: ScanResult) -> tuple[list[FixResult], TestRun]:
        tests = run_tests(self.repo, self.config.remediation.test_command, self.config.remediation.test_timeout_seconds)
        self.audit("baseline_tests", {"passed": tests.passed, "returncode": tests.returncode})
        if not tests.passed:
            return [
                FixResult(
                    plan=p,
                    status="manual" if p.kind == "manual" else "skipped",
                    reason=p.reason if p.kind == "manual" else "Baseline tests fail, so fixes cannot be validated.",
                )
                for p in plans
            ], tests
        open_now = {f.fingerprint for f in baseline.open_findings()}
        by_fingerprint = {f.fingerprint: f for f in baseline.findings if f.is_open}
        results: list[FixResult] = []
        for plan in plans:
            if plan.kind == "manual":
                results.append(FixResult(plan=plan, status="manual", reason=plan.reason))
                continue
            if not any(fp in open_now for fp in plan.fingerprints):
                results.append(
                    FixResult(plan=plan, status="already-resolved", reason="Resolved by an earlier fix in this run.")
                )
                continue
            result, after = self._apply(plan, by_fingerprint, open_now)
            self.audit("fix_" + result.status, {"plan": plan.id, "reason": result.reason, "commit": result.commit})
            results.append(result)
            if after is not None:
                open_now = {f.fingerprint for f in after.open_findings()}
                by_fingerprint.update({f.fingerprint: f for f in after.findings if f.is_open})
        return results, tests

    def _dependency_change(self, plan: FixPlan, text: str) -> str | None:
        target = plan.to_version or ""
        for _ in range(3):
            follow_ups = []
            for advisory in remaining_vulns(self.intel, "PyPI", plan.package or "", target):
                fixes = fixed_versions_for(advisory, plan.package or "", "PyPI", target)
                if fixes:
                    follow_ups.append(fixes[0])
            if not follow_ups:
                break
            target = max(follow_ups, key=version_key)
        if target != plan.to_version:
            plan.reason = f"Raised target from {plan.to_version} to {target}: the first fix is still vulnerable."
            plan.to_version = target
            plan.title = f"Upgrade {plan.package} {plan.from_version} -> {target}"
            plan.major_upgrade = _major(plan.from_version, target)
        return upgrade_requirement(text, plan.line, plan.package or "", target)

    def _apply(
        self, plan: FixPlan, by_fingerprint: dict[str, Finding], open_before: set[str]
    ) -> tuple[FixResult, ScanResult | None]:
        file = self.repo / plan.path
        try:
            original = file.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return FixResult(plan=plan, status="skipped", reason=f"Cannot read {plan.path}: {exc}"), None
        finding = by_fingerprint.get(plan.fingerprints[0])
        explanation = ""
        if plan.kind == "dependency":
            updated = self._dependency_change(plan, original)
        elif plan.kind == "codemod" and finding is not None:
            updated = apply_codemod(original, finding)
        elif plan.kind == "llm" and finding is not None and self.llm is not None:
            proposal, error = self.llm.propose(finding, original)
            if proposal is None:
                return FixResult(plan=plan, status="rejected", reason=error), None
            guard = check_proposal(
                proposal,
                finding,
                original,
                context_lines=self.config.llm.context_lines,
                min_confidence=self.config.llm.min_confidence,
            )
            explanation = proposal.explanation
            if not guard.ok:
                return FixResult(
                    plan=plan,
                    status="rejected",
                    reason="Guardrails rejected the model's patch.",
                    guardrail_violations=guard.violations,
                    explanation=explanation,
                ), None
            updated = guard.patched
        else:
            updated = None
        if not updated or updated == original:
            return FixResult(plan=plan, status="skipped", reason="No applicable change was produced."), None

        file.write_bytes(updated.encode("utf-8"))
        diff = unified_diff(original, updated, plan.path)
        tests = run_tests(self.repo, self.config.remediation.test_command, self.config.remediation.test_timeout_seconds)
        if not tests.passed:
            file.write_bytes(original.encode("utf-8"))
            return FixResult(
                plan=plan,
                status="reverted",
                tests_passed=False,
                diff=diff,
                explanation=explanation,
                reason=f"Tests failed after the change (exit {tests.returncode}); change rolled back.",
            ), None
        after = self.scan()
        open_after = {f.fingerprint for f in after.open_findings()}
        unresolved = [fp for fp in plan.fingerprints if fp in open_after]
        introduced = [
            f"{f.rule_id} at {f.path}:{f.line}" for f in after.open_findings() if f.fingerprint not in open_before
        ]
        if unresolved or introduced:
            file.write_bytes(original.encode("utf-8"))
            reason = (
                "Rescan still reports the finding" if unresolved else "Rescan found new issues"
            ) + "; change rolled back."
            return FixResult(
                plan=plan,
                status="reverted",
                tests_passed=True,
                introduced=introduced,
                diff=diff,
                explanation=explanation,
                reason=reason,
            ), None
        message = (
            f"fix(security): {plan.title}\n\nResolves: {', '.join(plan.rule_ids)}\n"
            f"Validated by VulnWarden: tests passed and rescan is clean."
        )
        commit = commit_files(self.repo, [plan.path], message)
        return FixResult(
            plan=plan,
            status="applied",
            tests_passed=True,
            commit=commit,
            diff=diff,
            explanation=explanation,
            reason=plan.reason,
        ), after
