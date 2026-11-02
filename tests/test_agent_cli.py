from __future__ import annotations

import json
from pathlib import Path

import httpx
from helpers import git
from langgraph.types import Command

from vulnwarden import cli
from vulnwarden.agent import AgentContext, build_graph, parse_decision
from vulnwarden.config import load_config
from vulnwarden.github import GitHubClient
from vulnwarden.store import Store

THREAD = {"configurable": {"thread_id": "t"}}


def _ctx(repo, intel, **kwargs) -> AgentContext:
    config = load_config(None, repo)
    config.remediation.test_command = ["{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    return AgentContext(repo=repo, config=config, intel=intel, store=Store(), **kwargs)


def test_parse_decision():
    ids = ["a", "b", "c"]
    assert parse_decision("all", ids) == ids and parse_decision(True, ids) == ids
    assert parse_decision("none", ids) == [] and parse_decision(None, ids) == []
    assert parse_decision("c, a, zzz", ids) == ["a", "c"] and parse_decision(["b"], ids) == ["b"]


def test_agent_pauses_for_human_approval_and_respects_a_decline(demo_repo, offline_intel):
    ctx = _ctx(demo_repo, offline_intel)
    graph = build_graph(ctx)
    state = graph.invoke({}, THREAD)
    question = state["__interrupt__"][0].value
    assert question["plans"] and all(p["kind"] != "manual" for p in question["plans"])
    final = graph.invoke(Command(resume="none"), THREAD)
    assert final["approved"] == [] and not final.get("results")
    assert git(demo_repo, "branch", "--list", "vulnwarden/*") == ""
    actions = [e["action"] for e in ctx.store.audit_entries()]
    assert actions == ["scan", "plan", "approval", "run_complete"]
    assert ctx.store.audit_entries()[2]["actor"] == "human"


def test_agent_applies_approved_subset_and_publishes_a_pull_request(demo_repo, offline_intel):
    calls: list[tuple[str, str, dict]] = []

    def github(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        calls.append((request.method, request.url.path, body))
        path = request.url.path
        if path == "/repos/acme/shop":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/acme/shop/git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": git(demo_repo, "rev-parse", "main")}})
        if path.startswith("/repos/acme/shop/git/commits/") and request.method == "GET":
            return httpx.Response(200, json={"tree": {"sha": "t0"}})
        if path.endswith("/git/trees") or path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": f"s{len(calls)}"})
        if path == "/repos/acme/shop/pulls":
            return httpx.Response(
                201,
                json={
                    "number": 12,
                    "html_url": "https://github.com/acme/shop/pull/12",
                    "created_at": "2026-11-02T00:00:00Z",
                },
            )
        return httpx.Response(201, json={})

    client = GitHubClient("acme/shop", "tok", transport=httpx.MockTransport(github))
    ctx = _ctx(demo_repo, offline_intel, github=client)
    graph = build_graph(ctx)
    state = graph.invoke({}, THREAD)
    plans = state["__interrupt__"][0].value["plans"]
    chosen = [p["id"] for p in plans if p["path"] in {"shop/catalog.py", "Dockerfile"}]
    final = graph.invoke(Command(resume=",".join(chosen)), THREAD)
    applied = [r for r in final["results"] if r["status"] == "applied"]
    assert {r["plan"]["path"] for r in applied} == {"shop/catalog.py", "Dockerfile"}
    assert final["pull_request"]["number"] == 12 and "breaking-change-risk" not in final["pull_request"]["labels"]
    trees = [b for m, p, b in calls if p.endswith("/git/trees")]
    assert {item["path"] for t in trees for item in t["tree"]} == {"shop/catalog.py", "Dockerfile"}
    pull_body = next(b for m, p, b in calls if p == "/repos/acme/shop/pulls")["body"]
    assert "A human must review and approve before merge" in pull_body
    assert ctx.store.pulls("open")[0]["number"] == 12
    assert git(demo_repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert ctx.store.verify_audit() == (True, None)


def test_cli_scan_reports_and_gates(demo_repo, tmp_path, capsys):
    args = [str(demo_repo), "--offline", "--intel-cache", str(cli_cache()), "--db", str(tmp_path / "s.db")]
    code = cli.main(
        [
            "scan",
            *args,
            "--sarif",
            str(demo_repo / "reports" / "semgrep.sarif"),
            "--trivy",
            str(demo_repo / "reports" / "trivy-image.json"),
            "--markdown",
            str(tmp_path / "r.md"),
            "--html",
            str(tmp_path / "r.html"),
            "--json",
            str(tmp_path / "r.json"),
            "--cbom",
            str(tmp_path / "cbom.json"),
            "--fail-on",
            "critical",
        ]
    )
    out = capsys.readouterr().out
    assert code == 2 and "Failing:" in out and "3 cross-scanner duplicates" in out
    report = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert "## Prioritized findings" in report and "## Cryptographic lifecycle" in report
    assert "<svg" not in (tmp_path / "r.html").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "cbom.json").read_text(encoding="utf-8"))["specVersion"] == "1.6"
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["summary"]["open"] > 50
    assert cli.main(["scan", *args]) == 0
    assert cli.main(["scan", *args, "--html", str(tmp_path / "t.html")]) == 0
    assert "<svg" in (tmp_path / "t.html").read_text(encoding="utf-8")


def test_cli_crypto_and_audit(demo_repo, tmp_path, capsys):
    assert cli.main(["crypto", str(demo_repo), "--cbom", str(tmp_path / "cbom.json")]) == 0
    out = capsys.readouterr().out
    assert "certificate legacy.shop.example.com" in out and "PQC migration candidates" in out
    db = tmp_path / "state.db"
    Store(db).audit("vulnwarden", "scan", {"open": 1})
    assert cli.main(["audit", "--db", str(db)]) == 0
    assert "chain intact" in capsys.readouterr().out


def test_cli_remediate_requires_explicit_approval_when_not_interactive(demo_repo, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code = cli.main(
        [
            "remediate",
            str(demo_repo),
            "--offline",
            "--intel-cache",
            str(cli_cache()),
            "--db",
            str(tmp_path / "s.db"),
            "--report",
            str(tmp_path / "rem.md"),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0 and "declining" in out and "no fixes attempted" in out


def cli_cache() -> Path:
    return Path(__file__).resolve().parents[1] / "benchmarks" / "intel-cache"
