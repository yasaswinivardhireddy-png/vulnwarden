from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from vulnwarden.config import Config, NotifyConfig
from vulnwarden.github import GitHubClient, GitHubError
from vulnwarden.models import Category, Finding, Severity
from vulnwarden.monitor import evaluate_pull, run_monitor
from vulnwarden.notify import Notifier
from vulnwarden.store import Store

NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)


class FakeGitHub:
    """Minimal in-memory GitHub REST API served through httpx.MockTransport."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict]] = []
        self.pulls: list[dict] = []
        self.reviews: dict[int, list[dict]] = {}
        self.fail_next: list[int] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        path = request.url.path
        self.requests.append((request.method, path, body))
        assert request.headers["Authorization"] == "Bearer test-token"
        if self.fail_next:
            return httpx.Response(self.fail_next.pop(0), json={"message": "try again"})
        if path == "/repos/acme/shop":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/acme/shop/git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": "base000"}})
        if path.startswith("/repos/acme/shop/git/commits/") and request.method == "GET":
            return httpx.Response(200, json={"tree": {"sha": "tree000"}})
        if path == "/repos/acme/shop/git/trees":
            return httpx.Response(201, json={"sha": f"tree{len(self.requests)}"})
        if path == "/repos/acme/shop/git/commits":
            return httpx.Response(201, json={"sha": f"commit{len(self.requests)}"})
        if path == "/repos/acme/shop/pulls" and request.method == "POST":
            pull = {
                "number": 7,
                "html_url": "https://github.com/acme/shop/pull/7",
                "created_at": "2026-11-02T00:00:00Z",
            }
            return httpx.Response(201, json=pull)
        if path == "/repos/acme/shop/pulls" and request.method == "GET":
            return httpx.Response(200, json=self.pulls)
        if path.endswith("/reviews"):
            return httpx.Response(200, json=self.reviews.get(int(path.split("/")[-2]), []))
        if path == "/repos/acme/shop/issues/404/labels":
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(201 if request.method == "POST" else 200, json={})

    def client(self) -> GitHubClient:
        return GitHubClient(
            "acme/shop", "test-token", transport=httpx.MockTransport(self.handler), sleep=lambda s: None
        )


def test_commit_files_uses_git_data_api_and_opens_pr():
    fake = FakeGitHub()
    gh = fake.client()
    assert gh.default_branch() == "main" and gh.branch_sha("main") == "base000"
    gh.create_branch("vulnwarden/fix", "base000")
    sha = gh.commit_files("vulnwarden/fix", "base000", {"app.py": "print('fixed')\n"}, "fix: yaml")
    pull = gh.open_pull_request("vulnwarden/fix", "main", "VulnWarden fixes", "body")
    gh.add_labels(pull["number"], ["security-remediation"])
    gh.request_reviewers(pull["number"], ["alice"])
    methods = [(m, p) for m, p, _ in fake.requests]
    assert ("POST", "/repos/acme/shop/git/refs") in methods and sha.startswith("commit")
    tree = next(b for m, p, b in fake.requests if p.endswith("/git/trees"))
    assert tree["base_tree"] == "tree000" and tree["tree"][0]["path"] == "app.py"
    ref_update = next(b for m, p, b in fake.requests if m == "PATCH")
    assert ref_update == {"sha": sha, "force": False}
    assert ("POST", "/repos/acme/shop/pulls/7/requested_reviewers") in methods


def test_github_retries_server_errors_and_raises_client_errors():
    fake = FakeGitHub()
    fake.fail_next = [502, 503]
    assert fake.client().default_branch() == "main"
    with pytest.raises(GitHubError) as error:
        fake.client().add_labels(404, ["x"])
    assert error.value.status == 404
    with pytest.raises(ValueError):
        GitHubClient("not-a-repo", "t")


def _pull(number: int, hours_old: float, **extra) -> dict:
    created = (NOW - timedelta(hours=hours_old)).isoformat().replace("+00:00", "Z")
    return {
        "number": number,
        "title": f"PR {number}",
        "created_at": created,
        "html_url": f"https://x/{number}",
        "labels": [{"name": "security-remediation"}],
        "requested_reviewers": [{"login": "alice"}],
        **extra,
    }


def test_evaluate_pull_thresholds_and_repeat_window():
    config = Config(owners=["bob"], escalation_contacts=["secops-lead"])
    assert evaluate_pull(_pull(1, 10), [], NOW, config, {}) is None
    remind = evaluate_pull(_pull(1, 30), [], NOW, config, {})
    assert remind.kind == "remind" and remind.recipients == ["alice", "bob"] and "No review" in remind.reason
    approved = evaluate_pull(_pull(1, 30), [{"state": "APPROVED"}], NOW, config, {})
    assert "Approved" in approved.reason
    escalate = evaluate_pull(_pull(1, 80), [], NOW, config, {})
    assert escalate.kind == "escalate" and "secops-lead" in escalate.recipients
    recent = {"escalate": NOW - timedelta(hours=2)}
    assert evaluate_pull(_pull(1, 80), [], NOW, config, recent) is None
    assert evaluate_pull(_pull(1, 80, draft=True), [], NOW, config, {}) is None


def test_run_monitor_notifies_comments_and_is_idempotent():
    fake = FakeGitHub()
    fake.pulls = [_pull(1, 30), _pull(2, 90), _pull(3, 5), {**_pull(4, 99), "labels": []}]
    store, sent = Store(), []
    notifier = Notifier(NotifyConfig(channels=["console"]), echo=sent.append)
    config = Config(escalation_contacts=["secops-lead"])
    actions = run_monitor(fake.client(), store, notifier, config, now=NOW)
    assert [(a.pr_number, a.kind) for a in actions] == [(1, "remind"), (2, "escalate")]
    assert len(sent) == 2 and "ESCALATION" in sent[1]
    comments = [p for m, p, _ in fake.requests if p.endswith("/comments")]
    assert comments == ["/repos/acme/shop/issues/1/comments", "/repos/acme/shop/issues/2/comments"]
    assert run_monitor(fake.client(), store, notifier, config, now=NOW + timedelta(hours=1)) == []
    later = run_monitor(fake.client(), store, notifier, config, now=NOW + timedelta(hours=25))
    assert [(a.pr_number, a.kind) for a in later] == [(1, "remind"), (2, "escalate"), (3, "remind")]


def test_notifier_channels():
    posted: list[dict] = []

    def webhook(request: httpx.Request) -> httpx.Response:
        posted.append({"url": str(request.url), **json.loads(request.content)})
        return httpx.Response(200)

    class FakeSMTP:
        instances: list[FakeSMTP] = []

        def __init__(self, host, port, timeout):
            self.host, self.port, self.sent, self.logged_in, self.tls = host, port, [], None, False
            FakeSMTP.instances.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context):
            self.tls = True

        def login(self, user, password):
            self.logged_in = user

        def send_message(self, message):
            self.sent.append(message)

    config = NotifyConfig(
        channels=["email", "slack", "teams", "pager"],
        smtp_host="smtp.example.com",
        email_to=["owners@example.com"],
        escalation_email_to=["ciso@example.com"],
    )
    env = {
        "VULNWARDEN_SLACK_WEBHOOK": "https://hooks.slack.com/services/x",
        "VULNWARDEN_TEAMS_WEBHOOK": "http://insecure.example.com/hook",
        "VULNWARDEN_SMTP_USERNAME": "bot",
        "VULNWARDEN_SMTP_PASSWORD": "pw",
    }
    notifier = Notifier(config, env=env, transport=httpx.MockTransport(webhook), smtp_factory=FakeSMTP)
    delivery = notifier.send("Subject", "Body", ["alice"], escalation=True)
    assert delivery.delivered == ["email", "slack"]
    assert "https" in delivery.errors["teams"] and "unknown channel" in delivery.errors["pager"]
    smtp = FakeSMTP.instances[0]
    assert smtp.tls and smtp.logged_in == "bot"
    assert smtp.sent[0]["To"] == "ciso@example.com, owners@example.com"
    assert posted[0]["text"].startswith("*Subject*") and "@alice" in posted[0]["text"]


def _finding(rule: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule,
        title=rule,
        category=Category.CODE,
        severity=severity,
        source="vulnwarden-sast",
        path="a.py",
        line=1,
        snippet=rule,
    )


def test_store_reconciles_finding_lifecycle_and_trend():
    store = Store()
    a, b = _finding("A"), _finding("B")
    first = store.sync_findings([a, b], "repo", NOW)
    assert len(first.new) == 2
    b_reclassified = b.model_copy(update={"severity": Severity.LOW})
    second = store.sync_findings([b_reclassified], "repo", NOW + timedelta(days=1))
    assert second.resolved == [a.fingerprint] and second.reclassified[0]["to"] == "low"
    third = store.sync_findings([a, b_reclassified], "repo", NOW + timedelta(days=2))
    assert third.reopened == [a.fingerprint]
    assert [t["open"] for t in store.trend()] == [2, 1, 2]


def test_audit_log_is_hash_chained_redacted_and_tamper_evident(tmp_path):
    store = Store(tmp_path / "state.db")
    store.audit("vulnwarden", "scan", {"open": 3})
    store.audit("human", "approval", {"approved": ["p1"], "github_token": "ghp_secret", "note": "password='x1y2z3'"})
    store.audit("vulnwarden", "pull_request_opened", {"url": "https://x/1"})
    assert store.verify_audit() == (True, None)
    entry = store.audit_entries()[1]
    assert entry["details"]["github_token"] == "***REDACTED***" and "x1y2z3" not in entry["details"]["note"]
    store.close()
    raw = sqlite3.connect(tmp_path / "state.db")
    raw.execute("UPDATE audit SET details = replace(details, '\"open\": 3', '\"open\": 0') WHERE id = 1")
    raw.commit()
    raw.close()
    assert Store(tmp_path / "state.db").verify_audit() == (False, 1)
