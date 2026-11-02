from __future__ import annotations

from pathlib import Path

from helpers import git, init_repo
from langchain_core.runnables import RunnableLambda

from vulnwarden.agent import AgentContext, run_scan
from vulnwarden.config import Config, load_config
from vulnwarden.llm import PatchModel, PatchProposal
from vulnwarden.models import Category, Finding, Severity
from vulnwarden.remediation import Remediator, plan_fixes, run_tests, sanitized_env, upgrade_requirement
from vulnwarden.store import Store


def test_upgrade_requirement_preserves_extras_markers_and_comments():
    text = "flask==1.1.2\nrequests[socks] == 2.25.1 ; python_version > '3.8'  # http\nPyYAML==5.3.1\n"
    assert upgrade_requirement(text, 2, "requests", "2.32.4") == (
        "flask==1.1.2\nrequests[socks] ==2.32.4 ; python_version > '3.8'  # http\nPyYAML==5.3.1\n"
    )
    assert "pyyaml" not in upgrade_requirement(text, 3, "pyyaml", "5.4") and "PyYAML==5.4" in upgrade_requirement(
        text, 3, "pyyaml", "5.4"
    )
    assert upgrade_requirement(text, 1, "requests", "9.9") is None


def _dep(cve: str, fixes: list[str], priority: str = "P2") -> Finding:
    return Finding(
        rule_id=cve,
        title=cve,
        category=Category.DEPENDENCY,
        severity=Severity.HIGH,
        source="osv",
        path="requirements.txt",
        line=1,
        package="requests",
        ecosystem="PyPI",
        installed_version="2.25.1",
        fixed_versions=fixes,
        aliases=[cve],
        priority=priority,
        risk_score=7.5,
    )


def test_plan_groups_dependency_upgrades_and_routes_the_rest():
    config = Config()
    findings = [
        _dep("CVE-1", ["2.31.0"]),
        _dep("CVE-2", ["2.32.4"]),
        _dep("CVE-3", []),
        Finding(
            rule_id="VW-PY-YAML-LOAD",
            title="yaml",
            category=Category.CODE,
            severity=Severity.HIGH,
            source="vulnwarden-sast",
            path="a.py",
            line=3,
            priority="P2",
        ),
        Finding(
            rule_id="VW-PY-PICKLE",
            title="pickle",
            category=Category.CODE,
            severity=Severity.HIGH,
            source="vulnwarden-sast",
            path="a.py",
            line=5,
            priority="P2",
        ),
        Finding(
            rule_id="VW-PY-HARDCODED-SECRET",
            title="secret",
            category=Category.CODE,
            severity=Severity.HIGH,
            source="vulnwarden-sast",
            path="b.py",
            line=1,
            snippet="K = '***'",
            priority="P2",
        ),
        Finding(
            rule_id="VW-CERT-SELF-SIGNED",
            title="self",
            category=Category.CRYPTO,
            severity=Severity.LOW,
            source="vulnwarden-crypto",
            path="c.pem",
            line=1,
            priority="P4",
        ),
    ]
    plans = {p.title: p for p in plan_fixes(findings, config, llm_available=True)}
    upgrade = plans["Upgrade requests 2.25.1 -> 2.32.4"]
    assert upgrade.kind == "dependency" and len(upgrade.fingerprints) == 2 and not upgrade.major_upgrade
    assert plans["Review requests 2.25.1"].kind == "manual"
    assert plans["yaml"].kind == "codemod" and plans["pickle"].kind == "llm"
    assert plans["secret"].kind == "codemod"
    assert plans["self"].kind == "manual"
    assert plan_fixes(findings, config, llm_available=False)[-1].kind == "manual"


def test_sanitized_env_strips_credentials(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("GOOGLE_API_KEY", "x")
    monkeypatch.setenv("VULNWARDEN_SLACK_WEBHOOK", "x")
    env = sanitized_env()
    assert not {"GITHUB_TOKEN", "GOOGLE_API_KEY", "VULNWARDEN_SLACK_WEBHOOK"} & set(env) and "PATH" in {
        k.upper() for k in env
    }


def test_run_tests_reports_pass_fail_and_missing_command(tmp_path):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    assert run_tests(tmp_path, ["{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider"], 120).passed
    (tmp_path / "test_bad.py").write_text("def test_bad():\n    assert False\n", encoding="utf-8")
    failed = run_tests(tmp_path, ["{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider"], 120)
    assert not failed.passed and failed.returncode == 1
    assert run_tests(tmp_path, ["definitely-not-a-command-xyz"], 10).returncode == 127


def _small_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "loader.py").write_text(
        "import yaml\n\n\ndef load(text):\n    return yaml.load(text, Loader=yaml.Loader)\n", encoding="utf-8"
    )
    (repo / "session.py").write_text(
        "import pickle\n\n\ndef read(blob):\n    return pickle.loads(blob)\n", encoding="utf-8"
    )
    (repo / "test_svc.py").write_text(
        "import json\nfrom loader import load\nfrom session import read\n\n\ndef test_load():\n"
        "    assert load('a: 1') == {'a': 1}\n\n\ndef test_read():\n    import pickle\n"
        "    assert read(pickle.dumps({'u': 1})) == {'u': 1}\n",
        encoding="utf-8",
    )
    (repo / "pytest.ini").write_text("[pytest]\npythonpath = .\n", encoding="utf-8")
    init_repo(repo)
    return repo


def test_remediator_applies_validated_fixes_and_rolls_back_breaking_ones(tmp_path, offline_intel):
    repo = _small_repo(tmp_path)
    config = load_config(None, repo)
    config.remediation.test_command = ["{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    ctx = AgentContext(repo=repo, config=config, intel=offline_intel, store=Store())
    baseline = run_scan(ctx, include_imports=False)
    # The scripted model "fixes" pickle with JSON, which breaks the round-trip test and must be rolled back.
    model = type(
        "Model",
        (),
        {
            "with_structured_output": lambda self, schema: RunnableLambda(
                lambda m: PatchProposal(
                    start_line=5,
                    end_line=5,
                    replacement="    return json.loads(blob)",
                    imports_to_add=["json"],
                    explanation="Use JSON instead of pickle.",
                    confidence=0.9,
                )
            )
        },
    )()
    plans = plan_fixes(baseline.findings, config, llm_available=True)
    git(repo, "switch", "-q", "-c", "fix")
    audit: list[str] = []
    remediator = Remediator(
        repo,
        config,
        offline_intel,
        lambda: run_scan(ctx, include_imports=False),
        llm=PatchModel(model),
        audit=lambda action, details: audit.append(action),
    )
    results, baseline_tests = remediator.run(plans, baseline)
    by_rule = {r.plan.rule_ids[0]: r for r in results}
    assert baseline_tests.passed
    assert by_rule["VW-PY-YAML-LOAD"].status == "applied" and by_rule["VW-PY-YAML-LOAD"].commit
    assert by_rule["VW-PY-PICKLE"].status == "reverted" and "Tests failed" in by_rule["VW-PY-PICKLE"].reason
    assert "yaml.safe_load(text)" in (repo / "loader.py").read_text(encoding="utf-8")
    assert "pickle.loads(blob)" in (repo / "session.py").read_text(encoding="utf-8")
    assert git(repo, "status", "--porcelain") == ""
    assert git(repo, "log", "-1", "--format=%an %s") == "VulnWarden Bot fix(security): Unsafe YAML deserialization"
    assert audit == ["baseline_tests", "fix_applied", "fix_reverted"]


def test_remediator_skips_everything_when_baseline_tests_fail(tmp_path, offline_intel):
    repo = _small_repo(tmp_path)
    (repo / "test_broken.py").write_text("def test_x():\n    assert False\n", encoding="utf-8")
    config = load_config(None, repo)
    config.remediation.test_command = ["{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    ctx = AgentContext(repo=repo, config=config, intel=offline_intel, store=Store())
    baseline = run_scan(ctx, include_imports=False)
    results, tests = Remediator(repo, config, offline_intel, lambda: baseline).run(
        plan_fixes(baseline.findings, config), baseline
    )
    assert not tests.passed and {r.status for r in results} <= {"skipped", "manual"}
