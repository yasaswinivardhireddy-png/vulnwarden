from __future__ import annotations

from datetime import date

from vulnwarden.models import Category, Finding, Severity
from vulnwarden.scanners.containers import eol_status, load_trivy, parse_dockerfile, scan_dockerfile
from vulnwarden.scanners.openapi import scan_openapi
from vulnwarden.scanners.python_sast import scan_python_source
from vulnwarden.scanners.sarif import load_sarif


def rules(findings: list[Finding]) -> list[str]:
    return sorted(f.rule_id for f in findings)


def test_yaml_load_respects_safe_loader_and_aliases():
    source = (
        "import yaml as y\nfrom yaml import load\n"
        "a = y.load(text)\n"
        "b = y.load(text, Loader=y.SafeLoader)\n"
        "c = load(text, Loader=y.Loader)\n"
        "d = y.safe_load(text)\n"
    )
    findings, _ = scan_python_source(source, "app.py")
    assert [f.line for f in findings if f.rule_id == "VW-PY-YAML-LOAD"] == [3, 5]


def test_shell_and_os_system_detection():
    source = (
        "import os, subprocess\n"
        "subprocess.run(cmd, shell=True)\n"
        "subprocess.run(['ls'], shell=False)\n"
        "os.system(f'rm {path}')\n"
        "os.system('ls')\n"
    )
    findings, _ = scan_python_source(source, "app.py")
    assert [f.line for f in findings if f.rule_id == "VW-PY-SHELL"] == [2, 4]


def test_sql_injection_patterns_and_parameterized_queries():
    source = (
        "def q(cur, name):\n"
        "    cur.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
        "    cur.execute('SELECT * FROM t WHERE n = %s' % name)\n"
        "    cur.execute('SELECT * FROM t WHERE n = ' + name)\n"
        "    cur.execute('SELECT * FROM t WHERE n = {}'.format(name))\n"
        "    cur.execute('SELECT * FROM t WHERE n = ?', (name,))\n"
    )
    findings, _ = scan_python_source(source, "db.py")
    assert [f.line for f in findings if f.rule_id == "VW-PY-SQL-INJECTION"] == [2, 3, 4, 5]


def test_hardcoded_secrets_are_redacted_and_placeholders_ignored():
    source = 'API_KEY = "s3cr3t-value-123456"\nPASSWORD = "changeme"\nTOKEN = ""\nconnect(password="hunter2-hunter2")\n'
    findings, _ = scan_python_source(source, "settings.py")
    secrets = [f for f in findings if f.rule_id == "VW-PY-HARDCODED-SECRET"]
    assert [f.line for f in secrets] == [1, 4]
    assert all("s3cr3t" not in f.snippet and "hunter2" not in f.snippet for f in secrets)


def test_environment_variable_names_are_not_secrets():
    source = (
        'smtp_password_env = "APP_SMTP_PASSWORD"\nDB_PASSWORD = "PROD_DB_PASSWORD"\n'
        'token_url = "https-token-endpoint"\nlogin(password="Pr0d-Passw0rd!")\n'
    )
    findings, _ = scan_python_source(source, "settings.py")
    assert [f.line for f in findings if f.rule_id == "VW-PY-HARDCODED-SECRET"] == [4]


def test_every_snippet_is_redacted():
    source = 'import requests\nrequests.get(u, headers={"token": "ghp_' + "a" * 36 + '"}, verify=False)\n'
    (finding,) = [f for f in scan_python_source(source, "x.py")[0] if f.rule_id == "VW-PY-TLS-VERIFY-OFF"]
    assert "ghp_" not in finding.snippet and "REDACTED" in finding.snippet


def test_tls_eval_pickle_debug_mktemp_rules():
    source = (
        "import pickle, requests, ssl, tempfile\n"
        "requests.get(u, verify=False)\n"
        "ctx = ssl._create_unverified_context()\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "eval(user_input)\n"
        "eval('1 + 1')\n"
        "pickle.loads(blob)\n"
        "app.run(debug=True)\n"
        "tempfile.mktemp()\n"
    )
    findings, _ = scan_python_source(source, "x.py")
    assert rules(findings) == sorted(
        ["VW-PY-TLS-VERIFY-OFF"] * 3 + ["VW-PY-EVAL", "VW-PY-PICKLE", "VW-PY-FLASK-DEBUG", "VW-PY-MKTEMP"]
    )


def test_invalid_python_returns_no_tree():
    findings, tree = scan_python_source("def broken(:\n", "bad.py")
    assert findings == [] and tree is None


def test_dockerfile_rules_and_eol_recommendation():
    text = (
        "FROM python:3.8-slim-buster AS build\nRUN pip wheel .\n"
        "FROM python:3.8-slim-buster\nENV API_KEY=abcdef123456\n"
        'ADD https://example.com/x.tgz /opt/\nRUN curl -sSL https://x.sh | sh\nCMD ["python"]\n'
    )
    findings = scan_dockerfile(text, "Dockerfile", today=date(2026, 11, 2))
    assert rules(findings) == sorted(
        ["VW-DOCKER-EOL-BASE", "VW-DOCKER-SECRET", "VW-DOCKER-REMOTE-ADD", "VW-DOCKER-PIPE-SHELL", "VW-DOCKER-ROOT"]
    )
    eol = next(f for f in findings if f.rule_id == "VW-DOCKER-EOL-BASE")
    assert eol.line == 3 and eol.details["recommended_image"] == "python:3.12-slim-bookworm"


def test_dockerfile_non_root_and_pinned_images_are_clean():
    text = 'FROM python:3.13-slim\nUSER 10001\nCMD ["python"]\n'
    assert scan_dockerfile(text, "Dockerfile", today=date(2026, 11, 2)) == []
    unpinned = scan_dockerfile("FROM ubuntu\nUSER app\n", "Dockerfile", today=date(2026, 11, 2))
    assert rules(unpinned) == ["VW-DOCKER-UNPINNED-BASE"]


def test_eol_rules_for_node_ubuntu_and_debian():
    today = date(2026, 11, 2)
    assert eol_status("node:16-alpine", today)[2] == "node:24-alpine"
    assert eol_status("ubuntu:18.04", today)[2] == "ubuntu:24.04"
    assert eol_status("debian:10", today)[0] == "debian buster"
    assert eol_status("node:24", today) is None


def test_dockerfile_line_continuations():
    instructions = parse_dockerfile("FROM alpine:3.20\nRUN apk add \\\n    curl \\\n    git\n")
    assert [i.keyword for i in instructions] == ["FROM", "RUN"]
    assert instructions[1].line == 2 and "git" in instructions[1].args


def test_trivy_import(tmp_path):
    report = tmp_path / "trivy.json"
    report.write_text(
        '{"ArtifactName": "img:1", "Results": [{"Target": "img:1 (debian 12)", "Class": "os-pkgs", "Type": "debian",'
        ' "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1",'
        ' "FixedVersion": "3.0.2, 3.1.0", "Severity": "MEDIUM",'
        ' "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": 9.8}}}]},'
        ' {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities":'
        ' [{"VulnerabilityID": "CVE-2024-0002", "PkgName": "Flask", "InstalledVersion": "1.0", "Severity": "HIGH"}]}]}',
        encoding="utf-8",
    )
    os_finding, lang_finding = load_trivy(report)
    assert os_finding.category == Category.CONTAINER and os_finding.fixed_versions == ["3.0.2", "3.1.0"]
    assert os_finding.cvss_score == 9.8 and os_finding.severity == Severity.MEDIUM
    assert lang_finding.category == Category.DEPENDENCY and lang_finding.ecosystem == "PyPI"


def test_sarif_import_maps_severity_and_cwe(tmp_path):
    report = tmp_path / "r.sarif"
    report.write_text(
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "py/sql-injection",'
        ' "shortDescription": {"text": "SQL query built from user-controlled sources"},'
        ' "properties": {"security-severity": "8.8", "tags": ["security", "external/cwe/cwe-089"]}}]}},'
        ' "results": [{"ruleIndex": 0, "message": {"text": "query depends on user input"},'
        ' "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./app/db.py"},'
        ' "region": {"startLine": 14}}}]}]}]}',
        encoding="utf-8",
    )
    (finding,) = load_sarif(report)
    assert finding.rule_id == "CodeQL:py/sql-injection" and finding.severity == Severity.HIGH
    assert finding.cwe == ["CWE-89"] and finding.path == "app/db.py" and finding.line == 14


def test_openapi_checks():
    spec = (
        "openapi: 3.0.0\nservers:\n  - url: http://api.example.com\n  - url: http://localhost:8080\n"
        "components:\n  securitySchemes:\n    k:\n      type: apiKey\n      in: query\n      name: key\n"
        "    b:\n      type: http\n      scheme: basic\n"
        "paths:\n  /public:\n    get:\n      security: []\n  /admin:\n    post:\n      responses: {}\n"
    )
    findings = scan_openapi(spec, "openapi.yaml")
    assert rules(findings) == sorted(["VW-API-CLEARTEXT", "VW-API-KEY-IN-QUERY", "VW-API-BASIC-AUTH", "VW-API-NO-AUTH"])
    assert scan_openapi("name: not-an-api\n", "x.yaml") == []


def test_fingerprint_is_stable_across_line_moves():
    a = Finding(
        rule_id="R",
        title="t",
        category=Category.CODE,
        severity=Severity.LOW,
        source="s",
        path="a.py",
        line=3,
        snippet="eval(x)",
    )
    b = a.model_copy(update={"line": 30})
    assert a.fingerprint == b.fingerprint
    dep = Finding(
        rule_id="CVE-1",
        title="t",
        category=Category.DEPENDENCY,
        severity=Severity.LOW,
        source="osv",
        path="requirements.txt",
        package="PyYAML",
        ecosystem="PyPI",
        installed_version="5.3",
        aliases=["GHSA-x", "CVE-2020-1"],
    )
    upgraded = dep.model_copy(update={"installed_version": "5.4", "package": "pyyaml"})
    assert dep.fingerprint == upgraded.fingerprint and dep.vuln_id == "CVE-2020-1"
