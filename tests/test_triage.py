from __future__ import annotations

from vulnwarden.config import Config
from vulnwarden.models import Category, Finding, Severity
from vulnwarden.triage import correlate, import_names, prioritize, priority_for, risk_score, summarize


def make(**overrides) -> Finding:
    base = dict(
        rule_id="R",
        title="t",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        source="vulnwarden-sast",
        path="app.py",
        line=1,
        snippet="x",
        sources=["vulnwarden-sast"],
    )
    base.update(overrides)
    return Finding(**base)


def dep(source: str, **overrides) -> Finding:
    values = dict(
        rule_id="CVE-2020-14343",
        category=Category.DEPENDENCY,
        source=source,
        sources=[source],
        path="requirements.txt",
        package="PyYAML",
        ecosystem="PyPI",
        installed_version="5.3.1",
        fixed_versions=["5.4"],
        aliases=["CVE-2020-14343"],
    )
    values.update(overrides)
    return make(**values)


class FakeIntel:
    def __init__(self, epss=None, kev=None):
        self._epss, self._kev = epss or {}, kev or set()

    def epss(self, cves):
        return {c: v for c, v in self._epss.items() if c in set(cves)}

    def kev(self):
        return self._kev


def test_cross_scanner_duplicates_merge_and_reclassify(tmp_path):
    osv = dep(
        "osv",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/x",
        aliases=["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
    )
    pysec = dep("osv", severity=Severity.MEDIUM, aliases=["CVE-2020-14343", "PYSEC-2021-142"])
    trivy = dep("trivy", severity=Severity.HIGH)
    findings = [osv, pysec, trivy]
    stats = correlate(
        findings, tmp_path, [{"name": "PyYAML", "version": "5.3.1", "ecosystem": "PyPI", "path": "requirements.txt"}]
    )
    assert osv.is_open and pysec.status == "duplicate" and trivy.status == "duplicate"
    assert stats == {"duplicate_advisories": 1, "duplicates": 1, "reclassified": 1}
    assert set(osv.sources) == {"osv", "trivy"} and "PYSEC-2021-142" in osv.aliases
    assert any("trivy reported high" in note for note in osv.notes)


def test_scanner_severity_is_reclassified_from_cvss(tmp_path):
    finding = make(severity=Severity.HIGH, cvss_score=5.3, source="trivy")
    stats = correlate([finding], tmp_path, [])
    assert finding.severity == Severity.MEDIUM and finding.details["reported_severity"] == "high"
    assert stats["reclassified"] == 1


def test_code_duplicates_prefer_first_party(tmp_path):
    ours = make(rule_id="VW-PY-SQL-INJECTION", line=13, cwe=["CWE-89"])
    semgrep = make(rule_id="Semgrep:sqli", line=14, cwe=["CWE-89"], source="sarif:Semgrep", sources=["sarif:Semgrep"])
    unrelated = make(rule_id="Semgrep:xss", line=14, cwe=["CWE-79"], source="sarif:Semgrep", sources=["sarif:Semgrep"])
    (tmp_path / "app.py").write_text("x\n", encoding="utf-8")
    stats = correlate([semgrep, ours, unrelated], tmp_path, [])
    assert ours.is_open and semgrep.status == "duplicate" and ours.sources == ["sarif:Semgrep", "vulnwarden-sast"]
    assert unrelated.is_open and stats["duplicates"] == 1


def test_stale_reports_are_detected(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    manifest = [{"name": "requests", "version": "2.25.1", "ecosystem": "PyPI", "path": "requirements.txt"}]
    upgraded = make(
        rule_id="CVE-2018-18074",
        category=Category.DEPENDENCY,
        source="trivy",
        path="requirements.txt",
        package="requests",
        ecosystem="PyPI",
        installed_version="2.19.1",
        fixed_versions=["2.20.0"],
        aliases=["CVE-2018-18074"],
    )
    removed = make(
        rule_id="CVE-1",
        category=Category.DEPENDENCY,
        source="trivy",
        path="requirements.txt",
        package="Django",
        ecosystem="PyPI",
        installed_version="2.2",
        aliases=["CVE-1"],
    )
    gone_file = make(rule_id="S:x", source="sarif:S", path="deleted.py", snippet="bad()")
    gone_code = make(rule_id="S:y", source="sarif:S", path="app.py", snippet="eval(name)")
    still_there = make(rule_id="S:z", source="sarif:S", path="app.py", snippet="print('hello')")
    stats = correlate([upgraded, removed, gone_file, gone_code, still_there], tmp_path, manifest)
    assert [f.status for f in (upgraded, removed, gone_file, gone_code, still_there)] == [
        "stale",
        "stale",
        "stale",
        "stale",
        "open",
    ]
    assert stats["stale"] == 4 and "Reporting discrepancy" in upgraded.notes[0]


def test_risk_score_and_priority_signals():
    finding = make(severity=Severity.HIGH, cvss_score=7.5, aliases=["CVE-1"], category=Category.DEPENDENCY)
    finding.in_kev, finding.epss = True, 0.9
    score, reasons = risk_score(finding, "internet-facing")
    assert score == 10.0 and priority_for(finding, score) == "P1"
    assert any("KEV" in r for r in reasons) and any("EPSS" in r for r in reasons)
    quiet = make(severity=Severity.LOW)
    assert priority_for(quiet, risk_score(quiet, "internal")[0]) == "P4"


def test_prioritize_enriches_sorts_and_sets_sla():
    config = Config()
    kev = dep("osv", severity=Severity.MEDIUM, cvss_score=5.0, rule_id="CVE-A", aliases=["CVE-A"], package="pyyaml")
    unused = dep("osv", severity=Severity.HIGH, cvss_score=7.5, rule_id="CVE-B", aliases=["CVE-B"], package="jinja2")
    code = make(severity=Severity.HIGH)
    findings = [code, unused, kev]
    prioritize(findings, FakeIntel(epss={"CVE-B": 0.5}, kev={"CVE-A"}), config, {"yaml"})
    assert findings[0] is kev and kev.priority == "P1" and kev.sla_hours == 72 and kev.reachable is True
    assert unused.reachable is False and unused.epss == 0.5
    assert summarize(findings)["by_priority"]["P1"] == 1


def test_import_name_mapping():
    assert import_names("PyYAML") == ["yaml"]
    assert import_names("python-dateutil") == ["dateutil"]
    assert import_names("my-lib") == ["my_lib"]
