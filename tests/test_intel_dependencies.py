from __future__ import annotations

import json

import httpx

from vulnwarden.intel import Intel, best_cvss, cvss_base_score
from vulnwarden.scanners.dependencies import (
    Dependency,
    dependency_findings,
    finding_from_osv,
    fixed_versions_for,
    parse_package_lock,
    parse_requirements,
)

ADVISORY = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2099-0001"],
    "summary": "Remote code execution in demo",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-94"]},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "Demo_Pkg"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.4.2"},
                        {"introduced": "2.0.0"},
                        {"fixed": "2.1.0"},
                    ],
                }
            ],
        }
    ],
}


def test_parse_requirements_handles_pins_extras_markers_and_options():
    text = (
        "# comment\n-r base.txt\nrequests[socks]==2.25.1 ; python_version > '3.8'\nflask>=2.0\n"
        "PyYAML===5.3.1  # pinned\ngit+https://example.com/x.git\nweird==1.*\n"
    )
    deps = parse_requirements(text, "requirements.txt")
    assert [(d.name, d.version, d.line) for d in deps] == [
        ("requests", "2.25.1", 3),
        ("flask", None, 4),
        ("PyYAML", "5.3.1", 5),
        ("weird", None, 7),
    ]


def test_parse_package_lock_v3_and_v1():
    v3 = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/pkg": {"version": "1.0.0"},
                "node_modules/linked": {"link": True},
            },
        }
    )
    assert {(d.name, d.version) for d in parse_package_lock(v3, "package-lock.json")} == {
        ("lodash", "4.17.20"),
        ("@scope/pkg", "1.0.0"),
    }
    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"minimist": {"version": "1.2.0"}}})
    assert [d.name for d in parse_package_lock(v1, "package-lock.json")] == ["minimist"]


def test_fixed_version_selects_the_matching_range():
    assert fixed_versions_for(ADVISORY, "demo-pkg", "PyPI", "1.3.0") == ["1.4.2"]
    assert fixed_versions_for(ADVISORY, "demo_pkg", "PyPI", "2.0.5") == ["2.1.0"]
    assert fixed_versions_for(ADVISORY, "demo-pkg", "PyPI", "2.1.0") == []
    assert fixed_versions_for(ADVISORY, "other", "PyPI", "1.0") == []


def test_finding_from_osv_uses_cvss_and_canonical_cve():
    dep = Dependency("Demo_Pkg", "1.3.0", "PyPI", "requirements.txt", 4, "Demo_Pkg==1.3.0")
    finding = finding_from_osv(dep, ADVISORY)
    assert finding.rule_id == "CVE-2099-0001" and finding.cvss_score == 9.8
    assert finding.severity.value == "critical" and finding.fixed_versions == ["1.4.2"]
    assert finding.cwe == ["CWE-94"] and "Upgrade Demo_Pkg to 1.4.2" in finding.fix_hint


def test_cvss_helpers():
    assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    assert cvss_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 9.3
    assert cvss_base_score("not-a-vector") is None
    vector, score = best_cvss(
        [
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        ]
    )
    assert vector.startswith("CVSS:3.1") and score == 7.5


def _osv_transport(calls: list[str], fail_first: int = 0):
    state = {"failures": fail_first}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if state["failures"] > 0:
            state["failures"] -= 1
            return httpx.Response(503)
        if request.url.path.endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]} if q["package"]["name"] == "Demo_Pkg" else {}
                        for q in queries
                    ]
                },
            )
        if request.url.path.endswith("/vulns/GHSA-aaaa-bbbb-cccc"):
            return httpx.Response(200, json=ADVISORY)
        if request.url.host == "api.first.org":
            return httpx.Response(200, json={"data": [{"cve": "CVE-2099-0001", "epss": "0.42"}]})
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2099-0001"}]})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_dependency_findings_query_osv_once_and_cache(tmp_path):
    calls: list[str] = []
    deps = [
        Dependency("Demo_Pkg", "1.3.0", "PyPI", "requirements.txt", 1, "Demo_Pkg==1.3.0"),
        Dependency("safe", "1.0", "PyPI", "requirements.txt", 2, "safe==1.0"),
        Dependency("unpinned", None, "PyPI", "requirements.txt", 3, "unpinned"),
    ]
    with Intel(cache_dir=tmp_path, transport=_osv_transport(calls), sleep=lambda s: None) as intel:
        findings = dependency_findings(deps, intel)
        assert [f.package for f in findings] == ["Demo_Pkg"]
        assert intel.epss(["CVE-2099-0001"]) == {"CVE-2099-0001": 0.42}
        assert intel.kev() == {"CVE-2099-0001"}
    assert calls.count("POST /v1/querybatch") == 1
    calls.clear()
    with Intel(cache_dir=tmp_path, offline=True) as offline:
        assert [f.package for f in dependency_findings(deps, offline)] == ["Demo_Pkg"]
        assert offline.epss(["CVE-2099-0001"]) == {"CVE-2099-0001": 0.42} and offline.errors == []
    assert calls == []


def test_intel_retries_transient_errors_and_reports_failures(tmp_path):
    calls: list[str] = []
    with Intel(cache_dir=tmp_path, transport=_osv_transport(calls, fail_first=2), sleep=lambda s: None) as intel:
        assert intel.osv_query([("PyPI", "Demo_Pkg", "1.3.0")]) == [["GHSA-aaaa-bbbb-cccc"]]
    assert len(calls) == 3

    def always_down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with Intel(transport=httpx.MockTransport(always_down), sleep=lambda s: None) as intel:
        assert intel.osv_query([("PyPI", "x", "1")]) == [[]]
        assert intel.errors and "HTTP 503" in intel.errors[0]


def test_offline_cache_miss_is_reported(tmp_path):
    with Intel(cache_dir=tmp_path, offline=True) as intel:
        assert intel.osv_query([("PyPI", "x", "1")]) == [[]]
        assert "offline" in intel.errors[0]
