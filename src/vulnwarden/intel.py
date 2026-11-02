"""Vulnerability intelligence: OSV advisories, FIRST EPSS scores and the CISA KEV catalog.

Every response is cached on disk so scans are fast, and a recorded cache can be replayed
offline for reproducible benchmarks and CI. Network failures never crash a scan; they are
collected in ``errors`` and surfaced as warnings so incomplete results are visible.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import httpx
from cvss import CVSS2, CVSS3, CVSS4

from . import __version__

OSV_URL = "https://api.osv.dev/v1"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_MISSING = object()


def cvss_base_score(vector: str | None) -> float | None:
    if not vector:
        return None
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
        return float(CVSS2(vector).base_score)
    except Exception:
        return None


def best_cvss(entries: Iterable[dict[str, Any]]) -> tuple[str | None, float | None]:
    """Pick the most widely used CVSS version available (v3, then v4, then v2)."""
    order = {"CVSS_V3": 0, "CVSS_V4": 1, "CVSS_V2": 2}
    for entry in sorted(entries, key=lambda e: order.get(e.get("type", ""), 9)):
        vector = entry.get("score")
        score = cvss_base_score(vector)
        if score is not None:
            return vector, score
    return None, None


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


class Intel:
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        offline: bool = False,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 20.0,
        max_age_hours: float | None = 24.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.offline = offline
        self.max_age_hours = max_age_hours
        self.errors: list[str] = []
        self._sleep = sleep
        self._kev: set[str] | None = None
        self._client: httpx.Client | None = None
        if not offline:
            self._client = httpx.Client(
                timeout=timeout,
                transport=transport,
                follow_redirects=True,
                headers={"User-Agent": f"vulnwarden/{__version__}"},
            )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> Intel:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------- cache
    def _cache_path(self, kind: str, key: str) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
        return self.cache_dir / kind / f"{digest}.json"

    def _cache_get(self, kind: str, key: str) -> Any:
        path = self._cache_path(kind, key)
        if path is None or not path.is_file():
            return _MISSING
        check_age = not self.offline and self.max_age_hours is not None
        if check_age and time.time() - path.stat().st_mtime > self.max_age_hours * 3600:
            return _MISSING
        try:
            return json.loads(path.read_text(encoding="utf-8"))["value"]
        except (OSError, ValueError, KeyError):
            return _MISSING

    def _cache_put(self, kind: str, key: str, value: Any) -> None:
        path = self._cache_path(kind, key)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"key": key, "value": value}, sort_keys=True), encoding="utf-8")

    # -------------------------------------------------------------- network
    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        if self._client is None:
            return None
        last_error = ""
        for attempt in range(3):
            try:
                response = self._client.request(method, url, **kwargs)
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code == 404:
                    return None
                if response.status_code in {429, 500, 502, 503, 504}:
                    last_error = f"HTTP {response.status_code}"
                elif response.is_error:
                    self.errors.append(f"{url}: HTTP {response.status_code}")
                    return None
                else:
                    try:
                        return response.json()
                    except ValueError:
                        self.errors.append(f"{url}: invalid JSON")
                        return None
            if attempt < 2:
                self._sleep(min(2**attempt, 8))
        self.errors.append(f"{url}: {last_error}")
        return None

    # ------------------------------------------------------------------ OSV
    def osv_query(self, packages: list[tuple[str, str, str]]) -> list[list[str]]:
        """Return vulnerability ids for each (ecosystem, name, version) using OSV's batch API."""
        results: list[list[str] | None] = []
        missing: list[int] = []
        for index, (ecosystem, name, version) in enumerate(packages):
            cached = self._cache_get("osv-query", f"{ecosystem}|{name}|{version}")
            if cached is _MISSING:
                results.append(None)
                missing.append(index)
            else:
                results.append(cached)
        if missing and self._client is None:
            self.errors.append(f"offline: {len(missing)} dependency lookups are not in the intel cache")
        for chunk in _chunks(missing, 500) if self._client is not None else []:
            body = {
                "queries": [
                    {"package": {"name": packages[i][1], "ecosystem": packages[i][0]}, "version": packages[i][2]}
                    for i in chunk
                ]
            }
            data = self._request("POST", f"{OSV_URL}/querybatch", json=body)
            if not isinstance(data, dict):
                continue
            for index, result in zip(chunk, data.get("results", []), strict=False):
                ids = sorted({v["id"] for v in (result or {}).get("vulns") or [] if "id" in v})
                results[index] = ids
                ecosystem, name, version = packages[index]
                self._cache_put("osv-query", f"{ecosystem}|{name}|{version}", ids)
        return [r or [] for r in results]

    def osv_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        cached = self._cache_get("osv-vuln", vuln_id)
        if cached is not _MISSING:
            return cached
        if self._client is None:
            self.errors.append(f"offline: advisory {vuln_id} is not in the intel cache")
            return None
        data = self._request("GET", f"{OSV_URL}/vulns/{vuln_id}")
        if isinstance(data, dict):
            self._cache_put("osv-vuln", vuln_id, data)
            return data
        return None

    # ----------------------------------------------------------- EPSS / KEV
    def epss(self, cves: Iterable[str]) -> dict[str, float]:
        """EPSS probability (0-1) that each CVE is exploited in the next 30 days."""
        scores: dict[str, float] = {}
        missing: list[str] = []
        for cve in sorted({c.upper() for c in cves if c.upper().startswith("CVE-")}):
            cached = self._cache_get("epss", cve)
            if cached is _MISSING:
                missing.append(cve)
            elif cached is not None:
                scores[cve] = float(cached)
        for chunk in _chunks(missing, 80) if self._client is not None else []:
            data = self._request("GET", EPSS_URL, params={"cve": ",".join(chunk)})
            if not isinstance(data, dict):
                continue
            found = {row.get("cve", "").upper(): float(row["epss"]) for row in data.get("data", []) if "epss" in row}
            for cve in chunk:
                value = found.get(cve)
                self._cache_put("epss", cve, value)
                if value is not None:
                    scores[cve] = value
        return scores

    def kev(self) -> set[str]:
        """CVE ids in CISA's Known Exploited Vulnerabilities catalog."""
        if self._kev is not None:
            return self._kev
        cached = self._cache_get("kev", "catalog")
        if cached is _MISSING:
            data = self._request("GET", KEV_URL)
            ids = sorted({v.get("cveID", "").upper() for v in (data or {}).get("vulnerabilities", [])} - {""})
            if data:
                self._cache_put("kev", "catalog", ids)
            cached = ids
        self._kev = set(cached)
        return self._kev
