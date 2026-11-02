from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from helpers import init_repo

from vulnwarden.config import Config
from vulnwarden.intel import Intel

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "vulnerable-shop"
CACHE = ROOT / "benchmarks" / "intel-cache"


@pytest.fixture
def offline_intel() -> Intel:
    """Recorded OSV/EPSS/KEV responses; no network access."""
    return Intel(cache_dir=CACHE, offline=True, max_age_hours=None)


@pytest.fixture
def no_network() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected network call: {request.url}")

    return httpx.MockTransport(handler)


@pytest.fixture
def demo_repo(tmp_path: Path) -> Path:
    """A git copy of the seeded demo service with freshly generated certificates."""
    repo = tmp_path / "vulnerable-shop"
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns("certs", ".vulnwarden", "__pycache__", ".pytest_cache"))
    subprocess.run([sys.executable, "make_certs.py"], cwd=repo, check=True, capture_output=True)
    init_repo(repo)
    return repo


@pytest.fixture
def config() -> Config:
    return Config()
