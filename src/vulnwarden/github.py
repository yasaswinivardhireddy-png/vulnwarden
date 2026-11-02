"""Minimal GitHub REST client: commits via the Git Data API, pull requests, labels, reviewers, comments."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from . import __version__


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


class GitHubClient:
    """Needs only a fine-grained token with Contents (read/write) and Pull requests (read/write) on one repo."""

    def __init__(
        self,
        repo: str,
        token: str,
        api_url: str = "https://api.github.com",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 20.0,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if repo.count("/") != 1:
            raise ValueError("repo must look like 'owner/name'")
        self.repo = repo
        self.max_retries = max_retries
        self._sleep = sleep
        self._client = httpx.Client(
            base_url=api_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": f"vulnwarden/{__version__}",
            },
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        last: httpx.Response | None = None
        for attempt in range(self.max_retries):
            try:
                response = self._client.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                if attempt == self.max_retries - 1:
                    raise GitHubError(0, f"network error: {exc}") from exc
                self._sleep(2**attempt)
                continue
            last = response
            rate_limited = response.status_code in {403, 429} and (
                response.headers.get("retry-after") or response.headers.get("x-ratelimit-remaining") == "0"
            )
            retryable = response.status_code in {500, 502, 503, 504} or rate_limited
            if retryable and attempt < self.max_retries - 1:
                self._sleep(min(float(response.headers.get("retry-after") or 2**attempt), 60.0))
                continue
            if response.is_error:
                try:
                    message = response.json().get("message", response.text)
                except ValueError:
                    message = response.text
                raise GitHubError(response.status_code, message)
            return response.json() if response.content else None
        raise GitHubError(last.status_code if last is not None else 0, "retries exhausted")

    def _repo(self, suffix: str) -> str:
        return f"/repos/{self.repo}{suffix}"

    def default_branch(self) -> str:
        return self._request("GET", self._repo(""))["default_branch"]

    def branch_sha(self, branch: str) -> str:
        return self._request("GET", self._repo(f"/git/ref/heads/{branch}"))["object"]["sha"]

    def create_branch(self, branch: str, sha: str) -> None:
        self._request("POST", self._repo("/git/refs"), json={"ref": f"refs/heads/{branch}", "sha": sha})

    def commit_files(self, branch: str, parent_sha: str, files: dict[str, str], message: str) -> str:
        """Create one commit on ``branch`` with full file contents, without needing git push credentials."""
        base_tree = self._request("GET", self._repo(f"/git/commits/{parent_sha}"))["tree"]["sha"]
        tree = self._request(
            "POST",
            self._repo("/git/trees"),
            json={
                "base_tree": base_tree,
                "tree": [{"path": p, "mode": "100644", "type": "blob", "content": c} for p, c in sorted(files.items())],
            },
        )["sha"]
        commit = self._request(
            "POST", self._repo("/git/commits"), json={"message": message, "tree": tree, "parents": [parent_sha]}
        )["sha"]
        self._request("PATCH", self._repo(f"/git/refs/heads/{branch}"), json={"sha": commit, "force": False})
        return commit

    def open_pull_request(self, head: str, base: str, title: str, body: str, draft: bool = False) -> dict[str, Any]:
        return self._request(
            "POST",
            self._repo("/pulls"),
            json={"head": head, "base": base, "title": title, "body": body, "draft": draft},
        )

    def add_labels(self, number: int, labels: list[str]) -> None:
        if labels:
            self._request("POST", self._repo(f"/issues/{number}/labels"), json={"labels": labels})

    def request_reviewers(self, number: int, reviewers: list[str]) -> None:
        if reviewers:
            self._request("POST", self._repo(f"/pulls/{number}/requested_reviewers"), json={"reviewers": reviewers})

    def comment(self, number: int, body: str) -> None:
        self._request("POST", self._repo(f"/issues/{number}/comments"), json={"body": body})

    def get_pull(self, number: int) -> dict[str, Any]:
        return self._request("GET", self._repo(f"/pulls/{number}"))

    def list_reviews(self, number: int) -> list[dict[str, Any]]:
        return self._request("GET", self._repo(f"/pulls/{number}/reviews"), params={"per_page": 100})

    def list_open_pulls(self, label: str | None = None, max_pages: int = 5) -> list[dict[str, Any]]:
        pulls: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            batch = self._request("GET", self._repo("/pulls"), params={"state": "open", "per_page": 100, "page": page})
            pulls.extend(batch)
            if len(batch) < 100:
                break
        if label:
            pulls = [p for p in pulls if any(lbl.get("name") == label for lbl in p.get("labels", []))]
        return pulls
