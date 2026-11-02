"""SQLite persistence: finding lifecycle, run trends, pull requests, notifications and a tamper-evident audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .files import redact_secrets
from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY, rule_id TEXT, title TEXT, category TEXT, severity TEXT, priority TEXT,
    status TEXT, path TEXT, first_seen TEXT, last_seen TEXT, resolved_at TEXT, pr_number INTEGER, data TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, repo TEXT, open_count INTEGER, summary TEXT
);
CREATE TABLE IF NOT EXISTS pulls (
    number INTEGER PRIMARY KEY, repo TEXT, url TEXT, branch TEXT, created_at TEXT, state TEXT,
    merged_at TEXT, fingerprints TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, pr_number INTEGER, kind TEXT, sent_at TEXT, channels TEXT,
    recipients TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, details TEXT, prev_hash TEXT, hash TEXT
);
"""
SENSITIVE_KEY = ("token", "secret", "password", "api_key", "apikey", "authorization", "webhook")


class SyncResult(BaseModel):
    new: list[str] = Field(default_factory=list)
    reopened: list[str] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)
    reclassified: list[dict[str, str]] = Field(default_factory=list)
    still_open: int = 0


def _now(now: datetime | None) -> str:
    return (now or datetime.now(UTC)).isoformat()


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: "***REDACTED***" if any(s in k.lower() for s in SENSITIVE_KEY) else _redact(v) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------ findings
    def sync_findings(self, findings: list[Finding], repo: str, now: datetime | None = None) -> SyncResult:
        """Reconcile a scan with history: new, reopened, resolved (verified by rescan), reclassified."""
        stamp = _now(now)
        current = {f.fingerprint: f for f in findings if f.is_open}
        existing = {row["fingerprint"]: row for row in self.db.execute("SELECT * FROM findings")}
        result = SyncResult()
        for fingerprint, finding in current.items():
            row = existing.get(fingerprint)
            data = json.dumps(finding.model_dump(mode="json"))
            if row is None:
                result.new.append(fingerprint)
                self.db.execute(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        fingerprint,
                        finding.rule_id,
                        finding.title,
                        finding.category.value,
                        finding.severity.value,
                        finding.priority,
                        "open",
                        finding.path,
                        stamp,
                        stamp,
                        None,
                        None,
                        data,
                    ),
                )
                continue
            if row["status"] != "open":
                result.reopened.append(fingerprint)
            if row["severity"] != finding.severity.value:
                result.reclassified.append(
                    {"fingerprint": fingerprint, "from": row["severity"], "to": finding.severity.value}
                )
            self.db.execute(
                "UPDATE findings SET severity=?, priority=?, status='open', last_seen=?, resolved_at=NULL, data=? "
                "WHERE fingerprint=?",
                (finding.severity.value, finding.priority, stamp, data, fingerprint),
            )
        for fingerprint, row in existing.items():
            if row["status"] == "open" and fingerprint not in current:
                result.resolved.append(fingerprint)
                self.db.execute(
                    "UPDATE findings SET status='resolved', resolved_at=? WHERE fingerprint=?", (stamp, fingerprint)
                )
        result.still_open = len(current)
        summary = {
            "new": len(result.new),
            "resolved": len(result.resolved),
            "reopened": len(result.reopened),
            "reclassified": len(result.reclassified),
            "by_severity": _count(f.severity.value for f in current.values()),
        }
        self.db.execute(
            "INSERT INTO runs (ts, repo, open_count, summary) VALUES (?,?,?,?)",
            (stamp, repo, len(current), json.dumps(summary)),
        )
        self.db.commit()
        return result

    def finding_status(self, fingerprint: str) -> str | None:
        row = self.db.execute("SELECT status FROM findings WHERE fingerprint=?", (fingerprint,)).fetchone()
        return row["status"] if row else None

    def trend(self, limit: int = 12) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT ts, open_count, summary FROM runs ORDER BY id DESC LIMIT ?", (limit,))
        return [{"ts": r["ts"], "open": r["open_count"], **json.loads(r["summary"])} for r in rows][::-1]

    # --------------------------------------------------------------- pulls
    def record_pull(
        self, number: int, repo: str, url: str, branch: str, fingerprints: list[str], created_at: str | None = None
    ) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO pulls VALUES (?,?,?,?,?,?,?,?)",
            (number, repo, url, branch, created_at or _now(None), "open", None, json.dumps(fingerprints)),
        )
        self.db.executemany(
            "UPDATE findings SET pr_number=? WHERE fingerprint=?", [(number, fp) for fp in fingerprints]
        )
        self.db.commit()

    def pulls(self, state: str | None = None) -> list[dict[str, Any]]:
        query, args = "SELECT * FROM pulls", ()
        if state:
            query, args = query + " WHERE state=?", (state,)
        return [{**dict(r), "fingerprints": json.loads(r["fingerprints"])} for r in self.db.execute(query, args)]

    def update_pull(self, number: int, state: str, merged_at: str | None = None) -> None:
        self.db.execute("UPDATE pulls SET state=?, merged_at=? WHERE number=?", (state, merged_at, number))
        self.db.commit()

    # ------------------------------------------------------- notifications
    def last_notification(self, pr_number: int, kind: str) -> datetime | None:
        row = self.db.execute(
            "SELECT sent_at FROM notifications WHERE pr_number=? AND kind=? ORDER BY id DESC LIMIT 1", (pr_number, kind)
        ).fetchone()
        return datetime.fromisoformat(row["sent_at"]) if row else None

    def record_notification(
        self, pr_number: int, kind: str, channels: list[str], recipients: list[str], now: datetime | None = None
    ) -> None:
        self.db.execute(
            "INSERT INTO notifications (pr_number, kind, sent_at, channels, recipients) VALUES (?,?,?,?,?)",
            (pr_number, kind, _now(now), ",".join(channels), ",".join(recipients)),
        )
        self.db.commit()

    # ---------------------------------------------------------------- audit
    def audit(self, actor: str, action: str, details: dict[str, Any] | None = None, now: datetime | None = None) -> str:
        """Append a hash-chained audit entry; secrets in details are redacted before storage."""
        row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        previous = row["hash"] if row else "0" * 64
        stamp = _now(now)
        payload = json.dumps(
            {"ts": stamp, "actor": actor, "action": action, "details": _redact(details or {})},
            sort_keys=True,
            default=str,
        )
        digest = hashlib.sha256((previous + payload).encode("utf-8")).hexdigest()
        self.db.execute(
            "INSERT INTO audit (ts, actor, action, details, prev_hash, hash) VALUES (?,?,?,?,?,?)",
            (stamp, actor, action, payload, previous, digest),
        )
        self.db.commit()
        return digest

    def verify_audit(self) -> tuple[bool, int | None]:
        """Recompute the hash chain; returns (ok, id of the first tampered entry)."""
        previous = "0" * 64
        for row in self.db.execute("SELECT * FROM audit ORDER BY id"):
            expected = hashlib.sha256((previous + row["details"]).encode("utf-8")).hexdigest()
            if row["prev_hash"] != previous or row["hash"] != expected:
                return False, row["id"]
            previous = row["hash"]
        return True, None

    def audit_entries(self) -> list[dict[str, Any]]:
        return [{"id": r["id"], **json.loads(r["details"])} for r in self.db.execute("SELECT * FROM audit ORDER BY id")]


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts
