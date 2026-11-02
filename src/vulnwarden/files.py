"""Repository file walking and secret redaction helpers."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

MAX_FILE_BYTES = 1_000_000

SECRET_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
]
SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_.-]*)
    (?P<sep>\s*[:=]\s*)
    (?P<quote>["'])(?P<value>[^"'\n]{4,})(?P=quote)
    """
)
REDACTED = "***REDACTED***"


def redact_secrets(text: str) -> str:
    """Mask credential-like values before text is logged, stored or sent to a model."""
    for pattern in SECRET_VALUE_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return SECRET_ASSIGNMENT.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}{m.group('quote')}{REDACTED}{m.group('quote')}", text
    )


def is_excluded(rel_path: str, exclude: Iterable[str]) -> bool:
    parts = Path(rel_path).parts
    for pattern in exclude:
        pattern = pattern.strip("/\\")
        if not pattern:
            continue
        if pattern in parts:
            return True
        normalized = rel_path.replace("\\", "/")
        if normalized == pattern or normalized.startswith(pattern.replace("\\", "/") + "/"):
            return True
    return False


def iter_files(root: Path, exclude: Iterable[str], suffixes: set[str] | None = None) -> Iterator[Path]:
    """Yield repository files (sorted, deterministic), skipping excluded and very large files."""
    exclude = list(exclude)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(d for d in dirnames if not is_excluded(os.path.join(rel_dir, d), exclude))
        for name in sorted(filenames):
            rel = os.path.join(rel_dir, name)
            if is_excluded(rel, exclude):
                continue
            path = Path(dirpath) / name
            if suffixes is not None and path.suffix.lower() not in suffixes and name not in suffixes:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")
