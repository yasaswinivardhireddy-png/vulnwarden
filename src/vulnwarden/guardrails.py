"""Guardrails that every model-proposed patch must pass before it touches the repository."""

from __future__ import annotations

import ast
import re

from pydantic import BaseModel, Field

from .llm import PatchProposal, editable_window
from .models import Finding
from .pyast import ensure_import

ALLOWED_IMPORTS = {
    "ast",
    "hashlib",
    "hmac",
    "html",
    "json",
    "os",
    "re",
    "secrets",
    "shlex",
    "sqlite3",
    "ssl",
    "tempfile",
    "yaml",
}
FORBIDDEN = [
    (re.compile(r"\beval\s*\("), "calls eval()"),
    (re.compile(r"\bexec\s*\("), "calls exec()"),
    (re.compile(r"\bos\.(system|popen|exec\w*|spawn\w*)\s*\("), "runs OS commands"),
    (re.compile(r"\bsubprocess\b"), "uses subprocess"),
    (re.compile(r"shell\s*=\s*True"), "enables shell=True"),
    (re.compile(r"\b(pickle|marshal|dill|shelve)\b"), "uses unsafe deserialization"),
    (re.compile(r"__import__|\bimportlib\b"), "imports modules dynamically"),
    (
        re.compile(r"\b(requests|httpx|urllib|socket|aiohttp|ftplib|smtplib|telnetlib)\b|http\.client"),
        "adds network access",
    ),
    (re.compile(r"https?://"), "embeds a URL"),
    (re.compile(r"verify\s*=\s*False"), "disables TLS verification"),
    (re.compile(r"\bbase64\b|\bcodecs\.decode\b"), "decodes encoded payloads"),
    (re.compile(r"\b(compile|globals|locals|getattr|setattr|vars)\s*\("), "uses reflection"),
    (re.compile(r"(?i)ignore (all |any )?(previous|prior|above) instructions"), "contains prompt-injection text"),
]
IMPORT_LINE = re.compile(r"^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import)", re.M)


class GuardrailResult(BaseModel):
    ok: bool
    violations: list[str] = Field(default_factory=list)
    patched: str | None = None


def check_proposal(
    proposal: PatchProposal, finding: Finding, source: str, *, context_lines: int = 8, min_confidence: float = 0.6
) -> GuardrailResult:
    lines = source.splitlines(keepends=True)
    violations: list[str] = []
    window_start, window_end = editable_window(finding, len(lines), context_lines)
    start, end = proposal.start_line, proposal.end_line
    if not window_start <= start <= end <= window_end:
        violations.append(f"edits lines {start}-{end}, outside the allowed window {window_start}-{window_end}")
    if finding.line and not start <= finding.line <= end:
        violations.append("does not change the flagged line")
    if proposal.confidence < min_confidence:
        violations.append(f"confidence {proposal.confidence:.2f} is below {min_confidence:.2f}")
    original = "".join(lines[max(start, 1) - 1 : max(end, 0)])
    if len(proposal.replacement.splitlines()) > 3 * max(1, end - start + 1) + 5:
        violations.append("replacement is too large for a minimal fix")
    for pattern, label in FORBIDDEN:
        if len(pattern.findall(proposal.replacement)) > len(pattern.findall(original)):
            violations.append(f"introduces code that {label}")
    requested = list(proposal.imports_to_add)
    requested += [a or b for a, b in IMPORT_LINE.findall(proposal.replacement) if (a or b) and (a or b) not in original]
    for module in requested:
        if not re.fullmatch(r"[A-Za-z_][\w.]*", module) or module.split(".")[0] not in ALLOWED_IMPORTS:
            violations.append(f"imports non-allowlisted module '{module}'")
    if proposal.replacement.strip() == original.strip():
        violations.append("proposes no change")
    if violations:
        return GuardrailResult(ok=False, violations=violations)

    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    replacement = proposal.replacement.replace("\r\n", "\n").rstrip("\n").replace("\n", newline) + newline
    patched = "".join(lines[: start - 1]) + replacement + "".join(lines[end:])
    try:
        for module in proposal.imports_to_add:
            patched = ensure_import(patched, module)
        ast.parse(patched)
    except SyntaxError as exc:
        return GuardrailResult(ok=False, violations=[f"patched file does not parse: {exc.msg} (line {exc.lineno})"])
    return GuardrailResult(ok=True, patched=patched)
