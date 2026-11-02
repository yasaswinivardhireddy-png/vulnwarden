"""Deterministic, format-preserving fixes (codemods) for common findings."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable

from .crypto import WEAK_SUITE_MARKERS, _protocol_token, canonical
from .models import Finding
from .pyast import ImportMap, const_str, ensure_import, is_const, kwarg, replace_node, segment
from .scanners.containers import parse_dockerfile
from .scanners.python_sast import SUBPROCESS_CALLS

Codemod = Callable[[str, Finding], str | None]
PARAMSTYLE = {"sqlite3": "?", "psycopg2": "%s", "psycopg": "%s", "pymysql": "%s", "MySQLdb": "%s"}


def _calls_at(tree: ast.AST, line: int | None) -> list[ast.Call]:
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line]
    return sorted(calls, key=lambda n: n.col_offset)


def _keyword(source: str, keyword: ast.keyword) -> str:
    value = segment(source, keyword.value)
    return f"{keyword.arg}={value}" if keyword.arg else f"**{value}"


def _rebuild(source: str, call: ast.Call, args: list[str], keywords: list[str]) -> str:
    return f"{segment(source, call.func)}({', '.join([*args, *keywords])})"


def fix_yaml_load(source: str, finding: Finding) -> str | None:
    tree = ast.parse(source)
    imports = ImportMap(tree)
    for call in _calls_at(tree, finding.line):
        qual = imports.qualname(call.func)
        if (
            qual in {"yaml.load", "yaml.unsafe_load", "yaml.load_all", "yaml.unsafe_load_all"}
            and call.args
            and isinstance(call.func, ast.Attribute)
        ):
            method = "safe_load_all" if qual.endswith("_all") else "safe_load"
            new = f"{segment(source, call.func.value)}.{method}({segment(source, call.args[0])})"
            return replace_node(source, call, new)
    return None


def fix_shell(source: str, finding: Finding) -> str | None:
    tree = ast.parse(source)
    imports = ImportMap(tree)
    for call in _calls_at(tree, finding.line):
        if imports.qualname(call.func) in SUBPROCESS_CALLS and is_const(kwarg(call, "shell"), True) and call.args:
            first = call.args[0]
            needs_shlex = not isinstance(first, (ast.List, ast.Tuple))
            arg0 = f"shlex.split({segment(source, first)})" if needs_shlex else segment(source, first)
            args = [arg0, *(segment(source, a) for a in call.args[1:])]
            keywords = [_keyword(source, k) for k in call.keywords if k.arg != "shell"]
            updated = replace_node(source, call, _rebuild(source, call, args, keywords))
            return ensure_import(updated, "shlex") if needs_shlex else updated
    return None


def fix_tls_verify(source: str, finding: Finding) -> str | None:
    tree = ast.parse(source)
    for call in _calls_at(tree, finding.line):
        if is_const(kwarg(call, "verify"), False):
            args = [segment(source, a) for a in call.args]
            keywords = [_keyword(source, k) for k in call.keywords if k.arg != "verify"]
            return replace_node(source, call, _rebuild(source, call, args, keywords))
    return None


def fix_debug(source: str, finding: Finding) -> str | None:
    tree = ast.parse(source)
    for call in _calls_at(tree, finding.line):
        value = kwarg(call, "debug")
        if is_const(value, True) and value is not None:
            return replace_node(source, value, "False")
    return None


def fix_sql(source: str, finding: Finding) -> str | None:
    """Rewrite f-string SQL into a parameterized query using the driver's paramstyle."""
    tree = ast.parse(source)
    imports = ImportMap(tree)
    style = next((PARAMSTYLE[m] for m in PARAMSTYLE if imports.has_module(m)), None)
    if style is None:
        return None
    for call in _calls_at(tree, finding.line):
        if not (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in {"execute", "executemany"}
            and len(call.args) == 1
            and not call.keywords
            and isinstance(call.args[0], ast.JoinedStr)
        ):
            continue
        parts: list[str] = []
        params: list[str] = []
        for value in call.args[0].values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
                parts.append("\x00")
                params.append(ast.unparse(value.value))
            else:
                return None
        sql = "".join(parts).replace("'\x00'", "\x00").replace('"\x00"', "\x00")
        for index, char in enumerate(sql):
            if char == "\x00" and sql[:index].count("'") % 2 == 1:
                return None  # placeholder inside a quoted literal (e.g. LIKE '%{x}%'): needs a human or the LLM
        sql = sql.replace("\x00", style)
        params_text = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
        return replace_node(source, call, f"{segment(source, call.func)}({sql!r}, {params_text})")
    return None


def fix_eval(source: str, finding: Finding) -> str | None:
    tree = ast.parse(source)
    for call in _calls_at(tree, finding.line):
        if isinstance(call.func, ast.Name) and call.func.id == "eval" and len(call.args) == 1 and not call.keywords:
            updated = replace_node(source, call, f"ast.literal_eval({segment(source, call.args[0])})")
            return ensure_import(updated, "ast")
    return None


def fix_hardcoded_secret(source: str, finding: Finding) -> str | None:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.lineno == finding.line:
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if not isinstance(target, ast.Name) or node.value is None or const_str(node.value) is None:
                return None
            updated = replace_node(source, node.value, f'os.environ["{target.id}"]')
            return ensure_import(updated, "os")
    return None


def fix_weak_hash(source: str, finding: Finding) -> str | None:
    if finding.details.get("context") == "password":
        return None  # password hashing needs a salted KDF and a migration plan, not a drop-in swap
    tree = ast.parse(source)
    imports = ImportMap(tree)
    for call in _calls_at(tree, finding.line):
        qual = imports.qualname(call.func)
        if qual in {"hashlib.md5", "hashlib.sha1"} and isinstance(call.func, ast.Attribute):
            return replace_node(source, call.func, f"{segment(source, call.func.value)}.sha256")
        if qual == "hashlib.new" and call.args and canonical(const_str(call.args[0]) or "") in {"MD5", "SHA1"}:
            return replace_node(source, call.args[0], '"sha256"')
    return None


def _lines(source: str) -> tuple[list[str], str]:
    lines = source.splitlines(keepends=True)
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    return lines, newline


def fix_docker_eol(source: str, finding: Finding) -> str | None:
    image, target = finding.details.get("image"), finding.details.get("recommended_image")
    lines, _ = _lines(source)
    index = (finding.line or 0) - 1
    if not image or not target or not 0 <= index < len(lines) or image not in lines[index]:
        return None
    lines[index] = lines[index].replace(image, target, 1)
    return "".join(lines)


def fix_docker_root(source: str, finding: Finding) -> str | None:
    lines, newline = _lines(source)
    instructions = parse_dockerfile(source)
    starts = [i for i, ins in enumerate(instructions) if ins.keyword == "FROM"]
    if not starts:
        return None
    final = instructions[starts[-1] :]
    entry = next((ins for ins in final if ins.keyword in {"CMD", "ENTRYPOINT"}), None)
    if entry is None:
        if lines and not lines[-1].endswith(("\n", "\r\n")):
            lines[-1] += newline
        lines.append(f"USER 10001{newline}")
    else:
        lines.insert(entry.line - 1, f"USER 10001{newline}")
    return "".join(lines)


def fix_legacy_tls_config(source: str, finding: Finding) -> str | None:
    lines, newline = _lines(source)
    index = (finding.line or 0) - 1
    if not 0 <= index < len(lines):
        return None
    line = lines[index].rstrip("\r\n")
    modern = {"1.2", "1.3"}
    if match := re.match(r"^(\s*ssl_protocols\s+)([^;]+)(;.*)$", line):
        tokens = [
            t
            for t in match.group(2).split()
            if (_protocol_token(t) or ("", ""))[1] in modern and (_protocol_token(t) or ("", ""))[0] == "tls"
        ] or ["TLSv1.2", "TLSv1.3"]
        lines[index] = f"{match.group(1)}{' '.join(tokens)}{match.group(3)}{newline}"
    elif match := re.match(r"^(\s*SSLProtocol\s+).+$", line, re.I):
        lines[index] = f"{match.group(1)}-all +TLSv1.2 +TLSv1.3{newline}"
    elif match := re.match(r"^(.*enabled-protocols\s*[=:]\s*).+$", line, re.I):
        lines[index] = f"{match.group(1)}TLSv1.2,TLSv1.3{newline}"
    else:
        return None
    return "".join(lines)


def fix_weak_tls_cipher(source: str, finding: Finding) -> str | None:
    lines, newline = _lines(source)
    index = (finding.line or 0) - 1
    if not 0 <= index < len(lines):
        return None
    line = lines[index].rstrip("\r\n")
    match = re.match(r"^(\s*(?:ssl_ciphers|SSLCipherSuite)\s+['\"]?)([^;'\"]+)(['\"]?\s*;?.*)$", line, re.I)
    if not match:
        return None
    tokens = [t for t in match.group(2).strip().split(":") if t]
    kept = [t for t in tokens if t.startswith(("!", "-")) or not any(m in t.upper() for m in WEAK_SUITE_MARKERS)]
    if not any(not t.startswith(("!", "-")) for t in kept):
        kept.insert(0, "HIGH")
    for exclusion in ("!aNULL", "!MD5", "!RC4", "!3DES"):
        if exclusion not in kept:
            kept.append(exclusion)
    lines[index] = f"{match.group(1)}{':'.join(kept)}{match.group(3)}{newline}"
    return "".join(lines)


PYTHON_CODEMODS: dict[str, Codemod] = {
    "VW-PY-YAML-LOAD": fix_yaml_load,
    "VW-PY-SHELL": fix_shell,
    "VW-PY-TLS-VERIFY-OFF": fix_tls_verify,
    "VW-PY-FLASK-DEBUG": fix_debug,
    "VW-PY-SQL-INJECTION": fix_sql,
    "VW-PY-EVAL": fix_eval,
    "VW-PY-HARDCODED-SECRET": fix_hardcoded_secret,
    "VW-CRYPTO-WEAK-HASH": fix_weak_hash,
}
TEXT_CODEMODS: dict[str, Codemod] = {
    "VW-DOCKER-EOL-BASE": fix_docker_eol,
    "VW-DOCKER-ROOT": fix_docker_root,
    "VW-CRYPTO-LEGACY-TLS": fix_legacy_tls_config,
    "VW-CRYPTO-WEAK-TLS-CIPHER": fix_weak_tls_cipher,
}


def codemod_for(finding: Finding) -> Codemod | None:
    if finding.path.endswith(".py"):
        if finding.rule_id == "VW-CRYPTO-WEAK-HASH" and finding.details.get("context") == "password":
            return None
        return PYTHON_CODEMODS.get(finding.rule_id)
    return TEXT_CODEMODS.get(finding.rule_id)


def apply_codemod(source: str, finding: Finding) -> str | None:
    codemod = codemod_for(finding)
    if codemod is None:
        return None
    try:
        updated = codemod(source, finding)
    except (SyntaxError, ValueError):
        return None
    return updated if updated and updated != source else None
