"""Small helpers for resolving imported names in Python ASTs."""

from __future__ import annotations

import ast


class ImportMap:
    """Maps local names to fully qualified names, e.g. ``y`` -> ``yaml`` or ``AES`` -> ``Crypto.Cipher.AES``."""

    def __init__(self, tree: ast.AST) -> None:
        self.aliases: dict[str, str] = {}
        self.modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    self.modules.add(top)
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                self.modules.add(node.module.split(".")[0])
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def qualname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def has_module(self, name: str) -> bool:
        return name in self.modules


def kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def const_int(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def line_at(lines: list[str], lineno: int | None) -> str:
    if lineno is None or lineno < 1 or lineno > len(lines):
        return ""
    return lines[lineno - 1].strip()


def char_offset(lines: list[str], lineno: int, col_bytes: int) -> int:
    """Convert an AST (line, UTF-8 byte column) position to an absolute character offset."""
    prefix = sum(len(line) for line in lines[: lineno - 1])
    line = lines[lineno - 1]
    col_chars = len(line.encode("utf-8")[:col_bytes].decode("utf-8", errors="ignore"))
    return prefix + col_chars


def node_span(source: str, node: ast.AST) -> tuple[int, int]:
    lines = source.splitlines(keepends=True)
    start = char_offset(lines, node.lineno, node.col_offset)  # type: ignore[attr-defined]
    end = char_offset(lines, node.end_lineno, node.end_col_offset)  # type: ignore[attr-defined]
    return start, end


def replace_node(source: str, node: ast.AST, text: str) -> str:
    start, end = node_span(source, node)
    return source[:start] + text + source[end:]


def segment(source: str, node: ast.AST) -> str:
    start, end = node_span(source, node)
    return source[start:end]


def ensure_import(source: str, module: str) -> str:
    """Add ``import <module>`` after the last top-level import (or the docstring) if it is missing."""
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Import) and any(a.name == module and not a.asname for a in node.names):
            return source
    lines = source.splitlines(keepends=True)
    insert_at = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) or (
            insert_at == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            insert_at = node.end_lineno or node.lineno
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    lines.insert(insert_at, f"import {module}{newline}")
    return "".join(lines)
