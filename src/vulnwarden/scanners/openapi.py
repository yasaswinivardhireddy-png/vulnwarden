"""API security checks for OpenAPI 3 / Swagger 2 specifications."""

from __future__ import annotations

from typing import Any

import yaml

from ..models import Category, Finding, Severity

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
LOCAL_HOSTS = ("http://localhost", "http://127.0.0.1", "http://[::1]")


def _line(text: str, needle: str) -> int | None:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else None


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    path: str,
    line: int | None,
    message: str,
    hint: str,
    snippet: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=Category.API,
        severity=severity,
        source="vulnwarden-api",
        path=path,
        line=line,
        message=message,
        snippet=snippet,
        cwe=[cwe],
        fix_hint=hint,
        sources=["vulnwarden-api"],
    )


def scan_openapi(text: str, path: str) -> list[Finding]:
    try:
        spec = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(spec, dict) or not ({"openapi", "swagger"} & set(spec)):
        return []
    findings: list[Finding] = []

    urls = [s.get("url", "") for s in spec.get("servers", []) if isinstance(s, dict)]
    if "http" in spec.get("schemes", []) and spec.get("host"):
        urls.append(f"http://{spec['host']}")
    for url in urls:
        if url.startswith("http://") and not url.startswith(LOCAL_HOSTS):
            findings.append(
                _finding(
                    "VW-API-CLEARTEXT",
                    "API served over cleartext HTTP",
                    Severity.HIGH,
                    "CWE-319",
                    path,
                    _line(text, url),
                    f"Server {url} sends credentials and data unencrypted.",
                    "Serve the API only over HTTPS (TLS 1.2+).",
                    url,
                )
            )

    components = spec.get("components", {}) if isinstance(spec.get("components"), dict) else {}
    schemes: dict[str, Any] = components.get("securitySchemes") or spec.get("securityDefinitions") or {}
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            findings.append(
                _finding(
                    "VW-API-KEY-IN-QUERY",
                    "API key sent in the URL query string",
                    Severity.MEDIUM,
                    "CWE-598",
                    path,
                    _line(text, f"{name}:"),
                    f"Scheme '{name}' puts the key in URLs, which end up in logs and history.",
                    "Send API keys in a header instead.",
                    f"{name}: apiKey in query",
                )
            )
        if scheme.get("type") == "basic" or (scheme.get("type") == "http" and scheme.get("scheme") == "basic"):
            findings.append(
                _finding(
                    "VW-API-BASIC-AUTH",
                    "HTTP Basic authentication",
                    Severity.MEDIUM,
                    "CWE-522",
                    path,
                    _line(text, f"{name}:"),
                    f"Scheme '{name}' sends reusable passwords with every request.",
                    "Prefer OAuth 2.0 / OIDC bearer tokens or mutual TLS.",
                    f"{name}: http basic",
                )
            )

    global_security = spec.get("security")
    for route, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            if "security" not in operation and not global_security:
                findings.append(
                    _finding(
                        "VW-API-NO-AUTH",
                        "API operation has no authentication",
                        Severity.HIGH,
                        "CWE-306",
                        path,
                        _line(text, f"{route}:"),
                        f"{method.upper()} {route} declares no security requirement.",
                        "Add a security requirement, or mark intentionally public endpoints with security: [].",
                        f"{method.upper()} {route}",
                    )
                )
    return findings
