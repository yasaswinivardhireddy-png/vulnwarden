# Benchmark results

Generated 2026-11-02 by `benchmarks/run_benchmark.py` on `examples/vulnerable-shop` (intel: recorded cache, no LLM, auto-approval).

| Metric | Result |
|---|---|
| Planted issues detected | **33/33** |
| Findings outside the planted list | 0 |
| Dependency advisories (OSV) | 38 across 7 packages (34 unique CVEs) |
| Cross-scanner duplicates merged | 3 |
| Duplicate advisories merged (GHSA/PYSEC) | 32 |
| Stale or discrepant reports flagged | 4 |
| Severities reclassified | 1 |
| Cryptographic assets inventoried | 15 |
| Fix plans (auto / total) | 20 / 42 |
| Fixes applied after tests + rescan | 17 (dependency: 6, codemod: 11) |
| Fixes rolled back by validation | 1 |
| Findings resolved by validated fixes | 49 |
| Open first-party findings before -> after | 71 -> 22 |
| Tests pass on the remediation branch | yes |
| Audit log entries / hash chain | 23 / intact |
| Scan time / agent run time | 0.44 s / 61.16 s |

## Detection

| Rule | Path | Expected | Found |
|---|---|---|---|
| VW-PY-HARDCODED-SECRET | `shop/config.py` | 1 | 1 |
| VW-PY-SQL-INJECTION | `shop/db.py` | 1 | 1 |
| VW-PY-YAML-LOAD | `shop/catalog.py` | 1 | 1 |
| VW-PY-SHELL | `shop/ops.py` | 1 | 1 |
| VW-PY-TLS-VERIFY-OFF | `shop/http_client.py` | 1 | 1 |
| VW-PY-PICKLE | `shop/auth.py` | 1 | 1 |
| VW-PY-FLASK-DEBUG | `shop/web.py` | 1 | 1 |
| VW-PY-EVAL | `shop/report.py` | 1 | 1 |
| VW-PY-MKTEMP | `shop/tmp.py` | 1 | 1 |
| VW-CRYPTO-WEAK-HASH | `shop/cache.py` | 1 | 1 |
| VW-CRYPTO-WEAK-HASH | `shop/auth.py` | 1 | 1 |
| VW-CRYPTO-ECB-MODE | `shop/crypto_box.py` | 1 | 1 |
| VW-CRYPTO-SHORT-KEY | `shop/crypto_box.py` | 1 | 1 |
| VW-CRYPTO-LEGACY-TLS | `shop/tls.py` | 1 | 1 |
| VW-CRYPTO-LEGACY-TLS | `deploy/nginx.conf` | 2 | 2 |
| VW-CRYPTO-WEAK-TLS-CIPHER | `deploy/nginx.conf` | 2 | 2 |
| VW-CERT-EXPIRING | `certs/legacy.pem` | 1 | 1 |
| VW-CERT-WEAK-SIGNATURE | `certs/legacy.pem` | 1 | 1 |
| VW-CRYPTO-SHORT-KEY | `certs/legacy.pem` | 1 | 1 |
| VW-CERT-LONG-VALIDITY | `certs/legacy.pem` | 1 | 1 |
| VW-CERT-SELF-SIGNED | `certs/legacy.pem` | 1 | 1 |
| VW-CRYPTO-ROTATION-DUE | `certs/legacy.pem` | 1 | 1 |
| VW-CRYPTO-PRIVATE-KEY | `certs/server.key` | 1 | 1 |
| VW-CRYPTO-DEPRECATED-LIB | `requirements.txt` | 1 | 1 |
| VW-DOCKER-EOL-BASE | `Dockerfile` | 1 | 1 |
| VW-DOCKER-SECRET | `Dockerfile` | 1 | 1 |
| VW-DOCKER-REMOTE-ADD | `Dockerfile` | 1 | 1 |
| VW-DOCKER-ROOT | `Dockerfile` | 1 | 1 |
| VW-API-CLEARTEXT | `api/openapi.yaml` | 1 | 1 |
| VW-API-KEY-IN-QUERY | `api/openapi.yaml` | 1 | 1 |
| VW-API-NO-AUTH | `api/openapi.yaml` | 1 | 1 |

## Remediation outcomes

| Status | Fix | Kind | Detail |
|---|---|---|---|
| applied | Upgrade PyYAML 5.3.1 -> 5.4 | dependency | - |
| applied | Upgrade cryptography 3.3.2 -> 50.0.0 | dependency | Raised target from 49.0.0 to 50.0.0: the first fix is still vulnerable. |
| applied | Upgrade urllib3 1.26.4 -> 2.8.0 | dependency | - |
| applied | Upgrade Flask 1.1.2 -> 3.1.3 | dependency | - |
| applied | Upgrade Jinja2 2.11.2 -> 3.1.6 | dependency | - |
| applied | Upgrade requests 2.25.1 -> 2.33.0 | dependency | - |
| applied | End-of-life base image | codemod | Rebuild on python:3.12-slim-bookworm. |
| applied | Unsafe YAML deserialization | codemod | Use yaml.safe_load() or pass Loader=yaml.SafeLoader. |
| reverted | Hardcoded secret in source code | codemod | Tests failed after the change (exit 2); change rolled back. |
| applied | SQL injection: query built with string formatting | codemod | Use a parameterized query. |
| applied | TLS certificate verification disabled | codemod | Remove verify=False and keep certificate and hostname verification on. |
| applied | OS command injection risk (shell execution) | codemod | Pass an argument list and keep shell=False. |
| applied | Code injection via eval/exec of dynamic input | codemod | Use ast.literal_eval() or explicit parsing. |
| applied | Legacy TLS/SSL protocol version enabled | codemod | Allow only TLS 1.2 and TLS 1.3. |
| already-resolved | Legacy TLS/SSL protocol version enabled | codemod | Resolved by an earlier fix in this run. |
| applied | Container runs as root | codemod | Add a non-root USER before CMD/ENTRYPOINT. |
| applied | Debug mode enabled in web server | codemod | Set debug=False outside local development. |
| applied | Weak TLS cipher suite enabled | codemod | Remove RC4, 3DES, NULL, EXPORT and MD5 suites; prefer AES-GCM and ChaCha20-Poly1305. |
| already-resolved | Weak TLS cipher suite enabled | codemod | Resolved by an earlier fix in this run. |
| applied | Weak hash algorithm | codemod | Use SHA-256 or stronger. |

22 findings were routed to owners (no safe automatic fix, below the auto-fix threshold, or no fixed release).
