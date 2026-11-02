# vulnerable-shop (intentionally insecure demo)

**Do not deploy this code.** It is a small, deliberately vulnerable shop service used to
benchmark VulnWarden end to end. Every planted issue is listed in
[`../../benchmarks/expected.yaml`](../../benchmarks/expected.yaml).

- `shop/` - application code with injection, deserialization, TLS and crypto mistakes
- `requirements.txt` - old pinned versions with published advisories
- `Dockerfile`, `deploy/nginx.conf`, `api/openapi.yaml` - container, TLS and API issues
- `reports/` - hand-written sample reports in Trivy JSON and SARIF format (as if exported
  by those tools on an older commit), used to exercise correlation and stale detection
- `make_certs.py` - generates throwaway test certificates and a key into `certs/` at run time,
  so no key material is ever committed

The tests in `tests/` pass on the vulnerable code; VulnWarden must keep them passing.
