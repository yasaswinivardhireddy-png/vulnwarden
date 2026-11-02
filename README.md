# VulnWarden

[![CI](https://github.com/yasaswinivardhireddy-png/vulnwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/yasaswinivardhireddy-png/vulnwarden/actions/workflows/ci.yml)

An agentic vulnerability and cryptography remediation tool. VulnWarden scans a repository, correlates
findings from its own scanners and from tools like Trivy, Semgrep and CodeQL, prioritizes them by real-world
risk, fixes what it safely can, proves each fix with the test suite and a security rescan, opens a GitHub
pull request for human review, and keeps following up until the finding is verifiably closed.

> Finding vulnerabilities is the easy part. Teams drown in duplicate, stale and mis-scored reports, and the
> fixes that do get written sit in unreviewed pull requests. VulnWarden works on the whole loop.

**Status:** portfolio project, built and evaluated on the seeded demo service in
[`examples/vulnerable-shop`](examples/vulnerable-shop). It is not a production service; see [Limitations](#limitations).

## Results

`benchmarks/run_benchmark.py` copies the demo into a fresh git repository, scans it together with sample
Trivy and SARIF reports, runs the agent with auto-approval and no LLM, then rescans the remediation branch.
OSV, EPSS and CISA KEV responses are recorded in `benchmarks/intel-cache`, so CI reproduces the run offline.

| Metric | Result |
|---|---|
| Planted issues detected (code, crypto, certificates, keys, container, API) | **33/33**, 0 findings outside the planted list |
| Dependency advisories from OSV | 38 across 7 packages (34 unique CVEs) |
| Correlation | 3 cross-scanner duplicates merged, 32 duplicate GHSA/PYSEC advisories merged, 4 stale reports flagged, 1 severity reclassified |
| Fixes applied after passing tests + rescan | **17** (6 dependency upgrades, 11 code/config/container codemods), one commit each |
| Fixes rolled back by validation | 1 (externalizing a hardcoded secret broke the app until the secret is provisioned) |
| Open first-party findings | **71 -> 22** (-69%); every remaining one is routed to an owner with guidance |
| Tests on the remediation branch | pass |
| Audit log | 23 hash-chained entries, chain verified |

Full tables: [benchmarks/RESULTS.md](benchmarks/RESULTS.md). The demo and its planted issues were written
alongside the scanners, so treat these as regression results, not a measure of recall on arbitrary code.

## How it works

The agent is a [LangGraph](https://github.com/langchain-ai/langgraph) state machine with a human-approval
interrupt. Every step writes to a tamper-evident audit log.

```text
 scan ──► triage ──► plan ──► approve ──► remediate ──► publish ──► report
  │         │          │     (interrupt)      │             │
  │         │          │                      │             └─ GitHub PR: branch + commits via the Git Data API,
  │         │          │                      │                labels, reviewers, evidence in the description
  │         │          │                      └─ per fix: apply -> run tests -> rescan -> commit, or roll back
  │         │          └─ dependency upgrade | deterministic codemod | LLM patch (guarded) | route to an owner
  │         └─ dedupe across scanners, flag stale reports, reclassify severity,
  │            risk = CVSS + EPSS + CISA KEV + exposure + reachability -> P1-P4 with SLA hours
  └─ Python SAST, dependencies (OSV), Dockerfiles, OpenAPI specs, crypto inventory,
     plus imported Trivy JSON and SARIF reports

 monitor (scheduled) ──► remind owners after 24 h, escalate after 72 h (email, Slack, Teams, PR comment)
 reconcile (on merge) ─► rescan, mark findings verified-closed or reopened, update PR status
```

**Scanning.** Import-aware Python SAST rules mapped to CWE (deserialization, command and SQL injection, eval,
TLS verification, secrets, debug mode, temp files); pinned dependencies in `requirements*.txt` and
`package-lock.json` checked against [OSV](https://osv.dev); Dockerfile rules (end-of-life base images with
dated support data, root user, secrets in layers, unverified downloads); OpenAPI checks (cleartext servers,
unauthenticated operations, keys in query strings, basic auth).

**Cryptography.** Discovers algorithms, modes and key sizes in Python (AST), Java, JavaScript/TypeScript, Go and
C#; TLS versions and cipher suites in nginx, Apache and Spring configs; X.509 certificates; private keys; and
crypto libraries. A YAML policy ([example](policies/enterprise-crypto-policy.yaml)) flags weak hashes (with a
stricter rule for password hashing), broken ciphers, ECB, short keys, legacy TLS, expiring or weakly signed
certificates, overdue key rotation, committed private keys and deprecated libraries. The lifecycle report lists
certificates by days to expiry and post-quantum migration candidates. The inventory exports as a
[CycloneDX 1.6 CBOM](https://cyclonedx.org/capabilities/cbom/), validated against the official schema in tests.

**Triage.** The same CVE reported by OSV (often twice, as GHSA and PYSEC) and by Trivy becomes one finding with
all sources attached. Reports that no longer match the repository (an upgraded package, a deleted file, removed
code) are marked stale instead of being re-filed. When a scanner's label disagrees with the CVSS vector, the
severity is reclassified and the reason recorded. Packages that first-party code never imports are scored lower.

**Remediation.** Dependency upgrades pick the smallest version that fixes every advisory, then re-query OSV and
raise the target if that version is still vulnerable (this happened for `cryptography` in the benchmark).
Codemods edit the exact AST span or config line, preserving formatting and line endings: `yaml.safe_load`,
parameterized SQL in the driver's paramstyle, `shlex.split` instead of `shell=True`, `ast.literal_eval`,
environment-backed secrets, SHA-256 for non-password hashing, supported base images, a non-root `USER`, TLS
1.2+ and strong cipher suites. Anything else can go to an LLM (Gemini through LangChain structured output) or
to an owner. Each change is kept only if the tests still pass and a rescan shows the target finding resolved
with no new findings; otherwise it is rolled back.

## Security model of the agent

An agent that edits code and opens pull requests is itself an attack surface, so VulnWarden is built to fail closed.

| Risk | Control |
|---|---|
| Prompt injection from repository content | Code is fenced as untrusted data (fence-break attempts are neutralized) and the system prompt says to ignore embedded instructions. Model output is never trusted directly: guardrails reject patches outside the flagged window, below a confidence threshold, oversized, unparseable, adding network access, shell, eval, deserialization, reflection, URLs or encoded payloads, or importing non-allowlisted modules. |
| Secrets leaking to the model, logs or PRs | Secrets are redacted before prompts, snippets and audit entries. Hardcoded-secret findings are never sent to the model. |
| Untrusted test code stealing credentials | Repository tests run with tokens, keys and webhook URLs stripped from the environment. |
| Excessive privilege | Needs only a fine-grained token with Contents and Pull requests write on one repository. Pushes through the Git Data API, so no git credentials are configured, and refuses to publish if the local base differs from GitHub. |
| Unreviewed changes | Fixes require approval (a LangGraph interrupt, or explicit `--yes`), land on a new branch, and the PR states that a human must approve before merge. Major-version upgrades get a `breaking-change-risk` label. |
| Tampering with the record | Every scan, plan, approval, fix, PR and notification is appended to a SHA-256 hash-chained audit log; `vulnwarden audit` detects edits. |

## Quick start

Requires Python 3.11+ and git.

```bash
uv sync                                   # or: pip install -e ".[gemini]"
python examples/vulnerable-shop/make_certs.py

# Scan, correlate and prioritize (imports are optional)
uv run vulnwarden scan examples/vulnerable-shop \
    --trivy examples/vulnerable-shop/reports/trivy-image.json \
    --sarif examples/vulnerable-shop/reports/semgrep.sarif \
    --markdown report.md --html dashboard.html --cbom cbom.json

# Cryptographic inventory, policy check and lifecycle
uv run vulnwarden crypto examples/vulnerable-shop --policy policies/enterprise-crypto-policy.yaml

# Run the agent (asks for approval; needs the target to be a clean git repo)
uv run vulnwarden remediate path/to/repo --report remediation.md
uv run vulnwarden remediate path/to/repo --github owner/name --yes   # opens a PR (GITHUB_TOKEN)

# Follow-up and verification
uv run vulnwarden monitor --github owner/name --dry-run
uv run vulnwarden reconcile path/to/repo --github owner/name
uv run vulnwarden audit path/to/repo

uv run pytest                              # 77 tests
uv run python benchmarks/run_benchmark.py  # end-to-end benchmark, offline
```

Use `vulnwarden scan --fail-on high` as a CI gate; this repository scans itself on every push.
[`examples/workflows/vulnwarden.yml`](examples/workflows/vulnwarden.yml) shows scheduled remediation, hourly
follow-up and post-merge verification in GitHub Actions.

### Configuration

Optional `vulnwarden.yaml` at the repository root:

```yaml
exposure: internet-facing          # adds risk to reachable issues
owners: [team-lead]                # PR reviewers and reminder recipients
escalation_contacts: [appsec-lead]
crypto_policy: policies/enterprise-crypto-policy.yaml
sla_hours: {P1: 72, P2: 168, P3: 720, P4: 2160}
monitor: {remind_after_hours: 24, escalate_after_hours: 72, repeat_every_hours: 24}
notify:
  channels: [email, slack, teams]  # webhook URLs and SMTP credentials come from environment variables
  smtp_host: smtp.example.com
  email_to: [owners@example.com]
remediation:
  test_command: ["{python}", "-m", "pytest", "-q"]
  max_priority: P3                 # auto-fix P1-P3; route P4 to owners
llm: {provider: gemini, model: gemini-3.5-flash}   # needs GOOGLE_API_KEY and the [gemini] extra
```

## Design decisions

- **Deterministic first, LLM second.** Codemods are predictable, reviewable and free; the model is only used
  where no codemod applies, and its output is treated as untrusted input.
- **Validation over confidence.** A fix that looks right but breaks tests or leaves the finding open is worth
  less than no fix, so every change must pass both checks or it is rolled back.
- **Stable fingerprints.** Code findings are keyed by rule, file and normalized code (not line numbers), and
  dependency findings by package and CVE (not version), so history survives unrelated edits and upgrades.
- **Imported reports describe the past.** Trivy/SARIF imports are used for correlation and reporting, but
  validation rescans use only VulnWarden's own scanners against the current tree.

## Limitations

- Python is the only language with SAST rules and code fixes; other languages get crypto discovery only.
- Dependency upgrades are validated with the repository's own test command. Configure it to install the
  upgraded requirements in an isolated environment if your tests do not already do that.
- The LLM path is unit-tested with a scripted model; live runs need a Gemini API key.
- The Trivy and SARIF files in `examples/vulnerable-shop/reports` are hand-written samples in those tools'
  formats, used to exercise correlation.
- End-of-life dates for base images are a dated table (November 2026) and need periodic updates.

## Project layout

```text
src/vulnwarden/
  scanners/      python_sast, dependencies (OSV), containers (+ Trivy import), sarif, openapi
  crypto.py      discovery, policy, lifecycle, CycloneDX CBOM
  intel.py       OSV, EPSS and CISA KEV clients with retries and a replayable cache
  triage.py      correlation, stale detection, reclassification, risk scoring
  codemods.py    format-preserving fixes
  llm.py         structured-output patch proposals (LangChain)
  guardrails.py  checks every model-proposed patch
  remediation.py planning, dependency upgrades, test + rescan validation, commits
  agent.py       LangGraph state machine with the approval interrupt
  github.py      REST client (Git Data API, PRs, labels, reviewers, comments)
  monitor.py     SLA reminders and escalations;  notify.py  email, Slack, Teams
  store.py       SQLite history, trends and hash-chained audit log
  report.py      Markdown, HTML dashboard and JSON reports
```

## License

MIT
