# Changelog

All notable changes to Kestrel-SGR (APCS) are documented here.

## [0.5.0] — 2026-08-19

### Added
- **IP / File Reputation** (`skills/reputation.py`) — new `check_ip_reputation` and `check_file_reputation` DAG nodes. IP lookups via VirusTotal, AbuseIPDB and AlienVault OTX with abuse-confidence scoring; SHA-256 file-hash lookups against VirusTotal + OTX. On-demand API endpoints `/api/reputation/ip` and `/api/reputation/file`.
- **Threat Intelligence Lookup** (`skills/reputation.py`) — `threat_intel_lookup` node performs URL/domain IoC matching via OTX pulses and VirusTotal.
- **OWASP Security Analysis** (`skills/owasp.py`) — `owasp_analysis` node with 10 pattern detectors covering OWASP Top 10 categories (Reflected/DOM XSS, SQL Injection, Open Redirect, SSRF, etc.). On-demand `/api/owasp/scan` endpoint.
- **Phishing Validation** (`skills/reputation.py`) — `phishing_validation` node detects brand impersonation, missing SSL, and header anomalies; contributes risk signals and feeds new veto overrides.
- **Phishing Report Portal** (`server.py`, `web/`) — `/api/report/phishing` submission endpoint (with optional auto-remediation) and `/api/reports` history listing; new customer-report web tab.
- **Email Security Integrations** (`core/integrations/`) — adapters for **Microsoft Defender for Email** (quarantine, block sender, verdict via Graph) and **Cisco ESA** (mark spam/clean, domain reputation, block sender), plus **VirusTotal**, **AbuseIPDB** and **AlienVault OTX** enrichment adapters.
- **New Risk Signals** — IP/file reputation scores, OWASP risk (score/2), brand impersonation (+30), missing SSL (+10), header mismatch (+15), and threat-intel IoC match (+30 each) folded into `aggregate_risk`.
- **New Veto Overrides** — IP reputation malicious → risk ≥ 80; file reputation malicious → risk ≥ 85; 2+ threat-intel IoC matches → risk ≥ 85; phishing likely (2+ signals) → risk ≥ 75.
- **Web UI** — new Reputation & OWASP tab, Phishing Reports tab, extended Settings & Integrations tab (Defender, Cisco ESA, VT, AbuseIPDB, OTX), per-scan enrichment summary panel, updated DAG graph with 5 new perception nodes, live SSE enrichment logging.
- **Expanded CI/CD** — docker build & push to `ghcr.io/rohit-barui/kestrel-sgr` (`latest` + commit SHA tags) on `main`, with `packages: write` permission; `pythonpath` pytest config for clean CI imports; test matrix on Python 3.11/3.12.

### Changed
- **DAG expanded from 19 to 26 nodes** — five new v0.5 perception nodes (`check_ip_reputation`, `check_file_reputation`, `threat_intel_lookup`, `owasp_analysis`, `phishing_validation`) wired into `ml_score` and `aggregate_risk`.
- **Auth bypass tightened** (`server.py`) — removed over-broad `/api/auth/` prefix allow-list; only the explicit `/api/auth/login` endpoint bypasses token auth, so `/api/auth/token/generate` correctly enforces the Admin role.
- **Dependencies** (`requirements.txt`) — `scikit-learn>=1.0.0` promoted from optional to required so the ML model path is exercised in CI.

### Fixed
- **Integration test auth** (`tests/test_integration.py`) — Admin token now provisioned via the live `server.auth_manager` instance; `test_auth.py` reloads `core.auth`, so using the module singleton wrote tokens to a temp file and `/api/policies` returned 403 in full-suite runs.
- **ML model-path tests** (`tests/test_ml.py`) — robust when scikit-learn is absent: `train_test_split`/`RandomForestClassifier`/`accuracy_score` are patched with fakes and `Stub` moved to module level so it is picklable.
- **CI lint on ruff 0.4.0** — added per-file ignores: `N802` for stdlib-required `do_GET`/`do_POST`/`do_PUT` in `server.py` and `N817` for the conventional `ET` alias in `ci/check_coverage.py`.

### Tests
- Suite grown to **506 tests** (up from ~303) with new `tests/test_server.py`, `tests/test_integrations.py`, `tests/test_reputation.py`, `tests/test_owasp.py`, `tests/test_detonation.py`, `tests/test_remediation.py`.
- Coverage gates: **97.34% overall**, **≥ 99% per core/skills file** (verified by `ci/check_coverage.py`).

## [Unreleased]

### Coming Soon (Planned for v0.6.0)
- **ML Model Retraining** — Extend feature extractor with v0.5 signals (IP/file reputation, OWASP risk, threat-intel IoC matches, phishing validation signals) and retrain the RandomForest risk scorer.
- **Integration Health Probes** — Per-provider connectivity checks (VirusTotal, AbuseIPDB, OTX, Defender, Cisco ESA) exposed via `/api/integrations/health` with readiness status in dashboard Settings tab.
- **Phishing Report Automation** — Persistent report store with `report_id`, status tracking, and automatic Defender/Cisco ESA remediation dispatch on `auto_remediate=true`.
- **Docker/K8s Deployment Docs** — Compose files, Helm chart, and secret-management guides for new integration credentials (vault-backed env injection).
- **Project Board** — GitHub Projects board for sprint planning (blocked on `gh` token `project` scope; requires manual setup).

### Added
- **URL Detonation Engine** (`core/detonation.py`) — Multi-link reputation analysis with CyberWatch API integration and local heuristics (domain length, keywords, IP-based, URL shorteners, HTTPS status). Returns per-URL malicious/suspicious/safe classification with confidence scores and CyberWatch detonation links.
- **File Upload Scanning** (`server.py`, `web/index.html`, `web/app.js`) — Upload `.eml`/`.txt`/`.msg`/`.html` files via `POST /api/scan/upload` (multipart/form-data). Content is extracted and passed through the full SGR pipeline.
- **URL/domain Investigation** (`web/index.html`, `web/app.js`) — Dedicated input field to submit URLs or domains for instant reputation analysis via `POST /api/detonate`. Results displayed as color-coded stats cards with per-URL breakdown.
- **Detonate Node in DAG** — `detonate_urls` skill added to the SGR graph, depends on `extract_urls`, feeds into `aggregate_risk` and `ml_score`.
- **Multi-Signal Risk Scoring** (`skills/decision.py`) — `aggregate_risk` now consumes: `ml_score` (ML risk score blended in), `validate_spf_dkim` (spoof flag +30, SPF/DKIM/DMARC fails +10-15 each), `extract_entities` (bulk entity count +8/+15), `enrich_external` (URL suspicion scores).
- **Veto Overrides** (`skills/decision.py`) — `apply_veto` now hard-overrides risk to 85+ on `is_spoofed=True`, `malicious_count>0`, or `ml_risk_score>=80`. Confidence set to 95 on override.
- **Context-Aware Actions** (`skills/decision.py`) — `recommend_actions` returns `["block", "alert_admin"]` on spoof/detonation threats, `["quarantine", "review"]` at moderate risk with low confidence, `["allow", "monitor"]` at low risk with low confidence.
- **Expanded Rego Policy** (`policies/remediation.rego`) — Policy now evaluates `is_spoofed`, `malicious_count`, `suspicious_count`, `ml_risk_score`, `ml_confidence`, `spf_result`, `dmarc_result` alongside classic signals.
- **Comprehensive Documentation** (`docs/`) — Added `CORE.md`, `SKILLS.md`, `POLICIES.md`, `WEB_UI.md`, `USAGE.md`, `TESTING.md`, `CONTRIBUTING.md`, `REPOSITORY_STRUCTURE.md`. Updated `ARCHITECTURE.md`, `HLD.md`, `LLD.md`, `README.md`, `docs/README.md`.
- **Detonation Results in Dashboard** (`web/style.css`, `web/app.js`) — New detonation panel with malicious/suspicious/safe stat counters, per-URL reputation with color-coded borders, and CyberWatch result links.
- **`urls` field support** (`server.py`, `skills/perception.py`) — `POST /api/scan` now accepts `{"urls": [...]}` payload for direct URL investigations that route through the full DAG pipeline.

### Fixed
- **SSE Real-time Connections** – Fixed bug where browser `EventSource` failed to connect due to missing API token; API updated to support `token=` URL parameter.
- **Static Asset Auth Bypass** – Fixed `401 Unauthorized` errors preventing `style.css` and `app.js` from loading by allowing static files to explicitly bypass Bearer auth checks.
- **Vault Config Merge Conflict** – Fixed `/api/integrations` PUT logic that was destructively overwriting the vault's secrets, destroying the internal encryption keys.
- **Encryption Crash** – Fixed fatal JSON decode error in `core/replay.py` `risk_trend()` method where encrypted data was not decrypted before parsing.
- **Duplicate Backend Code** – Resolved duplicate HTTP handlers in `server.py` for config PUT endpoints.
- **Duplicate import** – Removed redundant `from core.notifications import notifier` inside conditional block in `server.py`.
- **Fernet Decrypt Crash** – `core/replay.py` `stats()` now wraps decrypt in try/except to handle stale encryption keys gracefully.
- **Rego Policy Inversion** – Fixed `policies/remediation.rego` where `allow` rules had inverted logic (allowed high risk). Rewritten to properly deny high-risk threats.
- **Increased Scan Body Limit** – Raised from 10,000 to 500,000 characters to support uploaded file content.

### Changed
- **Risk Scoring Weights** (`skills/decision.py`) — Rebalanced all signal weights: reduced per-URL base from +20 to +5, archive password from +10 to +15, typo from +25 to +15, WHOIS odd year from +10 to +5. Added detonation reputation scores (+35 malicious, +20 suspicious), SPF/DKIM/DMARC authentication scores, ML score blending, entity count scores, and URL suspicion scores.
- **Scan Body Validation** (`server.py`) — Now accepts `urls` field in addition to `email`, `sms`, `voice`.
- **Policy Input Contract** (`server.py`) — Expanded from 5 fields to 12 fields sent to Rego evaluator.
- **Drift Tracking Thresholds** (`server.py`) — Adjusted FP threshold from <30 to <20, FN threshold from >70 to >60.


- **Celery integration** (`core/celery_app.py`, `core/tasks.py`) – Celery app with in-memory broker/backend; `run_skill` task wrapper that resolves skill functions from a global registry.
- **Skill registry** (`core/engine.py`) – `_SKILL_REGISTRY` and `register_skill()` method so Celery workers can resolve skill functions by name.
- **RBAC in AuthManager** (`core/auth.py`) – token now stores a `role` field (default `Analyst`). New methods: `has_role(token, role)`.
- **HMAC verification middleware** (`server.py`) – optional `X-HMAC` header verification using a secret fetched from the vault (`webhook_hmac_secret`).
- **Role-based endpoint protection** – `/api/auth/token/generate` (POST) and `/api/policies` (PUT) require `Admin` role.
- **mTLS support** – `--client-ca` argument for client certificate verification; upgraded to `ssl.create_default_context`.
- **Body caching** – `_read_body()` helper prevents double-read conflicts when HMAC and handlers both need the request body.
- **Auth role tests** – 5 new tests covering `generate_token` with role, `has_role` validation, and default role fallback.
- **Encrypted database layer** (`core/db.py`) – centralized `get_encrypted_conn()` helper with SQLCipher pragma support, sourced from the vault.
- **Vault client** (`core/vault.py`) – strategy-pattern secrets manager with JSON file backend (default for CI), env-var configurable for future Azure/HashiCorp/AWS providers.
- **Email parser tests** (`tests/test_email_parser.py`) – 100% line coverage for `core/email_parser.py`.
- **Database tests** (`tests/test_db.py`) – verify encryption key retrieval and error handling.
- **Vault tests** (`tests/test_vault.py`) – verify JSON backend reads, missing key exception, and invalid secret name rejection.

### Changed
- `core/engine.py` – migrated from `ThreadPoolExecutor` to Celery task execution with `_SKILL_REGISTRY`; fixed `heuristic_boost` confidence doubling bug (risk_score set to 0).
- `core/cache.py` – upgraded to use `get_encrypted_conn()` instead of raw `sqlite3.connect`.
- `core/replay.py` – upgraded to use `get_encrypted_conn()` instead of raw `sqlite3.connect`.
- `tests/test_auth.py` – improved truncation test for `AuthManager.list_tokens()`.
- `.gitignore` – added `.coverage` and `htmlcov/` entries.

### Fixed
- `core/ml.py` – resolved merge conflict (removed duplicate `import json` and redundant synthetic dataset definitions).
- `core/replay.py` – `risk_trend()` now decrypts stored trace data before parsing (previously crashed with a JSON decode error on real encrypted traces).
- `core/policy.py` – removed unreachable `NEWLINE` branch in `Parser.parse_primary()` (dead code; leading `skip_newlines()` always consumes newlines first).

### Infrastructure
- Hard-coded workflow: CI pipeline, `start-task.ps1`, `ci/check_coverage.py`, PR template, and `CONTRIBUTING.md` established.
- `.github/workflows/test.yml` – fixed malformed `coverage` job (broken YAML: unindented `- run:` line, `--cov-fail-under=100` split across lines); `test` job now runs `pytest` instead of `unittest discover` (the suite is pytest-based), and the `coverage` job mirrors `ci.yml` (pytest `--cov` + `ci/check_coverage.py`).
- `ci/check_coverage.py` – reconfigure stdout/stderr to UTF‑8 so emoji output does not crash on Windows consoles (cp1252).
- `.gitignore` – added `coverage.xml`; ignored nested `Kestrel-SGR/` and `Kestrel-SGR-repo/` directories.

### Tests
- Raised line coverage of `core/*.py` and `skills/*.py` to **100%** (293 tests passing).
- `tests/test_enricher.py` – fixed 4 WHOIS tests to patch the lazily-imported `whois` module via `sys.modules` instead of `core.enricher.whois`.
- Added coverage for `core/webhooks.py`, `core/gateway.py`, `core/cache.py`, `core/replay.py`, `skills/perception.py`, `core/auth.py`, `core/db.py`, `core/engine.py`, `core/export.py`, `core/graph.py`, `core/ml.py`, `core/policy.py`, `core/vault.py`, `skills/decision.py`, and `skills/dominance.py`.
- New tests added: `tests/test_logging.py`, `tests/test_policy.py`; expanded `tests/test_webhooks.py`, `tests/test_gateway.py`, `tests/test_cache.py`, `tests/test_replay.py`, `tests/test_perception.py`.
