# Changelog

All notable changes to Kestrel-SGR (APCS) are documented here.

## [Unreleased]

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
