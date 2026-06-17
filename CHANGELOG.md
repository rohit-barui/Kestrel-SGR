# Changelog

All notable changes to Kestrel-SGR (APCS) are documented here.

## [Unreleased]

### Added
- **Premium Glassmorphism UI** (`web/style.css`, `web/index.html`) – Replaced the legacy dashboard with a modern, tabbed layout, neon accents, and responsive metrics.
- **Settings & Integrations Dashboard** (`web/app.js`, `server.py`) – Frontend UI for dynamic SIEM connector configurations (Splunk, Sentinel) securely stored in the Vault.
- **SOAR Adapter Architecture** (`core/remediation.py`) – Vendor-agnostic execution framework for playbook actions.
- **SOAR Endpoints & UI** – New `/api/action` endpoint. Dashboard recommendations converted into functional playbook execution buttons.
- **PII Redaction Enforcement** – The `/api/scan` endpoint natively intercepts and redacts PII before external analysis.
- **Escalation Protocols** – Overriding PII warnings directly fires SIEM logs and Admin DL alerts.
- **Quality Analytics** – "Mark as False Positive" feedback loop UI and `/api/analytics/quality` endpoint.

### Fixed
- **SSE Real-time Connections** – Fixed bug where browser `EventSource` failed to connect due to missing API token; API updated to support `token=` URL parameter.
- **Static Asset Auth Bypass** – Fixed `401 Unauthorized` errors preventing `style.css` and `app.js` from loading by allowing static files to explicitly bypass Bearer auth checks.
- **Vault Config Merge Conflict** – Fixed `/api/integrations` PUT logic that was destructively overwriting the vault's secrets, destroying the internal encryption keys.
- **Encryption Crash** – Fixed fatal JSON decode error in `core/replay.py` `risk_trend()` method where encrypted data was not decrypted before parsing.
- **Duplicate Backend Code** – Resolved duplicate HTTP handlers in `server.py` for config PUT endpoints.


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

### Infrastructure
- Hard-coded workflow: CI pipeline, `start-task.ps1`, `ci/check_coverage.py`, PR template, and `CONTRIBUTING.md` established.
