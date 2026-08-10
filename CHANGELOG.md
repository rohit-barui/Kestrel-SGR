# Changelog

All notable changes to Kestrel-SGR (APCS) are documented here.

## [Unreleased]

### Added
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
