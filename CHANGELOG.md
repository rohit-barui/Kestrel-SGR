# Changelog

All notable changes to Kestrel-SGR (APCS) are documented here.

## [Unreleased]

### Added
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
- `core/cache.py` – upgraded to use `get_encrypted_conn()` instead of raw `sqlite3.connect`.
- `core/replay.py` – upgraded to use `get_encrypted_conn()` instead of raw `sqlite3.connect`.
- `tests/test_auth.py` – improved truncation test for `AuthManager.list_tokens()`.
- `.gitignore` – added `.coverage` and `htmlcov/` entries.

### Fixed
- `core/ml.py` – resolved merge conflict (removed duplicate `import json` and redundant synthetic dataset definitions).

### Infrastructure
- Hard-coded workflow: CI pipeline, `start-task.ps1`, `ci/check_coverage.py`, PR template, and `CONTRIBUTING.md` established.
