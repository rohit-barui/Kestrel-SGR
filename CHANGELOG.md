# Changelog

All notable changes to Kestrel-SGR (APCS) are documented here.

## [Unreleased]

### Added
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
