import json
import os
import tempfile

import pytest

from core import vault


@pytest.fixture(autouse=True)
def clear_backend():
    vault._backend = None
    yield
    vault._backend = None


def test_json_backend_reads_secret():
    secrets = {"db_encryption_key": "supersecret", "api_key": "abc123"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(secrets, f)
        path = f.name
    try:
        # Override env vars to use this temp file
        os.environ["VAULT_PROVIDER"] = "json"
        os.environ["VAULT_JSON_PATH"] = path
        vault._backend = None  # force re-init

        assert vault.get_secret("db_encryption_key") == "supersecret"
        assert vault.get_secret("api_key") == "abc123"
    finally:
        os.unlink(path)
        # Clean env so other tests aren't affected
        os.environ.pop("VAULT_PROVIDER", None)
        os.environ.pop("VAULT_JSON_PATH", None)
        vault._backend = None


def test_json_backend_missing_key_raises():
    secrets = {"some_key": "value"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(secrets, f)
        path = f.name
    try:
        os.environ["VAULT_PROVIDER"] = "json"
        os.environ["VAULT_JSON_PATH"] = path
        vault._backend = None

        with pytest.raises(KeyError, match="missing_key"):
            vault.get_secret("missing_key")
    finally:
        os.unlink(path)
        os.environ.pop("VAULT_PROVIDER", None)
        os.environ.pop("VAULT_JSON_PATH", None)
        vault._backend = None


def test_invalid_secret_name():
    with pytest.raises(ValueError, match="Invalid secret name"):
        vault.get_secret("_invalid")


def test_default_backend_creates_missing_file():
    # When json file doesn't exist, backend treats it as empty
    with tempfile.TemporaryDirectory() as tmpdir:
        missing_path = os.path.join(tmpdir, "nonexistent.json")
        os.environ["VAULT_PROVIDER"] = "json"
        os.environ["VAULT_JSON_PATH"] = missing_path
        vault._backend = None

        with pytest.raises(KeyError, match="test_default"):
            vault.get_secret("test_default")
    os.environ.pop("VAULT_PROVIDER", None)
    os.environ.pop("VAULT_JSON_PATH", None)
    vault._backend = None
