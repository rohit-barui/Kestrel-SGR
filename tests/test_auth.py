import json

import pytest

from core.auth import AuthManager


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    # Use a temporary token file for each test
    token_path = tmp_path / "tokens.json"
    monkeypatch.setenv("APCS_TOKEN_FILE", str(token_path))
    # Ensure module reload uses the env var
    import importlib

    import core.auth as auth_mod
    importlib.reload(auth_mod)
    # Rebind the class name this module holds so AuthManager() defaults to
    # the freshly reloaded TOKEN_FILE (temp path) instead of the stale class.
    global AuthManager
    AuthManager = auth_mod.AuthManager
    yield
    # Cleanup
    if token_path.exists():
        token_path.unlink()

def test_generate_and_validate_token(isolated_env):
    mgr = AuthManager()
    token = mgr.generate_token("unit-test")
    assert isinstance(token, str) and len(token) == 64
    # Validation returns stored dict with label
    info = mgr.validate_token(token)
    assert info is not None and info["label"] == "unit-test"

def test_revoke_token(isolated_env):
    mgr = AuthManager()
    token = mgr.generate_token()
    assert mgr.revoke_token(token) is True
    # After revocation, token should be missing
    assert mgr.validate_token(token) is None
    # Revoking again returns False
    assert mgr.revoke_token(token) is False

def test_list_tokens_truncation(isolated_env):
    mgr = AuthManager()
    long_token = mgr.generate_token(label="test")
    # Find the dict entry whose label matches our generated token
    matching_key = next(k for k, v in mgr.list_tokens().items() if v.get("label") == "test")
    expected_prefix = long_token[:8]
    assert matching_key.startswith(expected_prefix)
    assert matching_key.endswith('...')

def test_default_auto_generation(monkeypatch, tmp_path, capsys):
    # Ensure no token file exists initially
    token_path = tmp_path / "default_tokens.json"
    monkeypatch.setenv("APCS_TOKEN_FILE", str(token_path))
    # Reload module to trigger auto‑generation block
    import importlib

    import core.auth as auth_mod
    importlib.reload(auth_mod)
    captured = capsys.readouterr()
    # Should have printed a generated token line
    assert "[auth] Default API token generated" in captured.out
    # Token file should now exist and contain one token
    with open(token_path) as f:
        data = json.load(f)
    assert len(data) == 1


def test_generate_token_with_role(isolated_env):
    mgr = AuthManager()
    token = mgr.generate_token("admin-key", role="Admin")
    info = mgr.validate_token(token)
    assert info is not None
    assert info["role"] == "Admin"

def test_default_role_is_analyst(isolated_env):
    mgr = AuthManager()
    token = mgr.generate_token("default-key")
    info = mgr.validate_token(token)
    assert info["role"] == "Analyst"

def test_has_role_returns_true(isolated_env):
    mgr = AuthManager()
    token = mgr.generate_token("admin-key", role="Admin")
    assert mgr.has_role(token, "Admin") is True

def test_has_role_returns_false_for_wrong_role(isolated_env):
    mgr = AuthManager()
    token = mgr.generate_token("reader-key", role="Analyst")
    assert mgr.has_role(token, "Admin") is False

def test_has_role_returns_false_for_invalid_token(isolated_env):
    mgr = AuthManager()
    assert mgr.has_role("invalid-token", "Analyst") is False

def test_corrupt_token_file_treated_as_empty(tmp_path):
    # Write invalid JSON to the token file; AuthManager must not crash
    token_path = tmp_path / "corrupt_tokens.json"
    token_path.write_text("{not valid json[[[")
    mgr = AuthManager(str(token_path))
    assert mgr.list_tokens() == {}
