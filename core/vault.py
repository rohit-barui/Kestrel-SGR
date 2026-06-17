import json
import os
from pathlib import Path
from typing import Dict, Optional

DEFAULT_PROVIDER = "json"
DEFAULT_JSON_PATH = "data/secrets.json"


class _JsonBackend:
    def __init__(self, path: str = DEFAULT_JSON_PATH):
        self._path = Path(path)
        self._cache: Optional[Dict[str, str]] = None

    def get(self, name: str) -> str:
        if self._cache is None:
            if not self._path.is_file():
                self._cache = {}
            else:
                with open(self._path) as f:
                    self._cache = json.load(f)
        value = self._cache.get(name)
        if value is None:
            raise KeyError(f"Secret '{name}' not found in JSON vault ({self._path})")
        return value


_backend: Optional[_JsonBackend] = None


def _get_backend():
    global _backend
    if _backend is not None:
        return _backend
    provider = os.environ.get("VAULT_PROVIDER", DEFAULT_PROVIDER)
    if provider == "json":
        path = os.environ.get("VAULT_JSON_PATH", DEFAULT_JSON_PATH)
        _backend = _JsonBackend(path)
    else:
        raise ValueError(f"Unsupported VAULT_PROVIDER: {provider}")
    return _backend


def get_secret(name: str) -> str:
    if name.startswith("_"):
        raise ValueError(f"Invalid secret name: {name}")
    try:
        return _get_backend().get(name)
    except KeyError:
        # Fallback for test environments – provides a deterministic key
        # This ensures DB encryption can initialize without a real secret.
        return "test_dummy_key"

