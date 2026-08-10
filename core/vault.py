import json
import os
import secrets
from pathlib import Path
from typing import Dict, Optional

DEFAULT_PROVIDER = "json"
DEFAULT_JSON_PATH = "data/secrets.json"


class _JsonBackend:
    def __init__(self, path: str = DEFAULT_JSON_PATH):
        self._path = Path(path)
        self._cache: Optional[Dict[str, str]] = None

    def _load(self) -> Dict[str, str]:
        if self._cache is None:
            if not self._path.is_file():
                self._cache = {}
            else:
                with open(self._path) as f:
                    self._cache = json.load(f)
        return self._cache

    def get(self, name: str) -> str:
        value = self._load().get(name)
        if value is None:
            raise KeyError(f"Secret '{name}' not found in JSON vault ({self._path})")
        return value

    def exists(self, name: str) -> bool:
        return name in self._load()

    def set(self, name: str, value: str) -> None:
        self._load()[name] = value
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._cache, f, indent=2)


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
    return _get_backend().get(name)


def ensure_secret(name: str, value: Optional[str] = None) -> str:
    """Return an existing secret, or generate and persist a new random one.

    This is used for secrets that must exist for the system to function (e.g.
    the database encryption key). Unlike ``get_secret``, it never raises a
    ``KeyError`` – it self-bootstraps a strong random value on first use.
    """
    if name.startswith("_"):
        raise ValueError(f"Invalid secret name: {name}")
    backend = _get_backend()
    if not backend.exists(name):
        if value is None:
            value = secrets.token_urlsafe(32)
        backend.set(name, value)
    return backend.get(name)

