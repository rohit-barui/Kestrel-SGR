"""Simple API token authentication for APCS."""

import hashlib
import os
import json
import secrets
import time
from typing import Optional, Dict, Any

TOKEN_FILE = os.environ.get("APCS_TOKEN_FILE", "apcs_tokens.json")

class AuthManager:
    def __init__(self, token_file: str = TOKEN_FILE):
        self.token_file = token_file
        self._tokens: Dict[str, dict] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.token_file):
            try:
                with open(self.token_file) as f:
                    self._tokens = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._tokens = {}

    def _save(self):
        with open(self.token_file, "w") as f:
            json.dump(self._tokens, f, indent=2)

    def generate_token(self, label: str = "default", role: str = "Analyst") -> str:
        token = secrets.token_hex(32)
        self._tokens[token] = {"label": label, "created_at": time.time(), "role": role}
        self._save()
        return token

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        return self._tokens.get(token)

    def has_role(self, token: str, role: str) -> bool:
        info = self._tokens.get(token)
        if info is None:
            return False
        return info.get("role", "") == role

    def revoke_token(self, token: str) -> bool:
        if token in self._tokens:
            del self._tokens[token]
            self._save()
            return True
        return False

    def list_tokens(self) -> Dict[str, dict]:
        return {k[:8] + "...": v for k, v in self._tokens.items()}

    def has_tokens(self) -> bool:
        return len(self._tokens) > 0

auth_manager = AuthManager()

# Auto-generate a default token if none exist
if not auth_manager.has_tokens():
    token = auth_manager.generate_token("default")
    print(f"[auth] Default API token generated: {token}")
