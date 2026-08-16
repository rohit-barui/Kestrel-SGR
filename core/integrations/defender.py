import json
import logging
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class DefenderForEmail:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.tenant_id = self.config.get("tenant_id", "")
        self.client_id = self.config.get("client_id", "")
        self.client_secret = self.config.get("client_secret", "")

    def _get_access_token(self) -> str | None:
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            logger.warning("Defender: missing credentials")
            return None
        try:
            payload = json.dumps({
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://api.security.microsoft.com/.default",
                "grant_type": "client_credentials",
            }).encode()
            req = Request(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return data.get("access_token")
        except Exception as e:
            logger.error("Defender token acquisition failed: %s", e)
            return None

    def quarantine_email(self, message_id: str, reason: str = "phishing") -> bool:
        token = self._get_access_token()
        if not token:
            return self._mock("quarantine_email", message_id)
        try:
            payload = json.dumps({
                "MessageId": message_id,
                "Reason": reason,
            }).encode()
            req = Request(
                "https://api.security.microsoft.com/api/quarantine/emails/quarantine",
                data=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Defender quarantine failed: %s", e)
            return self._mock("quarantine_email", message_id)

    def block_sender(self, sender: str) -> bool:
        token = self._get_access_token()
        if not token:
            return self._mock("block_sender", sender)
        try:
            payload = json.dumps({
                "Sender": sender,
                "Action": "Block",
            }).encode()
            req = Request(
                "https://api.security.microsoft.com/api/tenant/blockedsenders",
                data=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Defender block sender failed: %s", e)
            return self._mock("block_sender", sender)

    def get_email_verdict(self, message_id: str) -> dict[str, Any]:
        token = self._get_access_token()
        if not token:
            return {"verdict": "unknown", "source": "mock"}
        try:
            req = Request(
                f"https://api.security.microsoft.com/api/email/messages/{message_id}/verdict",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.error("Defender verdict lookup failed: %s", e)
            return {"verdict": "unknown", "source": "mock"}

    def _mock(self, action: str, target: str) -> bool:
        logger.info("[Defender Mock] %s on %s", action, target)
        return True
