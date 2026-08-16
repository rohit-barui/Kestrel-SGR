import json
import logging
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class CiscoESA:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.host = self.config.get("host", "")
        self.api_key = self.config.get("api_key", "")

    def _request(self, method: str, path: str, data: dict | None = None) -> dict | None:
        if not self.host or not self.api_key:
            logger.warning("Cisco ESA: missing host or api_key")
            return None
        try:
            url = f"{self.host.rstrip('/')}/esa/api/v2.0{path}"
            headers = {
                "Authorization": f"Basic {self.api_key}",
                "Content-Type": "application/json",
            }
            body = json.dumps(data).encode() if data else None
            req = Request(url, data=body, headers=headers, method=method)
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.error("Cisco ESA request failed: %s", e)
            return None

    def mark_as_spam(self, message_id: str) -> bool:
        result = self._request("POST", f"/messages/{message_id}/spam")
        return result is not None

    def mark_as_clean(self, message_id: str) -> bool:
        result = self._request("POST", f"/messages/{message_id}/clean")
        return result is not None

    def update_reputation(self, domain: str, score: int) -> bool:
        result = self._request("POST", "/reputation/update", {
            "domain": domain,
            "score": min(max(score, -10), 10),
        })
        return result is not None

    def get_message_detail(self, message_id: str) -> dict[str, Any]:
        result = self._request("GET", f"/messages/{message_id}/details")
        return result or {"verdict": "unknown", "source": "mock"}

    def block_sender(self, sender: str) -> bool:
        result = self._request("POST", "/senders/block", {"sender": sender, "action": "block"})
        return result is not None
