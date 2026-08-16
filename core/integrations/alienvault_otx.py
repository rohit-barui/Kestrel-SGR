import json
import logging
import os
from urllib.request import Request, urlopen
from typing import Dict, Any, List, Optional

logger = logging.getLogger("apcs")

class AlienVaultOTX:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.api_key = self.config.get("api_key", os.environ.get("OTX_API_KEY", ""))
        self.base = "https://otx.alienvault.com/api/v1"

    def _get(self, path: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        try:
            req = Request(
                f"{self.base}{path}",
                headers={"X-OTX-API-KEY": self.api_key, "Accept": "application/json"},
            )
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.debug("AlienVault OTX error: %s", e)
            return None

    def check_ip(self, ip: str) -> Dict[str, Any]:
        result = self._get(f"/indicators/IPv4/{ip}/general")
        if not result:
            return {"ip": ip, "reputation": "unknown", "score": 0, "pulse_count": 0, "source": "otx"}
        pulse_count = result.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 10, 100)
        return {
            "ip": ip,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "pulse_count": pulse_count,
            "type": result.get("type", ""),
            "source": "otx",
        }

    def check_domain(self, domain: str) -> Dict[str, Any]:
        result = self._get(f"/indicators/domain/{domain}/general")
        if not result:
            return {"domain": domain, "reputation": "unknown", "score": 0, "pulse_count": 0, "source": "otx"}
        pulse_count = result.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 10, 100)
        return {
            "domain": domain,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "pulse_count": pulse_count,
            "whois": result.get("whois", ""),
            "source": "otx",
        }

    def check_url(self, url: str) -> Dict[str, Any]:
        import urllib.parse
        encoded = urllib.parse.quote(url, safe="")
        result = self._get(f"/indicators/url/{encoded}/general")
        if not result:
            return {"url": url, "reputation": "unknown", "score": 0, "pulse_count": 0, "source": "otx"}
        pulse_count = result.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 10, 100)
        return {
            "url": url,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "pulse_count": pulse_count,
            "source": "otx",
        }

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        result = self._get(f"/indicators/file/{file_hash}/general")
        if not result:
            return {"hash": file_hash, "reputation": "unknown", "score": 0, "pulse_count": 0, "source": "otx"}
        pulse_count = result.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 10, 100)
        return {
            "hash": file_hash,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "pulse_count": pulse_count,
            "source": "otx",
        }