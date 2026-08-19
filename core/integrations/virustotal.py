import hashlib
import json
import logging
import os
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class VirusTotal:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.api_key = self.config.get("api_key", os.environ.get("VT_API_KEY", ""))
        self.base = "https://www.virustotal.com/api/v3"

    def _get(self, path: str) -> dict | None:
        if not self.api_key:
            return None
        try:
            req = Request(
                f"{self.base}{path}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
            )
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.debug("VirusTotal API error: %s", e)
            return None

    def check_ip(self, ip: str) -> dict[str, Any]:
        result = self._get(f"/ip_addresses/{ip}")
        if not result:
            return {"ip": ip, "reputation": "unknown", "score": 0, "source": "vt"}
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        score = int((malicious + suspicious) / total * 100) if total else 0
        return {
            "ip": ip,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": stats.get("harmless", 0),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", 0),
            "source": "vt",
        }

    def check_url(self, url: str) -> dict[str, Any]:
        url_id = hashlib.sha256(url.encode()).hexdigest()
        result = self._get(f"/urls/{url_id}")
        if not result:
            return {"url": url, "reputation": "unknown", "score": 0, "source": "vt"}
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        score = int((malicious + suspicious) / total * 100) if total else 0
        return {
            "url": url,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": stats.get("harmless", 0),
            "source": "vt",
        }

    def check_file_hash(self, file_hash: str) -> dict[str, Any]:
        result = self._get(f"/files/{file_hash}")
        if not result:
            return {"hash": file_hash, "reputation": "unknown", "score": 0, "source": "vt"}
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        score = int((malicious + suspicious) / total * 100) if total else 0
        return {
            "hash": file_hash,
            "reputation": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "safe"),
            "score": score,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": stats.get("harmless", 0),
            "type": attrs.get("type_description", ""),
            "names": attrs.get("names", []),
            "source": "vt",
        }
