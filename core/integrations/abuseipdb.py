import json
import logging
import os
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class AbuseIPDB:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.api_key = self.config.get("api_key", os.environ.get("ABUSEIPDB_API_KEY", ""))
        self.base = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip: str, max_age: int = 90) -> dict[str, Any]:
        if not self.api_key:
            return {"ip": ip, "reputation": "unknown", "score": 0, "source": "abuseipdb"}
        try:
            url = f"{self.base}/check?ipAddress={ip}&maxAgeInDays={max_age}&verbose"
            req = Request(url, headers={
                "Key": self.api_key,
                "Accept": "application/json",
            })
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                attrs = data.get("data", {})
                abuse_score = attrs.get("abuseConfidenceScore", 0)
                return {
                    "ip": ip,
                    "reputation": "malicious" if abuse_score >= 50 else ("suspicious" if abuse_score >= 20 else "safe"),
                    "score": abuse_score,
                    "total_reports": attrs.get("totalReports", 0),
                    "last_reported_at": attrs.get("lastReportedAt", ""),
                    "country": attrs.get("countryCode", ""),
                    "isp": attrs.get("isp", ""),
                    "domain": attrs.get("domain", ""),
                    "usage_type": attrs.get("usageType", ""),
                    "source": "abuseipdb",
                }
        except Exception as e:
            logger.debug("AbuseIPDB error: %s", e)
            return {"ip": ip, "reputation": "unknown", "score": 0, "source": "abuseipdb"}
