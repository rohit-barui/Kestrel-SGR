"""Detonation module — CyberWatch integration and multi-link analysis.

Provides URL/domain reputation checking via cyberwatch.co.in and
a detonation skill for the SGR graph.
"""

import hashlib
import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("apcs")

CYBERWATCH_API_BASE = "https://cyberwatch.co.in/api"

DETONATION_EXTERNAL_SOURCES = [
    {"name": "CyberWatch", "base": CYBERWATCH_API_BASE},
]


def _fetch_url(url: str, timeout: int = 10) -> dict[str, Any] | None:
    """Fetch a URL and return parsed JSON or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Kestrel-SGR/0.4.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except Exception as e:
        logger.debug("Detonation fetch failed for %s: %s", url, e)
        return None


def check_url_reputation(url: str) -> dict[str, Any]:
    """Check a URL's reputation via CyberWatch and local heuristics.

    Returns a dict with:
      - url: the original URL
      - domain: extracted domain
      - reputation: "safe" | "suspicious" | "malicious"
      - score: 0-100
      - sources: list of sources consulted
      - detonation_links: list of detonation result links
    """
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]

    result: dict[str, Any] = {
        "url": url,
        "domain": domain,
        "reputation": "unknown",
        "score": 0,
        "sources": [],
        "detonation_links": [],
    }

    # Local heuristics
    score = 0
    reasons = []

    if len(domain) > 30:
        score += 15
        reasons.append("unusually long domain")
    if domain.count(".") > 3:
        score += 10
        reasons.append("excessive subdomains")
    suspicious_keywords = r"(secure|login|verify|account|bank|update|reset|confirm|auth|signin|webmail)\d*\."
    if re.search(suspicious_keywords, domain, re.IGNORECASE):
        score += 20
        reasons.append("suspicious keywords in domain")
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("IP-based URL")
    if not url.startswith("https"):
        score += 10
        reasons.append("non-HTTPS URL")
    if re.search(r"(bit\.ly|tinyurl|shorturl|t\.co|ow\.ly|is\.gd|buff\.ly)", url, re.IGNORECASE):
        score += 15
        reasons.append("URL shortener")

    result["score"] = min(score, 100)
    result["reasons"] = reasons
    if score >= 50:
        result["reputation"] = "malicious"
    elif score >= 20:
        result["reputation"] = "suspicious"
    else:
        result["reputation"] = "safe"

    # Try CyberWatch reputation API
    cw_result = _fetch_url(f"{CYBERWATCH_API_BASE}/reputation?url={urllib.parse.quote(url)}")
    if cw_result:
        result["sources"].append("cyberwatch")
        result["detonation_links"].append(f"https://cyberwatch.co.in/scan/{hashlib.sha256(url.encode()).hexdigest()[:16]}")
        ext_score = cw_result.get("score", cw_result.get("risk_score", 0))
        if ext_score:
            result["score"] = min(result["score"] + ext_score // 2, 100)
            result["reputation"] = (
                "malicious" if result["score"] >= 50 else ("suspicious" if result["score"] >= 20 else "safe")
            )

    return result


def detonate_urls(urls: list[str]) -> dict[str, Any]:
    """Detonate multiple URLs: check each URL's reputation.

    Returns:
      - total_urls: count
      - malicious_count: count flagged as malicious
      - suspicious_count: count flagged as suspicious
      - safe_count: count flagged as safe
      - results: list of per-URL reports
      - aggregate_score: 0-100 composite
    """
    if not urls:
        return {
            "total_urls": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
            "results": [],
            "aggregate_score": 0,
        }

    results = [check_url_reputation(url) for url in urls]
    malicious = sum(1 for r in results if r["reputation"] == "malicious")
    suspicious = sum(1 for r in results if r["reputation"] == "suspicious")
    safe = sum(1 for r in results if r["reputation"] == "safe")

    aggregate = 0
    if results:
        aggregate = min(int(sum(r["score"] for r in results) / len(results)), 100)

    return {
        "total_urls": len(urls),
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "results": results,
        "aggregate_score": aggregate,
    }


def detonation_skill(payload: dict[str, Any]) -> dict[str, Any]:
    """SGR skill node: perform URL detonation on extracted URLs.

    Expects payload with key 'extract_urls' containing {'urls': [...]}.
    """
    urls = payload.get("extract_urls", {}).get("urls", [])
    if not urls:
        return {"output": {"detonation": {"total_urls": 0}, "error": "No URLs to detonate"}, "confidence": 10}
    result = detonate_urls(urls)
    confidence = max(10, 100 - result["aggregate_score"])
    return {"output": {"detonation": result}, "confidence": confidence}
