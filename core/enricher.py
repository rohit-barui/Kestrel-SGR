"""External enrichment services with mock fallback.

Each function tries a real external lookup first; if it fails (no network,
timeout, rate-limited) it falls back to the mock implementation.
"""

import socket
import time
import json
from typing import Dict, Any, List, Optional

def resolve_dns(domain: str) -> Dict[str, Any]:
    """Real DNS resolution with fallback."""
    try:
        addrs = socket.getaddrinfo(domain, 80, socket.AF_INET)
        ips = list(set(a[4][0] for a in addrs))
        return {"A": ips, "status": "real"}
    except Exception:
        return {"A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"], "status": "mock"}

def whois_lookup_real(domain: str) -> Dict[str, Any]:
    """Real WHOIS lookup via whois python lib (mock fallback if unavailable)."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            "domain": domain,
            "creation_date": str(w.creation_date) if w.creation_date else "",
            "registrar": str(w.registrar) if w.registrar else "",
            "status": "real",
        }
    except Exception:
        import hashlib
        fake_date = f"20{int(hashlib.sha1(domain.encode()).hexdigest()[:2], 16) % 30:02d}-01-01"
        return {"domain": domain, "creation_date": fake_date, "registrar": "MockRegistrar", "status": "mock"}

def analyze_suspicious_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """Analyze URLs for suspicious characteristics."""
    import re
    results = []
    for url in urls:
        score = 0
        reasons = []
        domain = re.sub(r"https?://", "", url).split("/")[0]
        if len(domain) > 30:
            score += 20
            reasons.append("unusually long domain")
        if domain.count(".") > 3:
            score += 15
            reasons.append("excessive subdomains")
        if re.search(r"(secure|login|verify|account|bank|update)\d*\.", domain):
            score += 25
            reasons.append("suspicious keywords in domain")
        results.append({"url": url, "domain": domain, "suspicion_score": min(score, 100), "reasons": reasons})
    return results
