"""Perception Plane – ingestion and enrichment utilities

This module provides the basic skill functions that the Skill Graph Runtime (SGR)
will call during the perception phase.  Each function receives a *payload*
dictionary (typically the output of a previous node) and returns a dictionary
with at least two keys:

- ``output`` – the actual result payload that downstream nodes will see.
- ``confidence`` – an integer 0‑100 indicating how confident the skill is about
  its result (optional, defaults to 100 if omitted).

Side‑effects (e.g., network calls) can be recorded as ``side_effects`` entries
for the saga gateway, but the base implementation keeps everything pure.
"""

import re
import json
import hashlib
from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _default_confidence() -> int:
    return 100

# ---------------------------------------------------------------------------
# Skill implementations
# ---------------------------------------------------------------------------

def ingest_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    entry = payload.get("__entry__", payload)
    if "email" in entry:
        return {"output": {"type": "email", "content": entry["email"]}, "confidence": _default_confidence()}
    if "sms" in entry:
        return {"output": {"type": "sms", "content": entry["sms"]}, "confidence": _default_confidence()}
    if "voice" in entry:
        return {"output": {"type": "voice", "content": entry["voice"]}, "confidence": _default_confidence()}
    raise ValueError("Unsupported payload type for ingestion")


def extract_urls(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = payload.get("ingest", {}).get("content", "")
    urls = re.findall(r"https?://[^\s<>\"']+", text)
    domains = list({url.split("/")[2] for url in urls if "/" in url[8:]})
    return {"output": {"urls": urls, "domains": domains}, "confidence": 90 if urls else 30}


def scan_qr_codes(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = payload.get("ingest", {}).get("content", "")
    matches = re.findall(r"\[QR:(https?://[^\]]+)\]", text)
    return {"output": {"qr_urls": matches}, "confidence": 80 if matches else 20}


def extract_archive_password(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = payload.get("ingest", {}).get("content", "")
    m = re.search(r"(?i)password\s*[:=]\s*([\w!@#$%^&*]+)", text)
    pwd = m.group(1) if m else ""
    return {"output": {"archive_password": pwd}, "confidence": 70 if pwd else 10}


def whois_lookup(payload: Dict[str, Any]) -> Dict[str, Any]:
    domain = payload.get("extract_urls", {}).get("domains", [])
    if not domain:
        return {"output": {"whois": {}}, "confidence": 10}
    # Simple cache (module‑level)
    if not hasattr(whois_lookup, "_cache"):
        whois_lookup._cache = {}
    result = {}
    for d in domain:
        if d in whois_lookup._cache:
            result[d] = whois_lookup._cache[d]
        else:
            # Fake WHOIS data – creation date based on hash
            fake_date = f"20{int(hashlib.sha1(d.encode()).hexdigest()[:2], 16) % 30:02d}-01-01"
            data = {"domain": d, "creation_date": fake_date}
            whois_lookup._cache[d] = data
            result[d] = data
    return {"output": {"whois": result}, "confidence": 85}


def enrich_dns(payload: Dict[str, Any]) -> Dict[str, Any]:
    domains = payload.get("extract_urls", {}).get("domains", [])
    dns_info: Dict[str, Any] = {}
    for d in domains:
        dns_info[d] = {"A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]}
    return {"output": {"dns": dns_info}, "confidence": 80}


def detect_typo_squatting(payload: Dict[str, Any]) -> Dict[str, Any]:
    def _lev(a: str, b: str) -> int:
        if len(a) < len(b):
            return _lev(b, a)
        if not b:
            return len(a)
        previous = range(len(b) + 1)
        for i, c1 in enumerate(a):
            current = [i + 1]
            for j, c2 in enumerate(b):
                insertions = previous[j + 1] + 1
                deletions = current[j] + 1
                substitutions = previous[j] + (c1 != c2)
                current.append(min(insertions, deletions, substitutions))
            previous = current
        return previous[-1]

    trusted = ["example.com", "company.com", "mycorp.io"]
    domains = payload.get("extract_urls", {}).get("domains", [])
    suspicious: List[str] = []
    for d in domains:
        for t in trusted:
            if _lev(d, t) <= 2:
                suspicious.append(d)
                break
    return {"output": {"typo_squatting": suspicious}, "confidence": 75 if suspicious else 20}

# End of skills/perception.py
