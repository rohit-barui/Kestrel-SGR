import logging
import hashlib
import re
from typing import Dict, Any, List

logger = logging.getLogger("apcs")

from core.integrations import VirusTotal, AbuseIPDB, AlienVaultOTX
from core.vault import get_secret

def _load_integration_config(provider: str) -> dict:
    try:
        secrets = get_secret(f"{provider}_config")
        if isinstance(secrets, dict):
            return secrets
    except Exception:
        pass
    return {}

def check_ip_reputation(payload: Dict[str, Any]) -> Dict[str, Any]:
    domains = payload.get("extract_urls", {}).get("domains", [])
    urls = payload.get("extract_urls", {}).get("urls", [])

    vt = VirusTotal(_load_integration_config("virustotal"))
    abuse = AbuseIPDB(_load_integration_config("abuseipdb"))
    otx = AlienVaultOTX(_load_integration_config("otx"))

    results = {}
    for domain in domains:
        try:
            import socket
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = "0.0.0.0"
        ip_result = {"ip": ip, "domain": domain, "checks": {}}
        for name, check in [("vt", vt.check_ip), ("abuseipdb", abuse.check_ip), ("otx", otx.check_ip)]:
            try:
                ip_result["checks"][name] = check(ip)
            except Exception as e:
                logger.debug("IP check %s failed: %s", name, e)
        ip_result["aggregate_score"] = sum(
            c.get("score", 0) for c in ip_result["checks"].values()
        ) // max(len(ip_result["checks"]), 1)
        ip_result["malicious"] = any(
            c.get("reputation") == "malicious" for c in ip_result["checks"].values()
        )
        results[domain] = ip_result

    return {"output": {"ip_reputation": results}, "confidence": 85 if results else 20}


def check_file_reputation(payload: Dict[str, Any]) -> Dict[str, Any]:
    content = payload.get("ingest", {}).get("content", "")
    results = {}

    if content:
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        vt = VirusTotal(_load_integration_config("virustotal"))
        otx = AlienVaultOTX(_load_integration_config("otx"))
        checks = {}
        try:
            checks["vt"] = vt.check_file_hash(file_hash)
        except Exception as e:
            logger.debug("File rep check vt failed: %s", e)
        try:
            checks["otx"] = otx.check_hash(file_hash)
        except Exception as e:
            logger.debug("File rep check otx failed: %s", e)

        aggregate_score = sum(
            c.get("score", 0) for c in checks.values()
        ) // max(len(checks), 1)

        is_malicious = any(c.get("reputation") == "malicious" for c in checks.values())

        results = {
            "sha256": file_hash,
            "aggregate_score": aggregate_score,
            "malicious": is_malicious,
            "checks": checks,
        }

    malicious_count = 1 if results.get("malicious") else 0
    suspicious_count = sum(
        1 for c in results.get("checks", {}).values()
        if c.get("reputation") == "suspicious"
    )
    safe_count = sum(
        1 for c in results.get("checks", {}).values()
        if c.get("reputation") == "safe"
    )

    return {
        "output": {
            "file_reputation": results,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
        },
        "confidence": 75 if results else 15,
    }


def threat_intel_lookup(payload: Dict[str, Any]) -> Dict[str, Any]:
    urls = payload.get("extract_urls", {}).get("urls", [])
    domains = payload.get("extract_urls", {}).get("domains", [])

    vt = VirusTotal(_load_integration_config("virustotal"))
    otx = AlienVaultOTX(_load_integration_config("otx"))

    iocs = []
    for url in urls:
        for check in [vt.check_url, otx.check_url]:
            try:
                result = check(url)
                if result.get("reputation") in ("malicious", "suspicious"):
                    iocs.append({"type": "url", "value": url, "result": result})
            except Exception as e:
                logger.debug("TI lookup for url %s failed: %s", url, e)

    for domain in domains:
        try:
            result = otx.check_domain(domain)
            if result.get("reputation") in ("malicious", "suspicious"):
                iocs.append({"type": "domain", "value": domain, "result": result})
        except Exception as e:
            logger.debug("TI lookup for domain %s failed: %s", domain, e)

    return {
        "output": {"threat_intel": iocs},
        "confidence": 80 if iocs else 30,
    }


def phishing_validation(payload: Dict[str, Any]) -> Dict[str, Any]:
    content = payload.get("ingest", {}).get("content", "")
    urls = payload.get("extract_urls", {}).get("urls", [])
    domains = payload.get("extract_urls", {}).get("domains", [])
    spf = payload.get("validate_spf_dkim", {})

    signals = {
        "domain_age_risk": False,
        "missing_ssl": False,
        "brand_impersonation": False,
        "header_mismatch": False,
        "young_domain_suspicious": [],
        "impersonated_brands": [],
    }

    trusted_brands = [
        "microsoft", "google", "apple", "amazon", "paypal",
        "netflix", "facebook", "twitter", "linkedin", "adobe",
        "dropbox", "salesforce", "wells fargo", "chase", "bank of america",
        "citi", "american express", "mastercard", "visa",
    ]

    for url in urls:
        domain = url.split("/")[2] if "//" in url else url
        for brand in trusted_brands:
            brand_normalized = brand.replace(" ", "").lower()
            domain_normalized = domain.lower().replace("-", "").replace(".", "")
            if brand_normalized in domain_normalized and brand_normalized not in domain.lower():
                signals["brand_impersonation"] = True
                signals["impersonated_brands"].append(brand)
            elif brand_normalized in domain.lower() and brand not in domain.lower().replace("www.", "").split(".")[0]:
                signals["brand_impersonation"] = True
                signals["impersonated_brands"].append(brand)

        if not url.startswith("https"):
            signals["missing_ssl"] = True

    if spf.get("is_spoofed"):
        signals["header_mismatch"] = True

    risk_contributors = []
    if signals["brand_impersonation"]:
        risk_contributors.append("brand_impersonation")
    if signals["missing_ssl"]:
        risk_contributors.append("missing_ssl")
    if signals["header_mismatch"]:
        risk_contributors.append("header_mismatch")

    return {
        "output": {
            "phishing_signals": signals,
            "risk_contributors": risk_contributors,
            "phishing_likely": len(risk_contributors) >= 2,
        },
        "confidence": 80 if risk_contributors else 40,
    }