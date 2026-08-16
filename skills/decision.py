"""Decision Plane – risk scoring and action recommendation

Each function receives the output of the Perception plane (a dict under the key
``output``) and returns a dict containing the computed result and an optional
``confidence`` (0‑100).  The functions are deliberately simple – they can be
replaced by more sophisticated ML/LLM models later without changing the SGR
interface.
"""

from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# JSON Schema constants for input/output validation
# ---------------------------------------------------------------------------

AGGREGATE_RISK_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "extract_urls": {
            "type": "object",
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "domains": {"type": "array", "items": {"type": "string"}}
            }
        },
        "scan_qr_codes": {
            "type": "object",
            "properties": {
                "qr_urls": {"type": "array", "items": {"type": "string"}}
            }
        },
        "extract_archive_password": {
            "type": "object",
            "properties": {
                "archive_password": {"type": "string"}
            }
        },
        "whois_lookup": {
            "type": "object",
            "properties": {
                "whois": {"type": "object"}
            }
        },
        "enrich_dns": {
            "type": "object",
            "properties": {
                "dns": {"type": "object"}
            }
        },
        "detect_typo_squatting": {
            "type": "object",
            "properties": {
                "typo_squatting": {"type": "array", "items": {"type": "string"}}
            }
        }
    }
}

AGGREGATE_RISK_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {
            "type": "object",
            "properties": {
                "risk_score": {"type": "integer"}
            },
            "required": ["risk_score"]
        },
        "confidence": {"type": "integer"}
    },
    "required": ["output"]
}

APPLY_VETO_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "aggregate_risk": {
            "type": "object",
            "properties": {
                "risk_score": {"type": "integer"}
            }
        }
    },
    "required": ["aggregate_risk"]
}

APPLY_VETO_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {
            "type": "object",
            "properties": {
                "risk_score": {"type": "integer"},
                "final_confidence": {"type": "integer"}
            },
            "required": ["risk_score", "final_confidence"]
        },
        "confidence": {"type": "integer"}
    },
    "required": ["output"]
}

RECOMMEND_ACTIONS_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "apply_veto": {
            "type": "object",
            "properties": {
                "risk_score": {"type": "integer"},
                "final_confidence": {"type": "integer"}
            }
        }
    },
    "required": ["apply_veto"]
}

RECOMMEND_ACTIONS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {
            "type": "object",
            "properties": {
                "actions": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["actions"]
        },
        "confidence": {"type": "integer"}
    },
    "required": ["output"]
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _default_confidence() -> int:
    return 100

# ---------------------------------------------------------------------------
# Skill implementations
# ---------------------------------------------------------------------------

def aggregate_risk(perception_payload: Dict[str, Any]) -> Dict[str, Any]:
    urls = perception_payload.get("extract_urls", {}).get("urls", [])
    qr_urls = perception_payload.get("scan_qr_codes", {}).get("qr_urls", [])
    archive_pwd = perception_payload.get("extract_archive_password", {}).get("archive_password", "")
    whois = perception_payload.get("whois_lookup", {}).get("whois", {})
    typo = perception_payload.get("detect_typo_squatting", {}).get("typo_squatting", [])
    detonation = perception_payload.get("detonate_urls", {}).get("detonation", {})
    spf = perception_payload.get("validate_spf_dkim", {})
    ml = perception_payload.get("ml_score", {})
    entities = perception_payload.get("extract_entities", {})
    enrich = perception_payload.get("enrich_external", {})
    ip_rep = perception_payload.get("check_ip_reputation", {})
    file_rep = perception_payload.get("check_file_reputation", {})
    owasp = perception_payload.get("owasp_analysis", {})
    phishing_val = perception_payload.get("phishing_validation", {})
    threat_intel = perception_payload.get("threat_intel_lookup", {})

    score = 0

    # Classic signals
    if urls:
        score += 5 * len(urls)
    if qr_urls:
        score += 10 * len(qr_urls)
    if archive_pwd:
        score += 15
    for entry in whois.values():
        if entry.get("creation_date", "")[3] in "13579":
            score += 5
    if typo:
        score += 15 * len(typo)

    # Detonation-based risk scoring
    det_results = detonation.get("results", [])
    for r in det_results:
        rep = r.get("reputation", "unknown")
        if rep == "malicious":
            score += 35
        elif rep == "suspicious":
            score += 20
        score += r.get("score", 0) // 5

    # SPF/DKIM authentication
    if spf.get("is_spoofed"):
        score += 30
    if spf.get("spf_result") == "fail":
        score += 15
    if spf.get("dkim_result") == "fail":
        score += 10
    if spf.get("dmarc_result") == "fail":
        score += 10

    # ML model score
    ml_risk = ml.get("ml_risk_score", 0)
    if ml_risk:
        score += ml_risk // 2

    # Entity extraction — bulk harvesting signal
    entity_count = entities.get("entities_extracted", 0)
    if entity_count > 10:
        score += 15
    elif entity_count > 5:
        score += 8

    # External URL analysis
    for entry in enrich.get("url_analysis", []):
        score += entry.get("suspicion_score", 0) // 4

    # IP reputation signals
    for domain, ip_info in ip_rep.get("ip_reputation", {}).items():
        if ip_info.get("malicious"):
            score += 25
        for check_name, check_result in ip_info.get("checks", {}).items():
            if check_result.get("reputation") == "suspicious":
                score += 15
                break

    # File reputation signals
    file_rep_data = file_rep.get("file_reputation", {})
    if file_rep_data.get("malicious"):
        score += 35
    if file_rep.get("suspicious_count", 0) > 0:
        score += 20

    # OWASP findings
    owasp_risk = owasp.get("risk_score", 0)
    if owasp_risk:
        score += owasp_risk // 2

    # Phishing validation signals
    phish_signals = phishing_val.get("phishing_signals", {})
    if phish_signals.get("brand_impersonation"):
        score += 30
    if phish_signals.get("missing_ssl"):
        score += 10
    if phish_signals.get("header_mismatch"):
        score += 15

    # Threat intelligence IoC matches
    ioc_count = len(threat_intel.get("threat_intel", []))
    if ioc_count:
        score += 30 * ioc_count

    risk_score = min(score, 100)
    return {"output": {"risk_score": risk_score}, "confidence": _default_confidence()}


def apply_veto(decision_payload: Dict[str, Any]) -> Dict[str, Any]:
    risk = decision_payload.get("aggregate_risk", {}).get("risk_score", 0)
    spf = decision_payload.get("validate_spf_dkim", {})
    detonation = decision_payload.get("detonate_urls", {}).get("detonation", {})
    ml = decision_payload.get("ml_score", {})
    ip_rep = decision_payload.get("check_ip_reputation", {})
    file_rep = decision_payload.get("check_file_reputation", {})
    threat_intel = decision_payload.get("threat_intel_lookup", {})
    phishing_val = decision_payload.get("phishing_validation", {})

    overridden = False

    # Hard veto conditions — these override the risk score entirely
    if spf.get("is_spoofed"):
        risk = max(risk, 90)
        overridden = True
    if detonation.get("malicious_count", 0) > 0:
        risk = max(risk, 85)
        overridden = True
    if ml.get("ml_risk_score", 0) >= 80:
        risk = max(risk, 80)
        overridden = True

    # New veto conditions
    for domain, ip_info in ip_rep.get("ip_reputation", {}).items():
        if ip_info.get("malicious"):
            risk = max(risk, 80)
            overridden = True
            break
    file_rep_data = file_rep.get("file_reputation", {})
    if file_rep_data.get("malicious"):
        risk = max(risk, 85)
        overridden = True
    ioc_count = len(threat_intel.get("threat_intel", []))
    if ioc_count >= 2:
        risk = max(risk, 85)
        overridden = True
    if phishing_val.get("phishing_likely"):
        risk = max(risk, 75)
        overridden = True

    confidence = 95 if overridden else (100 if risk >= 70 else 50)

    return {"output": {"risk_score": risk, "final_confidence": confidence}, "confidence": confidence}


def recommend_actions(decision_payload: Dict[str, Any]) -> Dict[str, Any]:
    risk = decision_payload.get("apply_veto", {}).get("risk_score", 0)
    confidence = decision_payload.get("apply_veto", {}).get("final_confidence", 50)
    spf = decision_payload.get("validate_spf_dkim", {})
    detonation = decision_payload.get("detonate_urls", {}).get("detonation", {})
    ml = decision_payload.get("ml_score", {})

    if spf.get("is_spoofed") or detonation.get("malicious_count", 0) > 0:
        actions = ["block", "alert_admin"]
    elif ml.get("ml_risk_score", 0) >= 80:
        actions = ["block"]
    elif risk >= 70:
        actions = ["block"]
    elif risk >= 30:
        if confidence < 60:
            actions = ["quarantine", "review"]
        else:
            actions = ["quarantine"]
    else:
        if confidence >= 80:
            actions = ["allow"]
        else:
            actions = ["allow", "monitor"]

    return {"output": {"actions": actions}, "confidence": _default_confidence()}

def validate_spf_dkim(payload: Dict[str, Any]) -> Dict[str, Any]:
    content = payload.get("ingest", {}).get("content", "")
    spf_result = "neutral"
    dkim_result = "neutral"
    dmarc_result = "neutral"
    is_spoofed = False
    if "spf=pass" in content:
        spf_result = "pass"
    elif "spf=fail" in content:
        spf_result = "fail"
        is_spoofed = True
    if "dkim=pass" in content:
        dkim_result = "pass"
    if spf_result == "pass" and dkim_result == "pass":
        dmarc_result = "pass"
    elif spf_result == "fail" or dkim_result == "fail":
        dmarc_result = "fail"
    return {
        "output": {
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": dmarc_result,
            "is_spoofed": is_spoofed
        },
        "confidence": _default_confidence()
    }

# End of skills/decision.py
