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
    score = 0
    if urls:
        score += 20 * len(urls)
    if qr_urls:
        score += 15 * len(qr_urls)
    if archive_pwd:
        score += 10
    for entry in whois.values():
        if entry.get("creation_date", "")[3] in "13579":
            score += 10
    if typo:
        score += 25 * len(typo)
    risk_score = min(score, 100)
    return {"output": {"risk_score": risk_score}, "confidence": _default_confidence()}


def apply_veto(decision_payload: Dict[str, Any]) -> Dict[str, Any]:
    risk = decision_payload.get("aggregate_risk", {}).get("risk_score", 0)
    confidence = 100 if risk >= 70 else 50
    return {"output": {"risk_score": risk, "final_confidence": confidence}, "confidence": confidence}


def recommend_actions(decision_payload: Dict[str, Any]) -> Dict[str, Any]:
    risk = decision_payload.get("apply_veto", {}).get("risk_score", 0)
    if risk <= 30:
        actions = ["allow"]
    elif risk <= 70:
        actions = ["quarantine"]
    else:
        actions = ["block"]
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
