"""Decision Plane – risk scoring and action recommendation

Each function receives the output of the Perception plane (a dict under the key
``output``) and returns a dict containing the computed result and an optional
``confidence`` (0‑100).  The functions are deliberately simple – they can be
replaced by more sophisticated ML/LLM models later without changing the SGR
interface.
"""

from typing import Dict, Any, List

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

# End of skills/decision.py
