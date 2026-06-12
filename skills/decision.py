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
    """Compute a weighted risk score from perception outputs.

    Simple heuristic:
    - Each extracted URL adds 20 points.
    - Presence of a QR‑code URL adds 15 points.
    - Detected archive password adds 10 points.
    - WHOIS creation date < 5 years ago adds 10 points.
    - Typo‑squatting flag adds 25 points.
    The total is capped at 100.
    """
    output = perception_payload.get("output", {})
    score = 0
    # URLs
    if output.get("urls"):
        score += 20 * len(output["urls"])
    # QR URLs
    if output.get("qr_urls"):
        score += 15 * len(output["qr_urls"])
    # Archive password
    if output.get("archive_password"):
        score += 10
    # WHOIS recent creation
    whois = output.get("whois", {})
    for entry in whois.values():
        # fake check – if year ends with an odd digit treat as recent
        if entry.get("creation_date", "")[3] in "13579":
            score += 10
    # Typo squatting
    if output.get("typo_squatting"):
        score += 25 * len(output["typo_squatting"])
    # Cap
    risk_score = min(score, 100)
    return {"output": {"risk_score": risk_score}, "confidence": _default_confidence()}


def apply_veto(decision_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Veto overrides – if any confidence is 100 from a high‑confidence feed,
    force the final confidence to 100 regardless of other scores.
    """
    # In this minimal implementation we just look for a flag
    veto = decision_payload.get("output", {}).get("veto", False)
    confidence = 100 if veto else decision_payload.get("confidence", 0)
    return {"output": {"final_confidence": confidence}, "confidence": confidence}


def recommend_actions(decision_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Map risk score to remediation actions.

    - 0‑30 : ``allow`` (no action).
    - 31‑70 : ``quarantine``.
    - 71‑100 : ``block``.
    Returns ``actions`` list for the Dominance plane to consume.
    """
    risk = decision_payload.get("output", {}).get("risk_score", 0)
    if risk <= 30:
        actions = ["allow"]
    elif risk <= 70:
        actions = ["quarantine"]
    else:
        actions = ["block"]
    return {"output": {"actions": actions}, "confidence": _default_confidence()}

# End of skills/decision.py
