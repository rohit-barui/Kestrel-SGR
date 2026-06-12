from typing import Dict, Any, List

def rollback_noop(params: Dict[str, Any]):
    pass

def deploy_honey_credentials(payload: Dict[str, Any]) -> Dict[str, Any]:
    actions = payload.get("recommend_actions", {}).get("actions", [])
    risk = payload.get("apply_veto", {}).get("risk_score", 0)
    creds = []
    if "block" in actions or "quarantine" in actions:
        creds = [{"user": "honey_adm_" + str(hash(str(risk)))[-4:], "domain": "corp.local"}]
    return {
        "output": {"honey_credentials": creds},
        "confidence": 90 if creds else 10,
        "side_effects": [{"action": "deploy_honey_cred", "params": {"creds": creds}, "rollback": rollback_noop}]
    }

def rewrite_links(payload: Dict[str, Any]) -> Dict[str, Any]:
    urls = payload.get("extract_urls", {}).get("urls", [])
    actions = payload.get("recommend_actions", {}).get("actions", [])
    rewritten = {}
    if "block" in actions or "quarantine" in actions:
        for i, url in enumerate(urls):
            rewritten[url] = f"https://isolate.corp.local/proxy/{i}"
    return {
        "output": {"rewritten_urls": rewritten},
        "confidence": 85 if rewritten else 15,
        "side_effects": [{"action": "rewrite_links", "params": {"rewritten": rewritten}, "rollback": rollback_noop}]
    }

def containment_actions(payload: Dict[str, Any]) -> Dict[str, Any]:
    actions = payload.get("recommend_actions", {}).get("actions", [])
    risk = payload.get("apply_veto", {}).get("risk_score", 0)
    result = {"blocked_ips": [], "quarantined": False, "mfa_reset": False}
    effects = []
    if "block" in actions:
        result["blocked_ips"] = ["10.0.0." + str(int(risk) % 255)]
        effects.append({"action": "block_ip", "params": {"ip": result["blocked_ips"][0]}, "rollback": rollback_noop})
    if "quarantine" in actions or "block" in actions:
        result["quarantined"] = True
        msg_id = f"msg-{abs(hash(str(risk))) % 10000:04d}"
        effects.append({"action": "quarantine_email", "params": {"message_id": msg_id}, "rollback": rollback_noop})
    if "block" in actions and risk > 80:
        result["mfa_reset"] = True
        effects.append({"action": "trigger_mfa_reset", "params": {"user_id": "target_user"}, "rollback": rollback_noop})
    return {
        "output": result,
        "confidence": 95 if effects else 5,
        "side_effects": effects
    }
