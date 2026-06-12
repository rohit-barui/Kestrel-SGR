from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# JSON Schema constants for input/output validation
# ---------------------------------------------------------------------------

DEPLOY_HONEY_CREDENTIALS_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "recommend_actions": {
            "type": "object",
            "properties": {
                "actions": {"type": "array", "items": {"type": "string"}}
            }
        },
        "apply_veto": {
            "type": "object",
            "properties": {
                "risk_score": {"type": "integer"},
                "final_confidence": {"type": "integer"}
            }
        }
    },
    "required": ["recommend_actions", "apply_veto"]
}

DEPLOY_HONEY_CREDENTIALS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {
            "type": "object",
            "properties": {
                "honey_credentials": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "user": {"type": "string"},
                            "domain": {"type": "string"}
                        }
                    }
                }
            },
            "required": ["honey_credentials"]
        },
        "confidence": {"type": "integer"}
    },
    "required": ["output"]
}

REWRITE_LINKS_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "recommend_actions": {
            "type": "object",
            "properties": {
                "actions": {"type": "array", "items": {"type": "string"}}
            }
        },
        "extract_urls": {
            "type": "object",
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "domains": {"type": "array", "items": {"type": "string"}}
            }
        }
    },
    "required": ["recommend_actions", "extract_urls"]
}

REWRITE_LINKS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {
            "type": "object",
            "properties": {
                "rewritten_urls": {"type": "object"}
            },
            "required": ["rewritten_urls"]
        },
        "confidence": {"type": "integer"}
    },
    "required": ["output"]
}

CONTAINMENT_ACTIONS_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "recommend_actions": {
            "type": "object",
            "properties": {
                "actions": {"type": "array", "items": {"type": "string"}}
            }
        },
        "apply_veto": {
            "type": "object",
            "properties": {
                "risk_score": {"type": "integer"},
                "final_confidence": {"type": "integer"}
            }
        }
    },
    "required": ["recommend_actions", "apply_veto"]
}

CONTAINMENT_ACTIONS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {
            "type": "object",
            "properties": {
                "blocked_ips": {"type": "array", "items": {"type": "string"}},
                "quarantined": {"type": "boolean"},
                "mfa_reset": {"type": "boolean"}
            },
            "required": ["blocked_ips", "quarantined", "mfa_reset"]
        },
        "confidence": {"type": "integer"}
    },
    "required": ["output"]
}

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

def block_ip(payload: Dict[str, Any]) -> Dict[str, Any]:
    ip_address = "10.0.0.1"
    return {
        "output": {"blocked_ip": ip_address, "blocked": True},
        "confidence": 90,
        "side_effects": [{"action": "block_ip", "params": {"ip": ip_address}, "rollback": rollback_noop}]
    }

def quarantine_email(payload: Dict[str, Any]) -> Dict[str, Any]:
    message_id = "msg-0001"
    return {
        "output": {"message_id": message_id, "quarantined": True},
        "confidence": 90,
        "side_effects": [{"action": "quarantine_email", "params": {"message_id": message_id}, "rollback": rollback_noop}]
    }

def trigger_mfa_reset(payload: Dict[str, Any]) -> Dict[str, Any]:
    user_id = "target_user"
    return {
        "output": {"user_id": user_id, "mfa_reset": True},
        "confidence": 90,
        "side_effects": [{"action": "trigger_mfa_reset", "params": {"user_id": user_id}, "rollback": rollback_noop}]
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
