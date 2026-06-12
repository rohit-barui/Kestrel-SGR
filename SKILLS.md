# Skills Package Documentation

The `skills/` package contains the three planes of APCS logic.  Each skill is a pure function that receives a JSON payload, performs its operation, and returns a dict with `output` and optional `confidence` (0‑100).

## perception.py
- **ingest_payload(payload)** – Normalises raw email/SMS/voice data into a common schema.
- **extract_urls(text)** – Regex based URL finder.
- **scan_qr_codes(attachments)** – Simulates QR‑code detection using regex patterns; returns any URLs embedded in images (Quishing protection).
- **extract_archive_password(text)** – Looks for patterns like `password:\s*\d+` and returns the extracted password for later decryption attempts.
- **whois_lookup(domain)** – Performs cached WHOIS lookup; falls back to certificate transparency timestamps when port‑43 rate‑limits are hit.
- **enrich_dns(domain)** – Resolves A/AAAA records and gathers authoritative nameserver info.
- **detect_typo_squatting(domain, brand_list)** – Levenshtein distance based check against known corporate domains.

## decision.py
- **aggregate_risk(perception_outputs)** – Calculates a weighted risk score from the various perception signals.
- **apply_veto(overrides, base_score)** – If any high‑confidence feed (e.g., 100 % blocklist match) is present, force the final confidence to 100.
- **recommend_actions(risk_score, policy_decision)** – Maps the final confidence to remediation commands (quarantine, block IP, deploy honey cred, etc.).
- **validate_spf_dkim(headers)** – Cross‑checks SPF/DKIM results against the claimed sender identity.

## dominance.py
- **deploy_honey_credentials(target_user)** – Provisions a monitored AD account with zero privileges; logs usage.
- **rewrite_links(email_body, proxy_url)** – Replaces malicious URLs with a safe isolation proxy while preserving display text.
- **block_ip(ip_address)** – Adds the IP to a temporary blocklist (simulated firewall).
- **quarantine_email(message_id)** – Moves the email to a quarantine store and notifies the SOC.
- **trigger_mfa_reset(user_id)** – Forces an MFA reset for the compromised account.

All skills register their **input_schema** and **output_schema** at module import time so that `engine.py` can validate them automatically.

### Example Skill Definition
```python
# skills/perception.py
from core.schema import JsonSchema

INPUT_SCHEMA = JsonSchema({"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]})
OUTPUT_SCHEMA = JsonSchema({"type": "object", "properties": {"urls": {"type": "array", "items": {"type": "string"}}}, "required": ["urls"]})

def extract_urls(payload: dict) -> dict:
    text = payload["text"]
    urls = re.findall(r"https?://[^\s]+", text)
    return {"output": {"urls": urls}, "confidence": 80}
```

The engine will automatically validate the payload against `INPUT_SCHEMA` before invoking the function.
