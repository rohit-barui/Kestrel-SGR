# Policy Files (`policies/`)

## remediation.rego

The Rego policy at `policies/remediation.rego` governs the **ALLOW/DENY** decision for each scan. It uses a lightweight Python-based Rego evaluator (`core/policy.py`) that supports a subset of the OPA Rego language.

### Policy Rules

```rego
package apcs.remediation

default allow = false
```

The default is **DENY** — only explicitly allowed scans pass through.

### Rule 1: Low Risk, Authenticated, Clean

```rego
allow {
    input.risk_score < 30
    not input.is_spoofed
    input.malicious_count == 0
}
```

Allows messages with low risk score, no spoofing detected, and no confirmed malicious URLs.

### Rule 2: Moderate Risk, High Confidence, Clean

```rego
allow {
    input.risk_score < 60
    input.confidence >= 70
    not input.is_spoofed
    input.malicious_count == 0
    input.suspicious_count == 0
    input.archive_password == ""
}
```

Allows moderate-risk messages when the system has high confidence, no authentication or detonation threats, and no archive password.

### Rule 3: Moderate Risk with ML Backing

```rego
allow {
    input.risk_score < 60
    input.ml_risk_score < 40
    input.ml_confidence >= 70
    not input.is_spoofed
    input.malicious_count == 0
    input.spf_result != "fail"
    input.dmarc_result != "fail"
}
```

Allows moderate-risk messages when the ML model independently scores it low, with good ML confidence and valid SPF/DMARC.

### Rule 4: Whitelisted Senders

```rego
allow {
    input.is_whitelisted
    not input.is_spoofed
    input.malicious_count == 0
}
```

Narrow exception for whitelisted senders — still blocks if spoofed or malicious.

### Policy Input Contract

The policy engine receives this context dict:

```python
{
    "risk_score": int,           # 0-100 aggregate risk
    "confidence": int,           # 0-100 pipeline confidence
    "urls": [str],               # extracted URLs
    "archive_password": str,     # extracted password (if any)
    "is_whitelisted": bool,      # sender whitelist status
    "is_spoofed": bool,          # SPF/DKIM spoof detection
    "malicious_count": int,      # URLs confirmed malicious by detonation
    "suspicious_count": int,     # URLs flagged suspicious by detonation
    "ml_risk_score": int,        # ML model risk score (0-100)
    "ml_confidence": int,        # ML model confidence (0-100)
    "typo_squatting": [str],     # detected typo-squatted domains
    "spf_result": str,           # "pass" | "fail" | "neutral"
    "dmarc_result": str,         # "pass" | "fail" | "neutral"
}
```

### Editing Policies

Policies can be updated at runtime via the API:

```bash
# GET current policy
curl -H "Authorization: Bearer <admin-token>" http://localhost:9090/api/policies

# PUT updated policy
curl -X PUT -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"policy": "package apcs.remediation\n\ndefault allow = false\n\nallow {\n    input.risk_score < 50\n}"}' \
  http://localhost:9090/api/policies
```

The server reloads the policy engine automatically after a PUT. Admin role required.