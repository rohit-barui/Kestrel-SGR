# Usage Walkthrough

This guide covers the complete workflow from installation to advanced usage.

## Quick Start

```powershell
# One-click install
.\Kestrel-sgr.ps1

# Or manually:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

Open `http://localhost:9090` in your browser. Enter the default Analyst token when prompted:
```
fe12751c01c2ad2a4f99004855697e18c173cfe54fdf57436b29f2a2923946b5
```

## Basic Usage

### 1. Run a Preset Scenario

1. Select a scenario from the dropdown (e.g., "Credential Harvester")
2. Review the payload preview
3. Click **Execute Scan**
4. Watch the graph update in real-time as skills complete
5. View the risk score, decision (ALLOW/DENY), and recommended actions

### 2. Scan Custom Email Text

1. Paste email headers and body into the **Custom Investigation** textarea
2. Click **Run Custom Scan**
3. If PII is detected, review the warning and choose to proceed or abort
4. View results in the right panel

### 3. Investigate URLs / Domains

1. Enter URLs or domains in the **URL / Domain Investigation** field (comma-separated)
2. Click **Detonate URLs / Domains**
3. View per-URL reputation results: malicious (red), suspicious (amber), safe (green)
4. Click the CyberWatch link to view detailed analysis

### 4. Upload a File

1. Click the file upload area and select an `.eml`, `.txt`, `.msg`, or `.html` file
2. Click **Upload & Scan**
3. The file content is extracted and passed through the full SGR pipeline

## Advanced Usage

### Forensics & Analytics

1. Navigate to the **Forensics & Analytics** tab
2. View global telemetry (total scans, avg risk, allow/block rates)
3. Click **Load Latest Trace** to replay a completed scan step-by-step
4. Use **Prev** / **Next** to navigate skill outputs
5. Click **Mark as False Positive** to provide quality feedback

### Policy Management (Admin)

```bash
# View current policy
curl -H "Authorization: Bearer <admin-token>" http://localhost:9090/api/policies

# Update policy
curl -X PUT -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"policy": "package apcs.remediation\n\ndefault allow = false\n\nallow {\n    input.risk_score < 40\n}"}' \
  http://localhost:9090/api/policies
```

### API Usage

```bash
# Direct scan via API
curl -X POST http://localhost:9090/api/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "From: spoofed@evil.com\nSubject: Urgent\n\nClick https://phish.xyz"}'

# URL detonation
curl -X POST http://localhost:9090/api/detonate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://phish.xyz", "https://company.com"]}'

# IP reputation (v0.5)
curl -X POST http://localhost:9090/api/reputation/ip \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ips": ["8.8.8.8"]}'

# File hash reputation (v0.5)
curl -X POST http://localhost:9090/api/reputation/file \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"hashes": ["<sha256>"]}'

# OWASP scan (v0.5)
curl -X POST http://localhost:9090/api/owasp/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://phish.xyz/?q=<script>alert(1)</script>"}'

# Submit a phishing report (v0.5)
curl -X POST http://localhost:9090/api/report/phishing \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "suspicious message body...", "auto_remediate": true}'

# List phishing reports (v0.5)
curl -H "Authorization: Bearer <token>" \
  http://localhost:9090/api/reports

# File upload
curl -X POST http://localhost:9090/api/scan/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@suspicious_email.eml"

# Health check
curl http://localhost:9090/api/health
```

### Webhooks (v0.5)

```bash
# Send an external phishing report event to trigger a scan
curl -X POST http://localhost:9090/api/webhook \
  -H "Content-Type: application/json" \
  -H "X-APCS-Signature: <hmac-sha256 hex of body>" \
  -d '{"event": "phishing_report", "email": "report@phish.xyz\n\nClick https://evil.com"}'
```

### Integration Configuration (Admin, v0.5)

```bash
# Store threat-intel / email-security API keys
curl -X PUT http://localhost:9090/api/integrations \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"config": {"virustotal": {"api_key": "..."}, "abuseipdb": {"api_key": "..."}, "defender": {"client_id": "...", "client_secret": "..."}}}'
```

## Token Management (Admin)

```bash
# Generate new Analyst token
curl -X POST http://localhost:9090/api/auth/token/generate \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"label": "soc-analyst-1"}'

# List all tokens
curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:9090/api/auth/tokens
```

## Troubleshooting

- **Server won't start** — check port 9090 is free: `netstat -ano | findstr :9090`
- **401 Unauthorized** — verify the token exists in `apcs_tokens.json` and is correctly passed in the `Authorization` header
- **Scan returns error** — check `server.log` for detailed error messages
- **Dashboard not updating** — ensure SSE connections aren't blocked (no proxy stripping `text/event-stream`)
- **Fernet InvalidToken** — clear `data/replay.db` and `data/secrets.json`, then restart
- **File upload fails** — ensure files are UTF-8 encoded text; binary files are not supported