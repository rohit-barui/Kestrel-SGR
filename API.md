# API Reference

Base URL: `http://localhost:9090`

Authentication: Bearer token via `Authorization: Bearer <token>` header, or `?token=<token>` query parameter. Tokens carry a role (`Analyst` default, `Admin`) used for role-protected endpoints.

## Scan & Analysis

### POST /api/scan
Run the SGR pipeline on an email/SMS/voice/URL payload.

```json
{ "email": "From: spoofed@evil.com\n\nClick https://phish.xyz" }
```
Response: `{ "scan_id", "risk_score", "confidence", "decision", "actions", "graph_output" }`

### POST /api/scan/upload
Upload `.eml`/`.txt`/`.msg`/`.html` files (`multipart/form-data`) for full pipeline analysis.

### POST /api/detonate
Batch URL/domain reputation analysis.

```json
{ "urls": ["https://phish.xyz", "https://company.com"] }
```

### POST /api/reputation/ip
On-demand IP reputation check (VirusTotal, AbuseIPDB, AlienVault OTX).

```json
{ "ips": ["8.8.8.8"] }
```

### POST /api/reputation/file
On-demand SHA-256 file-hash reputation check.

```json
{ "hashes": ["<sha256>"] }
```

### POST /api/owasp/scan
On-demand OWASP Top 10 pattern scan.

```json
{ "url": "https://example.com/?q=<script>alert(1)</script>" }
```

### POST /api/check-pii
Redact PII from a payload before external processing.

```json
{ "text": "Contact support@example.com on 555-123-4567" }
```

## Phishing Reports

### POST /api/report/phishing
Submit a customer phishing report for full analysis. Set `"auto_remediate": true` to run containment actions automatically.

```json
{ "email": "...", "reporter": "customer@corp.com", "auto_remediate": true }
```

### GET /api/reports
List phishing report history.

## Webhooks

### POST /api/webhook
External event receiver (e.g. SIEM alert, phishing report, customer report). Event type defaults to `phishing_report` unless `event`/`type` is provided. Signatures verified with `X-APCS-Signature` (HMAC-SHA256) when `APCS_WEBHOOK_SECRET` is configured.

## Policies & Config

### GET /api/policies
Retrieve current Rego policy. **Admin role required.**

### PUT /api/policies
Update Rego policy (hot-reload). **Admin role required.**

```json
{ "policy": "package main\n..." }
```

### GET /api/integrations
View vault-stored integration config. **Admin role required.**

### PUT /api/integrations
Save integration secrets (VirusTotal, AbuseIPDB, OTX, Defender, Cisco ESA). **Admin role required.**

## Replay & Analytics

### GET /api/replay
List scan IDs with stored traces.

### GET /api/replay/<scan_id>
Get full forensic trace for a scan.

### GET /api/stats
Aggregate scan statistics.

### GET /api/trend
Risk trend data.

### GET /api/analytics/quality
Submit false-positive/quality feedback.

## Auth

### POST /api/auth/login
Validate a token.

```json
{ "token": "<token>" }
```

### POST /api/auth/token/generate
Generate a new API token. **Admin role required.**

```json
{ "label": "ci-admin" }
```

### GET /api/auth/tokens
List token metadata (truncated).

## Actions & Export

### POST /api/action
Execute a SOAR playbook action (block, quarantine, MFA reset).

### GET /api/export/csv
Download CSV export of scan history.

### GET /api/export/report
Download summary report.

## Observability

### GET /api/health
Liveness probe — version, uptime, scans processed.

### GET /api/metrics
Prometheus-compatible counters.

### GET /api/scenarios
List preset threat scenarios.

### GET /events
Server-Sent Events stream for live graph updates.

### GET /api/red-team
Generate synthetic adversarial payloads.