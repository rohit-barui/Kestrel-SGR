# Web UI Guide (`web/`)

The Kestrel-SGR dashboard is a single-page application built with vanilla HTML, CSS, and JavaScript. It uses D3.js for graph visualization and Server-Sent Events (SSE) for real-time updates.

## Pages / Tabs

### Dashboard Tab

The main scan interface with three panels:

**Left Panel — Ingestion Controls:**
- **Scenario Selector** — dropdown of pre-built threat scenarios (CEO fraud, credential harvester, malware drop, clean alert). Selecting a scenario populates the payload preview.
- **Execute Scan** — runs the selected scenario through the full SGR pipeline.
- **URL / Domain Investigation** — paste URLs or domains (comma-separated) and click "Detonate URLs / Domains" for instant reputation analysis.
- **File Upload** — upload `.eml`, `.txt`, `.msg`, or `.html` files for automatic scanning.
- **Custom Investigation** — paste email headers/body directly and click "Run Custom Scan".

**Center Panel — Skill Graph:**
- Real-time D3.js force-directed graph showing all 26 DAG nodes across the three planes (Perception, Decision, Dominance).
- Nodes change color as skills complete (cyan = done, rose = error).
- Edges animate with a dash flow effect on activation.
- Zoom and pan support.

**Right Panel — Results:**
- **Risk Score** — color-coded (green/amber/rose) numeric score.
- **Policy Decision** — ALLOW (green) or DENY (rose).
- **ML Confidence** — ML model's confidence percentage.
- **SOAR Playbooks** — action buttons (block, quarantine, etc.) that execute remediation.
- **Detonation Results** — per-URL reputation with malicious/suspicious/safe counts and CyberWatch links.
- **Enrichment Summary** — per-scan IP/file reputation, OWASP findings, phishing signals, and threat-intel IoC matches.
- **Execution Log** — timestamped event feed with skill completion, errors, and dominance actions.

### Reputation & OWASP Tab (v0.5)

- **IP Reputation** — submit IP addresses for instant VirusTotal/AbuseIPDB/OTX lookup via `POST /api/reputation/ip`.
- **File Reputation** — submit SHA-256 hashes for file-hash reputation via `POST /api/reputation/file`.
- **OWASP Scan** — submit a URL or content snippet for OWASP Top 10 pattern analysis via `POST /api/owasp/scan`.

### Phishing Reports Tab (v0.5)

- **Report Submission** — form to submit a customer phishing report (email content) with optional auto-remediation via `POST /api/report/phishing`.
- **Report History** — table of past submissions fetched from `GET /api/reports`.

### Forensics & Analytics Tab

- **Global Telemetry** — total scans, average risk, allow/block rates.
- **Risk Trend Chart** — SVG bar chart showing risk scores over recent scans.
- **Export Controls** — download CSV or summary report.
- **Trace Replay** — step through a completed scan's skill-by-skill execution with input/output details.
- **Quality Control** — "Mark as False Positive" feedback button.
- **Recent Critical Alerts** — list of high-risk scan results.

### Settings & Integrations Tab

- **SIEM Connectors** — configure Splunk HEC, Azure Sentinel, Google SecOps API keys.
- **SOAR & Alerting** — admin notification DL, Slack webhook URL, action webhook endpoint.
- **Threat Intel Providers (v0.5)** — VirusTotal, AbuseIPDB, AlienVault OTX API keys.
- **Email Security Integrations (v0.5)** — Microsoft Defender for Email and Cisco ESA credentials.
- All secrets are persisted to the encrypted vault. Admin role required.

## Architecture

- **`index.html`** — single entry point with all markup, modals (login, PII warning), and tab structure.
- **`style.css`** — dark-mode glassmorphic design with neon accents, responsive grid layout, custom scrollbars.
- **`app.js`** — ~1,000 lines handling: auth, scenario loading, scan submission, SSE event handling, D3 graph rendering, detonation results, file upload, IP/file reputation, OWASP scan, phishing reports, replay, analytics, and tab switching.

## Key JavaScript Objects

- **`GRAPH_NODES`** — array of 26 node definitions with id, plane, label, and dependency list. Used by the D3 force simulation to render the graph.
- **`state`** — reactive state object holding scenarios, selected scenario, scan ID, node status, and edge active states.
- **`PLANE_COLORS`** — color scheme for perception (blue), decision (amber), and dominance (rose).

## Event Flow

1. User submits a scan → `POST /api/scan` or `POST /api/scan/upload`
2. Server broadcasts `scan_start` → dashboard logs scan ID
3. As each skill completes, server sends `skill_done` → dashboard updates graph node color and log
4. On completion, server sends `run_complete` → dashboard displays risk score, decision, confidence, actions, dominance data, and detonation results
5. On error, server sends `run_error` → dashboard logs error and shows error state

## Development

The UI requires no build step — it's served directly as static files by the Python server. D3.js is loaded from CDN.

```bash
# Start server
python server.py

# Open in browser
open http://localhost:9090
```