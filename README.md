# Kestrel-SGR (APCS) — Autonomous Phishing Control System

**APCS** is a deterministic, multi‑plane security control system that detects, analyzes, predicts, and actively neutralises social‑engineering threats (phishing, smishing, vishing) across enterprise environments.

Built on a **Skill Graph Runtime (SGR)** — a Directed Acyclic Graph (DAG) executor that chains perception, decision, and dominance skills with schema validation, confidence aggregation, and saga-based rollback.

<p align="center">
  <a href="https://youtu.be/wF07MUFRXrQ">
    <img src="https://img.youtube.com/vi/wF07MUFRXrQ/0.jpg" alt="Kestrel-SGR Demo" width="600" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.5);">
  </a>
  <br>
  <em>Watch the Kestrel-SGR demo on YouTube</em>
</p>

---

## Features

- **Skill Graph Runtime** — DAG executor with JSON schema validation and confidence aggregation
- **URL Detonation Engine** — Multi-link reputation analysis via CyberWatch API + local heuristics (malicious/suspicious/safe classification)
- **File Upload Scanning** — Upload `.eml`, `.txt`, `.msg`, `.html` files for automatic pipeline analysis
- **Multi-Signal Risk Scoring** — 15+ signals including URL detonation, SPF/DKIM/DMARC spoof flags, ML risk score, entity extraction, and URL suspicion analysis
- **Veto Overrides** — Hard deny on spoofed emails, malicious detonations, or high ML risk
- **Lightweight Rego Policy Engine** — Python-based OPA evaluator with runtime policy updates
- **ML Scorer** — Optional scikit-learn based risk estimation (displayed as ML Confidence)
- **Real-Time Dashboard** — Glassmorphic UI with D3.js DAG visualization, SSE live updates, replay, and analytics
- **Forensic Replay** — Encrypted trace store with step-by-step skill replay
- **SOAR Playbooks** — Action buttons to execute remediation (block, quarantine, MFA reset)
- **PII Redaction** — Automatic detection and redaction of PII before external processing
- **RBAC** — Token-based auth with Analyst and Admin roles
- **Transaction Saga** — Automatic rollback of side-effects on failure
- **303 passing tests** — 100% line coverage across all core and skills modules

---

## Quick Start

```bash
# Install from PyPI
pip install kestrel-sgr
kestrel-sgr

# Or with Docker (after Docker Desktop is running):
# docker run -p 9090:9090 rohitbarui/kestrel-sgr

# Or one-click install (creates venv, installs deps, starts server):
.\Kestrel-sgr.ps1
```

Open **http://localhost:9090** and enter the default Analyst token:
```
fe12751c01c2ad2a4f99004855697e18c173cfe54fdf57436b29f2a2923946b5
```

---

## Architecture

```
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│   Perception Plane  │   │   Decision Plane    │   │   Dominance Plane   │
│  (Ingestion, parse, │   │ (Risk scoring,      │   │ (Deception,         │
│   enrichment)       │   │  policy evaluation) │   │  containment)       │
└───────┬─────────────┘   └───────┬─────────────┘   └───────┬─────────────┘
        │                         │                         │
        └───────► SGR ◄───────────┘                         │
                     │                                 │
                     ▼                                 ▼
               ┌─────────────────┐               ┌─────────────────┐
               │   Core Package  │               │   Web Dashboard │
               │ (engine, policy,│               │ (HTML/JS/CSS)   │
               │  gateway, etc) │               └─────────────────┘
               └─────────────────┘
```

### Planes

1. **Perception** — Ingests raw payloads, extracts URLs/QR codes/passwords, enriches with WHOIS/DNS, detects typo-squatting, extracts entities, checks URL reputation via CyberWatch
2. **Decision** — Aggregates risk from all signals, applies veto overrides, recommends actions, validates SPF/DKIM/DMARC
3. **Dominance** — Deploys honey credentials, rewrites links, blocks IPs, quarantines emails, triggers MFA resets

### DAG Flow (19 Nodes)

```
ingest → extract_urls → whois_lookup, enrich_dns, detect_typo_squatting, 
                         extract_entities, enrich_external, detonate_urls, 
                         validate_spf_dkim, scan_qr_codes, 
                         extract_archive_password
      → ml_score → aggregate_risk → apply_veto → recommend_actions
      → deploy_honey_credentials, rewrite_links, containment_actions, 
        block_ip, quarantine_email, trigger_mfa_reset
```

---

## API Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| `POST` | `/api/scan` | Yes | Any | Run SGR pipeline on email/SMS/voice/URL payload |
| `POST` | `/api/scan/upload` | Yes | Any | Upload `.eml`/`.txt`/`.msg`/`.html` for scanning |
| `POST` | `/api/detonate` | Yes | Any | Batch URL/domain reputation analysis |
| `GET` | `/api/scenarios` | Yes | Any | List preset threat scenarios |
| `GET` | `/api/health` | No | — | Liveness probe (version, uptime) |
| `GET` | `/api/stats` | Yes | Any | Aggregate scan statistics |
| `GET` | `/api/trend` | Yes | Any | Risk trend data |
| `GET` | `/api/replay/<id>` | Yes | Any | Forensic trace by scan ID |
| `GET` | `/api/metrics` | No | — | Prometheus-compatible counters |
| `GET` | `/api/policies` | Yes | Admin | Retrieve Rego policy |
| `PUT` | `/api/policies` | Yes | Admin | Update Rego policy (hot-reload) |
| `GET` | `/api/integrations` | Yes | Admin | View vault config |
| `PUT` | `/api/integrations` | Yes | Admin | Save integration secrets |
| `POST` | `/api/auth/login` | No | — | Validate token |
| `POST` | `/api/auth/token/generate` | Yes | Admin | Generate new API token |
| `POST` | `/api/action` | Yes | Any | Execute SOAR playbook action |
| `POST` | `/api/analytics/quality` | Yes | Any | Submit false positive feedback |
| `GET` | `/events` | No | — | Server-Sent Events stream |
| `GET` | `/api/export/csv` | Yes | Any | Download CSV export |
| `GET` | `/api/export/report` | Yes | Any | Download summary report |

---

## Repository Structure

```
Kestrel-SGR/
├── server.py                 # REST API + static router
├── core/                     # Core runtime (engine, policy, gateway, detonation, etc.)
├── skills/                   # DAG skill nodes (perception, decision, dominance)
├── policies/                 # Rego policy files
├── web/                      # Dashboard frontend (HTML/JS/CSS)
├── tests/                    # 303 unit tests
├── docs/                     # Documentation
├── docker/                   # Docker + nginx config
├── Kestrel-sgr.ps1           # One-click installer
└── requirements.txt
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | HLD, LLD, data flow, core components |
| [Core Package](docs/CORE.md) | Detailed module documentation |
| [Skills Package](docs/SKILLS.md) | All 19 DAG nodes and risk scoring formulas |
| [Policy Files](docs/POLICIES.md) | Rego rules and policy management |
| [Web UI Guide](docs/WEB_UI.md) | Dashboard features and development |
| [Usage Guide](docs/USAGE.md) | Complete walkthrough with API examples |
| [Testing Guide](docs/TESTING.md) | Test suite, coverage requirements |
| [Contributing](docs/CONTRIBUTING.md) | Workflow, code style, PR checklist |
| [Change Log](CHANGELOG.md) | Version history |

---

## License

MIT License — see `LICENSE` for details.

## Owner

**Rohit Barui** — [GitHub](https://github.com/rohit-barui)