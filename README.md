# Autonomous Phishing Control System (APCS)

**APCS** is a deterministic, multi‑plane security control system that detects, analyzes, predicts, and actively neutralises social‑engineering threats (phishing, smishing, vishing) across enterprise environments.

---

## Features
- **Skill Graph Runtime (SGR)** – DAG executor with schema validation and confidence aggregation.
- **Lightweight Rego policy engine** – Python‑based OPA evaluator.
- **Perception plane** – Email/SMS/voice ingestion, QR‑code scanning, archive‑password extraction, WHOIS caching, typo‑squatting detection.
- **Decision plane** – Weighted risk scoring, veto/override logic, action recommendation.
- **Dominance plane** – Active honey credentials, deception payloads, link rewriting, containment actions.
- **Dashboard** – Glass‑morphic web UI to run preset threat scenarios, visualise the skill graph and view forensics.
- **Transaction saga & gateway** – Automatic rollback of side‑effects on failure.

---

## Quick Start
```bash
# Clone the repository (already done under Kestrel‑SGR‑repo)
cd "C:/Users/user/Documents/projects/Kestrel SGR/Kestrel-SGR-repo"

# Install dependencies (Python 3.9+)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Run the server
python server.py
```
Open a browser at <http://localhost:8080> to access the dashboard.

---

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Run the SGR graph on a supplied payload (email, SMS, voice transcript). |
| `GET`  | `/api/scenarios` | List preset threat scenarios (CEO fraud, credential harvester, malware drop, clean alert). |
| `GET`  | `/api/policies` | Retrieve current Rego policies. |
| `PUT`  | `/api/policies` | Update Rego policies (JSON body with `policy` field). |

---

## Architecture Overview
APCS is composed of three logical planes that communicate through a **Skill Graph Runtime (SGR)**.  The runtime executes a directed‑acyclic graph (DAG) of **skill** nodes, validates input/output schemas, aggregates confidence scores and finally triggers remediation actions.
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
**Core components** include `engine.py`, `policy.py`, `gateway.py`, `graph.py`, `reasoning.py`, `drift.py`, `replay.py` and `red_team.py`.  They implement DAG execution, schema validation, saga roll‑back, identity graph, reasoning, drift adaptation, forensic replay and red‑team payload generation.

---

## Repository Structure
```
Kestrel‑SGR-repo/
├─ server.py               # REST server + static router
├─ core/                   # Core runtime
│   ├─ __init__.py
│   ├─ engine.py
│   ├─ policy.py
│   ├─ graph.py
│   ├─ gateway.py
│   ├─ reasoning.py
│   ├─ drift.py
│   ├─ replay.py
│   └─ red_team.py
├─ skills/                 # Perception, decision, dominance
│   ├─ __init__.py
│   ├─ perception.py
│   ├─ decision.py
│   └─ dominance.py
├─ policies/               # Rego rules
│   └─ remediation.rego
├─ web/                    # Dashboard UI
│   ├─ index.html
│   ├─ style.css
│   └─ app.js
├─ tests/                  # Unit tests (future)
├─ docs/                   # All documentation files
│   ├─ ARCHITECTURE.md
│   ├─ REPOSITORY_STRUCTURE.md
│   ├─ CORE.md
│   ├─ SKILLS.md
│   ├─ POLICIES.md
│   ├─ WEB_UI.md
│   ├─ USAGE.md
│   ├─ TESTING.md
│   ├─ CONTRIBUTING.md
│   └─ CHANGELOG.md
├─ README.md               # (this file)
├─ LICENSE
└─ requirements.txt        # jsonschema>=4.0.0
```
Each top‑level folder has a single responsibility, making the codebase easy to navigate and extend.

---

## Core Package (`core/`)
- **engine.py** – DAG executor, schema validation, confidence aggregation, error handling.
- **policy.py** – Lightweight Rego compiler & evaluator.
- **gateway.py** – Saga pattern implementation; records side‑effects and rollbacks on failure.
- **graph.py** – In‑memory entity‑relationship graph.
- **reasoning.py** – Multi‑model risk aggregation.
- **drift.py** – Tracks FP/FN feedback for adaptive thresholds.
- **replay.py** – Persists execution traces for forensic replay.
- **red_team.py** – Generates synthetic phishing payloads for robustness testing.

---

## Skills Package (`skills/`)
### perception.py
- `ingest_payload`, `extract_urls`, `scan_qr_codes`, `extract_archive_password`, `whois_lookup`, `enrich_dns`, `detect_typo_squatting`.
### decision.py
- `aggregate_risk`, `apply_veto`, `recommend_actions`, `validate_spf_dkim`.
### dominance.py
- `deploy_honey_credentials`, `rewrite_links`, `block_ip`, `quarantine_email`, `trigger_mfa_reset`.
All skills expose `input_schema` and `output_schema` for automatic validation by the engine.

---

## Policies (`policies/`)
`remediation.rego` contains OPA Rego rules that decide whether to **ALLOW** or **DENY** remediation actions based on risk score, confidence, extracted URLs, detected passwords, etc.  The policy engine compiles this file and evaluates it against the decision payload.

---

## Web UI Guide (`web/`)
- **index.html** – Entry point, loads UI assets.
- **style.css** – Dark‑mode glass‑morphic design.
- **app.js** – Handles scenario selection, triggers scans, receives Server‑Sent Events for live DAG updates, displays metrics and forensic replay.
The UI shows a live graph, metrics panel, action log and replay controls.

---

## Usage Walk‑through (`USAGE.md`)
1. Set up virtual environment and install `requirements.txt`.
2. Run `python server.py`.
3. Open <http://localhost:8080>.
4. Select a scenario (e.g., Credential Harvester) and click **Run**.
5. Observe live graph updates and final decision.
6. Click **Replay** to step through the forensic trace.
7. (Optional) Use `curl` to call the API directly.

---

## Testing (`TESTING.md`)
Run the suite with:
```powershell
python -m unittest discover -s tests
```
Tests cover engine DAG execution, policy evaluation, saga rollback, skill functionality and replay generation.  Add new tests under `tests/` and aim for ≥80 % coverage.

---

## Contributing (`CONTRIBUTING.md`)
- Fork, create a `feature/<desc>` branch, follow PEP‑8, add tests, write clear commit messages, and open a PR against `main`.
- Update documentation for any public API changes.
- CI will run the test suite automatically.

---

## Changelog (`CHANGELOG.md`)
- **[Unreleased]** – Added full documentation suite and `requirements.txt`.
- **0.1.0 – 2026‑06‑12** – Initial scaffold with LICENSE and placeholder README.

---

## License
See the `LICENSE` file for details.
