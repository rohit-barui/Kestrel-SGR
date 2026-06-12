# Autonomous Phishing Control System (APCS)

**APCS** is a deterministic, multi‑plane security control system that detects, analyzes, predicts, and actively neutralises social‑engineering threats (phishing, smishing, vishing) across enterprise environments.

## Features
- **Skill Graph Runtime (SGR)** – DAG executor with schema validation and confidence aggregation.
- **Lightweight Rego policy engine** – Python‑based OPA evaluator.
- **Perception plane** – Email/SMS/voice ingestion, QR‑code scanning, archive‑password extraction, WHOIS caching, typo‑squatting detection.
- **Decision plane** – Weighted risk scoring, veto/override logic, action recommendation.
- **Dominance plane** – Active honey credentials, deception payloads, link rewriting, containment actions.
- **Dashboard** – Glass‑morphic web UI to run preset threat scenarios, visualise the skill graph and view forensics.
- **Transaction saga & gateway** – Automatic rollback of side‑effects on failure.

## Quick Start
```bash
# Clone the repository (already done under Kestrel‑SGR‑repo)
cd "C:/Users/user/Documents/projects/Kestrel SGR/Kestrel-SGR-repo"

# Install dependencies (Python 3.9+)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt  # create this file if needed

# Run the server
python server.py
```
Open a browser at <http://localhost:8080> to access the dashboard.

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Run the SGR graph on a supplied payload (email, SMS, voice transcript). |
| `GET`  | `/api/scenarios` | List preset threat scenarios (CEO fraud, credential harvester, malware drop, clean alert). |
| `GET`  | `/api/policies` | Retrieve current Rego policies. |
| `PUT`  | `/api/policies` | Update Rego policies (JSON body with `policy` field). |

## Documentation
- [Architecture Overview](ARCHITECTURE.md)
- [Repository Structure](REPOSITORY_STRUCTURE.md)
- [Core Package](CORE.md)
- [Skills Package](SKILLS.md)
- [Policy Files](POLICIES.md)
- [Web UI Guide](WEB_UI.md)
- [Usage Walk‑through](USAGE.md)
- [Testing](TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Change Log](CHANGELOG.md)

## License
This project is licensed under the terms of the `LICENSE` file.
