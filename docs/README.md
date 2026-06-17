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

## Quick Start – One‑Click Install
```powershell
# 1️⃣ Clone the repo (skip if already present)
git clone https://github.com/your-org/Kestrel-SGR.git
cd Kestrel-SGR

# 2️⃣ Run the installer script (creates venv, installs deps, starts server)
.\Kestrel-sgr.ps1
```
The script:
- Creates a virtual environment (`.venv`)
- Installs `requirements.txt`
- Launches `python server.py`
- Opens the dashboard automatically in the default browser (`http://localhost:8080`)

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
