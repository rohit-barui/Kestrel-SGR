# Low‑Level Design (LLD)

## Core Components
- **engine.py** – builds a skill graph (`SkillNode`) and runs it (`SkillGraphRuntime`).
- **gateway.py** – thin wrapper around external services (SMTP, webhook, etc.).
- **policy.py** – loads Rego policy (`policies/remediation.rego`) via `opa-python` and evaluates context dicts.
- **notifications.py** – `Notifier` pushes alerts to Slack, webhook, or SIEM based on risk score.
- **siem_connectors.py** – `SplunkConnector` (`/services/collector`) and `ElasticConnector` (`/_bulk`).
- **replay.py** – encrypted SQLite store with background purge thread. Uses `cryptography.Fernet` derived from `db_encryption_key` secret.
- **auth.py** – JWT‑style token manager with role‑based access control.
- **rate_limiter.py** – in‑memory token‑bucket per client IP.

## API Endpoints (`APIHandler`)
| Path | Method | Auth | Role | Description |
|------|--------|------|------|-------------|
| `/api/scan` | POST | Yes | – | Execute full SGR pipeline.
| `/api/policies` | GET/PUT | Yes | Admin | Retrieve or update Rego policy file.
| `/api/integrations` | GET/PUT | Yes | Admin | View or replace vault JSON secrets.
| `/api/replay/<id>` | GET | Yes | – | Get encrypted trace of a scan.
| `/api/replay` | GET | Yes | – | List all replay IDs.
| `/api/stats` | GET | Yes | – | Summarise replay store metrics.
| `/api/trend` | GET | Yes | – | Recent risk trend.
| `/api/red-team` | GET | Yes | – | Generate synthetic threat payloads.
| `/api/health` | GET | No | – | Liveness probe.
| `/api/metrics` | GET | No | – | Prometheus‑compatible counters.
| `/events` | GET (SSE) | No | – | Server‑Sent Events for UI updates.

## Persistence
- **Secrets Vault** – JSON file at `data/secrets.json`. Accessed via `core/vault.py`. Missing keys fall back to a deterministic test value (`test_dummy_key`).
- **Replay DB** – Encrypted SQLite (`data/replay.db`) using the secret `db_encryption_key`.
- **Whois Cache** – Encrypted SQLite (`data/whois_cache.db`).

## Production Hardening Details
- **Docker Image** – `python:3.11-slim` with OpenSSL installed, runs on port `9090`.
- **NGINX** – Terminates TLS using `docker/selfsigned.crt`/`.key`, proxies to `app:9090`.
- **Volumes** – `./data:/app/data` ensures persistence of vault, replay DB, and caches.
- **Rate Limiting** – Configured at 1000 requests/min per IP (already in code).
- **Load‑Test Script** – `docker/load_test.py` fires concurrent scan requests (default 100) and reports latency.

## Future Extensions
- Replace self‑signed cert with real cert via secret manager.
- Add Prometheus exporter for custom metrics.
- Horizontal scaling behind NGINX load‑balancer.
