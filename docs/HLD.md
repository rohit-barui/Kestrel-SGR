# High‑Level Design (HLD)

## Overview
- **Kestrel‑SGR** is a modular Security Governance Runtime that ingests email payloads, enriches them, scores risk, decides action, and optionally escalates to external SIEMs.
- Architecture is split into four **planes**:
  1. **Perception** – ingestion & enrichment (URL extraction, QR scan, WHOIS, DNS, typo‑squatting, archive password).
  2. **Decision** – risk aggregation, veto, SPF/DKIM validation, action recommendation.
  3. **Dominance** – containment (IP block, quarantine, honey‑creds, link rewrite, MFA reset).
  4. **Policy Integration** – Rego policies governing allow/deny decisions.
- A **REST API** (`server.py`) exposes endpoints for scanning, policy retrieval, integration configuration, replay, health, metrics and SSE events.
- **SIEM connectors** (`core/siem_connectors.py`) push high‑risk alerts to Splunk and Elastic.
- **Replay store** (`core/replay.py`) persists encrypted trace data for later audit.
- **Rate limiting** (`RateLimiter`) protects the service from abuse.

## Deployment Model
- Containerised app (Python 3.11) built from the repository.
- Front‑end static assets served by the same container.
- Production deployment adds an **NGINX reverse‑proxy** terminating TLS and forwarding to the Python service.
- Persistent volumes mount `./data` (secrets, replay DB, etc.) into both containers.
- CI runs the full test suite; Docker‑Compose provides a local dev environment.
