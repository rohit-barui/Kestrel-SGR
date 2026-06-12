# Architecture Overview

APCS is composed of three logical planes that communicate through a **Skill Graph Runtime (SGR)**.  The runtime executes a directed‑acyclic graph (DAG) of **skill** nodes, validates input/output schemas, aggregates confidence scores and finally triggers remediation actions.

```
┌─────────────────────┐   ┌─────────────────────┐   �┌─────────────────────┐
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

## Core Components
- **engine.py** – Executes the DAG, enforces schemas, aggregates confidence, and propagates state.
- **policy.py** – Lightweight Rego compiler/interpreter; evaluates `.rego` files against the decision payload.
- **gateway.py** – Implements the saga pattern. Every side‑effect (IP block, quarantine, credential provisioning) is logged; on abort the actions are rolled back in reverse order.
- **graph.py** – Identity graph holding entities (users, devices, IPs) and relationships.
- **reasoning.py** – Multi‑model consensus (heuristic + LLM) to boost decision accuracy.
- **drift.py** – Tracks false‑positive/false‑negative feedback for model adaptation.
- **replay.py** – Stores execution traces for forensics and replay.
- **red_team.py** – Generates synthetic adversarial payloads for robustness testing.

## Data Flow
1. **Ingestion** – `perception.py` reads raw payloads, extracts URLs, QR codes, passwords, WHOIS data, etc.
2. **Enrichment** – External lookups (DNS, WHOIS, certificate transparency) are cached to avoid rate limits.
3. **Decision** – `decision.py` builds a risk vector, applies veto overrides, and calls `policy.py` for OPA‑based remediation rules.
4. **Remediation** – `dominance.py` performs containment actions (honey‑cred deployment, link rewriting, session lockout).
5. **Audit & Rollback** – All side‑effects are recorded in the gateway; if any step fails, the saga rolls back.

## High‑Level Design (HLD)
- **Modular** – Each plane lives in its own Python package under `skills/` and communicates only via typed JSON contracts.
- **Extensible** – New skills can be added without touching the core runtime; the engine discovers them via entry‑points.
- **Fault‑tolerant** – Gateway ensures state consistency even when external services (WHOIS, DNS) fail.
- **Observability** – `replay.py` stores a full execution log; the dashboard visualises it in real time.

## Low‑Level Design (LLD)
- **Skill schema** – Defined as a JSON‑Schema object (`input_schema`, `output_schema`). The engine validates each node before execution.
- **Confidence aggregation** – Weighted average of skill confidences; veto overrides set final confidence to 100.
- **Saga log format** – JSON array `[ {"action":"block_ip","params":{...}}, … ]`. Rollback functions are registered per action.
- **Cache layer** – Simple on‑disk SQLite DB used by `perception.py` for WHOIS and DNS results with TTL.
- **Policy engine** – Parses `.rego` files into an AST; each rule compiles to a Python lambda for fast evaluation.
- **Dashboard socket** – Server pushes execution events over Server‑Sent Events (SSE) to `app.js` for live graph updates.

---

For deeper details see the individual module docs (`CORE.md`, `SKILLS.md`).