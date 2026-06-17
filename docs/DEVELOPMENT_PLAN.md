**Installation** – Run `Kestrel-sgr.ps1` (one‑click) to set up the virtual environment, install dependencies, and start the server.







## Overview
All new work will be performed on a single dedicated development branch.
When a phase (or set of changes) is complete, you will review and approve.
After approval the branch will be merged into `main`, the `CHANGELOG.md` updated,
the development branch deleted, and the process repeats for the next set of work.

## Process Rules
1. **Create a new branch** `feature/apcs-development` (or a suitably‑named feature branch) from `main`.
2. **All coding, documentation, testing, and CI updates** happen **only** on that branch.
3. When you deem a change set complete, you will:
   - Review the changes.
   - Approve or request adjustments.
4. Upon approval:
   - Merge the branch into `main`.
   - Append a concise entry to `CHANGELOG.md` describing the merged work.
   - Delete the development branch.
5. No work may be committed directly to `main` unless explicitly authorized.
6. This `DEVELOPMENT_PLAN.md` file must remain unchanged unless a formal revision of the plan is needed, and any such revision follows the same branch‑review‑merge workflow.

## Phased Roadmap (Base Plan)

| Phase | Goal | Key Deliverables | Approx. Duration |
|-------|------|------------------|------------------|
| **0 – Set‑up** | Workspace, CI stub | Repo ready, virtual‑env, `requirements.txt`, GitHub Actions placeholder | 1 wk |
| **1 – Core Engine** | SGR runtime, saga, policy evaluator | `core/engine.py`, `core/policy.py`, `core/gateway.py` + unit tests | 2 wks |
| **2 – Perception Plane** | Ingestion & enrichment | `skills/perception.py` (URL extraction, QR scan, archive password, WHOIS cache, DNS, typo‑squatting) + tests | 3 wks |
| **3 – Decision Plane** | Risk scoring & veto logic | `skills/decision.py` (aggregate risk, veto, action recommendation, SPF/DKIM validation) + tests | 2 wks |
| **4 – Dominance Plane** | Containment & deception | `skills/dominance.py` (honey creds, link rewrite, IP block, quarantine, MFA reset) + tests | 2 wks |
| **5 – Policy Integration** | Rego rules wired into flow | Load `policies/remediation.rego`, `/api/policies` GET/PUT, tests | 1 wk |
| **6 – Server & REST API** | HTTP interface + SSE | `server.py` (scan, scenarios, policies, events), health‑check, integration tests | 2 wks |
| **7 – Dashboard UI** | Visual cockpit | `web/index.html`, `style.css`, `app.js` (scenario selector, live DAG, metrics, replay) responsive | 3 wks |
| **8 – Red‑Team & Test Suite** | Synthetic threats & CI | `core/red_team.py`, full `tests/` suite, GitHub Actions CI, coverage ≥80 % | 2 wks |
| **9 – Documentation & HLD/LLD** | Final docs, GitHub Pages | Verify all docs, add Mermaid diagrams, optional Pages site | 1 wk |
| **10 – Production Hardening** | Deploy‑ready container | Dockerfile, TLS via reverse‑proxy, persistent replay DB, rate limiting, load test | 3 wks |

### Definition of Done (DoD) for Each Phase
- Code merged into the **development branch**.
- All new/modified code has passing unit tests.
- CI pipeline succeeds (no failures).
- Relevant documentation updated (including `CHANGELOG.md` entry).
- Demoable functionality verified by the reviewer.

### Branch Naming Convention
```
feature/apcs-<phase-number>-<short-description>
```
e.g., `feature/apcs-1-core-engine`.

### Change Log
All merges must add a bullet to `CHANGELOG.md` summarising the change.
The changelog entry is the single source of truth for release notes.

---
*This plan is now stored in the repository and will be the immutable baseline
for every future activity unless a formal revision is performed via the same
branch‑review‑merge workflow described above.*