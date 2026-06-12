# Repository Structure

The project follows a clean, top‑level layout that mirrors the three‑plane architecture described in the implementation plan.

```
Kestrel‑SGR-repo/
├─ server.py               # Pure Python REST server + static file router
├─ core/                   # Core runtime and supporting utilities
│   ├─ __init__.py
│   ├─ engine.py           # Skill Graph Runtime (DAG executor, schema validation)
│   ├─ policy.py           # Lightweight Rego compiler & evaluator
│   ├─ graph.py            # Identity graph (entities & relationships)
│   ├─ gateway.py          # Saga pattern, rollback, audit logging
│   ├─ reasoning.py        # Multi‑model reasoning & consensus
│   ├─ drift.py            # Feedback‑driven adaptation tracker
│   ├─ replay.py           # Forensics & replay storage
│   └─ red_team.py         # Synthetic adversary generators
├─ skills/                 # Perception, decision & dominance planes
│   ├─ __init__.py
│   ├─ perception.py       # Ingestion, QR‑code scanner, archive‑password extractor, WHOIS cache
│   ├─ decision.py         # Risk scoring, veto overrides, action recommendation
│   └─ dominance.py        # Honey credentials, deception, containment, link rewriting
├─ policies/               # OPA Rego policies
│   └─ remediation.rego   # Quarantine, delete, session revocation rules
├─ web/                    # Dashboard UI (static assets)
│   ├─ index.html
│   ├─ style.css
│   └─ app.js
├─ tests/                  # Unit‑ and integration‑tests (future work)
├─ docs/                   # All generated documentation files
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
├─ README.md               # Project overview and quick‑start guide
├─ LICENSE                 # License file (present)
└─ requirements.txt        # Python dependencies (to be created)
```

Each top‑level folder has a single responsibility, making it easy to locate code, add new features, and write focused documentation.
