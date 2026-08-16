# Repository Structure

```
Kestrel-SGR/
├── server.py                 # REST API server + static file router
├── config/
│   └── constants.py          # Example URLs and shared constants
├── core/                     # Core runtime components
│   ├── __init__.py
│   ├── auth.py               # Token-based authentication & RBAC
│   ├── cache.py              # Encrypted SQLite cache with TTL
│   ├── db.py                 # Encrypted database connection helper
│   ├── detonation.py         # URL/domain reputation engine (CyberWatch + local heuristics)
│   ├── drift.py              # False-positive/false-negative drift tracking
│   ├── email_parser.py       # RFC 822 email parser
│   ├── engine.py             # SGR DAG executor (SkillGraphRuntime)
│   ├── enricher.py           # External enrichment (DNS, WHOIS, URL analysis)
│   ├── export.py             # CSV and report generation
│   ├── gateway.py            # Saga pattern transaction manager
│   ├── graph.py              # In-memory entity-relationship graph
│   ├── logging.py            # Structured logging setup
│   ├── ml.py                 # Optional ML risk scorer
│   ├── notifications.py      # Slack, webhook, SIEM alert broadcaster
│   ├── policy.py             # Lightweight Rego compiler & evaluator
│   ├── privacy.py            # PII redaction engine
│   ├── reasoning.py          # Multi-model risk aggregation
│   ├── red_team.py           # Synthetic adversarial payload generator
│   ├── remediation.py        # SOAR playbook adapter
│   ├── replay.py             # Encrypted forensic trace store
│   ├── siem_connectors.py    # Splunk / Elastic SIEM integration
│   ├── tasks.py              # Celery async task definitions
│   ├── vault.py              # Secrets manager (JSON file backend)
│   └── webhooks.py           # Inbound webhook handler
├── skills/                   # DAG skill nodes (3 planes)
│   ├── __init__.py
│   ├── perception.py         # Ingestion, URL extraction, QR, WHOIS, DNS, typo, entities
│   ├── decision.py           # Risk scoring, veto, actions, SPF/DKIM validation
│   └── dominance.py          # Honey creds, link rewrite, IP block, quarantine, MFA reset
├── policies/
│   └── remediation.rego      # Rego allow/deny policy rules
├── web/                      # Dashboard frontend
│   ├── index.html            # Entry point (glassmorphism UI)
│   ├── style.css             # Dark-mode glassmorphic styles
│   └── app.js                # Scan submission, SSE, D3 graph, analytics
├── tests/                    # 303 unit tests
│   ├── test_auth.py
│   ├── test_cache.py
│   ├── test_db.py
│   ├── test_decision.py
│   ├── test_detonation.py
│   ├── test_dominance.py
│   ├── test_engine.py
│   ├── test_enricher.py
│   ├── test_export.py
│   ├── test_gateway.py
│   ├── test_graph.py
│   ├── test_integration.py
│   ├── test_logging.py
│   ├── test_ml.py
│   ├── test_notifications.py
│   ├── test_perception.py
│   ├── test_policy.py
│   ├── test_rate_limiter.py
│   ├── test_rbac.py
│   ├── test_replay.py
│   ├── test_vault.py
│   └── test_webhooks.py
├── docs/                     # Documentation
│   ├── README.md
│   ├── ARCHITECTURE.md
│   ├── HLD.md
│   ├── LLD.md
│   ├── DEVELOPMENT_PLAN.md
│   └── CHANGELOG.md
├── docker/                   # Containerization
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── nginx.conf
│   ├── selfsigned.crt
│   ├── selfsigned.key
│   └── load_test.py
├── ci/                       # CI tooling
│   └── check_coverage.py     # Coverage enforcement (>=95% overall, >=99% per-file)
├── scripts/
│   └── generate_cert.py      # Self-signed TLS certificate generator
├── tools/
│   └── start-task.ps1        # Branch creation helper
├── .github/
│   └── pull_request_template.md
├── Kestrel-sgr.ps1           # One-click PowerShell installer
├── requirements.txt
├── Makefile
├── pyproject.toml
└── .gitignore
```