# Kestrel-SGR — Autonomous Phishing Control System

Welcome to the Kestrel-SGR documentation hub.

## Quick Start

```powershell
.\Kestrel-sgr.ps1
# Opens http://localhost:9090
```

## Documentation

- [Architecture Overview](ARCHITECTURE.md) — System design, HLD, LLD, data flow
- [Repository Structure](REPOSITORY_STRUCTURE.md) — Complete file and directory reference
- [Core Package](CORE.md) — engine.py, policy.py, gateway.py, detonation.py, replay.py, and more
- [Skills Package](SKILLS.md) — All 19 DAG nodes, risk scoring formulas, action selection
- [Policy Files](POLICIES.md) — Rego rules, policy input contract, API management
- [Web UI Guide](WEB_UI.md) — Dashboard features, D3 graph, SSE event flow
- [Usage Walkthrough](USAGE.md) — Complete guide with API examples and troubleshooting
- [Testing](TESTING.md) — 303 test suite, coverage requirements, writing tests
- [Contributing](CONTRIBUTING.md) — Workflow, code style, PR checklist
- [Change Log](CHANGELOG.md) — Version history and release notes
- [Development Plan](DEVELOPMENT_PLAN.md) — Phased roadmap and process rules

## API at a Glance

```bash
# Health check
curl http://localhost:9090/api/health

# Scan an email
curl -X POST http://localhost:9090/api/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "From: spoofed@evil.com\nSubject: Urgent\n\nClick https://phish.xyz"}'

# Detonate URLs
curl -X POST http://localhost:9090/api/detonate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://phish.xyz", "https://company.com"]}'

# Upload file
curl -X POST http://localhost:9090/api/scan/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@suspicious_email.eml"
```

## License

MIT — see `LICENSE` for details.