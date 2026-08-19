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
- [Core Package](CORE.md) — engine.py, policy.py, gateway.py, detonation.py, replay.py, integrations, and more
- [Skills Package](SKILLS.md) — All 26 DAG nodes, risk scoring formulas, action selection
- [Policy Files](POLICIES.md) — Rego rules, policy input contract, API management
- [Web UI Guide](WEB_UI.md) — Dashboard features, D3 graph, SSE event flow
- [Usage Walkthrough](USAGE.md) — Complete guide with API examples and troubleshooting
- [Testing](TESTING.md) — 506 test suite, coverage requirements, writing tests
- [Contributing](CONTRIBUTING.md) — Workflow, code style, PR checklist
- [Change Log](CHANGELOG.md) — Version history and release notes
- [v0.5 Roadmap](ROADMAP_v0.5.md) — Next-version capability plan
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

# Check IP reputation
curl -X POST http://localhost:9090/api/reputation/ip \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ips": ["8.8.8.8"]}'

# OWASP scan
curl -X POST http://localhost:9090/api/owasp/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://phish.xyz/?q=<script>alert(1)</script>"}'

# Submit a phishing report
curl -X POST http://localhost:9090/api/report/phishing \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "suspicious message body...", "auto_remediate": true}'

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

GNU Affero General Public License v3.0 — see `LICENSE` for details.