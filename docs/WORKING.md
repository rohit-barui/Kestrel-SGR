# Kestrel-SGR v0.5 — Working Document

Status: **Merged & Released** · Branch: `main` · PR: [#5](https://github.com/rohit-barui/Kestrel-SGR/pull/5) (merged) · Tag: `v0.5.0`

## Current State

The v0.5 feature work has been **merged into `main`** via PR #5. All CI checks (lint, tests on Python 3.11/3.12, coverage, Docker) are green, and the container image is published to `ghcr.io/rohit-barui/kestrel-sgr`.

### What Was Delivered
- 5 new perception skills: `check_ip_reputation`, `check_file_reputation`, `threat_intel_lookup`, `owasp_analysis`, `phishing_validation`
- 5 integration adapters: Defender for Email, Cisco ESA, VirusTotal, AbuseIPDB, AlienVault OTX
- 5 new API endpoints: `/api/report/phishing`, `/api/reputation/ip`, `/api/reputation/file`, `/api/owasp/scan`, `/api/reports`
- Decision engine: 9 new risk signals + new veto conditions
- DAG expanded from 19 → 26 nodes
- Dashboard: Reputation & OWASP tab, Phishing Reports tab, extended Settings
- **506 tests passing**, overall coverage 97.34%, ≥99% per-file for `core/*` and `skills/*`

---

## Post-Release Roadmap

| # | Task | Status |
|---|------|--------|
| 1 | Extend ML feature extractor with v0.5 signals + retrain | Open |
| 2 | Integration health/readiness status (per-provider config & connectivity probe) | Open |
| 3 | Automate phishing report storage & auto-remediation (report DB + report_id + Defender/Cisco dispatch) | Open |
| 4 | Docker/K8s deployment support for new integration credentials | Open |

---

## Deployment Priorities

1. ~~CI green on PR #5~~ — done, merged
2. ~~Merge v0.5-next → main~~ — done, tag `v0.5.0`
3. ~~Containerize~~ — done, image pushed to GHCR
4. Production hardening — nginx TLS unchanged, verify new tabs served correctly
5. Operational readiness — integration health probe, phishing report portal live

## Definition of Done (v0.5)

- [x] PR #5 merged with all tests + CI green
- [x] Unit tests for every new skill and adapter (≥99% per-file coverage)
- [x] Integration adapters self-configure from vault
- [ ] Phishing report flow persists reports and dispatches auto-remediation
- [ ] ML model consumes new reputation/OWASP signals
- [x] Docker compose + docs for production secrets
- [x] v0.5.0 tagged and released