# Kestrel-SGR v0.5 — Working Document

Status: **In Development** · Branch: `v0.5-next` · PR: [#5](https://github.com/rohit-barui/Kestrel-SGR/pull/5) · Milestone: [v0.5 Next Version](https://github.com/rohit-barui/Kestrel-SGR/milestone/1)

## Current State

The v0.5 feature work is implemented on branch `v0.5-next` and opened as PR #5. The branch is rebased on the latest `main` (including the GNU AGPLv3 license update).

### What's Already Done
- 5 new perception skills: `check_ip_reputation`, `check_file_reputation`, `threat_intel_lookup`, `owasp_analysis`, `phishing_validation`
- 5 integration adapters: Defender for Email, Cisco ESA, VirusTotal, AbuseIPDB, AlienVault OTX
- 5 new API endpoints: `/api/report/phishing`, `/api/reputation/ip`, `/api/reputation/file`, `/api/owasp/scan`, `/api/reports`
- Decision engine: 9 new risk signals + new veto conditions
- DAG expanded from 19 → 26 nodes
- Dashboard: Reputation & OWASP tab, Phishing Reports tab, extended Settings
- **303/303 tests passing**, zero regressions

---

## Prioritized Roadmap

### P0 — Merge Readiness (blocking PR #5)

| # | Task | Issue | Status |
|---|------|-------|--------|
| 1 | Unit tests for new v0.5 skills & integration adapters (CI enforces 95/99% coverage) | [#6](https://github.com/rohit-barui/Kestrel-SGR/issues/6) | Open |
| 2 | Update `SKILL_WEIGHTS` in `core/engine.py` for the 5 new nodes | [#7](https://github.com/rohit-barui/Kestrel-SGR/issues/7) | Open |
| 3 | Refactor integration adapters to self-contained vault config (decouple from skills layer) | [#9](https://github.com/rohit-barui/Kestrel-SGR/issues/9) | Open |
| 4 | Add v0.5 architecture ADR / design doc | [#8](https://github.com/rohit-barui/Kestrel-SGR/issues/8) | Open |

### P1 — Core Value Delivery

| # | Task | Issue | Status |
|---|------|-------|--------|
| 5 | Automate phishing report storage & auto-remediation (report DB + report_id + Defender/Cisco dispatch) | [#10](https://github.com/rohit-barui/Kestrel-SGR/issues/10) | Open |
| 6 | Docker/K8s deployment support for new integration credentials | [#12](https://github.com/rohit-barui/Kestrel-SGR/issues/12) | Open |
| 7 | Integration health/readiness status (per-provider config & connectivity probe) | [#13](https://github.com/rohit-barui/Kestrel-SGR/issues/13) | Open |

### P2 — Optimization

| # | Task | Issue | Status |
|---|------|-------|--------|
| 8 | Extend ML feature extractor with v0.5 signals + retrain | [#11](https://github.com/rohit-barui/Kestrel-SGR/issues/11) | Open |

---

## Deployment Priorities

1. **CI green on PR #5** — coverage thresholds met, ruff clean (blocking merge)
2. **Merge v0.5-next → main**, tag `v0.5.0`
3. **Containerize** — new integration env vars in Dockerfile/compose, secrets via vault
4. **Production hardening** — nginx TLS unchanged, verify new tabs served correctly
5. **Operational readiness** — integration health probe, phishing report portal live

## Definition of Done (v0.5)

- [ ] PR #5 merged with all tests + CI green
- [ ] Unit tests for every new skill and adapter (≥99% per-file coverage)
- [ ] Integration adapters self-configure from vault
- [ ] Phishing report flow persists reports and dispatches auto-remediation
- [ ] ML model consumes new reputation/OWASP signals
- [ ] Docker compose + docs for production secrets
- [ ] v0.5.0 tagged and released