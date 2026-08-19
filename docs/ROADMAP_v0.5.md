# Kestrel-SGR v0.5 — Next Version Roadmap

## Overview

Version 0.5 introduces three major capability pillars on top of the existing v0.4 DAG pipeline:

1. **Reputation & Threat Intelligence** — IP reputation, file hash reputation, and multi-source threat intel
2. **OWASP Security Analysis** — Automated scanning for OWASP Top 10 patterns (XSS, SQLi, SSRF, etc.)
3. **Phishing Validation & Customer Reports** — Brand impersonation detection, phishing report submission portal, direct remediation integrations

---

## New Skill Nodes (5 added, 26 total)

| Node | Module | Dependencies | Purpose |
|------|--------|-------------|---------|
| `check_ip_reputation` | `skills/reputation.py` | `extract_urls` | Queries VirusTotal, AbuseIPDB, AlienVault OTX for IP reputation |
| `check_file_reputation` | `skills/reputation.py` | `ingest` | SHA-256 hash lookup against VirusTotal + OTX |
| `threat_intel_lookup` | `skills/reputation.py` | `extract_urls` | URL/domain IoC matching via OTX pulses + VT |
| `owasp_analysis` | `skills/owasp.py` | `extract_urls`, `ingest` | 10 OWASP pattern detectors (XSS, SQLi, SSRF, etc.) |
| `phishing_validation` | `skills/reputation.py` | `ingest`, `validate_spf_dkim`, `extract_urls` | Brand impersonation, SSL checks, header anomaly detection |

## New Integration Adapters (`core/integrations/`)

| Adapter | File | Type | Capabilities |
|---------|------|------|-------------|
| **VirusTotal** | `core/integrations/virustotal.py` | Enrichment | IP, URL, file hash lookups |
| **AbuseIPDB** | `core/integrations/abuseipdb.py` | Enrichment | IP reputation with abuse confidence scoring |
| **AlienVault OTX** | `core/integrations/alienvault_otx.py` | Enrichment | IP, domain, URL, hash via OTX pulses |
| **Defender for Email** | `core/integrations/defender.py` | Remediation | Quarantine email, block sender, get verdict via Microsoft Graph |
| **Cisco ESA** | `core/integrations/cisco_esa.py` | Remediation | Mark spam/clean, update domain reputation, block sender |

## New API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/report/phishing` | POST | Yes | Submit customer phishing report for full analysis + optional auto-remediate |
| `/api/reputation/ip` | POST | Yes | On-demand IP reputation check |
| `/api/reputation/file` | POST | Yes | On-demand file hash reputation check |
| `/api/owasp/scan` | POST | Yes | On-demand OWASP pattern scan for URL/content |
| `/api/reports` | GET | Yes | List phishing report history |

## New Decision Signals

| Signal | Source | Risk Contribution |
|--------|--------|-------------------|
| IP reputation malicious | `check_ip_reputation` | +25 per malicious domain |
| IP reputation suspicious | `check_ip_reputation` | +15 per suspicious domain |
| File reputation malicious | `check_file_reputation` | +35 |
| File reputation suspicious | `check_file_reputation` | +20 |
| OWASP risk score | `owasp_analysis` | score / 2 |
| Brand impersonation | `phishing_validation` | +30 |
| Missing SSL | `phishing_validation` | +10 |
| Header mismatch | `phishing_validation` | +15 |
| Threat intel IoC match | `threat_intel_lookup` | +30 per match |

## New Veto Overrides

| Condition | Effect |
|-----------|--------|
| IP reputation malicious | risk >= 80 |
| File reputation malicious | risk >= 85 |
| 2+ threat intel IoC matches | risk >= 85 |
| Phishing likely (2+ signals) | risk >= 75 |

## Web UI Changes

- New **Reputation & OWASP** tab with IP/file/OWASP lookup tools
- New **Phishing Reports** tab with report submission form + history
- Extended **Settings & Integrations** tab with Defender, Cisco ESA, VT, AbuseIPDB, OTX fields
- **Enrichment Summary** panel on dashboard showing per-scan IP/OWASP/phishing/TI results
- Updated DAG graph with 5 new perception nodes
- Live enrichment logging via SSE events

## Backward Compatibility

All v0.4 API endpoints remain unchanged. Existing replay stores, vault configs, and skill contracts are fully compatible. The new skill nodes are optional — the DAG still functions if integration API keys are not configured (returns "unknown" with score 0).