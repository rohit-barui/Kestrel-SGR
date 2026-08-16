# Skills Package (`skills/`)

The skills package implements the three logical planes of the APCS architecture. Each skill is a pure function that receives a context dictionary containing upstream node outputs and returns `{"output": {...}, "confidence": int}`.

## perception.py — Perception Plane

Skills that ingest, parse, and enrich raw payloads:

| Skill | Input | Output | Description |
|-------|-------|--------|-------------|
| `ingest_payload` | Raw payload dict | `{type, content}` | Routes email/SMS/voice/URLs to the correct pipeline |
| `extract_urls` | Ingest output | `{urls, domains}` | Regex-based URL and domain extraction |
| `scan_qr_codes` | Ingest output | `{qr_urls}` | Extracts QR code URLs from `[QR:...]` markers |
| `extract_archive_password` | Ingest output | `{archive_password}` | Extracts embedded passwords via regex |
| `whois_lookup` | Extracted domains | `{whois}` | Cached WHOIS lookups with creation date |
| `enrich_dns` | Extracted domains | `{dns}` | DNS A/AAAA record resolution |
| `detect_typo_squatting` | Extracted domains | `{typo_squatting}` | Levenshtein distance against trusted domains |
| `extract_entities` | Ingest output | `{entities_extracted, emails, domains}` | Identity graph entity extraction |
| `enrich_external` | Extracted URLs/domains | `{dns_real, whois_real, url_analysis}` | Real DNS/WHOIS + suspicion scoring |

## decision.py — Decision Plane

Skills that evaluate risk and recommend actions:

| Skill | Input | Output | Description |
|-------|-------|--------|-------------|
| `aggregate_risk` | All perception outputs | `{risk_score}` | Weighted scoring from 12+ signals |
| `apply_veto` | aggregate_risk + context | `{risk_score, final_confidence}` | Hard overrides on spoof/malicious/ML |
| `recommend_actions` | apply_veto + context | `{actions}` | Action selection with confidence variants |
| `validate_spf_dkim` | Ingest content | `{spf_result, dkim_result, dmarc_result, is_spoofed}` | Email authentication validation |

### Risk Scoring Signals (aggregate_risk)

| Signal | Source | Weight |
|--------|--------|--------|
| URL count | extract_urls | +5 per URL |
| QR code URLs | scan_qr_codes | +10 per QR |
| Archive password | extract_archive_password | +15 |
| Odd WHOIS year | whois_lookup | +5 per domain |
| Typo-squatted domain | detect_typo_squatting | +15 per match |
| Malicious URL (detonation) | detonate_urls | +35 + score/5 per URL |
| Suspicious URL (detonation) | detonate_urls | +20 + score/5 per URL |
| SPF spoofed | validate_spf_dkim | +30 |
| SPF fail | validate_spf_dkim | +15 |
| DKIM fail | validate_spf_dkim | +10 |
| DMARC fail | validate_spf_dkim | +10 |
| ML risk score | ml_score | ml_risk_score / 2 |
| Bulk entities (>5) | extract_entities | +8 |
| Bulk entities (>10) | extract_entities | +15 |
| URL suspicion score | enrich_external | score/4 per URL |

### Veto Overrides (apply_veto)

| Condition | Effect |
|-----------|--------|
| `is_spoofed == True` | risk_score → max(risk, 90), confidence → 95 |
| `malicious_count > 0` | risk_score → max(risk, 85) |
| `ml_risk_score >= 80` | risk_score → max(risk, 80) |

### Action Selection (recommend_actions)

| Condition | Actions |
|-----------|---------|
| Spoofed or malicious detonation | `["block", "alert_admin"]` |
| ML risk >= 80 | `["block"]` |
| risk >= 70 | `["block"]` |
| 30 <= risk < 70, confidence < 60 | `["quarantine", "review"]` |
| 30 <= risk < 70, confidence >= 60 | `["quarantine"]` |
| risk < 30, confidence >= 80 | `["allow"]` |
| risk < 30, confidence < 80 | `["allow", "monitor"]` |

## dominance.py — Dominance Plane

Skills that execute containment and deception actions:

| Skill | Input | Output | Description |
|-------|-------|--------|-------------|
| `deploy_honey_credentials` | Actions + veto | `{honey_credentials}` | Deploys fake credentials to lure attackers |
| `rewrite_links` | Actions + URLs | `{rewritten_urls}` | Rewrites suspicious URLs to pass through a proxy |
| `containment_actions` | Actions + veto | `{blocked_ips, quarantined, mfa_reset}` | IP blocking, email quarantine, MFA reset |
| `block_ip` | Actions | `{blocked_ip}` | Blocks originating IP at the network level |
| `quarantine_email` | Actions | `{quarantined}` | Moves email to quarantine folder |
| `trigger_mfa_reset` | Actions | `{mfa_reset}` | Forces MFA re-authentication for compromised accounts |