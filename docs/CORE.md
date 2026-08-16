# Core Package (`core/`)

## engine.py
**Skill Graph Runtime** — the heart of the system. Builds a DAG of `SkillNode` instances, validates input/output against JSON schemas, executes nodes in topological order, aggregates confidence scores across all nodes, and collects final graph output.

Key classes:
- `SkillNode(name, func, deps, input_schema, output_schema)` — a single DAG node
- `SkillGraphRuntime(nodes, gateway)` — executor with topological sort, parallel dispatch, error propagation, and saga rollback

## policy.py
**Lightweight Rego Compiler & Evaluator** — tokenizes, parses, and evaluates a subset of the OPA Rego language. Supports:
- Comparisons: `==`, `!=`, `>`, `>=`, `<`, `<=`
- Logical operators: `&&` (and), `||` (or), `not`
- Parenthesized expressions
- `input.field` access with arbitrary nesting
- Multiple `allow { ... }` rules (OR'd together)
- Multi-line rule bodies (lines AND'd together)
- Comment lines (`//`)

## gateway.py
**Saga Pattern Implementation** — records every side-effect performed by skills (IP blocks, quarantine actions, credential deployment) and provides automatic rollback in reverse order if any node fails. Key methods:
- `record(action, params, rollback_fn)` — log a side-effect
- `commit()` — clear the log on success
- `rollback()` — undo all side-effects in reverse order on failure

## detonation.py
**URL/domain reputation engine** — checks URLs against local heuristics (length, subdomains, keywords, IP-based, shorteners, HTTPS) and the CyberWatch API (`https://cyberwatch.co.in/api`). Returns per-URL reputation (malicious/suspicious/safe), confidence scores, and detonation result links.

Key functions:
- `check_url_reputation(url)` — single URL analysis
- `detonate_urls(urls)` — batch analysis with aggregate stats
- `detonation_skill(payload)` — SGR skill node wrapper

## replay.py
**Encrypted Forensic Trace Store** — persists every scan's execution trace to an encrypted SQLite database using `cryptography.fernet.Fernet`. Key features:
- `store()` — encrypt and persist `(scan_id, trace_data, decision, risk_score, confidence, actions)`
- `get(scan_id)` — retrieve and decrypt a full trace with event list
- `list_ids()` — return all stored scan IDs
- `stats()` — aggregate statistics (total scans, avg risk, allow/deny counts)
- `risk_trend()` — recent scans for dashboard charts
- Background purge thread removes entries older than 7 days

## auth.py
**Token-Based Authentication & RBAC** — manages API tokens with role assignment (Analyst, Admin). Stores tokens in a JSON file. Key methods:
- `generate_token(label, role)` — create a new token with optional role
- `validate_token(token)` — verify token validity
- `has_role(token, role)` — check role permissions
- `has_tokens()` — check if any tokens are configured
- `list_tokens()` — return all token metadata (without secrets)

## vault.py
**Secrets Manager** — strategy-pattern implementation with JSON file backend. Designed to be swappable for Azure Key Vault, HashiCorp Vault, or AWS Secrets Manager. Key functions:
- `ensure_secret(name)` — get or create a secret
- `get_secret(name)` — retrieve an existing secret
- `set_secret(name, value)` — store a secret

## enricher.py
**External Enrichment** — real DNS resolution (`socket.getaddrinfo`), WHOIS lookup (`whois` library), and URL suspicion analysis with mock fallback when external services are unavailable.

## ml.py
**Optional ML Scorer** — scikit-learn based risk estimation using extracted features (entity count, URL length, typo detection flag, archive password flag). Provides `ml_risk_score` and `ml_confidence` outputs consumed by the decision plane.

## drift.py
**Drift Tracker** — monitors false-positive/false-negative rates for policy rules. Tracks TP/FP/TN/FN counts and provides `should_adjust()` to signal when adaptive thresholds may be needed.

## privacy.py
**PII Redaction** — detects and redacts personally identifiable information (emails, phone numbers, SSNs, credit card numbers) from scan payloads before external processing.

## remediation.py
**SOAR Adapter** — vendor-agnostic playbook execution framework. The `get_active_adapter()` function returns the configured adapter for executing remediation actions.

## graph.py
**Identity Graph** — in-memory entity-relationship graph that tracks entities (email addresses, domains, IPs) and their relationships across scans. Used by `extract_entities` in perception.

## notifications.py
**Alert Broadcaster** — pushes alerts to Slack webhooks, SIEM connectors, and admin distribution lists based on risk score thresholds. Configurable via `notify_config.json`.

## webhooks.py
**Inbound Webhook Handler** — processes incoming webhook events (phishing reports, threat intel feeds) and converts them into scan payloads for the SGR pipeline. Supports HMAC signature verification.

## cache.py
**Encrypted Cache** — SQLite-backed key-value store with TTL support. Used by perception skills (WHOIS, DNS) to avoid redundant lookups.

## db.py
**Database Helper** — centralized `get_encrypted_conn()` function that creates SQLite connections with encryption pragmas. Used by replay store and cache.

## export.py
**Data Export** — generates CSV exports of scan traces and summary reports for SOC analysts.

## logging.py
**Structured Logging** — configures Python logging with optional JSON output for integration with log aggregation platforms (Splunk, ELK).

## reasoning.py
**Risk Reasoning** — multi-model aggregation framework (currently heuristic + ML) that combines signals from all perception skills into a unified risk assessment.

## red_team.py
**Red Team Generator** — produces synthetic phishing, smishing, and vishing payloads for testing and validation of the detection pipeline.

## tasks.py
**Celery Task Definitions** — async task wrappers for running individual SGR skills via Celery workers, enabling distributed execution.