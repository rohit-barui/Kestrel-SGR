# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-06-12
- Fixed engine topological sort (breadth-first)
- Added schema validation with jsonschema
- Added INPUT_SCHEMA/OUTPUT_SCHEMA for all skills
- Implemented weighted confidence aggregation
- Rewrote Rego parser with AST-based evaluation
- Added standalone block_ip, quarantine_email, trigger_mfa_reset
- Added validate_spf_dkim decision function
- Wired reasoning, drift, graph modules into runtime
- Added real-time SSE node coloring in dashboard
- Added forensic replay UI to dashboard
- Replaced vanilla SVG with D3.js interactive graph
- Created GitHub Actions CI pipeline
- Added server integration tests
- Created API.md documentation

## [Unreleased]
- Added comprehensive documentation suite (ARCHITECTURE, REPOSITORY_STRUCTURE, CORE, SKILLS, POLICIES, WEB_UI, USAGE, TESTING, CONTRIBUTING, CHANGELOG).
- Introduced `requirements.txt` with `jsonschema` dependency.
- Created `feature/docs` branch for documentation work.

## [0.1.0] - 2026-06-12
- Initial repository scaffold with placeholder `LICENSE` and `README.md`.
- No functional code yet.
