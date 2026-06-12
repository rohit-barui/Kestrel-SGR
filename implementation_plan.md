# Autonomous Phishing Control System (APCS) Implementation Plan

APCS is a deterministic, multi-plane security control system designed to detect, analyze, predict, and actively neutralize social engineering threats (phishing, smishing, vishing) across enterprise environments.

This plan details the code structure, execution mechanics of the Skill Graph Runtime (SGR), lightweight Rego policy engine, perception/decision/dominance modules, and a premium dashboard to run and visualize simulated threat scenarios in real-time.

---

## Analysis of Gaps, Issues & Advanced Recommendations

After checking the master specification and performing a deep architectural analysis ([architectural_analysis.md](file:///C:/Users/user/.gemini/antigravity-ide/brain/03d654a8-8be4-48d8-a23b-8bed38ed36f7/architectural_analysis.md)), we are adding the following architectural enhancements:

1. **Transaction Saga & Gateway Rollbacks (`core/gateway.py`)**:
   - Implements a transaction log. If a graph run is aborted or policy check fails, executed side-effects are rolled back in reverse order (e.g. unblocking a temporarily isolated IP or restoring a quarantined email).
2. **QR Code Scanner (`skills/perception.py`)**:
   - Added a `scan_qr_codes` skill using simulated/regex visual analysis to extract URLs hidden in image attachments and inline graphics (Quishing prevention).
3. **Archive Password Extractor (`skills/perception.py`)**:
   - Added `extract_archive_password` to scrap email bodies for passwords (e.g. "password: 1234") and pass them to the sandbox detonation skill to analyze encrypted archives.
4. **WHOIS Cache & Fallback (`skills/perception.py`)**:
   - Avoids WHOIS port 43 rate limits by caching lookups and using certificate transparency timestamps as backups.
5. **Active Honey Credentials (`skills/dominance.py`)**:
   - Deploys monitored, real corporate AD accounts with zero access. When the attacker attempts to use these credentials on their phishing server, APCS triggers immediate attacker IP blocking.
6. **Veto Overrides in Confidence Engine (`skills/decision.py`)**:
   - Ensures high-confidence threat feeds (100% blocklist match) immediately escalate the risk score to 100, preventing score dilution.

---

## Proposed Repository Structure

We will build the repository under `C:\Users\user\.gemini\antigravity-ide\scratch\apcs` with the following layout:

```
apcs/
├── server.py              # Pure Python REST Server (Zero-Dependency API + static router)
├── core/
│   ├── __init__.py
│   ├── engine.py          # Skill Graph Runtime (SGR) DAG executor + Schema validator
│   ├── policy.py          # Rego policy compiler & interpreter in Python
│   ├── graph.py           # Identity Graph System (Entities & Relationships)
│   ├── gateway.py         # Execution Gateway (Saga rollbacks, rate limits, audits)
│   ├── reasoning.py       # Multi-Model Reasoning Layer & Consensus
│   ├── drift.py           # Drift & Adaptation tracker (FP/FN feedback loops)
│   ├── replay.py          # Forensics & Replay storage
│   └── red_team.py        # Chaos & Red Team bypass generators
├── skills/
│   ├── __init__.py
│   ├── perception.py      # Ingestion, parsing (QR & password), detonation, WHOIS, DNS
│   ├── decision.py        # Risk scoring (Veto overrides), signal validation, action recommendation
│   └── dominance.py       # Typo-squatting, active honey creds, click tracking, block action
├── policies/
│   └── remediation.rego   # OPA Rego rules defining allow/deny for quarantine & blocking
├── web/                   # Web interface
│   ├── index.html         # Rich APCS cockpit layout (Glassmorphism design system)
│   ├── style.css          # Stunning dark mode styles with neon highlights
│   └── app.js             # Visualizes SGR nodes, API interactions, and live metrics
└── README.md              # Documentation
```

---

## Detailed File Implementations

### [Component: SGR Engine & Policies]
Coordinates execution of skills as a Directed Acyclic Graph (DAG) with schema enforcement, and evaluates policy decisions using OPA Rego rules parsed in Python.

#### [NEW] [engine.py](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/core/engine.py)
- Defines the `Skill` base class and `SkillGraphRuntime`.
- Implements topological sorting to execute skills sequentially or in parallel.
- Validates inputs and outputs against skill schemas.
- Aggregates confidence and handles state propagation.

#### [NEW] [policy.py](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/core/policy.py)
- Implements a lightweight Rego rule compiler and evaluator in Python.
- Parses `.rego` files (extracts conditions and rule names).
- Evaluates rules against the decision input payload and outputs the allowed/denied status.

#### [NEW] [remediation.rego](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/policies/remediation.rego)
- Contains Open Policy Agent rules for quarantine, deleting emails, and session revocation.

---

### [Component: Perception, Decision & Dominance Planes]
Core operational skills mapped directly from the master specification.

#### [NEW] [perception.py](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/skills/perception.py)
- **Ingestion Skills**: Loads email payloads (RFC 822 format), SMS logs, chat strings, and voice transcripts.
- **Parsing Skills**: Regex for URL extraction, QR code url parser, archive password parser, attachment file metadata extraction, and MIME/header parsing (DKIM/SPF/DMARC checks).
- **Detonation & Enrichment**: Resolves real/mock DNS chains, crawls public WHOIS endpoints or falls back to lookups, scans SSL certificates, and identifies brand typosquatting.
- **Behavioral & LLM-Bound Skills**: Evaluates text for urgency markers, suspicious requests (wire transfers, gift cards, passwords), and spoofed domains (using Levenshtein display-name matching).

#### [NEW] [decision.py](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/skills/decision.py)
- **Risk Score Aggregator**: Computes weighted risk values from perception inputs with Veto/Override support.
- **Action Recommender**: Formulates allowed remediation commands based on confidence.
- **Signal Validator**: Cross-checks SPF/DKIM validation with sender identity consistency.

#### [NEW] [dominance.py](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/skills/dominance.py)
- **Deception Systems**: Generates active honey credentials and triggers automated, deceptive payload submissions back to the attacker's harvesting link (simulated adversary disruption).
- **Containment Systems**: Simulates user/session lockout, MFA resets, and domain blocklisting.
- **Link Control**: Rewrites email URLs to point to a simulated isolation proxy.

---

### [Component: Dashboard & Control Server]
Provides a stunning visual console to trigger threat scenarios, trace skill graph execution, inspect OPA evaluations, and see active containment actions.

#### [NEW] [server.py](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/server.py)
- Pure Python HTTP REST API and Static File Server (using `http.server` and `socketserver`).
- Binds to `localhost:8080`.
- Offers endpoints `/api/scan` (runs the SGR graph on a payload), `/api/scenarios` (retrieves preset threat scenarios), and `/api/policies` (retrieves and updates Rego policies).

#### [NEW] [index.html](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/web/index.html)
- Fully responsive, glassmorphic layout.
- Integrates Google Fonts (Inter, Fira Code) and Lucide Icons.

#### [NEW] [style.css](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/web/style.css)
- Dark mode design system: dark-indigo background (`#0B0C10`), glassmorphic panels (`rgba(20, 24, 33, 0.7)`), cyan/emerald accents for safe execution paths, and amber/rose accents for threat detections.
- Interactive animations for graph node processing.

#### [NEW] [app.js](file:///C:/Users/user/.gemini/antigravity-ide/scratch/apcs/web/app.js)
- Renders the interactive Skill Graph DAG showing running nodes, active schemas, and outputs.
- Displays incident metrics (Risk Score, Policy status, Confidence, Active Threat Containment actions).
- Provides interactive triggers for preset scenarios:
  1. *CEO Fraud (Vishing/Email Combination)*
  2. *Credential Harvester (Lookalike Domain + Deceptive Honey Token Insertion)*
  3. *Malware Drop (Invoice Zip attachment with PE header)*
  4. *Clean Alert (Valid internal corporate communications)*

---

## Verification Plan

### Automated Tests
We will build a verification script to validate the components:
- `python -m unittest discover -s test` - runs unit tests validating topological DAG sort, schema checks, identity graph relations, and OPA Rego evaluator.

### Manual Verification
1. Run `python server.py` and open `http://localhost:8080` in the browser.
2. Select the **Credential Harvester** scenario.
3. Observe SGR execution, WHOIS scanning, OPA rule checks, and Deception credential payload deployment.
4. Open the **Forensics & Replay** view and scrub through the past incident execution trace step-by-step.
5. Trigger **Red Team bypass test** to verify if policy modifications block obfuscated payloads.
