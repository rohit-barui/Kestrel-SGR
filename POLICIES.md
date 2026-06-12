# Policies Documentation

APCS uses **Open Policy Agent (OPA) Rego** rules to make final allow/deny decisions for remediation actions.  The rules live in the `policies/` directory and are loaded at runtime by `core/policy.py`.

## remediation.rego (example)
```rego
package apcs.remediation

default allow = false

# Blocklist rule – if any URL matches a known phishing blocklist, deny immediately
allow {
    some i
    input.risk_score >= 70
    input.urls[i] = url
    contains_blocklist(url)
}

# Quarantine rule – if confidence > 80 and no explicit allow, quarantine the email
allow {
    input.confidence > 80
    not input.is_whitelisted
}

# Password exposure – if an archive password is detected, allow decryption for inspection
allow {
    input.archive_password != ""
}
```

## How Policies Are Evaluated
1. The **Decision plane** produces a JSON payload containing:
   - `risk_score` (0‑100)
   - `confidence` (0‑100)
   - `urls` (list of extracted URLs)
   - `archive_password` (optional string)
   - `is_whitelisted` (bool)
2. `core/policy.py` compiles `remediation.rego` into an AST and evaluates the `allow` rule against the payload.
3. The boolean result is returned to the runtime; `True` means the requested remediation action is permitted, `False` aborts the Saga and triggers rollback.

## Updating Policies
- **Via API** – `PUT /api/policies` accepts a JSON body `{ "policy": "<rego content>" }`. The server overwrites `policies/remediation.rego` and reloads the compiler.
- **Manually** – Edit `policies/remediation.rego` and commit the change.  After a commit, restart the server to load the new rules.

## Adding New Rules
1. Create a new `.rego` file in `policies/` (e.g., `advanced_checks.rego`).
2. Import the base package if you need shared helpers:
   ```rego
   import data.apcs.remediation
   ```
3. Define a new rule (e.g., `allow { ... }`).
4. Ensure the rule returns a boolean `allow` decision; the engine expects a single entry point named `allow`.
5. Update the API documentation in `API.md` (to be added) if you expose additional endpoints.

---

*Note:* The lightweight Rego interpreter in `core/policy.py` currently supports a subset of OPA features (basic rules, imports, and built‑in helpers).  For complex policies consider swapping in the official `opa` binary.
