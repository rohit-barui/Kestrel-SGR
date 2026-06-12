# Testing Guide

APCS includes a Python `unittest` suite that validates core functionality, skill execution, policy evaluation and the saga rollback mechanism.

## Running the tests
```powershell
cd "C:/Users/user/Documents/projects/Kestrel SGR/Kestrel-SGR-repo"
python -m unittest discover -s tests
```
The command discovers all `test_*.py` files under the `tests/` directory and executes them.

## Test Coverage
| Area | Description |
|------|-------------|
| Core engine | Topological sort, parallel execution, schema validation, confidence aggregation. |
| Policy engine | Loading `.rego` files, evaluating allow/deny rules, handling syntax errors. |
| Gateway saga | Recording side‑effects, successful commit, forced rollback on failure. |
| Skills | Typical perception (URL extraction, QR scanning), decision (risk scoring), dominance (honey cred deployment). |
| Replay | Generation of execution trace JSON and its integrity. |

## Adding new tests
1. Create a new file named `test_<module>.py` inside `tests/`.
2. Import the target module and use `unittest.TestCase`.
3. Ensure each test is deterministic – mock external network calls (WHOIS, DNS) with `unittest.mock`.
4. Run the suite locally before committing.

## Continuous Integration (future)
A CI pipeline can invoke `python -m unittest` and enforce a minimum coverage threshold (e.g., 80 %).
