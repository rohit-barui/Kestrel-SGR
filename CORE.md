# Core Package Documentation

The `core/` package implements the engine that powers APCS.  All modules are pure Python and have no external runtime dependencies beyond the standard library.

## engine.py
- **SkillGraphRuntime** – Accepts a JSON definition of a DAG where each node references a Python skill function.
- **Schema validation** – Uses `jsonschema` (declared in `requirements.txt`) to validate each node’s `input_schema` and `output_schema` before execution.
- **Execution model** – Performs a topological sort; nodes with no dependencies run in parallel using `concurrent.futures.ThreadPoolExecutor`.  Results are merged and fed to downstream nodes.
- **Confidence aggregation** – Each skill returns a `confidence` (0‑100).  The runtime computes a weighted average; veto overrides (see `decision.py`) force the final confidence to 100.
- **Error handling** – On any exception the runtime invokes `gateway.rollback()` and aborts remaining nodes.

## policy.py
- **RegoCompiler** – Parses `.rego` files into a lightweight AST.
- **Evaluator** – Executes compiled rules against the decision payload (JSON).  Returns `allow`/`deny` with optional `metadata`.
- **Extensibility** – Custom builtin functions (e.g., `contains_url`, `is_honey_cred`) can be registered from Python.

## gateway.py
- Implements the **Saga pattern** for side‑effect management.
- **record(action, params, rollback)** – Stores an entry; `rollback` is a callable that reverses the action.
- **commit()** – Marks the saga as successful; no rollback will be performed.
- **rollback()** – Executes stored rollback callables in reverse order if the saga aborts.
- Example side‑effects: `block_ip`, `quarantine_email`, `deploy_honey_cred`.

## graph.py
- Simple in‑memory entity‑relationship graph using adjacency lists.
- Provides `add_entity`, `add_relationship`, `query_path` utilities used by perception and decision logic.

## reasoning.py
- Aggregates heuristic scores with optional LLM‑based scoring (placeholder for future integration).
- Exposes `combine(scores: List[float]) -> float`.

## drift.py
- Stores feedback (`fp`, `fn`) per rule/skill.
- Adaptive thresholding: if a rule’s false‑positive rate exceeds 5 % the engine automatically lowers its weight.

## replay.py
- Persists a JSON execution trace per scan: input payload, node‑wise outputs, timestamps, and final decision.
- Used by the dashboard to provide a step‑by‑step forensic replay.

## red_team.py
- Generates synthetic phishing payloads for robustness testing:
  - `generate_ceo_fraud()`, `generate_credential_harvester()`, `generate_malware_drop()`.
- Returns a mock email/SMS object consumable by `perception.py`.

---

All public classes/functions are exported in `core/__init__.py` for convenient imports:
```python
from core import engine, policy, gateway
```