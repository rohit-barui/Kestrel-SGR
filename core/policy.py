"""Core Policy – lightweight Rego evaluator

This is a minimal implementation sufficient for the current prototype.
It parses a very small subset of Rego syntax (only `package`, `default`, and
simple rule bodies using `input` fields and basic boolean expressions).
For full OPA compatibility you would replace this with the official `opa`
binary or a proper Rego parser.
"""

import re
import json
from typing import Dict, Any

class SimpleRegoEngine:
    def __init__(self, rego_path: str):
        self.rego_path = rego_path
        self.rules = {}
        self._load_rego()

    def _load_rego(self):
        with open(self.rego_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Extract rule named "allow"
        # Very naïve regex: allow { <expr> }
        match = re.search(r"allow\s*\{([^}]*)\}", content, re.DOTALL)
        if not match:
            raise ValueError("'allow' rule not found in Rego file")
        expr = match.group(1).strip()
        self.rules["allow"] = expr

    def _eval_expr(self, expr: str, input_data: Dict[str, Any]) -> bool:
        # Replace references like input.risk_score with actual values
        # Only supports dot access and simple comparisons (>, >=, ==)
        def repl_var(m):
            path = m.group(1).split('.')
            val = input_data
            for p in path[1:]:  # skip leading 'input'
                val = val.get(p)
                if val is None:
                    break
            return json.dumps(val)
        expr_python = re.sub(r"input\.([A-Za-z0-9_\.]+)", repl_var, expr)
        # Replace logical operators
        expr_python = expr_python.replace("&&", "and").replace("||", "or")
        try:
            return eval(expr_python, {"__builtins__": {}})
        except Exception as e:
            raise RuntimeError(f"Failed to evaluate Rego expression: {e}")

    def evaluate(self, input_data: Dict[str, Any]) -> bool:
        expr = self.rules.get("allow")
        if expr is None:
            raise RuntimeError("No 'allow' rule loaded")
        return self._eval_expr(expr, input_data)

# Example usage (used by the engine at runtime):
# engine = SimpleRegoEngine('policies/remediation.rego')
# decision = engine.evaluate(payload)
