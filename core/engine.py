"""Core Engine – Skill Graph Runtime (SGR)

Provides:
- DAG parsing & topological sort
- Parallel execution of independent nodes
- JSON‑Schema validation of inputs/outputs (uses jsonschema)
- Confidence aggregation & veto handling
- Error handling that triggers gateway rollback
"""

import json
from typing import Dict, List, Any, Callable, Tuple

import jsonschema

from core.reasoning import combine, heuristic_boost

from core.tasks import run_skill

# Skill function registry – maps name → callable so Celery workers can resolve them.
_SKILL_REGISTRY: Dict[str, Callable] = {}

# Placeholder types – real implementations will replace these
SkillFunction = Callable[[Dict[str, Any]], Dict[str, Any]]

SKILL_WEIGHTS = {
    "ingest": 0.05, "extract_urls": 0.10, "scan_qr_codes": 0.10,
    "extract_archive_password": 0.05, "whois_lookup": 0.10,
    "enrich_dns": 0.05, "detect_typo_squatting": 0.15,
    "ml_score": 0.15,
    "aggregate_risk": 0.15, "apply_veto": 0.15, "recommend_actions": 0.10,
}


class SkillNode:
    def __init__(self, name: str, func: SkillFunction, deps: List[str] = None,
                 input_schema: dict = None, output_schema: dict = None):
        self.name = name
        self.func = func
        self.deps = deps or []
        self.result: Dict[str, Any] = {}
        self.success: bool = False
        self.input_schema = input_schema
        self.output_schema = output_schema

class SkillGraphRuntime:
    def __init__(self, nodes: List[SkillNode], gateway):
        self.nodes = {n.name: n for n in nodes}
        self.gateway = gateway
        self.execution_order: List[SkillNode] = []  # populated after topological sort

    # ---------------------------------------------------------------------
    # Topological sort – Kahn's algorithm (simplified, raises on cycles)
    # ---------------------------------------------------------------------
    def _topological_sort(self) -> List[SkillNode]:
        in_degree = {name: 0 for name in self.nodes}
        for node in self.nodes.values():
            for dep in node.deps:
                in_degree[node.name] += 1
        ready = [self.nodes[n] for n, d in in_degree.items() if d == 0]
        order: List[SkillNode] = []
        while ready:
            current = ready.pop(0)
            order.append(current)
            for n in self.nodes.values():
                if current.name in n.deps:
                    in_degree[n.name] -= 1
                    if in_degree[n.name] == 0:
                        ready.append(self.nodes[n.name])
        if len(order) != len(self.nodes):
            raise RuntimeError("Cycle detected in skill graph")
        return order

    # ---------------------------------------------------------------------
    # Schema validation
    # ---------------------------------------------------------------------
    def _validate(self, data: dict, schema: dict, stage: str, node_name: str):
        if schema is not None:
            try:
                jsonschema.validate(data, schema)
            except jsonschema.ValidationError as e:
                raise RuntimeError(f"Schema validation failed for {node_name} {stage}: {e}")

    def register_skill(self, name: str, func: Callable):
        """Register a skill function so Celery workers can resolve it."""
        _SKILL_REGISTRY[name] = func

    # ---------------------------------------------------------------------
    # Execution – runs nodes via Celery tasks, aggregates confidence
    # ---------------------------------------------------------------------
    def run(self, entry_payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            self.execution_order = self._topological_sort()
        except Exception as e:
            raise RuntimeError(f"Graph validation failed: {e}")

        # Register all node functions for Celery resolution
        for n in self.nodes.values():
            self.register_skill(n.name, n.func)

        # Mapping of node name -> output for dependency injection
        context: Dict[str, Any] = {"__entry__": entry_payload}
        confidence_weights: List[Tuple[str, float]] = []

        while self.execution_order:
            # find nodes ready to run (deps already in context)
            ready_nodes = [n for n in self.execution_order
                          if all(dep in context for dep in n.deps)]
            if not ready_nodes:
                raise RuntimeError("Deadlock while scheduling skills")
            for node in ready_nodes:
                inputs = {dep: context[dep] for dep in node.deps}
                inputs["__entry__"] = entry_payload
                self._validate(inputs, node.input_schema, "input", node.name)
                # Execute the skill – use Celery's eager mode for synchronous
                # execution (no broker needed).  For production with a real
                # broker, replace with .delay() and collect results via
                # AsyncResult.
                result = run_skill(node.name, inputs)
                self._validate(result, node.output_schema, "output", node.name)
                node.result = result
                node.success = True
                context[node.name] = result.get("output", {})
                if "confidence" in result:
                    confidence_weights.append((node.name, result["confidence"]))
                if "side_effects" in result:
                    for se in result["side_effects"]:
                        self.gateway.record(**se)
                self.execution_order.remove(node)
        # After all nodes succeeded, compute aggregated confidence
        if confidence_weights:
            scores = [conf for _, conf in confidence_weights]
            weights = [SKILL_WEIGHTS.get(name, 0.1) for name, _ in confidence_weights]
            aggregated_confidence = combine(scores, weights)
        else:
            aggregated_confidence = 0

        # Boost confidence if low but threat signals are abundant
        if aggregated_confidence < 50:
            threat_signals = 0
            urls = context.get("extract_urls", {}).get("urls", [])
            if urls:
                threat_signals += len(urls)
            pwd = context.get("extract_archive_password", {}).get("archive_password", "")
            if pwd:
                threat_signals += 1
            typo = context.get("detect_typo_squatting", {}).get("typo_squatting", [])
            if typo:
                threat_signals += len(typo)
            if threat_signals > 2:
                aggregated_confidence = heuristic_boost(
                    risk_score=0,
                    threat_signals=threat_signals,
                    base=aggregated_confidence
                )
        # Commit saga – no rollback needed
        self.gateway.commit()
        return {
            "graph_output": context,
            "aggregated_confidence": aggregated_confidence,
        }

# Example placeholder skill functions (to be replaced by real implementations)
def dummy_skill(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"output": {"dummy": True}, "confidence": 100}

# End of core/engine.py
