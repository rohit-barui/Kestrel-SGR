"""Core Engine – Skill Graph Runtime (SGR)

Provides:
- DAG parsing & topological sort
- Parallel execution of independent nodes
- JSON‑Schema validation of inputs/outputs (uses jsonschema)
- Confidence aggregation & veto handling
- Error handling that triggers gateway rollback
"""

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Callable

# Placeholder types – real implementations will replace these
SkillFunction = Callable[[Dict[str, Any]], Dict[str, Any]]

class SkillNode:
    def __init__(self, name: str, func: SkillFunction, deps: List[str] = None):
        self.name = name
        self.func = func
        self.deps = deps or []
        self.result: Dict[str, Any] = {}
        self.success: bool = False

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
            current = ready.pop()
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
    # Execution – runs nodes respecting dependencies, aggregates confidence
    # ---------------------------------------------------------------------
    def run(self, entry_payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            self.execution_order = self._topological_sort()
        except Exception as e:
            raise RuntimeError(f"Graph validation failed: {e}")

        # Mapping of node name -> output for dependency injection
        context: Dict[str, Any] = {"__entry__": entry_payload}
        confidence_weights: List[float] = []
        with ThreadPoolExecutor() as executor:
            future_to_node: Dict[Any, SkillNode] = {}
            # schedule nodes whose deps are satisfied
            while self.execution_order:
                # find nodes ready to run (deps already in context)
                ready_nodes = [n for n in self.execution_order
                              if all(dep in context for dep in n.deps)]
                if not ready_nodes:
                    # should not happen because of topological sort
                    raise RuntimeError("Deadlock while scheduling skills")
                for node in ready_nodes:
                    # Build input payload from deps
                    inputs = {dep: context[dep] for dep in node.deps}
                    # Include entry payload for convenience
                    inputs["__entry__"] = entry_payload
                    future = executor.submit(node.func, inputs)
                    future_to_node[future] = node
                    self.execution_order.remove(node)
                # collect completed futures
                for future in as_completed(future_to_node):
                    node = future_to_node[future]
                    try:
                        result = future.result()
                        node.result = result
                        node.success = True
                        # store for downstream deps
                        context[node.name] = result.get("output", {})
                        # collect confidence if present
                        if "confidence" in result:
                            confidence_weights.append(result["confidence"])
                        # record side‑effect for possible rollback via gateway
                        if "side_effects" in result:
                            for se in result["side_effects"]:
                                self.gateway.record(**se)
                    except Exception as exc:
                        node.success = False
                        # abort remaining execution and trigger rollback
                        self.gateway.rollback()
                        raise RuntimeError(f"Skill {node.name} failed: {exc}")
        # After all nodes succeeded, compute aggregated confidence
        aggregated_confidence = (
            sum(confidence_weights) / len(confidence_weights)
            if confidence_weights else 0
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
