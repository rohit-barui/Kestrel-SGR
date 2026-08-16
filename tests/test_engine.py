import unittest

from core.engine import SkillGraphRuntime, SkillNode
from core.gateway import Gateway, rollback_noop
from core.tasks import run_skill


def dummy_skill(payload):
    return {"output": {"value": 1}, "confidence": 80}


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.gateway = Gateway()

    def test_successful_execution(self):
        # Two independent nodes
        node_a = SkillNode(name="a", func=dummy_skill)
        node_b = SkillNode(name="b", func=dummy_skill)
        runtime = SkillGraphRuntime(nodes=[node_a, node_b], gateway=self.gateway)
        result = runtime.run(entry_payload={})
        self.assertIn("graph_output", result)
        self.assertEqual(result["aggregated_confidence"], 80)
        # Both nodes should have succeeded
        self.assertTrue(node_a.success)
        self.assertTrue(node_b.success)

    def test_dependency_execution(self):
        # b depends on a
        def dependent_skill(payload):
            # payload will contain output from a
            val = payload.get("a", {}).get("value", 0)
            return {"output": {"value": val + 1}, "confidence": 90}
        node_a = SkillNode(name="a", func=dummy_skill)
        node_b = SkillNode(name="b", func=dependent_skill, deps=["a"])
        runtime = SkillGraphRuntime(nodes=[node_a, node_b], gateway=self.gateway)
        result = runtime.run(entry_payload={})
        self.assertTrue(80 <= result["aggregated_confidence"] <= 90)  # confidence should be between node confidences
        self.assertEqual(result["graph_output"]["b"]["value"], 2)

    def test_failure_triggers_rollback(self):
        def failing_skill(payload):
            raise RuntimeError("boom")
        node_a = SkillNode(name="a", func=dummy_skill)
        node_fail = SkillNode(name="fail", func=failing_skill, deps=["a"])
        runtime = SkillGraphRuntime(nodes=[node_a, node_fail], gateway=self.gateway)
        with self.assertRaises(RuntimeError):
            runtime.run(entry_payload={})
        # After failure, gateway should have performed rollback (no exception here)
        self.assertFalse(self.gateway._committed)

    def test_cycle_detection_raises(self):
        # a depends on b, b depends on a -> cycle
        node_a = SkillNode(name="a", func=dummy_skill, deps=["b"])
        node_b = SkillNode(name="b", func=dummy_skill, deps=["a"])
        runtime = SkillGraphRuntime(nodes=[node_a, node_b], gateway=self.gateway)
        with self.assertRaisesRegex(RuntimeError, "Graph validation failed"):
            runtime.run(entry_payload={})

    def test_unknown_dependency_raises_cycle(self):
        # Node depends on a node that does not exist -> cycle detection
        node_a = SkillNode(name="a", func=dummy_skill, deps=["phantom"])
        runtime = SkillGraphRuntime(nodes=[node_a], gateway=self.gateway)
        with self.assertRaisesRegex(RuntimeError, "Graph validation failed"):
            runtime.run(entry_payload={})

    def test_input_schema_validation_pass(self):
        schema = {"type": "object", "required": ["__entry__"]}
        node = SkillNode(name="a", func=dummy_skill, input_schema=schema)
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        result = runtime.run(entry_payload={})
        self.assertEqual(result["aggregated_confidence"], 80)

    def test_input_schema_validation_failure(self):
        # Schema requires a field that the injected inputs never provide
        schema = {"type": "object", "required": ["__entry__", "missing_field"]}
        node = SkillNode(name="a", func=dummy_skill, input_schema=schema)
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        with self.assertRaisesRegex(RuntimeError, "Schema validation failed"):
            runtime.run(entry_payload={})

    def test_output_schema_validation_failure(self):
        schema = {"type": "object", "required": ["output", "confidence"], "properties": {"output": {"type": "number"}}}
        node = SkillNode(name="a", func=dummy_skill, output_schema=schema)
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        with self.assertRaisesRegex(RuntimeError, "Schema validation failed"):
            runtime.run(entry_payload={})

    def test_side_effects_recorded_to_gateway(self):
        def skill_with_effects(payload):
            return {
                "output": {"value": 1},
                "confidence": 50,
                "side_effects": [
                    {"action": "block_ip", "params": {"ip": "10.0.0.1"}, "rollback": rollback_noop}
                ],
            }
        node = SkillNode(name="a", func=skill_with_effects)
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        # Capture what gets passed to gateway.record before commit clears the log
        recorded = []
        original_record = self.gateway.record
        def spy_record(**kwargs):
            recorded.append(kwargs)
            return original_record(**kwargs)
        self.gateway.record = spy_record
        runtime.run(entry_payload={})
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["action"], "block_ip")
        self.assertEqual(recorded[0]["params"], {"ip": "10.0.0.1"})
        # Saga committed successfully
        self.assertTrue(self.gateway._committed)
        self.assertEqual(self.gateway._log, [])

    def test_no_confidence_aggregates_zero(self):
        def skill_no_conf(payload):
            return {"output": {"value": 1}}
        node = SkillNode(name="a", func=skill_no_conf)
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        result = runtime.run(entry_payload={})
        self.assertEqual(result["aggregated_confidence"], 0)

    def test_heuristic_boost_applied(self):
        # Low confidence skill but multiple threat signals -> boosted
        def urls_skill(payload):
            return {"output": {"urls": ["http://a", "http://b", "http://c"]}, "confidence": 30}
        def typo_skill(payload):
            return {"output": {"typo_squatting": ["microsooft.com"]}, "confidence": 30}
        node_urls = SkillNode(name="extract_urls", func=urls_skill)
        node_typo = SkillNode(name="detect_typo_squatting", func=typo_skill)
        runtime = SkillGraphRuntime(nodes=[node_urls, node_typo], gateway=self.gateway)
        result = runtime.run(entry_payload={})
        # base ~30, 4 threat signals (3 urls + 1 typo) -> 30 + 20 = 50, but wait: heuristic
        # applied only when aggregated_confidence < 50 (base = 30)
        self.assertGreater(result["aggregated_confidence"], 30)

    def test_register_skill(self):
        runtime = SkillGraphRuntime(nodes=[], gateway=self.gateway)
        runtime.register_skill("my_skill", dummy_skill)
        # The task runner can now resolve it
        result = run_skill("my_skill", {})
        self.assertEqual(result["output"]["value"], 1)

    def test_run_skill_unknown_skill_raises(self):
        from core.tasks import run_skill as run_unknown
        with self.assertRaisesRegex(ValueError, "Unknown skill"):
            run_unknown("does_not_exist", {})

    def test_execution_order_populated(self):
        # Track actual execution order via shared list
        order = []
        def tracked_skill(name):
            def fn(payload):
                order.append(name)
                return {"output": {"value": name}, "confidence": 80}
            return fn
        node_a = SkillNode(name="a", func=tracked_skill("a"))
        node_b = SkillNode(name="b", func=tracked_skill("b"), deps=["a"])
        runtime = SkillGraphRuntime(nodes=[node_a, node_b], gateway=self.gateway)
        runtime.run(entry_payload={})
        self.assertEqual(order, ["a", "b"])

    def test_deadlock_raises(self):
        # Force the scheduling loop into a state where no node is ready
        def phantom_dep_skill(payload):
            return {"output": {}, "confidence": 50}
        node = SkillNode(name="x", func=phantom_dep_skill, deps=["ghost"])
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        # Bypass topological sort so the phantom dep is not caught by validation
        runtime._topological_sort = lambda: [node]
        with self.assertRaisesRegex(RuntimeError, "Deadlock while scheduling"):
            runtime.run(entry_payload={})

    def test_threat_boost_counts_archive_password(self):
        # aggregated_confidence < 50 with an archive password -> threat_signal
        def pwd_skill(payload):
            return {"output": {"archive_password": "hunter2"}, "confidence": 30}
        node = SkillNode(name="extract_archive_password", func=pwd_skill)
        runtime = SkillGraphRuntime(nodes=[node], gateway=self.gateway)
        result = runtime.run(entry_payload={})
        # No boost (only 1 signal, needs > 2), but base confidence preserved
        self.assertEqual(result["aggregated_confidence"], 30)

    def test_core_engine_dummy_skill(self):
        from core.engine import dummy_skill as engine_dummy
        result = engine_dummy({})
        self.assertEqual(result, {"output": {"dummy": True}, "confidence": 100})


if __name__ == "__main__":
    unittest.main()
