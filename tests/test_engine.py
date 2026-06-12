import unittest
from core.engine import SkillNode, SkillGraphRuntime
from core.gateway import Gateway

# Simple dummy skill that returns a constant output and confidence

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

if __name__ == "__main__":
    unittest.main()
