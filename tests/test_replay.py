import unittest
import os
import tempfile
from unittest.mock import patch
from core.replay import ReplayStore

class TestReplayStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        self.store = ReplayStore(self.tmp)

    def tearDown(self):
        self.store.conn.close()
        os.unlink(self.tmp)

    def test_store_and_retrieve(self):
        self.store.store("scan1", {"email": "test"}, {"extract_urls": {"urls": []}}, "ALLOW", 0, 50, ["allow"])
        trace = self.store.get("scan1")
        self.assertEqual(trace["scan_id"], "scan1")
        self.assertEqual(trace["decision"], "ALLOW")
        self.assertEqual(trace["risk_score"], 0)
        self.assertEqual(trace["actions"], ["allow"])

    def test_add_event(self):
        self.store.store("scan1", {}, {}, "ALLOW", 0, 0, [])
        self.store.add_event("scan1", "extract_urls", {"urls": []}, 90)
        trace = self.store.get("scan1")
        self.assertEqual(len(trace["events"]), 1)
        self.assertEqual(trace["events"][0]["node"], "extract_urls")

    def test_list_ids(self):
        self.store.store("s1", {}, {}, "ALLOW", 0, 0, [])
        self.store.store("s2", {}, {}, "DENY", 0, 0, [])
        self.assertEqual(len(self.store.list_ids()), 2)
        self.assertIn("s1", self.store.list_ids())

    def test_get_nonexistent(self):
        self.assertIsNone(self.store.get("nonexistent"))

    def test_stats_with_scans(self):
        self.store.store("s1", {}, {"risk_score": 50, "confidence": 80}, "ALLOW", 50, 80, ["allow"])
        self.store.store("s2", {}, {"risk_score": 90, "confidence": 95}, "DENY", 90, 95, ["block"])
        stats = self.store.stats()
        self.assertEqual(stats["total_scans"], 2)
        self.assertEqual(stats["allow_count"], 1)
        self.assertEqual(stats["deny_count"], 1)
        self.assertAlmostEqual(stats["avg_risk"], 70.0)

    def test_to_json(self):
        self.store.store("s1", {}, {}, "ALLOW", 0, 0, [])
        json_str = self.store.to_json("s1")
        self.assertIsNotNone(json_str)
        self.assertIn("scan_id", json_str)

    def test_to_json_nonexistent(self):
        self.assertIsNone(self.store.to_json("missing"))

    def test_add_event_creates_placeholder(self):
        # Adding an event for a scan that was never stored creates a placeholder trace
        self.store.add_event("ghost", "extract_urls", {"urls": []}, 90)
        trace = self.store.get("ghost")
        self.assertIsNotNone(trace)
        self.assertEqual(trace["decision"], "")
        self.assertEqual(len(trace["events"]), 1)
        self.assertEqual(trace["events"][0]["node"], "extract_urls")

    def test_stats_empty(self):
        stats = self.store.stats()
        self.assertEqual(stats["total_scans"], 0)
        self.assertEqual(stats["avg_risk"], 0)
        self.assertEqual(stats["actions_breakdown"], {})

    def test_stats_actions_breakdown(self):
        self.store.store("s1", {}, {}, "ALLOW", 50, 80, ["allow", "notify"])
        self.store.store("s2", {}, {}, "DENY", 90, 95, ["block"])
        stats = self.store.stats()
        self.assertEqual(stats["actions_breakdown"]["allow"], 1)
        self.assertEqual(stats["actions_breakdown"]["notify"], 1)
        self.assertEqual(stats["actions_breakdown"]["block"], 1)
        self.assertEqual(stats["total_scans"], 2)

    def test_risk_trend_order(self):
        self.store.store("s1", {}, {}, "ALLOW", 10, 50, [])
        self.store.store("s2", {}, {}, "DENY", 80, 90, [])
        trend = self.store.risk_trend()
        self.assertEqual(len(trend), 2)
        # Most recent scan appears last in the trend list
        self.assertEqual(trend[-1]["scan_id"], "s2")
        self.assertEqual(trend[-1]["risk_score"], 80)
        self.assertEqual(trend[0]["scan_id"], "s1")

    def test_risk_trend_respects_limit(self):
        for i in range(5):
            self.store.store(f"s{i}", {}, {}, "ALLOW", i, i, [])
        trend = self.store.risk_trend(limit=3)
        self.assertEqual(len(trend), 3)

    def test_purge_loop_runs_purge(self):
        # The background loop sleeps then purges; make the first sleep return
        # immediately and the second raise to break the loop.
        with patch("core.replay.time.sleep", side_effect=[None, KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                self.store._purge_loop()

if __name__ == "__main__":
    unittest.main()
