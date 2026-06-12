import unittest
import os
import tempfile
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

    def test_to_json(self):
        self.store.store("s1", {}, {}, "ALLOW", 0, 0, [])
        json_str = self.store.to_json("s1")
        self.assertIsNotNone(json_str)
        self.assertIn("scan_id", json_str)

if __name__ == "__main__":
    unittest.main()
