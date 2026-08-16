import os
import tempfile
import time
import unittest

from core.replay import ReplayStore


class TestReplayPurge(unittest.TestCase):
    def setUp(self):
        # Use a temporary DB file to avoid interfering with real data
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "replay_test.db")
        self.store = ReplayStore(db_path=self.db_path)

    def tearDown(self):
        # Ensure DB connection is closed before removing temp dir
        self.store.conn.close()
        self.temp_dir.cleanup()


    def test_purge_old_entries(self):
        # Insert a trace with an old timestamp (8 days ago)
        old_scan_id = "old123"
        old_timestamp = time.time() - 8 * 24 * 3600
        placeholder = {
            "scan_id": old_scan_id,
            "input": {},
            "node_outputs": {},
            "decision": "",
            "risk_score": 0,
            "confidence": 0,
            "actions": [],
        }
        # Direct insert bypassing store() to set custom created_at
        encrypted = self.store._fernet.encrypt(str(placeholder).encode()).decode()
        with self.store.lock:
            self.store.conn.execute(
                "INSERT INTO replay_traces (scan_id, data, created_at) VALUES (?, ?, ?)",
                (old_scan_id, encrypted, old_timestamp),
            )
            self.store.conn.commit()
        # Ensure the old entry is present
        self.assertIn(old_scan_id, self.store.list_ids())
        # Run purge
        self.store.purge_old()
        # The old entry should be gone
        self.assertNotIn(old_scan_id, self.store.list_ids())

if __name__ == "__main__":
    unittest.main()
