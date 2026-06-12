import unittest
import os
import tempfile
import json
from core.cache import Cache


class TestCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        self.cache = Cache(self.tmp)

    def tearDown(self):
        self.cache.conn.close()
        os.unlink(self.tmp)

    def test_set_get(self):
        self.cache.set("key1", {"a": 1})
        val = self.cache.get("key1")
        self.assertEqual(val, {"a": 1})

    def test_expired(self):
        self.cache.set("key2", "val", ttl=-1)
        val = self.cache.get("key2")
        self.assertIsNone(val)

    def test_nonexistent(self):
        self.assertIsNone(self.cache.get("nope"))


if __name__ == "__main__":
    unittest.main()
