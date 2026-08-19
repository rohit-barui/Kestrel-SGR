import json
import os
import threading
import time

from .db import get_encrypted_conn


class Cache:
    def __init__(self, db_path="data/cache.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.lock = threading.Lock()
        self.conn = get_encrypted_conn(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS cache ("
            "key TEXT PRIMARY KEY, value TEXT, expires_at REAL)"
        )

    def get(self, key):
        with self.lock:
            row = self.conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
            if row and row[1] > time.time():
                return json.loads(row[0])
            return None

    def set(self, key, value, ttl=3600):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), time.time() + ttl),
            )
            self.conn.commit()

    def clear(self):
        with self.lock:
            self.conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
            self.conn.commit()
