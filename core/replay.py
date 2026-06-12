import json
import time
import sqlite3
import os
import threading
from typing import Dict, Any, List, Optional


class ReplayStore:
    def __init__(self, db_path="data/replay.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS replay_traces ("
            "scan_id TEXT PRIMARY KEY, data TEXT, created_at REAL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS replay_events ("
            "scan_id TEXT, node TEXT, output TEXT, confidence REAL, timestamp REAL)"
        )
        self.conn.commit()

    def store(self, scan_id: str, entry_payload: Dict[str, Any], node_outputs: Dict[str, Any],
              final_decision: str, risk_score: float, confidence: float, actions: List[str]):
        trace_data = {
            "scan_id": scan_id,
            "input": entry_payload,
            "node_outputs": node_outputs,
            "decision": final_decision,
            "risk_score": risk_score,
            "confidence": confidence,
            "actions": actions,
        }
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO replay_traces (scan_id, data, created_at) VALUES (?, ?, ?)",
                (scan_id, json.dumps(trace_data), time.time()),
            )
            self.conn.commit()

    def add_event(self, scan_id: str, node: str, output: Dict[str, Any], confidence: float):
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM replay_traces WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if not row:
                placeholder = {
                    "scan_id": scan_id, "input": {}, "node_outputs": {},
                    "decision": "", "risk_score": 0, "confidence": 0, "actions": [],
                }
                self.conn.execute(
                    "INSERT INTO replay_traces (scan_id, data, created_at) VALUES (?, ?, ?)",
                    (scan_id, json.dumps(placeholder), time.time()),
                )
            self.conn.execute(
                "INSERT INTO replay_events (scan_id, node, output, confidence, timestamp) VALUES (?, ?, ?, ?, ?)",
                (scan_id, node, json.dumps(output), confidence, time.time()),
            )
            self.conn.commit()

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT data, created_at FROM replay_traces WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if not row:
                return None
            trace = json.loads(row[0])
            trace["timestamp"] = row[1]
            events = self.conn.execute(
                "SELECT node, output, confidence, timestamp FROM replay_events WHERE scan_id = ? ORDER BY timestamp",
                (scan_id,),
            ).fetchall()
            trace["events"] = [
                {"node": e[0], "output": json.loads(e[1]), "confidence": e[2], "timestamp": e[3]}
                for e in events
            ]
            return trace

    def list_ids(self) -> List[str]:
        with self.lock:
            rows = self.conn.execute("SELECT scan_id FROM replay_traces").fetchall()
            return [r[0] for r in rows]

    def to_json(self, scan_id: str) -> Optional[str]:
        trace = self.get(scan_id)
        return json.dumps(trace, indent=2) if trace else None
