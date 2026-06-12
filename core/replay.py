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

    def stats(self) -> Dict[str, Any]:
        rows = self.conn.execute("SELECT data FROM replay_traces").fetchall()
        total = len(rows)
        if total == 0:
            return {"total_scans": 0, "avg_risk": 0, "avg_confidence": 0, "allow_count": 0, "deny_count": 0, "actions_breakdown": {}}

        risks = []
        confs = []
        allows = 0
        denies = 0
        actions_count = {}

        for row in rows:
            trace = json.loads(row[0])
            risks.append(trace.get("risk_score", 0))
            confs.append(trace.get("confidence", 0))
            if trace.get("decision") == "ALLOW":
                allows += 1
            else:
                denies += 1
            for action in trace.get("actions", []):
                actions_count[action] = actions_count.get(action, 0) + 1

        return {
            "total_scans": total,
            "avg_risk": round(sum(risks) / len(risks), 1) if risks else 0,
            "avg_confidence": round(sum(confs) / len(confs), 1) if confs else 0,
            "allow_count": allows,
            "deny_count": denies,
            "actions_breakdown": actions_count,
        }

    def risk_trend(self, limit=20) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT data FROM replay_traces ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        trend = []
        for row in reversed(rows):
            trace = json.loads(row[0])
            trend.append({
                "scan_id": trace["scan_id"],
                "risk_score": trace.get("risk_score", 0),
                "decision": trace.get("decision", ""),
                "timestamp": trace.get("timestamp", 0),
            })
        return trend

    def to_json(self, scan_id: str) -> Optional[str]:
        trace = self.get(scan_id)
        return json.dumps(trace, indent=2) if trace else None
