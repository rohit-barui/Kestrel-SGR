import json
import time
import os
import threading
import hashlib
import base64
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet
from .db import get_encrypted_conn
from .vault import ensure_secret


def _fernet_from_secret(secret: str) -> Fernet:
    """Derive a Fernet instance from an arbitrary secret string.
    The secret is hashed with SHA‑256 to obtain 32 bytes, then base64‑url‑encoded
    as required by cryptography.fernet.Fernet."""
    key = hashlib.sha256(secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


class ReplayStore:
    def __init__(self, db_path="data/replay.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.lock = threading.Lock()
        self.conn = get_encrypted_conn(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS replay_traces ("
            "scan_id TEXT PRIMARY KEY, data TEXT, created_at REAL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS replay_events ("
            "scan_id TEXT, node TEXT, output TEXT, confidence REAL, timestamp REAL)"
        )
        self.conn.commit()
        # Fernet instance for encrypting trace data
        self._fernet = _fernet_from_secret(ensure_secret("db_encryption_key"))
        # Start background purge thread (runs every hour)
        self._purge_thread = threading.Thread(target=self._purge_loop, daemon=True)
        self._purge_thread.start()


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
            # Serialize then encrypt the trace data
            plain = json.dumps(trace_data).encode()
            encrypted = self._fernet.encrypt(plain).decode()
            self.conn.execute(
                "INSERT OR REPLACE INTO replay_traces (scan_id, data, created_at) VALUES (?, ?, ?)",
                (scan_id, encrypted, time.time()),
            )
            self.conn.commit()

    def add_event(self, scan_id: str, node: str, output: Dict[str, Any], confidence: float):
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM replay_traces WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if not row:
                placeholder = {
                    "scan_id": scan_id,
                    "input": {},
                    "node_outputs": {},
                    "decision": "",
                    "risk_score": 0,
                    "confidence": 0,
                    "actions": [],
                }
                encrypted_placeholder = self._fernet.encrypt(json.dumps(placeholder).encode()).decode()
                self.conn.execute(
                    "INSERT INTO replay_traces (scan_id, data, created_at) VALUES (?, ?, ?)",
                    (scan_id, encrypted_placeholder, time.time()),
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
            # Decrypt the stored trace data
            decrypted = self._fernet.decrypt(row[0].encode()).decode()
            trace = json.loads(decrypted)
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

    # ---- Purge old entries (7‑day TTL) ----
    def purge_old(self):
        """Delete replay traces and events older than 7 days."""
        cutoff = time.time() - 7 * 24 * 3600
        with self.lock:
            self.conn.execute(
                "DELETE FROM replay_traces WHERE created_at < ?", (cutoff,)
            )
            self.conn.execute(
                "DELETE FROM replay_events WHERE timestamp < ?", (cutoff,)
            )
            self.conn.commit()

    def _purge_loop(self):
        """Background thread loop – runs purge_old() every hour."""
        while True:
            time.sleep(3600)  # 1 hour
            self.purge_old()


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
            decrypted = self._fernet.decrypt(row[0].encode()).decode()
            trace = json.loads(decrypted)
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
            try:
                decrypted = self._fernet.decrypt(row[0].encode()).decode()
                trace = json.loads(decrypted)
            except Exception:
                continue
            trend.append({
                "scan_id": trace.get("scan_id", ""),
                "risk_score": trace.get("risk_score", 0),
                "decision": trace.get("decision", ""),
                "timestamp": trace.get("timestamp", 0),
            })
        return trend

    def to_json(self, scan_id: str) -> Optional[str]:
        trace = self.get(scan_id)
        return json.dumps(trace, indent=2) if trace else None
