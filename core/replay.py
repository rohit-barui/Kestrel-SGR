import json
import time
from typing import Dict, Any, List, Optional

class ReplayStore:
    def __init__(self):
        self._traces: Dict[str, Dict[str, Any]] = {}

    def store(self, scan_id: str, entry_payload: Dict[str, Any], node_outputs: Dict[str, Any],
              final_decision: str, risk_score: float, confidence: float, actions: List[str]):
        existing = self._traces.get(scan_id, {})
        self._traces[scan_id] = {
            "scan_id": scan_id,
            "timestamp": time.time(),
            "input": entry_payload,
            "node_outputs": node_outputs,
            "decision": final_decision,
            "risk_score": risk_score,
            "confidence": confidence,
            "actions": actions,
            "events": existing.get("events", []),
        }

    def add_event(self, scan_id: str, node: str, output: Dict[str, Any], confidence: float):
        if scan_id not in self._traces:
            self._traces[scan_id] = {
                "scan_id": scan_id, "timestamp": time.time(),
                "input": {}, "node_outputs": {},
                "decision": "", "risk_score": 0, "confidence": 0,
                "actions": [], "events": [],
            }
        self._traces[scan_id]["events"].append({
            "node": node,
            "output": output,
            "confidence": confidence,
            "timestamp": time.time(),
        })

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self._traces.get(scan_id)

    def list_ids(self) -> List[str]:
        return list(self._traces.keys())

    def to_json(self, scan_id: str) -> Optional[str]:
        trace = self._traces.get(scan_id)
        return json.dumps(trace, indent=2) if trace else None
