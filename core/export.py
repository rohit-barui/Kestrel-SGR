"""Data export utilities for APCS."""

import csv
import json
import io
from typing import Dict, Any, List


def export_csv(traces: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Timestamp", "Risk Score", "Confidence", "Decision", "Actions"])
    for t in traces:
        writer.writerow([
            t.get("scan_id", ""),
            t.get("timestamp", 0),
            t.get("risk_score", 0),
            t.get("confidence", 0),
            t.get("decision", ""),
            ", ".join(t.get("actions", [])),
        ])
    return output.getvalue()


def export_json_report(trace: Dict[str, Any]) -> str:
    return json.dumps(trace, indent=2)


def generate_summary_report(stats: Dict[str, Any], trend: List[Dict[str, Any]]) -> str:
    lines = []
    lines.append("APCS Summary Report")
    lines.append("=" * 40)
    lines.append(f"Total Scans: {stats.get('total_scans', 0)}")
    lines.append(f"Average Risk Score: {stats.get('avg_risk', 0)}")
    lines.append(f"Average Confidence: {stats.get('avg_confidence', 0)}")
    lines.append(f"Allow/Deny: {stats.get('allow_count', 0)}/{stats.get('deny_count', 0)}")
    lines.append("")
    lines.append("Recent Trend (last 20):")
    for t in trend[-20:]:
        lines.append(f"  {t.get('scan_id', '')[:8]}  risk={t.get('risk_score', 0)}  {t.get('decision', '')}")
    return "\n".join(lines)
