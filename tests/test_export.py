import unittest
from core.export import export_csv, generate_summary_report

class TestExport(unittest.TestCase):
    def test_export_csv_headers(self):
        traces = [{"scan_id": "abc", "timestamp": 0, "risk_score": 50, "confidence": 80, "decision": "ALLOW", "actions": ["allow"]}]
        csv_data = export_csv(traces)
        self.assertIn("Scan ID", csv_data)
        self.assertIn("abc", csv_data)

    def test_export_csv_empty(self):
        csv_data = export_csv([])
        self.assertIn("Scan ID", csv_data)

    def test_summary_report(self):
        stats = {"total_scans": 5, "avg_risk": 50, "avg_confidence": 80, "allow_count": 3, "deny_count": 2}
        trend = [{"scan_id": "abc", "risk_score": 50, "decision": "ALLOW"}]
        report = generate_summary_report(stats, trend)
        self.assertIn("Total Scans: 5", report)
        self.assertIn("APCS Summary Report", report)
