"""Tests for the ML scoring integration.

The ML model may or may not be available (scikit‑learn optional). The tests check
that the ``ml_score`` node runs without error and returns a risk score in the
expected range. A deterministic synthetic payload is used so the rule‑based
fallback produces a known value.
"""
import unittest

from core.ml import ml_score

class TestMLIntegration(unittest.TestCase):
    def test_ml_score_structure(self):
        # Minimal perception payload that mimics earlier perception nodes.
        payload = {
            "extract_urls": {"urls": ["https://example.com"], "domains": ["example.com"]},
            "scan_qr_codes": {"qr_urls": []},
            "extract_archive_password": {"archive_password": ""},
            "whois_lookup": {"whois": {}},
            "enrich_dns": {"dns": {}},
            "detect_typo_squatting": {"typo_squatting": []},
            "extract_entities": {"entities_extracted": 0},
            "enrich_external": {"output": {}},
            "validate_spf_dkim": {"is_spoofed": False},
            "ingest": {"content": "test email body"},
        }
        result = ml_score(payload)
        self.assertIn("output", result)
        out = result["output"]
        self.assertIn("ml_risk_score", out)
        self.assertIn("ml_confidence", out)
        self.assertIsInstance(out["ml_risk_score"], int)
        self.assertIsInstance(out["ml_confidence"], int)
        self.assertGreaterEqual(out["ml_risk_score"], 0)
        self.assertLessEqual(out["ml_risk_score"], 100)

if __name__ == "__main__":
    unittest.main()
