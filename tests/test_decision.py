import unittest
from skills.decision import (
    aggregate_risk,
    apply_veto,
    recommend_actions,
    validate_spf_dkim,
)


class TestDecision(unittest.TestCase):
    def test_aggregate_risk_empty(self):
        payload = {}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 0)

    def test_aggregate_risk_with_urls(self):
        payload = {"extract_urls": {"urls": ["https://evil.com", "https://phish.net"]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 40)

    def test_aggregate_risk_with_qr(self):
        payload = {"scan_qr_codes": {"qr_urls": ["https://phish.xyz/qr"]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 15)

    def test_aggregate_risk_with_archive_pwd(self):
        payload = {"extract_archive_password": {"archive_password": "secret123"}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 10)

    def test_aggregate_risk_with_typo(self):
        payload = {"detect_typo_squatting": {"typo_squatting": ["examp1e.com"]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 25)

    def test_aggregate_risk_caps_at_100(self):
        payload = {"extract_urls": {"urls": ["a", "b", "c", "d", "e", "f"]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 100)

    def test_apply_veto_below_threshold(self):
        payload = {"aggregate_risk": {"risk_score": 30}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 30)
        self.assertEqual(result["confidence"], 50)

    def test_apply_veto_above_threshold(self):
        payload = {"aggregate_risk": {"risk_score": 85}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 85)
        self.assertEqual(result["confidence"], 100)

    def test_recommend_actions_allow(self):
        payload = {"apply_veto": {"risk_score": 20}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["allow"])

    def test_recommend_actions_quarantine(self):
        payload = {"apply_veto": {"risk_score": 50}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["quarantine"])

    def test_recommend_actions_block(self):
        payload = {"apply_veto": {"risk_score": 85}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["block"])

    def test_validate_spf_dkim_pass(self):
        payload = {"ingest": {"content": "From: test@example.com spf=pass dkim=pass"}}
        result = validate_spf_dkim(payload)
        self.assertEqual(result["output"]["spf_result"], "pass")
        self.assertEqual(result["output"]["dkim_result"], "pass")
        self.assertEqual(result["output"]["dmarc_result"], "pass")
        self.assertFalse(result["output"]["is_spoofed"])

    def test_validate_spf_dkim_fail(self):
        payload = {"ingest": {"content": "From: spoofed@evil.com spf=fail"}}
        result = validate_spf_dkim(payload)
        self.assertEqual(result["output"]["spf_result"], "fail")
        self.assertEqual(result["output"]["dkim_result"], "neutral")
        self.assertEqual(result["output"]["dmarc_result"], "fail")
        self.assertTrue(result["output"]["is_spoofed"])

    def test_validate_spf_dkim_neutral(self):
        payload = {"ingest": {"content": "From: unknown@test.com"}}
        result = validate_spf_dkim(payload)
        self.assertEqual(result["output"]["spf_result"], "neutral")
        self.assertEqual(result["output"]["dkim_result"], "neutral")
        self.assertEqual(result["output"]["dmarc_result"], "neutral")
        self.assertFalse(result["output"]["is_spoofed"])


if __name__ == "__main__":
    unittest.main()
