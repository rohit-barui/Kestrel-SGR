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
        self.assertEqual(result["output"]["risk_score"], 10)

    def test_aggregate_risk_with_qr(self):
        payload = {"scan_qr_codes": {"qr_urls": ["https://phish.xyz/qr"]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 10)

    def test_aggregate_risk_with_archive_pwd(self):
        payload = {"extract_archive_password": {"archive_password": "secret123"}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 15)

    def test_aggregate_risk_with_typo(self):
        payload = {"detect_typo_squatting": {"typo_squatting": ["examp1e.com"]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 15)

    def test_aggregate_risk_whois_odd_year(self):
        payload = {"whois_lookup": {"whois": {"evil.com": {"creation_date": "2023-01-01"}}}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 5)

    def test_aggregate_risk_whois_even_year(self):
        payload = {"whois_lookup": {"whois": {"evil.com": {"creation_date": "2020-01-01"}}}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 0)

    def test_aggregate_risk_caps_at_100(self):
        payload = {
            "extract_urls": {"urls": ["a", "b", "c", "d", "e", "f"]},
            "detonate_urls": {"detonation": {"results": [{"reputation": "malicious", "score": 100}]}},
            "validate_spf_dkim": {"is_spoofed": True},
            "enrich_external": {"url_analysis": [{"suspicion_score": 80}]},
        }
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 100)

    def test_aggregate_risk_with_spoof(self):
        payload = {"validate_spf_dkim": {"is_spoofed": True, "spf_result": "fail", "dkim_result": "neutral", "dmarc_result": "fail"}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 55)

    def test_aggregate_risk_with_ml(self):
        payload = {"ml_score": {"ml_risk_score": 80, "ml_confidence": 90}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 40)

    def test_aggregate_risk_with_entities(self):
        payload = {"extract_entities": {"entities_extracted": 12}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 15)

    def test_aggregate_risk_with_signals_combined(self):
        payload = {
            "extract_urls": {"urls": ["https://evil.com"]},
            "detonate_urls": {"detonation": {"results": [{"reputation": "malicious", "score": 90}]}},
            "validate_spf_dkim": {"is_spoofed": True, "spf_result": "fail", "dkim_result": "fail", "dmarc_result": "fail"},
        }
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 100)

    def test_aggregate_risk_suspicious_detonation(self):
        payload = {"detonate_urls": {"detonation": {"results": [{"reputation": "suspicious", "score": 50}]}}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 30)

    def test_aggregate_risk_ip_rep_malicious(self):
        payload = {
            "check_ip_reputation": {
                "ip_reputation": {"1.2.3.4": {"malicious": True, "checks": {"vt": {"reputation": "safe"}}}}
            }
        }
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 25)

    def test_aggregate_risk_ip_rep_suspicious_check(self):
        payload = {
            "check_ip_reputation": {
                "ip_reputation": {"1.2.3.4": {"malicious": False, "checks": {"vt": {"reputation": "suspicious"}}}}
            }
        }
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 15)

    def test_aggregate_risk_file_rep_malicious(self):
        payload = {"check_file_reputation": {"file_reputation": {"malicious": True}}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 35)

    def test_aggregate_risk_file_rep_suspicious(self):
        payload = {"check_file_reputation": {"suspicious_count": 2}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 20)

    def test_aggregate_risk_owasp(self):
        payload = {"owasp_analysis": {"risk_score": 60}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 30)

    def test_aggregate_risk_phishing_signals(self):
        payload = {"phishing_validation": {"phishing_signals": {"brand_impersonation": True, "missing_ssl": True, "header_mismatch": True}}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 55)

    def test_aggregate_risk_threat_intel(self):
        payload = {"threat_intel_lookup": {"threat_intel": [{"type": "url"}, {"type": "domain"}]}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 60)

    def test_aggregate_risk_entities_medium(self):
        payload = {"extract_entities": {"entities_extracted": 6}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 8)

    def test_aggregate_risk_owasp_zero_no_op(self):
        payload = {"owasp_analysis": {"risk_score": 0}}
        result = aggregate_risk(payload)
        self.assertEqual(result["output"]["risk_score"], 0)

    def test_apply_veto_ml_high(self):
        payload = {"aggregate_risk": {"risk_score": 20}, "ml_score": {"ml_risk_score": 85}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 80)
        self.assertEqual(result["confidence"], 95)

    def test_apply_veto_ip_rep_malicious(self):
        payload = {"aggregate_risk": {"risk_score": 20}, "check_ip_reputation": {"ip_reputation": {"1.1.1.1": {"malicious": True}}}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 80)

    def test_apply_veto_file_rep_malicious(self):
        payload = {"aggregate_risk": {"risk_score": 20}, "check_file_reputation": {"file_reputation": {"malicious": True}}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 85)

    def test_apply_veto_threat_intel_two_iocs(self):
        payload = {"aggregate_risk": {"risk_score": 20}, "threat_intel_lookup": {"threat_intel": [{"type": "url"}, {"type": "domain"}]}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 85)

    def test_apply_veto_phishing_likely(self):
        payload = {"aggregate_risk": {"risk_score": 20}, "phishing_validation": {"phishing_likely": True}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 75)

    def test_recommend_actions_ml_high_block(self):
        payload = {"apply_veto": {"risk_score": 20, "final_confidence": 50}, "ml_score": {"ml_risk_score": 90}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["block"])

    def test_apply_veto_no_override_below_70_keeps_confidence_100(self):
        payload = {"aggregate_risk": {"risk_score": 75}}
        result = apply_veto(payload)
        self.assertEqual(result["confidence"], 100)

    def test_apply_veto_above_threshold(self):
        payload = {"aggregate_risk": {"risk_score": 85}}
        result = apply_veto(payload)
        self.assertEqual(result["output"]["risk_score"], 85)
        self.assertEqual(result["confidence"], 100)

    def test_apply_veto_spoofed_overrides(self):
        payload = {"aggregate_risk": {"risk_score": 20}, "validate_spf_dkim": {"is_spoofed": True}}
        result = apply_veto(payload)
        self.assertGreaterEqual(result["output"]["risk_score"], 90)
        self.assertEqual(result["confidence"], 95)

    def test_apply_veto_malicious_detonation_overrides(self):
        payload = {"aggregate_risk": {"risk_score": 25}, "detonate_urls": {"detonation": {"malicious_count": 2}}}
        result = apply_veto(payload)
        self.assertGreaterEqual(result["output"]["risk_score"], 85)

    def test_recommend_actions_allow(self):
        payload = {"apply_veto": {"risk_score": 20, "final_confidence": 85}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["allow"])

    def test_recommend_actions_allow_monitor(self):
        payload = {"apply_veto": {"risk_score": 20, "final_confidence": 50}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["allow", "monitor"])

    def test_recommend_actions_quarantine(self):
        payload = {"apply_veto": {"risk_score": 50, "final_confidence": 70}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["quarantine"])

    def test_recommend_actions_quarantine_review(self):
        payload = {"apply_veto": {"risk_score": 50, "final_confidence": 40}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["quarantine", "review"])

    def test_recommend_actions_block(self):
        payload = {"apply_veto": {"risk_score": 85, "final_confidence": 100}}
        result = recommend_actions(payload)
        self.assertEqual(result["output"]["actions"], ["block"])

    def test_recommend_actions_block_spoofed(self):
        payload = {"apply_veto": {"risk_score": 30, "final_confidence": 50}, "validate_spf_dkim": {"is_spoofed": True}}
        result = recommend_actions(payload)
        self.assertIn("block", result["output"]["actions"])
        self.assertIn("alert_admin", result["output"]["actions"])

    def test_recommend_actions_block_malicious_detonation(self):
        payload = {"apply_veto": {"risk_score": 30, "final_confidence": 50}, "detonate_urls": {"detonation": {"malicious_count": 1}}}
        result = recommend_actions(payload)
        self.assertIn("block", result["output"]["actions"])

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
