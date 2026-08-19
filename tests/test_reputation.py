import unittest
from unittest.mock import MagicMock, patch

from skills.reputation import (
    _load_integration_config,
    check_file_reputation,
    check_ip_reputation,
    phishing_validation,
    threat_intel_lookup,
)


class TestLoadIntegrationConfig(unittest.TestCase):
    @patch("skills.reputation.get_secret")
    def test_returns_dict_from_secret(self, mock_secret):
        mock_secret.return_value = {"api_key": "x"}
        self.assertEqual(_load_integration_config("virustotal"), {"api_key": "x"})

    @patch("skills.reputation.get_secret")
    def test_returns_empty_when_not_dict(self, mock_secret):
        mock_secret.return_value = "not-a-dict"
        self.assertEqual(_load_integration_config("virustotal"), {})

    @patch("skills.reputation.get_secret")
    def test_returns_empty_on_exception(self, mock_secret):
        mock_secret.side_effect = RuntimeError("boom")
        self.assertEqual(_load_integration_config("virustotal"), {})


class TestCheckIpReputation(unittest.TestCase):
    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_empty_domains(self, mock_dns):
        result = check_ip_reputation({"extract_urls": {"domains": []}})
        self.assertEqual(result["output"]["ip_reputation"], {})
        self.assertEqual(result["confidence"], 20)

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_domain_resolves_and_checks(self, mock_dns):
        vt = MagicMock()
        vt.check_ip.return_value = {"reputation": "malicious", "score": 80}
        abuse = MagicMock()
        abuse.check_ip.return_value = {"reputation": "safe", "score": 5}
        otx = MagicMock()
        otx.check_ip.return_value = {"reputation": "suspicious", "score": 30}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AbuseIPDB", return_value=abuse
        ), patch("skills.reputation.AlienVaultOTX", return_value=otx):
            result = check_ip_reputation({"extract_urls": {"domains": ["evil.com"]}})
        entry = result["output"]["ip_reputation"]["evil.com"]
        self.assertEqual(entry["ip"], "1.2.3.4")
        self.assertEqual(entry["aggregate_score"], (80 + 5 + 30) // 3)
        self.assertTrue(entry["malicious"])
        self.assertEqual(result["confidence"], 85)

    @patch("socket.gethostbyname", side_effect=OSError("nxdomain"))
    def test_dns_failure_uses_fallback_ip(self, mock_dns):
        vt = MagicMock()
        vt.check_ip.return_value = {"reputation": "unknown", "score": 0}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AbuseIPDB", return_value=MagicMock()
        ), patch("skills.reputation.AlienVaultOTX", return_value=MagicMock()):
            result = check_ip_reputation({"extract_urls": {"domains": ["nx.example"]}})
        self.assertEqual(result["output"]["ip_reputation"]["nx.example"]["ip"], "0.0.0.0")

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_check_exception_is_skipped(self, mock_dns):
        vt = MagicMock()
        vt.check_ip.side_effect = RuntimeError("boom")
        abuse = MagicMock()
        abuse.check_ip.return_value = {"reputation": "unknown", "score": 0}
        otx = MagicMock()
        otx.check_ip.return_value = {"reputation": "safe", "score": 0}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AbuseIPDB", return_value=abuse
        ), patch("skills.reputation.AlienVaultOTX", return_value=otx):
            result = check_ip_reputation({"extract_urls": {"domains": ["a.com"]}})
        self.assertEqual(result["output"]["ip_reputation"]["a.com"]["aggregate_score"], 0)


class TestCheckFileReputation(unittest.TestCase):
    def test_empty_content(self):
        result = check_file_reputation({"ingest": {"content": ""}})
        self.assertEqual(result["output"]["file_reputation"], {})
        self.assertEqual(result["output"]["malicious_count"], 0)
        self.assertEqual(result["confidence"], 15)

    def test_content_with_all_checks(self):
        vt = MagicMock()
        vt.check_file_hash.return_value = {"reputation": "malicious", "score": 90}
        otx = MagicMock()
        otx.check_hash.return_value = {"reputation": "suspicious", "score": 30}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AlienVaultOTX", return_value=otx
        ):
            result = check_file_reputation({"ingest": {"content": "malware payload"}})
        output = result["output"]
        self.assertEqual(output["malicious_count"], 1)
        self.assertEqual(output["suspicious_count"], 1)
        self.assertTrue(output["file_reputation"]["malicious"])
        self.assertIn("sha256", output["file_reputation"])
        self.assertEqual(result["confidence"], 75)

    def test_content_with_failed_checks(self):
        vt = MagicMock()
        vt.check_file_hash.side_effect = RuntimeError("boom")
        otx = MagicMock()
        otx.check_hash.side_effect = RuntimeError("boom")
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AlienVaultOTX", return_value=otx
        ):
            result = check_file_reputation({"ingest": {"content": "abc"}})
        self.assertEqual(result["output"]["safe_count"], 0)
        self.assertEqual(result["output"]["file_reputation"]["aggregate_score"], 0)

    def test_safe_checks_count(self):
        vt = MagicMock()
        vt.check_file_hash.return_value = {"reputation": "safe", "score": 0}
        otx = MagicMock()
        otx.check_hash.return_value = {"reputation": "safe", "score": 0}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AlienVaultOTX", return_value=otx
        ):
            result = check_file_reputation({"ingest": {"content": "clean body"}})
        self.assertEqual(result["output"]["safe_count"], 2)


class TestThreatIntelLookup(unittest.TestCase):
    def test_empty_urls_and_domains(self):
        result = threat_intel_lookup({"extract_urls": {"urls": [], "domains": []}})
        self.assertEqual(result["output"]["threat_intel"], [])
        self.assertEqual(result["confidence"], 30)

    def test_malicious_url_collected(self):
        vt = MagicMock()
        vt.check_url.return_value = {"reputation": "malicious", "score": 90}
        otx = MagicMock()
        otx.check_url.return_value = {"reputation": "safe", "score": 0}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AlienVaultOTX", return_value=otx
        ):
            result = threat_intel_lookup({"extract_urls": {"urls": ["https://evil.com/x"], "domains": []}})
        self.assertEqual(len(result["output"]["threat_intel"]), 1)
        self.assertEqual(result["output"]["threat_intel"][0]["type"], "url")
        self.assertEqual(result["confidence"], 80)

    def test_suspicious_domain_collected(self):
        vt = MagicMock()
        vt.check_url.return_value = {"reputation": "safe", "score": 0}
        otx = MagicMock()
        otx.check_url.return_value = {"reputation": "safe", "score": 0}
        otx.check_domain.return_value = {"reputation": "suspicious", "score": 40}
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AlienVaultOTX", return_value=otx
        ):
            result = threat_intel_lookup(
                {"extract_urls": {"urls": ["https://site.com"], "domains": ["phish.example"]}}
            )
        self.assertEqual(len(result["output"]["threat_intel"]), 1)
        self.assertEqual(result["output"]["threat_intel"][0]["type"], "domain")

    def test_lookup_exception_skipped(self):
        vt = MagicMock()
        vt.check_url.side_effect = RuntimeError("boom")
        otx = MagicMock()
        otx.check_url.side_effect = RuntimeError("boom")
        otx.check_domain.side_effect = RuntimeError("boom")
        with patch("skills.reputation.VirusTotal", return_value=vt), patch(
            "skills.reputation.AlienVaultOTX", return_value=otx
        ):
            result = threat_intel_lookup(
                {"extract_urls": {"urls": ["https://a.com"], "domains": ["b.com"]}}
            )
        self.assertEqual(result["output"]["threat_intel"], [])


class TestPhishingValidation(unittest.TestCase):
    def test_clean_payload(self):
        result = phishing_validation({"extract_urls": {"urls": ["https://trusted.com"]}, "validate_spf_dkim": {}})
        self.assertFalse(result["output"]["phishing_likely"])
        self.assertEqual(result["output"]["risk_contributors"], [])
        self.assertEqual(result["confidence"], 40)

    def test_brand_impersonation_and_missing_ssl(self):
        result = phishing_validation(
            {"extract_urls": {"urls": ["http://login.paypal.evil.com/verify"]}, "validate_spf_dkim": {}}
        )
        signals = result["output"]["phishing_signals"]
        self.assertTrue(signals["brand_impersonation"])
        self.assertTrue(signals["missing_ssl"])
        self.assertIn("paypal", signals["impersonated_brands"])
        self.assertTrue(result["output"]["phishing_likely"])
        self.assertEqual(result["confidence"], 80)

    def test_brand_obfuscated_with_dash(self):
        result = phishing_validation(
            {"extract_urls": {"urls": ["https://wells-fargo-secure.evil.com"]}, "validate_spf_dkim": {}}
        )
        signals = result["output"]["phishing_signals"]
        self.assertTrue(signals["brand_impersonation"])
        self.assertIn("wells fargo", signals["impersonated_brands"])

    def test_spoofed_header_signal(self):
        result = phishing_validation(
            {"extract_urls": {"urls": []}, "validate_spf_dkim": {"is_spoofed": True}}
        )
        self.assertTrue(result["output"]["phishing_signals"]["header_mismatch"])

    def test_exact_brand_domain_not_flagged(self):
        result = phishing_validation(
            {"extract_urls": {"urls": ["https://www.microsoft.com"]}, "validate_spf_dkim": {}}
        )
        self.assertFalse(result["output"]["phishing_signals"]["brand_impersonation"])

    def test_url_without_scheme(self):
        result = phishing_validation(
            {"extract_urls": {"urls": ["login.microsoft.evil.com"]}, "validate_spf_dkim": {}}
        )
        self.assertTrue(result["output"]["phishing_signals"]["brand_impersonation"])


if __name__ == "__main__":
    unittest.main()
