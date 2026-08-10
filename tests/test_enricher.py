import sys
import unittest
from unittest.mock import MagicMock, patch

from core.enricher import analyze_suspicious_urls, resolve_dns, whois_lookup_real


def socket_error(*args, **kwargs):
    raise OSError("DNS failure")


class TestEnricher(unittest.TestCase):
    def test_resolve_dns_returns_dict(self):
        result = resolve_dns("example.com")
        self.assertIn("A", result)
        self.assertIn("status", result)

    @patch("core.enricher.socket.getaddrinfo")
    def test_resolve_dns_real_path(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("1.2.3.4", 80)),
            (2, 1, 6, "", ("5.6.7.8", 80)),
        ]
        result = resolve_dns("example.com")
        self.assertEqual(result["status"], "real")
        self.assertIn("1.2.3.4", result["A"])
        self.assertIn("5.6.7.8", result["A"])

    @patch("core.enricher.socket.getaddrinfo", side_effect=socket_error)
    def test_resolve_dns_fallback_path(self, mock_getaddrinfo):
        result = resolve_dns("example.com")
        self.assertEqual(result["status"], "mock")
        self.assertIn("A", result)

    def test_whois_fallback_when_lib_missing(self):
        # Simulate the `whois` module being unavailable
        with patch.dict(sys.modules, {"whois": None}):
            result = whois_lookup_real("example.com")
            self.assertEqual(result["status"], "mock")

    def test_whois_fallback_with_exception(self):
        mock_whois = MagicMock()
        mock_whois.whois.side_effect = Exception("whois unavailable")
        with patch.dict(sys.modules, {"whois": mock_whois}):
            result = whois_lookup_real("example.com")
            self.assertEqual(result["status"], "mock")
            self.assertEqual(result["registrar"], "MockRegistrar")
            self.assertIn("creation_date", result)

    def test_whois_real_path(self):
        mock_whois = MagicMock()
        class W:
            creation_date = "2020-01-01"
            registrar = "GoDaddy"
        mock_whois.whois.return_value = W()
        with patch.dict(sys.modules, {"whois": mock_whois}):
            result = whois_lookup_real("example.com")
            self.assertEqual(result["status"], "real")
            self.assertEqual(result["registrar"], "GoDaddy")

    def test_whois_real_path_missing_fields(self):
        mock_whois = MagicMock()
        class W:
            creation_date = None
            registrar = None
        mock_whois.whois.return_value = W()
        with patch.dict(sys.modules, {"whois": mock_whois}):
            result = whois_lookup_real("example.com")
            self.assertEqual(result["status"], "real")
            self.assertEqual(result["creation_date"], "")
            self.assertEqual(result["registrar"], "")

    def test_whois_fallback(self):
        result = whois_lookup_real("nonexistent-domain-xyz.com")
        self.assertIn("domain", result)
        self.assertIn("status", result)

    def test_analyze_suspicious(self):
        results = analyze_suspicious_urls(["https://secure-login.xyz/verify"])
        self.assertEqual(len(results), 1)
        self.assertIn("suspicion_score", results[0])

    def test_analyze_long_domain(self):
        long_domain = "https://" + "a" * 40 + ".com/x"
        results = analyze_suspicious_urls([long_domain])
        self.assertGreaterEqual(results[0]["suspicion_score"], 20)
        self.assertIn("unusually long domain", results[0]["reasons"])

    def test_analyze_excessive_subdomains(self):
        results = analyze_suspicious_urls(["https://a.b.c.d.example.com"])
        self.assertIn("excessive subdomains", results[0]["reasons"])
        self.assertGreaterEqual(results[0]["suspicion_score"], 15)

    def test_analyze_suspicious_keywords(self):
        results = analyze_suspicious_urls(["https://bank2.verify-login.net/update"])
        self.assertIn("suspicious keywords in domain", results[0]["reasons"])
        self.assertGreaterEqual(results[0]["suspicion_score"], 25)

    def test_analyze_benign_url(self):
        results = analyze_suspicious_urls(["https://example.com/page"])
        self.assertEqual(results[0]["suspicion_score"], 0)
        self.assertEqual(results[0]["reasons"], [])

    def test_analyze_caps_score_at_100(self):
        # Long + subdomains + keywords -> capped at 100
        url = "https://secure1.verify2.update3.login4.account5.bank6.example.com/x"
        results = analyze_suspicious_urls([url])
        self.assertLessEqual(results[0]["suspicion_score"], 100)

    def test_analyze_empty_list(self):
        self.assertEqual(analyze_suspicious_urls([]), [])

    def test_analyze_strips_scheme(self):
        results = analyze_suspicious_urls(["http://example.com"])
        self.assertEqual(results[0]["domain"], "example.com")


class TestEmailParser(unittest.TestCase):
    def test_parse_simple(self):
        from core.email_parser import parse_email
        raw = "From: test@example.com\nSubject: Hello\n\nBody text"
        result = parse_email(raw)
        self.assertIn("from", result)
        self.assertIn("body", result)

    def test_parse_empty(self):
        from core.email_parser import parse_email
        result = parse_email("")
        self.assertIn("body", result)


if __name__ == "__main__":
    unittest.main()
