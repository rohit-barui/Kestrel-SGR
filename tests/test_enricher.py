import unittest
from core.enricher import resolve_dns, whois_lookup_real, analyze_suspicious_urls

class TestEnricher(unittest.TestCase):
    def test_resolve_dns_returns_dict(self):
        result = resolve_dns("example.com")
        self.assertIn("A", result)
        self.assertIn("status", result)
    
    def test_whois_fallback(self):
        result = whois_lookup_real("nonexistent-domain-xyz.com")
        self.assertIn("domain", result)
        self.assertIn("status", result)
    
    def test_analyze_suspicious(self):
        results = analyze_suspicious_urls(["https://secure-login.xyz/verify"])
        self.assertEqual(len(results), 1)
        self.assertIn("suspicion_score", results[0])

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
