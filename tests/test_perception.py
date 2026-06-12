import unittest
from skills.perception import (
    ingest_payload,
    extract_urls,
    scan_qr_codes,
    extract_archive_password,
    whois_lookup,
    enrich_dns,
    detect_typo_squatting,
)

class TestPerception(unittest.TestCase):
    def test_ingest_email(self):
        result = ingest_payload({"email": "Hello world"})
        self.assertEqual(result["output"]["type"], "email")
        self.assertEqual(result["output"]["content"], "Hello world")

    def test_extract_urls(self):
        payload = {"ingest": {"content": "Visit https://example.com and http://test.org"}}
        result = extract_urls(payload)
        self.assertIn("https://example.com", result["output"]["urls"])
        self.assertIn("http://test.org", result["output"]["urls"])

    def test_scan_qr_codes(self):
        payload = {"ingest": {"content": "Here is a link [QR:https://phish.com]"}}
        result = scan_qr_codes(payload)
        self.assertEqual(result["output"]["qr_urls"], ["https://phish.com"])

    def test_extract_archive_password(self):
        payload = {"ingest": {"content": "The zip is protected, password: Secret123"}}
        result = extract_archive_password(payload)
        self.assertEqual(result["output"]["archive_password"], "Secret123")

    def test_whois_lookup_cache(self):
        payload = {"extract_urls": {"domains": ["example.com"]}}
        first = whois_lookup(payload)
        second = whois_lookup(payload)
        self.assertEqual(first, second)

    def test_enrich_dns(self):
        payload = {"extract_urls": {"domains": ["example.com"]}}
        result = enrich_dns(payload)
        self.assertIn("example.com", result["output"]["dns"])
        self.assertIn("A", result["output"]["dns"]["example.com"])

    def test_detect_typo_squatting(self):
        payload = {"extract_urls": {"domains": ["examp1e.com", "legit.com"]}}
        result = detect_typo_squatting(payload)
        self.assertIn("examp1e.com", result["output"]["typo_squatting"])
        self.assertNotIn("legit.com", result["output"]["typo_squatting"])

if __name__ == "__main__":
    unittest.main()
