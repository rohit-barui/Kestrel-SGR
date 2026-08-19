import unittest

from skills.perception import (
    detect_typo_squatting,
    enrich_dns,
    enrich_external,
    extract_archive_password,
    extract_entities,
    extract_urls,
    ingest_payload,
    scan_qr_codes,
    whois_lookup,
)


class TestPerception(unittest.TestCase):
    def test_ingest_email(self):
        result = ingest_payload({"email": "Hello world"})
        self.assertEqual(result["output"]["type"], "email")
        self.assertEqual(result["output"]["content"], "Hello world")

    def test_ingest_sms(self):
        result = ingest_payload({"sms": "Hello via sms"})
        self.assertEqual(result["output"]["type"], "sms")
        self.assertEqual(result["output"]["content"], "Hello via sms")

    def test_ingest_voice(self):
        result = ingest_payload({"voice": "Hello via voice"})
        self.assertEqual(result["output"]["type"], "voice")
        self.assertEqual(result["output"]["content"], "Hello via voice")

    def test_ingest_prefers_email(self):
        result = ingest_payload({"__entry__": {"email": "e", "sms": "s"}})
        self.assertEqual(result["output"]["type"], "email")

    def test_ingest_unsupported_raises(self):
        with self.assertRaises(ValueError):
            ingest_payload({"fax": "nope"})

    def test_ingest_empty_raises(self):
        with self.assertRaises(ValueError):
            ingest_payload({})

    def test_ingest_urls_list(self):
        result = ingest_payload({"urls": ["https://evil.com", "https://phish.xyz"]})
        self.assertEqual(result["output"]["type"], "email")
        self.assertIn("https://evil.com", result["output"]["content"])
        self.assertIn("https://phish.xyz", result["output"]["content"])

    def test_ingest_urls_string(self):
        result = ingest_payload({"urls": "https://evil.com"})
        self.assertEqual(result["output"]["type"], "email")
        self.assertIn("https://evil.com", result["output"]["content"])

    def test_extract_urls(self):
        payload = {"ingest": {"content": "Visit https://example.com and http://test.org"}}
        result = extract_urls(payload)
        self.assertIn("https://example.com", result["output"]["urls"])
        self.assertIn("http://test.org", result["output"]["urls"])

    def test_extract_urls_no_urls(self):
        result = extract_urls({"ingest": {"content": "no links here"}})
        self.assertEqual(result["output"]["urls"], [])
        self.assertEqual(result["confidence"], 30)

    def test_scan_qr_codes(self):
        payload = {"ingest": {"content": "Here is a link [QR:https://phish.com]"}}
        result = scan_qr_codes(payload)
        self.assertEqual(result["output"]["qr_urls"], ["https://phish.com"])

    def test_scan_qr_codes_none(self):
        result = scan_qr_codes({"ingest": {"content": "no qr"}})
        self.assertEqual(result["output"]["qr_urls"], [])
        self.assertEqual(result["confidence"], 20)

    def test_extract_archive_password(self):
        payload = {"ingest": {"content": "The zip is protected, password: Secret123"}}
        result = extract_archive_password(payload)
        self.assertEqual(result["output"]["archive_password"], "Secret123")

    def test_extract_archive_password_none(self):
        result = extract_archive_password({"ingest": {"content": "no password mentioned"}})
        self.assertEqual(result["output"]["archive_password"], "")
        self.assertEqual(result["confidence"], 10)

    def test_whois_lookup_cache(self):
        payload = {"extract_urls": {"domains": ["example.com"]}}
        first = whois_lookup(payload)
        second = whois_lookup(payload)
        self.assertEqual(first, second)

    def test_whois_lookup_empty_domains(self):
        result = whois_lookup({"extract_urls": {}})
        self.assertEqual(result["output"]["whois"], {})
        self.assertEqual(result["confidence"], 10)

    def test_whois_lookup_miss_populates_cache(self):
        import uuid
        domain = f"miss-{uuid.uuid4().hex[:8]}.io"
        payload = {"extract_urls": {"domains": [domain]}}
        result = whois_lookup(payload)
        self.assertIn(domain, result["output"]["whois"])
        self.assertEqual(result["confidence"], 85)

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

    def test_detect_typo_squatting_empty_domain(self):
        result = detect_typo_squatting({"extract_urls": {"domains": [""]}})
        self.assertEqual(result["output"]["typo_squatting"], [])
        self.assertEqual(result["confidence"], 20)

    def test_enrich_external_with_domains(self):
        payload = {"extract_urls": {"domains": ["example.com"], "urls": ["https://example.com"]}}
        result = enrich_external(payload)
        self.assertIn("dns_real", result["output"])
        self.assertIn("whois_real", result["output"])
        self.assertIn("url_analysis", result["output"])
        self.assertEqual(result["confidence"], 85)

    def test_enrich_external_no_domains(self):
        payload = {"extract_urls": {"urls": []}}
        result = enrich_external(payload)
        self.assertEqual(result["confidence"], 30)

    def test_extract_entities(self):
        content = "contact dev@example.com or visit https://corp.example.org"
        result = extract_entities({"ingest": {"content": content}})
        self.assertEqual(result["output"]["entities_extracted"], 2)
        self.assertEqual(result["output"]["emails"], ["dev@example.com"])
        self.assertEqual(result["output"]["domains"], ["corp.example.org"])

    def test_extract_entities_empty(self):
        result = extract_entities({"ingest": {"content": "nothing here"}})
        self.assertEqual(result["output"]["entities_extracted"], 0)
        self.assertEqual(result["output"]["emails"], [])
        self.assertEqual(result["output"]["domains"], [])

if __name__ == "__main__":
    unittest.main()
