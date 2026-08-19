import unittest
from unittest.mock import patch

from core.detonation import (
    _fetch_url,
    check_url_reputation,
    detonate_urls,
    detonation_skill,
)


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestFetchUrl(unittest.TestCase):
    def test_fetch_success(self):
        with patch("core.detonation.urllib.request.urlopen", return_value=FakeResponse(b'{"a": 1}')):
            self.assertEqual(_fetch_url("https://x.com"), {"a": 1})

    def test_fetch_failure(self):
        with patch("core.detonation.urllib.request.urlopen", side_effect=OSError("boom")):
            self.assertIsNone(_fetch_url("https://x.com"))

    def test_fetch_invalid_json(self):
        with patch("core.detonation.urllib.request.urlopen", return_value=FakeResponse(b"not-json")):
            self.assertIsNone(_fetch_url("https://x.com"))


class TestCheckUrlReputation(unittest.TestCase):
    def test_safe_url(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("https://trusted.com")
        self.assertEqual(result["reputation"], "safe")
        self.assertEqual(result["score"], 0)

    def test_long_domain(self):
        long_domain = "a" * 40 + ".com"
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation(f"https://{long_domain}")
        self.assertGreaterEqual(result["score"], 15)

    def test_excessive_subdomains(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("https://a.b.c.d.e.com")
        self.assertGreaterEqual(result["score"], 10)

    def test_suspicious_keywords(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("https://secure-login.example.com")
        self.assertGreaterEqual(result["score"], 20)
        self.assertGreaterEqual(result["score"], 20)

    def test_ip_based_url(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("https://192.168.1.1/admin")
        self.assertGreaterEqual(result["score"], 25)

    def test_non_https(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("http://example.com")
        self.assertGreaterEqual(result["score"], 10)

    def test_shortener(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("https://bit.ly/abc123")
        self.assertGreaterEqual(result["score"], 15)

    def test_malicious_aggregate(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("http://secure-login.verify-bank.123.456.7.8/bit.ly")
        self.assertEqual(result["reputation"], "malicious")

    def test_cyberwatch_reputation_updates(self):
        cw = {"score": 40}
        with patch("core.detonation._fetch_url", return_value=cw):
            result = check_url_reputation("https://trusted.com")
        self.assertIn("cyberwatch", result["sources"])
        self.assertGreater(result["score"], 0)
        self.assertEqual(len(result["detonation_links"]), 1)

    def test_url_without_scheme_uses_path(self):
        with patch("core.detonation._fetch_url", return_value=None):
            result = check_url_reputation("example.com/path")
        self.assertEqual(result["domain"], "example.com")


class TestDetonateUrls(unittest.TestCase):
    def test_empty(self):
        result = detonate_urls([])
        self.assertEqual(result["total_urls"], 0)
        self.assertEqual(result["aggregate_score"], 0)

    def test_multiple(self):
        with patch("core.detonation.check_url_reputation", side_effect=[
            {"reputation": "malicious", "score": 100},
            {"reputation": "suspicious", "score": 30},
            {"reputation": "safe", "score": 0},
        ]):
            result = detonate_urls(["a", "b", "c"])
        self.assertEqual(result["malicious_count"], 1)
        self.assertEqual(result["suspicious_count"], 1)
        self.assertEqual(result["safe_count"], 1)
        self.assertEqual(result["aggregate_score"], 43)


class TestDetonationSkill(unittest.TestCase):
    def test_no_urls(self):
        result = detonation_skill({"extract_urls": {"urls": []}})
        self.assertEqual(result["output"]["detonation"]["total_urls"], 0)
        self.assertEqual(result["confidence"], 10)

    def test_with_urls(self):
        with patch("core.detonation.detonate_urls", return_value={
            "total_urls": 1,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 1,
            "results": [{"url": "https://x.com", "reputation": "safe", "score": 0}],
            "aggregate_score": 0,
        }):
            result = detonation_skill({"extract_urls": {"urls": ["https://x.com"]}})
        self.assertEqual(result["output"]["detonation"]["aggregate_score"], 0)
        self.assertEqual(result["confidence"], 100)


if __name__ == "__main__":
    unittest.main()
