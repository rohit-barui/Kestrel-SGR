import unittest

from skills.owasp import OWASP_PATTERNS, owasp_analysis


class TestOwaspPatterns(unittest.TestCase):
    def test_pattern_count(self):
        self.assertGreaterEqual(len(OWASP_PATTERNS), 10)

    def test_all_patterns_have_required_fields(self):
        for rule in OWASP_PATTERNS:
            self.assertIn("id", rule)
            self.assertIn("name", rule)
            self.assertIn("owasp_category", rule)
            self.assertIn("severity", rule)
            self.assertIn("pattern", rule)


class TestOwaspAnalysis(unittest.TestCase):
    def test_empty_payload(self):
        result = owasp_analysis({"extract_urls": {"urls": [], "domains": []}, "ingest": {}})
        self.assertEqual(result["output"]["owasp_findings"], [])
        self.assertEqual(result["output"]["risk_score"], 0)
        self.assertEqual(result["confidence"], 60)

    def test_no_matches(self):
        result = owasp_analysis(
            {"extract_urls": {"urls": ["https://trusted.com"], "domains": []}, "ingest": {"content": "plain text"}}
        )
        self.assertEqual(result["output"]["total_findings"], 0)

    def test_sql_injection_critical(self):
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": "'; SELECT * FROM users WHERE id=1"}}
        )
        output = result["output"]
        self.assertGreaterEqual(output["total_findings"], 1)
        self.assertEqual(output["by_severity"]["critical"], 1)
        self.assertEqual(output["risk_score"], 30)
        self.assertEqual(result["confidence"], 90)

    def test_xss_and_open_redirect(self):
        content = "<script>alert(1)</script>?redirect=https://evil.com"
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": content}}
        )
        output = result["output"]
        ids = {f["id"] for f in output["owasp_findings"]}
        self.assertIn("xss-reflected", ids)
        self.assertIn("open-redirect", ids)

    def test_findings_sorted_by_severity(self):
        content = "http://evil.com/path?next=https://evil.com <script>x</script> ../etc"
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": content}}
        )
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        severities = [f["severity"] for f in result["output"]["owasp_findings"]]
        self.assertEqual(severities, sorted(severities, key=lambda s: order.get(s, 0), reverse=True))

    def test_command_injection(self):
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": "| powershell -c whoami"}}
        )
        ids = {f["id"] for f in result["output"]["owasp_findings"]}
        self.assertIn("command-injection", ids)

    def test_csrf_weak_token(self):
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": "csrf_token=123456"}}
        )
        ids = {f["id"] for f in result["output"]["owasp_findings"]}
        self.assertIn("csrf-weak", ids)

    def test_risk_score_capped_at_100(self):
        content = "SELECT 1 OR 1; <script>x</script> | bash -c ls ..%2f ..%5c"
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": content}}
        )
        self.assertLessEqual(result["output"]["risk_score"], 100)

    def test_matched_in_truncated(self):
        long_content = "A" * 500 + "<script>bad</script>"
        result = owasp_analysis(
            {"extract_urls": {"urls": [], "domains": []}, "ingest": {"content": long_content}}
        )
        for finding in result["output"]["owasp_findings"]:
            self.assertLessEqual(len(finding["matched_in"]), 200)


if __name__ == "__main__":
    unittest.main()
