import unittest, json
from core.webhooks import WebhookHandler

class TestWebhookHandler(unittest.TestCase):
    def setUp(self):
        self.handler = WebhookHandler()

    def test_phishing_report(self):
        result = self.handler.process("phishing_report", {"email": "test@phish.com", "url": "https://phish.xyz"})
        self.assertEqual(result["status"], "accepted")

    def test_siem_alert(self):
        result = self.handler.process("siem_alert", {"message": "malware detected", "source_ip": "10.0.0.5"})
        self.assertEqual(result["status"], "accepted")

    def test_unknown_event(self):
        result = self.handler.process("unknown_type", {})
        self.assertEqual(result["status"], "error")

    def test_phishing_creates_scan_payload(self):
        result = self.handler.process("phishing_report", {"email": "suspicious email body"})
        self.assertIn("scan_payload", result)
        self.assertIn("email", result["scan_payload"])
