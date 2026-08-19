import hashlib
import hmac
import unittest
from unittest.mock import patch

from core.webhooks import WebhookHandler


class TestWebhookHandler(unittest.TestCase):
    def setUp(self):
        self.handler = WebhookHandler()

    def test_phishing_report(self):
        result = self.handler.process("phishing_report", {"email": "test@phish.com", "url": "https://phish.xyz"})
        self.assertEqual(result["status"], "accepted")

    def test_phishing_report_without_email_uses_url(self):
        result = self.handler.process("phishing_report", {"url": "https://phish.xyz"})
        self.assertEqual(result["status"], "accepted")
        self.assertIn("https://phish.xyz", result["scan_payload"]["email"])

    def test_phishing_report_no_fields(self):
        result = self.handler.process("phishing_report", {})
        self.assertEqual(result["status"], "accepted")

    def test_siem_alert(self):
        result = self.handler.process("siem_alert", {"message": "malware detected", "source_ip": "10.0.0.5"})
        self.assertEqual(result["status"], "accepted")
        self.assertIn("10.0.0.5", result["scan_payload"]["email"])
        self.assertIn("malware detected", result["scan_payload"]["email"])

    def test_siem_alert_default_source_ip(self):
        result = self.handler.process("siem_alert", {"message": "alert"})
        self.assertEqual(result["status"], "accepted")
        self.assertIn("unknown", result["scan_payload"]["email"])

    def test_unknown_event(self):
        result = self.handler.process("unknown_type", {})
        self.assertEqual(result["status"], "error")
        self.assertIn("Unknown event type", result["message"])

    def test_handler_exception_returns_error(self):
        def broken_handler(payload):
            raise ValueError("boom")
        self.handler.register("broken", broken_handler)
        result = self.handler.process("broken", {})
        self.assertEqual(result["status"], "error")
        self.assertIn("boom", result["message"])

    def test_register_overwrites(self):
        def new_handler(payload):
            return {"status": "custom"}
        self.handler.register("siem_alert", new_handler)
        result = self.handler.process("siem_alert", {})
        self.assertEqual(result["status"], "custom")

    def test_verify_signature_no_secret_allows(self):
        # When SECRET is empty, signatures are accepted without verification
        with patch("core.webhooks.SECRET", ""):
            self.assertTrue(self.handler.verify_signature(b"{}", "anything"))

    def test_verify_signature_valid(self):
        secret = "my-secret"
        payload = b'{"a": 1}'
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        with patch("core.webhooks.SECRET", secret):
            self.assertTrue(self.handler.verify_signature(payload, expected))

    def test_verify_signature_invalid(self):
        secret = "my-secret"
        payload = b'{"a": 1}'
        with patch("core.webhooks.SECRET", secret):
            self.assertFalse(self.handler.verify_signature(payload, "deadbeef"))

    def test_phishing_creates_scan_payload(self):
        result = self.handler.process("phishing_report", {"email": "suspicious email body"})
        self.assertIn("scan_payload", result)
        self.assertIn("email", result["scan_payload"])

    def test_customer_report(self):
        result = self.handler.process(
            "customer_report",
            {"email": "phish body", "reporter": "jane@acme.com", "message_id": "msg-1", "auto_remediate": True},
        )
        self.assertEqual(result["status"], "accepted")
        self.assertTrue(result["auto_remediate"])
        self.assertEqual(result["scan_payload"]["_reporter"], "jane@acme.com")
        self.assertEqual(result["scan_payload"]["_message_id"], "msg-1")
        self.assertTrue(result["scan_payload"]["_report"])

    def test_customer_report_no_message_id(self):
        result = self.handler.process("customer_report", {"email": "phish body", "reporter": "jane@acme.com"})
        self.assertEqual(result["status"], "accepted")
        self.assertNotIn("_message_id", result["scan_payload"])

    def test_customer_report_missing_fields(self):
        result = self.handler.process("customer_report", {"reporter": "jane@acme.com"})
        self.assertEqual(result["status"], "error")
        self.assertIn("No email content or message_id", result["message"])


if __name__ == "__main__":
    unittest.main()
