import unittest
from core.notifications import Notifier

class TestNotifier(unittest.TestCase):
    def setUp(self):
        self.notifier = Notifier()

    def test_slack_fails_gracefully(self):
        result = self.notifier.send_slack("https://invalid.webhook.url", "test")
        self.assertFalse(result)

    def test_webhook_fails_gracefully(self):
        result = self.notifier.send_webhook("https://invalid.webhook.url", {"test": True})
        self.assertFalse(result)

    def test_alert_skips_low_risk(self):
        result = self.notifier.alert("test123", 30, "ALLOW", ["allow"], {})
        self.assertIsNone(result)

    def test_alert_high_risk_runs(self):
        result = self.notifier.alert("test123", 90, "DENY", ["block"], {"blocked_ips": ["10.0.0.1"]})
        self.assertIsNone(result)  # no crash
