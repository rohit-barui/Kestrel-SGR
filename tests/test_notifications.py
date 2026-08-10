import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from core.notifications import Notifier


class TestNotifier(unittest.TestCase):
    def setUp(self):
        self.notifier = Notifier()

    # ---- Slack ----
    @patch("core.notifications.urlopen")
    def test_slack_success(self, mock_urlopen):
        mock_urlopen.return_value.__enter__ = MagicMock()
        self.assertTrue(self.notifier.send_slack("https://hooks.slack.com/x", "hello"))

    def test_slack_fails_gracefully(self):
        self.assertFalse(self.notifier.send_slack("https://invalid.webhook.url", "test"))

    # ---- Webhook ----
    @patch("core.notifications.urlopen")
    def test_webhook_success(self, mock_urlopen):
        self.assertTrue(self.notifier.send_webhook("https://example.com/hook", {"a": 1}))

    def test_webhook_fails_gracefully(self):
        self.assertFalse(self.notifier.send_webhook("https://invalid.webhook.url", {"test": True}))

    # ---- Email ----
    def test_email_fails_gracefully(self):
        cfg = {"host": "no-such-host.invalid", "port": 25, "to": "x@y.z"}
        self.assertFalse(self.notifier.send_email(cfg, "subj", "body"))

    @patch("smtplib.SMTP")
    def test_email_success(self, mock_smtp):
        server = MagicMock()
        mock_smtp.return_value.__enter__ = MagicMock(return_value=server)
        cfg = {"host": "smtp.local", "port": 25, "from": "a@b.c", "to": "x@y.z"}
        self.assertTrue(self.notifier.send_email(cfg, "Subj", "Body"))

    @patch("smtplib.SMTP")
    def test_email_uses_defaults(self, mock_smtp):
        server = MagicMock()
        mock_smtp.return_value.__enter__ = MagicMock(return_value=server)
        # No host/from/to -> defaults used, still should succeed against the mock
        self.assertTrue(self.notifier.send_email({}, "S", "B"))

    # ---- Config loading ----
    def test_load_config_from_file(self):
        cfg = {"slack_webhook": "https://hooks.slack.com/x", "smtp": {"to": "x@y.z"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        try:
            n = Notifier(config_path=path)
            self.assertEqual(n.config["slack_webhook"], "https://hooks.slack.com/x")
        finally:
            os.unlink(path)

    def test_load_config_missing_file_returns_empty(self):
        self.assertEqual(self.notifier._load_config(""), {})
        self.assertEqual(self.notifier._load_config("nonexistent.json"), {})

    # ---- Alert branching ----
    def test_alert_skips_low_risk(self):
        self.assertIsNone(self.notifier.alert("test123", 30, "ALLOW", ["allow"], {}))

    def test_alert_high_risk_without_dominance(self):
        with patch.object(self.notifier, "send_slack") as m_slack, \
             patch.object(self.notifier, "send_webhook") as m_webhook, \
             patch("core.siem_connectors.send_to_siem") as m_siem:
            self.notifier.alert("id1", 90, "DENY", ["block"], {})
            m_slack.assert_not_called()
            m_webhook.assert_not_called()
            m_siem.assert_called_once()

    def test_alert_high_risk_with_dominance(self):
        with patch.object(self.notifier, "send_slack") as m_slack, \
             patch.object(self.notifier, "send_webhook") as m_webhook:
            dominance = {"blocked_ips": ["10.0.0.1", "10.0.0.2"], "quarantined": True, "mfa_reset": True}
            self.notifier.alert("id2", 90, "DENY", ["block"], dominance)
            m_slack.assert_not_called()
            m_webhook.assert_not_called()

    def test_alert_with_slack_and_webhook_config(self):
        self.notifier.config = {
            "slack_webhook": "https://hooks.slack.com/x",
            "webhook": "https://example.com/alert",
        }
        with patch.object(self.notifier, "send_slack") as m_slack, \
             patch.object(self.notifier, "send_webhook") as m_webhook, \
             patch("core.siem_connectors.send_to_siem") as m_siem:
            self.notifier.alert("id3", 90, "DENY", ["block"], {})
            m_slack.assert_called_once()
            m_webhook.assert_called_once()
            m_siem.assert_called_once()

    def test_alert_siem_only_for_high_score(self):
        # risk 75 triggers slack/webhook but NOT siem (threshold is >= 80)
        self.notifier.config = {"slack_webhook": "x", "webhook": "y"}
        with patch.object(self.notifier, "send_slack"), \
             patch.object(self.notifier, "send_webhook"), \
             patch("core.siem_connectors.send_to_siem") as m_siem:
            self.notifier.alert("id4", 75, "ALLOW", [], {})
            m_siem.assert_not_called()

    def test_alert_with_smtp_config(self):
        self.notifier.config = {"smtp": {"to": "x@y.z"}}
        with patch.object(self.notifier, "send_email") as m_email:
            self.notifier.alert("id5", 90, "DENY", ["block"], {})
            m_email.assert_called_once()
            self.assertEqual(m_email.call_args[0][1], "APCS Alert - Risk 90")


if __name__ == "__main__":
    unittest.main()
