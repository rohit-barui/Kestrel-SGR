"""Notification dispatcher for APCS alerts."""

import json
import logging
import os
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class Notifier:
    def __init__(self, config_path: str | None = None):
        self.config = self._load_config(config_path or os.environ.get("APCS_NOTIFY_CONFIG", ""))

    def _load_config(self, path: str) -> dict[str, Any]:
        if path and os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return {}

    def send_slack(self, webhook_url: str, message: str) -> bool:
        try:
            payload = json.dumps({"text": message}).encode()
            req = Request(webhook_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning("Slack notification failed: %s", e)
            return False

    def send_email(self, smtp_config: dict[str, Any], subject: str, body: str) -> bool:
        try:
            import smtplib
            from email.message import EmailMessage
            msg = EmailMessage()
            msg.set_content(body)
            msg["Subject"] = subject
            msg["From"] = smtp_config.get("from", "apcs@localhost")
            msg["To"] = smtp_config.get("to", "")
            with smtplib.SMTP(smtp_config.get("host", "localhost"), smtp_config.get("port", 25), timeout=5) as s:
                s.send_message(msg)
            return True
        except Exception as e:
            logger.warning("Email notification failed: %s", e)
            return False

    def send_webhook(self, url: str, payload: dict[str, Any]) -> bool:
        try:
            data = json.dumps(payload).encode()
            req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
            urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning("Webhook notification failed: %s", e)
            return False

    def alert(self, scan_id: str, risk_score: float, decision: str, actions: list, dominance: dict):
        if risk_score < 70:
            return
        message = (
            f"[APCS Alert] High-risk scan detected\n"
            f"Scan ID: {scan_id}\n"
            f"Risk Score: {risk_score}\n"
            f"Decision: {decision}\n"
            f"Actions: {', '.join(actions)}\n"
        )
        if dominance:
            if dominance.get("blocked_ips"):
                message += f"Blocked IPs: {', '.join(dominance['blocked_ips'])}\n"
            if dominance.get("quarantined"):
                message += "Email quarantined\n"
            if dominance.get("mfa_reset"):
                message += "MFA reset triggered\n"

        slack_url = self.config.get("slack_webhook", os.environ.get("SLACK_WEBHOOK", ""))
        if slack_url:
            self.send_slack(slack_url, message)

        smtp = self.config.get("smtp", {})
        if smtp.get("to"):
            self.send_email(smtp, f"APCS Alert - Risk {risk_score}", message)

        webhook_url = self.config.get("webhook", os.environ.get("ALERT_WEBHOOK", ""))
        if webhook_url:
            payload = {
                "scan_id": scan_id,
                "risk_score": risk_score,
                "decision": decision,
                "actions": actions,
                "dominance": dominance,
            }
            self.send_webhook(webhook_url, payload)

        if risk_score >= 80:
            from core.siem_connectors import send_to_siem
            send_to_siem({
                "scan_id": scan_id,
                "risk_score": risk_score,
                "decision": decision,
                "actions": actions,
                "dominance": dominance,
            })

notifier = Notifier()
