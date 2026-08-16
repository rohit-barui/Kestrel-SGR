"""Webhook receiver for APCS - accepts external events to trigger scans."""

import json
import logging
import hashlib
import hmac
import os
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger("apcs")

SECRET = os.environ.get("APCS_WEBHOOK_SECRET", "")

class WebhookHandler:
    def __init__(self):
        self._handlers: Dict[str, Callable] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register("phishing_report", self._handle_phishing_report)
        self.register("siem_alert", self._handle_siem_alert)
        self.register("customer_report", self._handle_customer_report)

    def register(self, event_type: str, handler: Callable):
        self._handlers[event_type] = handler

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        if not SECRET:
            return True
        expected = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def process(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        handler = self._handlers.get(event_type)
        if not handler:
            return {"status": "error", "message": f"Unknown event type: {event_type}"}
        try:
            return handler(payload)
        except Exception as e:
            logger.error("Webhook handler %s failed: %s", event_type, e)
            return {"status": "error", "message": str(e)}

    def _handle_phishing_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        email = payload.get("email", "")
        url = payload.get("url", "")
        content = email or f"Reported phishing URL: {url}"
        return {"status": "accepted", "scan_payload": {"email": content}}

    def _handle_siem_alert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        message = payload.get("message", "")
        source_ip = payload.get("source_ip", "unknown")
        return {"status": "accepted", "scan_payload": {"email": f"SIEM alert from {source_ip}: {message}"}}

    def _handle_customer_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        email = payload.get("email", "")
        reporter = payload.get("reporter", "unknown")
        message_id = payload.get("message_id", "")
        auto_remediate = payload.get("auto_remediate", False)
        if not email and not message_id:
            return {"status": "error", "message": "No email content or message_id provided"}
        scan_payload = {"email": email, "_report": True, "_reporter": reporter}
        if message_id:
            scan_payload["_message_id"] = message_id
        return {"status": "accepted", "scan_payload": scan_payload, "auto_remediate": auto_remediate}

webhook_handler = WebhookHandler()
