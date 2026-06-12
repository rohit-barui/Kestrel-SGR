"""Email parsing utilities using stdlib email module."""

import email
import re
from typing import Dict, Any, Optional

def parse_email(raw: str) -> Dict[str, Any]:
    """Parse RFC 822 email and extract headers/body."""
    try:
        msg = email.message_from_string(raw)
        headers = dict(msg.items())
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    break
        else:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace") if msg.get_payload(decode=True) else ""
        
        from_header = headers.get("From", "")
        subject = headers.get("Subject", "")
        spf_match = re.search(r"spf=(pass|fail|neutral)", raw, re.IGNORECASE)
        
        return {
            "from": from_header,
            "subject": subject,
            "body": body,
            "headers": headers,
            "spf": spf_match.group(1) if spf_match else "neutral",
        }
    except Exception:
        return {"from": "", "subject": "", "body": raw, "headers": {}, "spf": "neutral"}
