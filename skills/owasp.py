import logging
import re
from typing import Any

logger = logging.getLogger("apcs")

OWASP_PATTERNS = [
    {
        "id": "xss-reflected",
        "name": "Reflected XSS",
        "owasp_category": "A03:2021 – Injection",
        "severity": "high",
        "pattern": r"<script[^>]*>.*?</script>",
        "description": "Inline script tags in input or URL",
    },
    {
        "id": "xss-event",
        "name": "DOM-based XSS via event handler",
        "owasp_category": "A03:2021 – Injection",
        "severity": "high",
        "pattern": r"on\w+\s*=\s*['\"].*?(?:alert|prompt|confirm|eval|document\.cookie)",
        "description": "Event handler with JavaScript execution",
    },
    {
        "id": "sql-injection",
        "name": "SQL Injection",
        "owasp_category": "A03:2021 – Injection",
        "severity": "critical",
        "pattern": r"['\";].*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|xp_cmdshell)\s",
        "description": "SQL metacharacters with SQL keywords",
    },
    {
        "id": "open-redirect",
        "name": "Open Redirect",
        "owasp_category": "A01:2021 – Broken Access Control",
        "severity": "medium",
        "pattern": r"(?:redirect|return|next|url|link|goto|target|to|continue|dest)\s*=\s*(?:https?://|//)",
        "description": "Unvalidated redirect parameters pointing to external URLs",
    },
    {
        "id": "path-traversal",
        "name": "Path Traversal",
        "owasp_category": "A01:2021 – Broken Access Control",
        "severity": "high",
        "pattern": r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c)",
        "description": "Directory traversal sequences",
    },
    {
        "id": "command-injection",
        "name": "OS Command Injection",
        "owasp_category": "A03:2021 – Injection",
        "severity": "critical",
        "pattern": r"(?:\||;|`|\$\().*(?:cmd|powershell|bash|sh|exec|wget|curl|nc)\s",
        "description": "Shell metacharacters with command execution attempts",
    },
    {
        "id": "csrf-weak",
        "name": "CSRF Weak Token Pattern",
        "owasp_category": "A01:2021 – Broken Access Control",
        "severity": "medium",
        "pattern": r"(?:csrf|csrf_token|_token)\s*=\s*['\"]?\d{1,6}['\"]?",
        "description": "Weak or predictable CSRF token (short numeric)",
    },
    {
        "id": "ldap-injection",
        "name": "LDAP Injection",
        "owasp_category": "A03:2021 – Injection",
        "severity": "high",
        "pattern": r"[()&|!=>~*].*(?:ldap|cn=|dc=|ou=)\s",
        "description": "LDAP filter syntax with directory path",
    },
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery",
        "owasp_category": "A10:2021 – SSRF",
        "severity": "high",
        "pattern": r"(?:url|uri|fetch|proxy|load|import|include)\s*=\s*(?:https?://)(?:127\.0\.0\.1|localhost|169\.254|10\.|172\.(?:1[6-9]|2\d|3[01])|192\.168)",
        "description": "Parameters pointing to internal/private IPs",
    },
    {
        "id": "data-uri-xss",
        "name": "Data URI Injection",
        "owasp_category": "A03:2021 – Injection",
        "severity": "high",
        "pattern": r"data:\s*text/html[^,]*base64,",
        "description": "Base64-encoded data URI with HTML content",
    },
]


def owasp_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    urls = payload.get("extract_urls", {}).get("urls", [])
    content = payload.get("ingest", {}).get("content", "")
    domains = payload.get("extract_urls", {}).get("domains", [])

    findings = []

    scan_texts = list(urls) + [content] + list(domains)

    for text in scan_texts:
        if not text:
            continue
        for rule in OWASP_PATTERNS:
            if re.search(rule["pattern"], text, re.IGNORECASE | re.DOTALL):
                findings.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "owasp_category": rule["owasp_category"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "matched_in": text[:200],
                })

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 0), reverse=True)

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    risk_score = min(
        by_severity["critical"] * 30 + by_severity["high"] * 15 +
        by_severity["medium"] * 8 + by_severity["low"] * 3,
        100
    )

    return {
        "output": {
            "owasp_findings": findings,
            "by_severity": by_severity,
            "risk_score": risk_score,
            "total_findings": len(findings),
        },
        "confidence": 90 if findings else 60,
    }
