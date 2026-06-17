import re

# Regular expressions for common PII patterns
_SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Simplistic credit card regex: 16 digits, optionally separated by spaces or dashes
_CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
# API key pattern: a sequence of uppercase letters/digits of length >= 12
_APIKEY_REGEX = re.compile(r"\b[A-Z0-9]{12,}\b")

def redact_pii(text: str) -> str:
    """Return *text* with detected PII replaced by ``[REDACTED]``.

    The function looks for SSNs, credit‑card numbers and generic API‑key‑like strings.
    It is deliberately simple – the goal is to mask obvious identifiers before any
    downstream processing or UI rendering.
    """
    redacted = _SSN_REGEX.sub("[REDACTED]", text)
    redacted = _CC_REGEX.sub("[REDACTED]", redacted)
    redacted = _APIKEY_REGEX.sub("[REDACTED]", redacted)
    return redacted
