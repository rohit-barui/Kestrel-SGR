import pytest
from core.email_parser import parse_email

RAW_SIMPLE = """From: alice@example.com\nSubject: Test\n\nHello World"""

RAW_MULTIPART = """From: bob@example.com\nSubject: Multipart\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"BOUNDARY\"\n\n--BOUNDARY\nContent-Type: text/plain; charset=\"utf-8\"\n\nPlain part\n--BOUNDARY\nContent-Type: text/html; charset=\"utf-8\"\n\n<html><body>HTML part</body></html>\n--BOUNDARY--"""

def test_parse_simple():
    result = parse_email(RAW_SIMPLE)
    assert result["from"] == "alice@example.com"
    assert result["subject"] == "Test"
    assert result["body"].strip() == "Hello World"
    assert result["spf"] == "neutral"
    assert "From" in result["headers"]

def test_parse_multipart():
    result = parse_email(RAW_MULTIPART)
    assert result["from"] == "bob@example.com"
    assert result["subject"] == "Multipart"
    # Should pick the text/plain part
    assert "Plain part" in result["body"]
    assert result["spf"] == "neutral"

def test_spf_detection_pass():
    raw = RAW_SIMPLE + "\nReceived: by mx.example.com spf=pass"
    result = parse_email(raw)
    assert result["spf"] == "pass"

def test_spf_detection_fail():
    raw = RAW_SIMPLE + "\nReceived: by mx.example.com spf=fail"
    result = parse_email(raw)
    assert result["spf"] == "fail"

def test_malformed_input_returns_fallback():
    # Pass a non‑string (e.g., None) to trigger the except block
    result = parse_email(None)  # type: ignore
    assert result["from"] == ""
    assert result["subject"] == ""
    assert result["body"] is None or result["body"] == ""
    assert result["headers"] == {}
    assert result["spf"] == "neutral"
