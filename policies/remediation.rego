package apcs.remediation

default allow = false

allow {
    input.risk_score < 30
    not input.is_spoofed
    input.malicious_count == 0
}

allow {
    input.risk_score < 60
    input.confidence >= 70
    not input.is_spoofed
    input.malicious_count == 0
    input.suspicious_count == 0
    input.archive_password == ""
}

allow {
    input.risk_score < 60
    input.ml_risk_score < 40
    input.ml_confidence >= 70
    not input.is_spoofed
    input.malicious_count == 0
    input.spf_result != "fail"
    input.dmarc_result != "fail"
}

allow {
    input.is_whitelisted
    not input.is_spoofed
    input.malicious_count == 0
}