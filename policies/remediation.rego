package apcs.remediation

default allow = false

allow {
    (input.risk_score >= 70) || (input.confidence > 80 && not input.is_whitelisted) || (input.archive_password != "")
}
