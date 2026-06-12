package apcs.remediation

default allow = false

allow {
    input.risk_score >= 70
}

allow {
    input.confidence > 80
    not input.is_whitelisted
}

allow {
    input.archive_password != ""
}
