from typing import Dict, Any

def generate_ceo_fraud() -> Dict[str, Any]:
    return {
        "email": (
            "From: ceo@cornpany.com\n"
            "Subject: Urgent: wire transfer needed\n\n"
            "Hi, I'm in a meeting and need $50K wired to vendor ASAP.\n"
            "Account: 123456789, routing: 987654321.\n"
            "Password: urgent2024\n"
            "Reply urgently."
        )
    }

def generate_credential_harvester() -> Dict[str, Any]:
    return {
        "email": (
            "From: support@secure-login.xyz\n"
            "Subject: Verify your account\n\n"
            "Dear user, your account has been compromised.\n"
            "Click here to secure it: https://secure-login.xyz/verify\n"
            "[QR:https://phish.xyz/scan]\n"
            "password: verify2024"
        )
    }

def generate_malware_drop() -> Dict[str, Any]:
    return {
        "email": (
            "From: billing@mycompay.co\n"
            "Subject: Overdue invoice #INV-4421\n\n"
            "Dear customer,\n"
            "Please find the attached invoice.\n"
            "Archive password: inv4421\n"
            "Download: https://mycompay.co/invoice.exe"
        )
    }

def generate_all() -> Dict[str, Dict[str, Any]]:
    return {
        "ceo_fraud": generate_ceo_fraud(),
        "credential_harvester": generate_credential_harvester(),
        "malware_drop": generate_malware_drop(),
    }
