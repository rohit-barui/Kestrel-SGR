import unittest
from core.privacy import redact_pii

class TestPrivacy(unittest.TestCase):
    def test_redact_ssn(self):
        txt = "User SSN: 123-45-6789"
        self.assertIn("[REDACTED]", redact_pii(txt))
        self.assertNotIn("123-45-6789", redact_pii(txt))

    def test_redact_credit_card(self):
        txt = "Card: 4111 1111 1111 1111"
        self.assertIn("[REDACTED]", redact_pii(txt))
        self.assertNotIn("4111", redact_pii(txt))

    def test_redact_api_key(self):
        txt = "APIKEY=ABCD1234EFGH5678"
        self.assertIn("[REDACTED]", redact_pii(txt))
        self.assertNotIn("ABCD1234EFGH5678", redact_pii(txt))

if __name__ == "__main__":
    unittest.main()
