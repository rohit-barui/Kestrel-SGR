import unittest

from core.red_team import generate_all, generate_ceo_fraud, generate_credential_harvester, generate_malware_drop


class TestRedTeam(unittest.TestCase):
    def test_ceo_fraud_has_email(self):
        payload = generate_ceo_fraud()
        self.assertIn("email", payload)
        self.assertIn("ceo", payload["email"].lower())

    def test_credential_harvester_has_url(self):
        payload = generate_credential_harvester()
        self.assertIn("https://", payload["email"])
        self.assertIn("password", payload["email"])

    def test_malware_drop_has_exe(self):
        payload = generate_malware_drop()
        self.assertIn(".exe", payload["email"])
        self.assertIn("password", payload["email"])

    def test_generate_all_returns_dict(self):
        all_payloads = generate_all()
        self.assertEqual(len(all_payloads), 3)
        self.assertIn("ceo_fraud", all_payloads)
        self.assertIn("credential_harvester", all_payloads)
        self.assertIn("malware_drop", all_payloads)

if __name__ == "__main__":
    unittest.main()
