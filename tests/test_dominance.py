import unittest
from skills.dominance import deploy_honey_credentials, rewrite_links, containment_actions, block_ip, quarantine_email, trigger_mfa_reset

class TestDominance(unittest.TestCase):
    def test_deploy_honey_creds_on_block(self):
        payload = {"recommend_actions": {"actions": ["block"]}, "apply_veto": {"risk_score": 75}}
        result = deploy_honey_credentials(payload)
        self.assertTrue(len(result["output"]["honey_credentials"]) > 0)
        self.assertIn("honey", result["output"]["honey_credentials"][0]["user"])
        self.assertEqual(result["confidence"], 90)

    def test_deploy_honey_creds_on_allow(self):
        payload = {"recommend_actions": {"actions": ["allow"]}, "apply_veto": {"risk_score": 10}}
        result = deploy_honey_credentials(payload)
        self.assertEqual(result["output"]["honey_credentials"], [])
        self.assertEqual(result["confidence"], 10)

    def test_rewrite_links_on_block(self):
        payload = {"recommend_actions": {"actions": ["block"]}, "extract_urls": {"urls": ["https://phish.xyz"]}}
        result = rewrite_links(payload)
        self.assertIn("https://phish.xyz", result["output"]["rewritten_urls"])
        self.assertIn("isolate.corp.local", result["output"]["rewritten_urls"]["https://phish.xyz"])
        self.assertEqual(result["confidence"], 85)

    def test_rewrite_links_on_allow(self):
        payload = {"recommend_actions": {"actions": ["allow"]}, "extract_urls": {"urls": ["https://example.com"]}}
        result = rewrite_links(payload)
        self.assertEqual(result["output"]["rewritten_urls"], {})
        self.assertEqual(result["confidence"], 15)

    def test_containment_block(self):
        payload = {"recommend_actions": {"actions": ["block"]}, "apply_veto": {"risk_score": 75}}
        result = containment_actions(payload)
        self.assertTrue(len(result["output"]["blocked_ips"]) > 0)
        self.assertTrue(result["output"]["quarantined"])
        self.assertFalse(result["output"]["mfa_reset"])
        self.assertEqual(result["confidence"], 95)

    def test_containment_block_high_risk_triggers_mfa(self):
        payload = {"recommend_actions": {"actions": ["block"]}, "apply_veto": {"risk_score": 90}}
        result = containment_actions(payload)
        self.assertTrue(result["output"]["mfa_reset"])
        self.assertEqual(result["confidence"], 95)

    def test_containment_allow(self):
        payload = {"recommend_actions": {"actions": ["allow"]}, "apply_veto": {"risk_score": 10}}
        result = containment_actions(payload)
        self.assertEqual(result["output"]["blocked_ips"], [])
        self.assertFalse(result["output"]["quarantined"])
        self.assertFalse(result["output"]["mfa_reset"])
        self.assertEqual(result["confidence"], 5)

    def test_containment_quarantine(self):
        payload = {"recommend_actions": {"actions": ["quarantine"]}, "apply_veto": {"risk_score": 50}}
        result = containment_actions(payload)
        self.assertEqual(result["output"]["blocked_ips"], [])
        self.assertTrue(result["output"]["quarantined"])
        self.assertEqual(result["confidence"], 95)

    def test_side_effects_present(self):
        payload = {"recommend_actions": {"actions": ["block"]}, "apply_veto": {"risk_score": 75}}
        result = deploy_honey_credentials(payload)
        self.assertTrue(len(result.get("side_effects", [])) > 0)
        self.assertEqual(result["side_effects"][0]["action"], "deploy_honey_cred")

    def test_block_ip(self):
        payload = {"recommend_actions": {"actions": ["block"]}}
        result = block_ip(payload)
        self.assertTrue(result["output"]["blocked"])
        self.assertEqual(result["output"]["blocked_ip"], "10.0.0.1")
        self.assertEqual(result["confidence"], 90)
        self.assertEqual(len(result["side_effects"]), 1)
        self.assertEqual(result["side_effects"][0]["action"], "block_ip")

    def test_quarantine_email(self):
        payload = {"recommend_actions": {"actions": ["block"]}}
        result = quarantine_email(payload)
        self.assertTrue(result["output"]["quarantined"])
        self.assertEqual(result["output"]["message_id"], "msg-0001")
        self.assertEqual(result["confidence"], 90)
        self.assertEqual(len(result["side_effects"]), 1)
        self.assertEqual(result["side_effects"][0]["action"], "quarantine_email")

    def test_trigger_mfa_reset(self):
        payload = {"recommend_actions": {"actions": ["block"]}, "apply_veto": {"risk_score": 90}}
        result = trigger_mfa_reset(payload)
        self.assertTrue(result["output"]["mfa_reset"])
        self.assertEqual(result["output"]["user_id"], "target_user")
        self.assertEqual(result["confidence"], 90)
        self.assertEqual(len(result["side_effects"]), 1)
        self.assertEqual(result["side_effects"][0]["action"], "trigger_mfa_reset")

if __name__ == "__main__":
    unittest.main()
