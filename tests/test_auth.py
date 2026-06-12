import unittest, tempfile, os, json
from core.auth import AuthManager

class TestAuth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".json")
        self.auth = AuthManager(self.tmp)

    def tearDown(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_generate_and_validate(self):
        token = self.auth.generate_token("test-key")
        info = self.auth.validate_token(token)
        self.assertIsNotNone(info)
        self.assertEqual(info["label"], "test-key")

    def test_revoke(self):
        token = self.auth.generate_token("test")
        self.assertTrue(self.auth.revoke_token(token))
        self.assertIsNone(self.auth.validate_token(token))

    def test_list_tokens(self):
        self.auth.generate_token("a")
        self.auth.generate_token("b")
        tokens = self.auth.list_tokens()
        self.assertEqual(len(tokens), 2)

    def test_invalid_token(self):
        self.assertIsNone(self.auth.validate_token("invalid_token_here"))
