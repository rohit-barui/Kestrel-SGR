import unittest
from unittest.mock import patch

from core.remediation import MockM365Adapter, RemediationProvider, WebhookAdapter, get_active_adapter


class FakeResponse:
    def __init__(self):
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestRemediationProvider(unittest.TestCase):
    def test_provider_is_abstract(self):
        with self.assertRaises(TypeError):
            RemediationProvider()

    def test_abstract_execute_is_callable(self):
        class Stub(RemediationProvider):
            def execute(self, action, target, context):
                return super().execute(action, target, context)

        self.assertIsNone(Stub().execute("block", "evil.com", {}))


class TestWebhookAdapter(unittest.TestCase):
    def test_execute_success(self):
        adapter = WebhookAdapter("https://example.com/hook")
        with patch("core.remediation.urlopen", return_value=FakeResponse()):
            self.assertTrue(adapter.execute("block", "evil.com", {}))

    def test_execute_failure(self):
        adapter = WebhookAdapter("https://example.com/hook")
        with patch("core.remediation.urlopen", side_effect=OSError("boom")):
            self.assertFalse(adapter.execute("block", "evil.com", {}))


class TestMockM365Adapter(unittest.TestCase):
    def test_execute_returns_true(self):
        adapter = MockM365Adapter()
        self.assertTrue(adapter.execute("quarantine", "m1", {}))


class TestGetActiveAdapter(unittest.TestCase):
    def test_returns_mock_adapter(self):
        self.assertIsInstance(get_active_adapter(), MockM365Adapter)


if __name__ == "__main__":
    unittest.main()
