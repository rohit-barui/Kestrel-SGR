import unittest
import json
from core.auth import AuthManager
from server import APIHandler, ThreadedHTTPServer, PORT
import threading
import time
import urllib.request

class TestRBAC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server in a background thread
        cls.server = ThreadedHTTPServer(("localhost", PORT), APIHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.5)  # give server a moment to start
        # Create tokens
        cls.auth_manager = AuthManager()
        cls.admin_token = cls.auth_manager.generate_token(label="admin", role="Admin")
        cls.analyst_token = cls.auth_manager.generate_token(label="analyst", role="Analyst")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def _request(self, method, path, token=None, data=None):
        url = f"http://localhost:{PORT}{path}"
        req = urllib.request.Request(url, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if data:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(data).encode()
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    def test_admin_can_access_integrations(self):
        status, body = self._request("GET", "/api/integrations", token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertIn("config", body)

    def test_analyst_cannot_access_integrations(self):
        status, _ = self._request("GET", "/api/integrations", token=self.analyst_token)
        self.assertEqual(status, 403)

    def test_admin_can_update_integrations(self):
        new_config = {"new_key": "value"}
        status, body = self._request("PUT", "/api/integrations", token=self.admin_token, data={"config": new_config})
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "updated")
        # Verify persisted
        status2, body2 = self._request("GET", "/api/integrations", token=self.admin_token)
        self.assertEqual(status2, 200)
        self.assertEqual(body2["config"].get("new_key"), "value")

if __name__ == "__main__":
    unittest.main()
