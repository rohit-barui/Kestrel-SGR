import unittest, json, threading, time, http.client
import sys, os
from server import PORT

def _auth_headers():
    """Read token from apcs_tokens.json, preferring an Admin role if present."""
    token_file = os.environ.get("APCS_TOKEN_FILE", "apcs_tokens.json")
    if os.path.exists(token_file):
        with open(token_file) as f:
            tokens = json.load(f)
        # Prefer token with Admin role
        admin_token = None
        for t, info in tokens.items():
            if info.get("role") == "Admin":
                admin_token = t
                break
        token = admin_token if admin_token else (next(iter(tokens)) if tokens else None)
        if token:
            return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}

class TestServerIntegration(unittest.TestCase):
    server = None
    thread = None

    @classmethod
    def setUpClass(cls):
        from server import APIHandler, ThreadedHTTPServer, PORT
        cls.server = ThreadedHTTPServer(('127.0.0.1', PORT), APIHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
        if hasattr(cls, 'thread'):
            cls.thread.join()

    def _request(self, method, path, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=5)
        headers = _auth_headers()
        try:
            conn.request(method, path, body, headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, json.loads(data) if data else {}
        finally:
            conn.close()

    def test_scenarios_endpoint(self):
        status, data = self._request('GET', '/api/scenarios')
        self.assertEqual(status, 200)
        self.assertGreater(len(data), 0)

    def test_scan_endpoint_threat(self):
        status, data = self._request('POST', '/api/scan', json.dumps({"email": "click https://phish.xyz password: test"}))
        self.assertIn("scan_id", data)
        self.assertIn("decision", data)

    def test_scan_endpoint_clean(self):
        status, data = self._request('POST', '/api/scan', json.dumps({"email": "meeting at 3pm"}))
        self.assertEqual(data["risk_score"], 0)

    def test_policies_endpoint(self):
        status, data = self._request('GET', '/api/policies')
        self.assertIn("policy", data)

    def test_replay_endpoint(self):
        status, scan_data = self._request('POST', '/api/scan', json.dumps({"email": "test"}))
        scan_id = scan_data["scan_id"]
        status, trace = self._request('GET', f'/api/replay/{scan_id}')
        self.assertEqual(trace["scan_id"], scan_id)
