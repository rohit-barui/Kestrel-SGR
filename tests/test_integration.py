import unittest, json, threading, time, http.client
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

class TestServerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from server import APIHandler, ThreadedHTTPServer, PORT
        cls.server = ThreadedHTTPServer(('127.0.0.1', PORT), APIHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(1)
        cls.conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=5)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.server.shutdown()

    def test_scenarios_endpoint(self):
        self.conn.request('GET', '/api/scenarios')
        resp = self.conn.getresponse()
        data = json.loads(resp.read())
        self.assertEqual(resp.status, 200)
        self.assertGreater(len(data), 0)

    def test_scan_endpoint_threat(self):
        body = json.dumps({"email": "click https://phish.xyz password: test"})
        self.conn.request('POST', '/api/scan', body, {'Content-Type': 'application/json'})
        resp = self.conn.getresponse()
        data = json.loads(resp.read())
        self.assertIn("scan_id", data)
        self.assertIn("decision", data)

    def test_scan_endpoint_clean(self):
        body = json.dumps({"email": "meeting at 3pm"})
        self.conn.request('POST', '/api/scan', body, {'Content-Type': 'application/json'})
        resp = self.conn.getresponse()
        data = json.loads(resp.read())
        self.assertEqual(data["risk_score"], 0)

    def test_policies_endpoint(self):
        self.conn.request('GET', '/api/policies')
        resp = self.conn.getresponse()
        data = json.loads(resp.read())
        self.assertIn("policy", data)

    def test_replay_endpoint(self):
        body = json.dumps({"email": "test"})
        self.conn.request('POST', '/api/scan', body, {'Content-Type': 'application/json'})
        r = json.loads(self.conn.getresponse().read())
        self.conn.request('GET', f'/api/replay/{r["scan_id"]}')
        resp = self.conn.getresponse()
        trace = json.loads(resp.read())
        self.assertEqual(trace["scan_id"], r["scan_id"])
