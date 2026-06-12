import unittest, json, threading, time, http.client
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

class TestHealthEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from server import APIHandler, ThreadedHTTPServer, PORT
        cls.server = ThreadedHTTPServer(('127.0.0.1', PORT + 1), APIHandler)
        cls.port = PORT + 1
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_health_endpoint(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', '/api/health')
        resp = conn.getresponse()
        data = json.loads(resp.read())
        self.assertEqual(resp.status, 200)
        self.assertEqual(data["status"], "ok")
        conn.close()

    def test_metrics_endpoint(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', '/api/metrics')
        resp = conn.getresponse()
        data = json.loads(resp.read())
        self.assertIn("metrics", data)
        conn.close()

class TestObservability(unittest.TestCase):
    def test_rate_limiter_exists(self):
        from server import rate_limiter
        self.assertIsNotNone(rate_limiter)

    def test_rate_limiter_is_instance(self):
        from server import RateLimiter, rate_limiter
        self.assertIsInstance(rate_limiter, RateLimiter)

if __name__ == "__main__":
    unittest.main()
