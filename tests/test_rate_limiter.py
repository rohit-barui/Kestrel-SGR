import unittest

from server import RateLimiter


class TestRateLimiter(unittest.TestCase):
    def test_allows_within_limit(self):
        rl = RateLimiter(max_requests=5, window=60)
        for _ in range(5):
            self.assertTrue(rl.is_allowed("1.2.3.4"))

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_requests=3, window=60)
        for _ in range(3):
            rl.is_allowed("1.2.3.4")
        self.assertFalse(rl.is_allowed("1.2.3.4"))

    def test_different_ips_independent(self):
        rl = RateLimiter(max_requests=2, window=60)
        rl.is_allowed("1.1.1.1")
        rl.is_allowed("1.1.1.1")
        self.assertTrue(rl.is_allowed("2.2.2.2"))

if __name__ == "__main__":
    unittest.main()
