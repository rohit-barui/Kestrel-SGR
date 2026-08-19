import unittest

from core.drift import DriftTracker


class TestDriftTracker(unittest.TestCase):
    def setUp(self):
        self.drift = DriftTracker(max_fp_rate=0.05)

    def test_initial_fp_rate(self):
        self.assertEqual(self.drift.fp_rate("rule1"), 0.0)

    def test_fp_rate_calculation(self):
        self.drift.record_fp("rule1")
        self.drift.record_tn("rule1")
        self.drift.record_tn("rule1")
        self.assertAlmostEqual(self.drift.fp_rate("rule1"), 1/3)

    def test_fn_rate_calculation(self):
        self.drift.record_fn("rule1")
        self.drift.record_tp("rule1")
        self.drift.record_tp("rule1")
        self.assertAlmostEqual(self.drift.fn_rate("rule1"), 1/3)

    def test_should_adjust(self):
        for _ in range(10):
            self.drift.record_fp("rule1")
        self.drift.record_tn("rule1")
        self.assertTrue(self.drift.should_adjust("rule1"))

    def test_should_not_adjust(self):
        self.drift.record_tp("rule1")
        self.drift.record_tn("rule1")
        self.assertFalse(self.drift.should_adjust("rule1"))

    def test_adjusted_weight_reduced(self):
        for _ in range(10):
            self.drift.record_fp("rule1")
        adj = self.drift.adjusted_weight("rule1", 1.0)
        self.assertLess(adj, 1.0)

    def test_adjusted_weight_unchanged(self):
        self.drift.record_tp("rule1")
        adj = self.drift.adjusted_weight("rule1", 1.0)
        self.assertEqual(adj, 1.0)

    def test_stats(self):
        self.drift.record_tp("rule1")
        self.drift.record_fp("rule1")
        stats = self.drift.stats("rule1")
        self.assertEqual(stats["tp"], 1)
        self.assertEqual(stats["fp"], 1)

if __name__ == "__main__":
    unittest.main()
