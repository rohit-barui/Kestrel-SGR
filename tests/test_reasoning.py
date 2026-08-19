import unittest

from core.reasoning import combine, heuristic_boost


class TestReasoning(unittest.TestCase):
    def test_combine_empty(self):
        self.assertEqual(combine([]), 0.0)

    def test_combine_unweighted(self):
        result = combine([10, 20, 30])
        self.assertAlmostEqual(result, 20.0)

    def test_combine_weighted(self):
        result = combine([10, 90], [0.9, 0.1])
        self.assertAlmostEqual(result, 18.0)

    def test_combine_weight_mismatch(self):
        with self.assertRaises(ValueError):
            combine([1, 2], [1])

    def test_combine_zero_weight(self):
        result = combine([50, 50], [0, 0])
        self.assertEqual(result, 0.0)

    def test_heuristic_boost(self):
        result = heuristic_boost(50, 3)
        self.assertEqual(result, 65.0)

    def test_heuristic_boost_capped(self):
        result = heuristic_boost(90, 5)
        self.assertEqual(result, 100.0)

if __name__ == "__main__":
    unittest.main()
