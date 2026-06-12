from typing import Dict

class DriftTracker:
    def __init__(self, max_fp_rate: float = 0.05):
        self.max_fp_rate = max_fp_rate
        self._stats: Dict[str, Dict[str, int]] = {}

    def _ensure(self, rule: str):
        if rule not in self._stats:
            self._stats[rule] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

    def record_fp(self, rule: str):
        self._ensure(rule)
        self._stats[rule]["fp"] += 1

    def record_fn(self, rule: str):
        self._ensure(rule)
        self._stats[rule]["fn"] += 1

    def record_tp(self, rule: str):
        self._ensure(rule)
        self._stats[rule]["tp"] += 1

    def record_tn(self, rule: str):
        self._ensure(rule)
        self._stats[rule]["tn"] += 1

    def fp_rate(self, rule: str) -> float:
        s = self._stats.get(rule, {})
        total = s.get("fp", 0) + s.get("tn", 0)
        return s.get("fp", 0) / total if total > 0 else 0.0

    def fn_rate(self, rule: str) -> float:
        s = self._stats.get(rule, {})
        total = s.get("fn", 0) + s.get("tp", 0)
        return s.get("fn", 0) / total if total > 0 else 0.0

    def should_adjust(self, rule: str) -> bool:
        return self.fp_rate(rule) > self.max_fp_rate

    def adjusted_weight(self, rule: str, base_weight: float = 1.0) -> float:
        if not self.should_adjust(rule):
            return base_weight
        rate = self.fp_rate(rule)
        return base_weight * (1.0 - min(rate, 0.5))

    def stats(self, rule: str) -> Dict[str, int]:
        return self._stats.get(rule, {})
