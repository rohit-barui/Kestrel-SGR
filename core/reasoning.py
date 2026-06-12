from typing import List

def combine(scores: List[float], weights: List[float] = None) -> float:
    if not scores:
        return 0.0
    if weights is None:
        return sum(scores) / len(scores)
    if len(scores) != len(weights):
        raise ValueError("scores and weights must have same length")
    total_weight = sum(weights)
    if total_weight == 0:
        return 0.0
    return sum(s * w for s, w in zip(scores, weights)) / total_weight

def heuristic_boost(risk_score: float, threat_signals: int, base: float = 0.0) -> float:
    return min(100.0, base + risk_score + threat_signals * 5)
