"""Machine Learning module for phishing risk scoring.

The module provides a thin wrapper around a scikit‑learn model (if available).
If scikit‑learn is not installed, a deterministic rule‑based fallback is used so the
system remains functional without extra dependencies.

Key classes:
- ``PhishingFeatureExtractor`` – converts the perception payload into a numeric
  feature vector.
- ``MLScorer`` – loads (or trains) a model, scores a payload and returns a dict
  with ``ml_risk_score`` (0‑100) and ``ml_confidence``.

The model is persisted to ``data/ml_model.pkl`` and is automatically trained on
first run when no model is present.  Training data is synthetic but covers the
typical clean, phishing and borderline cases used throughout the test suite.
"""
import os
import pickle
from typing import Any

from config.constants import EXAMPLE_URLS

# Try optional import of scikit‑learn – if unavailable we fall back to rule‑based.
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover – import may fail on minimal CI images.
    SKLEARN_AVAILABLE = False

MODEL_PATH = os.path.join("data", "ml_model.pkl")

class PhishingFeatureExtractor:
    """Extract numeric features from the perception payload.

    The payload is the ``context`` dict passed from ``SkillGraphRuntime`` – it
    contains the outputs of the perception skills keyed by their node name.
    The extractor is deliberately lightweight; all values are integers or
    floats so they work with both scikit‑learn and the rule‑based fallback.
    """

    SUSPICIOUS_KEYWORDS = ["urgent", "password", "wire", "transfer", "verify", "login", "account"]

    def _url_entropy(self, url: str) -> float:
        """Calculate a simple Shannon entropy of the URL characters.
        Higher entropy often correlates with obfuscated/phishing links.
        """
        if not url:
            return 0.0
        freq = {}
        for ch in url:
            freq[ch] = freq.get(ch, 0) + 1
        import math
        entropy = -sum((count / len(url)) * math.log2(count / len(url)) for count in freq.values())
        return entropy

    def extract(self, payload: dict[str, Any]) -> list[float]:
        # URLs
        urls = payload.get("extract_urls", {}).get("urls", [])
        url_count = len(urls)
        avg_url_len = sum(len(u) for u in urls) / url_count if url_count else 0
        avg_url_entropy = sum(self._url_entropy(u) for u in urls) / url_count if url_count else 0

        # QR codes
        qr_count = len(payload.get("scan_qr_codes", {}).get("qr_urls", []))

        # Archive password
        archive_pwd = payload.get("extract_archive_password", {}).get("archive_password", "")
        has_pwd = 1 if archive_pwd else 0
        pwd_len = len(archive_pwd)

        # Typo‑squatting
        typo_cnt = len(payload.get("detect_typo_squatting", {}).get("typo_squatting", []))

        # Entities
        entity_cnt = payload.get("extract_entities", {}).get("entities_extracted", 0)

        # Domains
        domains = payload.get("extract_urls", {}).get("domains", [])
        unique_domains = len(set(domains))

        # SPF/DKIM – treat a "fail" as a binary spoof flag.
        spf_dkim = payload.get("validate_spf_dkim", {})
        spoofed = 1 if spf_dkim.get("is_spoofed") else 0

        # Keyword presence in the raw email/content.
        content = payload.get("ingest", {}).get("content", "").lower()
        keyword_hits = sum(kw in content for kw in self.SUSPICIOUS_KEYWORDS)

        return [
            url_count,
            avg_url_len,
            avg_url_entropy,
            qr_count,
            has_pwd,
            pwd_len,
            typo_cnt,
            entity_cnt,
            unique_domains,
            spoofed,
            keyword_hits,
        ]

class MLScorer:
    """Thin wrapper around a scikit‑learn model with a rule‑based fallback.

    The public ``score`` method returns a dict compatible with the SGR contract:
    ``{"output": {"ml_risk_score": int, "ml_confidence": int}, "confidence": int}``
    where ``ml_confidence`` reflects the model's probability (scaled 0‑100) and
    ``confidence`` mirrors the same value for downstream aggregation.
    """

    def __init__(self):
        self.extractor = PhishingFeatureExtractor()
        self.model = None
        if SKLEARN_AVAILABLE and os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
            except Exception:
                self.model = None
        if not self.model and SKLEARN_AVAILABLE:
            # Train a tiny synthetic model if none exists.
            self._train_and_save()

    # ---------------------------------------------------------------------
    # Synthetic training – deterministic so tests are repeatable.
    # ---------------------------------------------------------------------
    def _synthetic_dataset(self):
        """Generate a minimal deterministic dataset.

        Returns ``X, y`` where ``y`` is binary (0 = benign, 1 = phishing).
        The feature ordering matches ``PhishingFeatureExtractor.extract``.
        """
        # Helper to create a feature vector manually for clarity.
        def make_vec(urls, qr, pwd, typo, ents, domains, spoof, kw):
            return [
                len(urls),                       # url_count
                sum(len(u) for u in urls) / len(urls) if urls else 0,  # avg_url_len
                sum(self.extractor._url_entropy(u) for u in urls) / len(urls) if urls else 0,  # avg_entropy
                len(qr),                        # qr_count
                1 if pwd else 0,                # has_pwd
                len(pwd),                       # pwd_len
                len(typo),                      # typo_cnt
                ents,                           # entity_cnt
                len(set(domains)),              # unique_domains
                1 if spoof else 0,              # spoofed
                kw,                             # keyword_hits
            ]
        # Benign example – few URLs, no password, no typo.
        benign = make_vec([EXAMPLE_URLS["company"]], [], "", [], 3, ["company.com"], False, 0)
        # Phishing – many URLs, password, typo domains, spoofed spf/dkim.
        phishing = make_vec(
            [EXAMPLE_URLS["secure_login"], EXAMPLE_URLS["malicious_phish"]],
            [EXAMPLE_URLS["malicious_qr"]],
            "urgent123",
            ["secur3-login.xyz"],
            5,
            ["secure-login.xyz", "malicious.co"],
            True,
            3,
        )
        # Borderline – moderate signals.
        borderline = make_vec(
            ["https://trusted.com"],
            [],
            "",
            [],
            2,
            ["trusted.com"],
            False,
            1,
        )
        x = [benign, phishing, borderline]
        y = [0, 1, 0]
        return x, y

    def _train_and_save(self):
        x, y = self._synthetic_dataset()
        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.33, random_state=42)
        model = RandomForestClassifier(n_estimators=50, random_state=42)
        model.fit(x_train, y_train)
        # Simple sanity check – ensure >80% accuracy on this tiny set.
        preds = model.predict(x_test)
        if accuracy_score(y_test, preds) < 0.8:
            # Fallback to rule‑based if training is absurdly bad.
            self.model = None
            return
        self.model = model
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)

    # ---------------------------------------------------------------------
    # Scoring – returns a dict compatible with SGR expectations.
    # ---------------------------------------------------------------------
    def score(self, payload: dict[str, Any]) -> dict[str, Any]:
        features = self.extractor.extract(payload)
        # If we have a trained sklearn model, use it.
        if self.model is not None:
            prob = self.model.predict_proba([features])[0][1]  # prob of phishing
            ml_risk = int(prob * 100)
            ml_conf = int(prob * 100)
            return {"output": {"ml_risk_score": ml_risk, "ml_confidence": ml_conf}, "confidence": ml_conf}
        # Rule‑based fallback – mirrors the simple logic used in ``aggregate_risk``.
        # Weighted sum of key signals, scaled to 0‑100.
        (
            url_cnt, _, _, qr_cnt, has_pwd, pwd_len, typo_cnt, entity_cnt, uniq_dom, spoofed, kw_hits
        ) = features
        score = (
            15 * url_cnt +
            10 * qr_cnt +
            10 * has_pwd +
            5 * (pwd_len > 0) +
            20 * typo_cnt +
            5 * uniq_dom +
            10 * spoofed +
            5 * kw_hits
        )
        ml_risk = min(score, 100)
        ml_conf = max(50, int(ml_risk * 0.7))  # heuristic confidence
        return {"output": {"ml_risk_score": ml_risk, "ml_confidence": ml_conf}, "confidence": ml_conf}

# Helper for external callers – a singleton instance is sufficient.
scorer = MLScorer()

def ml_score(payload: dict[str, Any]) -> dict[str, Any]:
    """Public wrapper used by the DAG.

    ``payload`` is the same dict passed to other skill functions – it contains the
    outputs of upstream perception nodes.
    """
    return scorer.score(payload)

# End of core/ml.py
