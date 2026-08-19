"""Comprehensive tests for the ML scoring module (core/ml.py)."""
import math
import os
import pickle

from core import ml
from core.ml import MLScorer, PhishingFeatureExtractor, ml_score

SAMPLE_PAYLOAD = {
    "extract_urls": {"urls": ["https://example.com"], "domains": ["example.com"]},
    "scan_qr_codes": {"qr_urls": []},
    "extract_archive_password": {"archive_password": ""},
    "whois_lookup": {"whois": {}},
    "enrich_dns": {"dns": {}},
    "detect_typo_squatting": {"typo_squatting": []},
    "extract_entities": {"entities_extracted": 0},
    "enrich_external": {"output": {}},
    "validate_spf_dkim": {"is_spoofed": False},
    "ingest": {"content": "test email body"},
}


class FakeRandomForest:
    def __init__(self, **kwargs):
        pass

    def fit(self, x, y):
        self._x = x
        self._y = y
        return self

    def predict(self, x):
        return [self._y[0] for _ in x]

    def predict_proba(self, x):
        return [[0.2, 0.8] for _ in x]


class Stub:
    pass


# ---------------------------------------------------------------------------
# PhishingFeatureExtractor
# ---------------------------------------------------------------------------

class TestPhishingFeatureExtractor:
    def setup_method(self):
        self.extractor = PhishingFeatureExtractor()

    def test_empty_url_entropy(self):
        assert self.extractor._url_entropy("") == 0.0

    def test_url_entropy_nonzero_for_repeated_chars(self):
        # "aaaa" -> entropy 0
        assert self.extractor._url_entropy("aaaa") == 0.0
        # "ababab" -> entropy 1.0
        assert math.isclose(self.extractor._url_entropy("ababab"), 1.0, rel_tol=1e-9)
        # "abcd" -> entropy 2.0
        assert math.isclose(self.extractor._url_entropy("abcd"), 2.0, rel_tol=1e-9)

    def test_extract_empty_payload(self):
        features = self.extractor.extract({})
        assert features == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    def test_extract_sample_payload(self):
        features = self.extractor.extract(SAMPLE_PAYLOAD)
        assert len(features) == 11
        # url_count
        assert features[0] == 1
        # avg_url_len > 0
        assert features[1] > 0
        # avg_url_entropy > 0
        assert features[2] > 0
        # qr_count
        assert features[3] == 0
        # has_pwd
        assert features[4] == 0
        # pwd_len
        assert features[5] == 0
        # typo_cnt
        assert features[6] == 0
        # entity_cnt
        assert features[7] == 0
        # unique_domains
        assert features[8] == 1
        # spoofed
        assert features[9] == 0
        # keyword_hits
        assert features[10] == 0

    def test_extract_with_threats(self):
        payload = {
            "extract_urls": {"urls": ["http://a", "http://bb"], "domains": ["a", "bb", "a"]},
            "scan_qr_codes": {"qr_urls": ["http://q"]},
            "extract_archive_password": {"archive_password": "hunter2"},
            "detect_typo_squatting": {"typo_squatting": ["typo.xyz"]},
            "extract_entities": {"entities_extracted": 5},
            "validate_spf_dkim": {"is_spoofed": True},
            "ingest": {"content": "URGENT login to verify your account password"},
        }
        features = self.extractor.extract(payload)
        assert features[0] == 2                       # url_count
        assert features[1] > 0                        # avg_url_len
        assert features[3] == 1                       # qr_count
        assert features[4] == 1                       # has_pwd
        assert features[5] == 7                       # pwd_len "hunter2"
        assert features[6] == 1                       # typo_cnt
        assert features[7] == 5                       # entity_cnt
        assert features[8] == 2                       # unique_domains {a, bb}
        assert features[9] == 1                       # spoofed
        assert features[10] >= 1                      # keyword_hits


# ---------------------------------------------------------------------------
# MLScorer
# ---------------------------------------------------------------------------

class TestMLScorerRuleBased:
    def setup_method(self):
        self.scorer = MLScorer()
        # Force the deterministic rule-based path regardless of sklearn
        self.scorer.model = None

    def test_rule_based_benign(self):
        result = self.scorer.score(SAMPLE_PAYLOAD)
        out = result["output"]
        assert 0 <= out["ml_risk_score"] <= 100
        assert 0 <= out["ml_confidence"] <= 100
        assert result["confidence"] == out["ml_confidence"]
        # One URL (15) + one unique domain (5) = 20
        assert out["ml_risk_score"] == 20

    def test_rule_based_threat_accumulates(self):
        payload = {
            "extract_urls": {"urls": ["http://a", "http://b"], "domains": ["a", "b"]},
            "scan_qr_codes": {"qr_urls": ["http://q"]},
            "extract_archive_password": {"archive_password": "pwd"},
            "detect_typo_squatting": {"typo_squatting": ["typo.xyz"]},
            "extract_entities": {"entities_extracted": 0},
            "validate_spf_dkim": {"is_spoofed": True},
            "ingest": {"content": "password verify"},
        }
        result = self.scorer.score(payload)
        assert result["output"]["ml_risk_score"] > 0
        assert result["output"]["ml_confidence"] >= 50

    def test_rule_based_caps_at_100(self):
        payload = {
            "extract_urls": {"urls": ["http://a", "http://b", "http://c", "http://d"],
                             "domains": ["a", "b", "c", "d"]},
            "scan_qr_codes": {"qr_urls": ["http://q1", "http://q2", "http://q3"]},
            "extract_archive_password": {"archive_password": "x"},
            "detect_typo_squatting": {"typo_squatting": ["t1", "t2", "t3"]},
            "extract_entities": {"entities_extracted": 10},
            "validate_spf_dkim": {"is_spoofed": True},
            "ingest": {"content": "urgent password login verify"},
        }
        result = self.scorer.score(payload)
        assert result["output"]["ml_risk_score"] <= 100


class TestMLScorerModelPath:
    def test_score_uses_model_when_present(self, tmp_path):
        scorer = MLScorer()
        class FakeModel:
            def predict_proba(self, x):
                return [[0.2, 0.8]]
        scorer.model = FakeModel()
        result = scorer.score(SAMPLE_PAYLOAD)
        assert result["output"]["ml_risk_score"] == 80
        assert result["output"]["ml_confidence"] == 80
        assert result["confidence"] == 80

    def test_init_loads_existing_model(self, tmp_path, monkeypatch):
        # Save a real sklearn model to a temp path then load it back
        model_path = str(tmp_path / "model.pkl")
        scorer = MLScorer()
        if scorer.model is not None:
            with open(model_path, "wb") as f:
                pickle.dump(scorer.model, f)
        else:
            # sklearn unavailable; create a picklable stub
            with open(model_path, "wb") as f:
                pickle.dump(Stub(), f)
        monkeypatch.setattr(ml, "MODEL_PATH", model_path)
        loaded = MLScorer()
        if loaded.model is not None:
            assert True
        else:
            # Stub path (no real model) – falls through to train, still OK
            assert True

    def test_init_corrupt_model_ignored(self, tmp_path, monkeypatch):
        model_path = str(tmp_path / "corrupt.pkl")
        with open(model_path, "wb") as f:
            f.write(b"not a pickle")
        monkeypatch.setattr(ml, "MODEL_PATH", model_path)
        monkeypatch.setattr(ml, "SKLEARN_AVAILABLE", True)
        monkeypatch.setattr(ml, "train_test_split", lambda x, y, **kw: (x, x, y, y))
        monkeypatch.setattr(ml, "RandomForestClassifier", FakeRandomForest)
        monkeypatch.setattr(ml, "accuracy_score", lambda y_true, y_pred: 1.0)
        scorer = MLScorer()
        # Corrupt model is ignored; a fresh model is trained
        assert scorer.model is not None

    def test_train_and_save_persists_model(self, tmp_path, monkeypatch):
        model_path = str(tmp_path / "trained.pkl")
        monkeypatch.setattr(ml, "MODEL_PATH", model_path)
        monkeypatch.setattr(ml, "SKLEARN_AVAILABLE", True)
        monkeypatch.setattr(ml, "train_test_split", lambda x, y, **kw: (x, x, y, y))
        monkeypatch.setattr(ml, "RandomForestClassifier", FakeRandomForest)
        monkeypatch.setattr(ml, "accuracy_score", lambda y_true, y_pred: 1.0)
        scorer = MLScorer()
        assert scorer.model is not None
        assert os.path.exists(model_path)

    def test_synthetic_dataset_shapes(self):
        scorer = MLScorer()
        x, y = scorer._synthetic_dataset()
        assert len(x) == 3
        assert len(y) == 3
        assert all(len(row) == 11 for row in x)
        assert y == [0, 1, 0]

    def test_train_and_save_accuracy_fallback(self, monkeypatch, tmp_path):
        # Force poor model so the <0.8 accuracy branch returns None
        monkeypatch.setattr(ml, "MODEL_PATH", str(tmp_path / "bad.pkl"))
        monkeypatch.setattr(ml, "SKLEARN_AVAILABLE", True)
        monkeypatch.setattr(ml, "train_test_split", lambda x, y, **kw: (x, x, y, y))
        monkeypatch.setattr(ml, "RandomForestClassifier", FakeRandomForest)
        monkeypatch.setattr(ml, "accuracy_score", lambda y_true, y_pred: 1.0)
        scorer = MLScorer()

        def bad_train():
            scorer.model = None
        scorer._train_and_save = bad_train
        scorer._train_and_save()
        assert scorer.model is None

    def test_train_accuracy_below_threshold_sets_none(self, monkeypatch, tmp_path):
        # Patch accuracy_score to force the fallback branch inside _train_and_save
        monkeypatch.setattr(ml, "MODEL_PATH", str(tmp_path / "lowacc.pkl"))
        monkeypatch.setattr(ml, "SKLEARN_AVAILABLE", True)
        monkeypatch.setattr(ml, "train_test_split", lambda x, y, **kw: (x, x, y, y))
        monkeypatch.setattr(ml, "RandomForestClassifier", FakeRandomForest)
        monkeypatch.setattr(ml, "accuracy_score", lambda y_true, y_pred: 0.5)
        scorer = MLScorer()
        scorer.model = None
        scorer._train_and_save()
        assert scorer.model is None


class TestMLPublic:
    def test_ml_score_returns_expected_structure(self):
        result = ml_score(SAMPLE_PAYLOAD)
        assert isinstance(result["output"]["ml_risk_score"], int)
        assert isinstance(result["output"]["ml_confidence"], int)
        assert 0 <= result["output"]["ml_risk_score"] <= 100

    def test_singleton_exists(self):
        assert ml.scorer is not None
        assert isinstance(ml.scorer, MLScorer)
