# Testing

## Running Tests

```powershell
# Run full test suite
python -m pytest tests/ --tb=short -q

# Run with coverage
python -m pytest tests/ --cov=core --cov=skills --cov=server --cov-report=term

# Run specific test file
python -m pytest tests/test_decision.py -v

# Run specific test
python -m pytest tests/test_decision.py::TestDecision::test_aggregate_risk_with_spoof -v
```

## Test Suite

**303 tests** covering all core modules and skills:

| Test File | Coverage |
|-----------|----------|
| `test_auth.py` | Token generation, validation, RBAC roles |
| `test_cache.py` | Encrypted cache get/set/delete, TTL expiry |
| `test_db.py` | Encrypted database connection |
| `test_decision.py` | Risk scoring, veto logic, action recommendation, SPF/DKIM |
| `test_dominance.py` | Honey credentials, link rewrite, IP block, quarantine, MFA reset |
| `test_engine.py` | DAG execution, schema validation, error handling, confidence aggregation |
| `test_enricher.py` | DNS resolution, WHOIS lookup, URL suspicion analysis |
| `test_export.py` | CSV and report generation |
| `test_gateway.py` | Saga pattern record/commit/rollback |
| `test_graph.py` | Entity-relationship graph operations |
| `test_integration.py` | Server API endpoints, end-to-end scan flow |
| `test_logging.py` | Structured logging setup |
| `test_ml.py` | ML risk scoring |
| `test_notifications.py` | Alert broadcasting |
| `test_perception.py` | Ingestion, URL extraction, QR scan, WHOIS, DNS, typo detection |
| `test_policy.py` | Rego tokenization, parsing, evaluation |
| `test_rate_limiter.py` | Rate limiting per client IP |
| `test_rbac.py` | Role-based access control for API endpoints |
| `test_replay.py` | Encrypted trace storage and retrieval |
| `test_vault.py` | Secrets management |
| `test_webhooks.py` | Inbound webhook processing |

## Coverage Requirements

The CI pipeline enforces:
- **Overall coverage >= 95%**
- **Per-file coverage >= 99%** for all `core/*.py` and `skills/*.py`

Run coverage check locally:
```powershell
python -m pytest --cov=core --cov=skills --cov=server --cov-report=xml
python ci/check_coverage.py
```

## Writing Tests

- Tests use `pytest` with `unittest.TestCase` style
- Mock external services (DNS, WHOIS, CyberWatch API) to avoid network dependencies
- Place test files in the `tests/` directory with `test_` prefix
- Follow the naming convention: `test_<module>_<scenario>` for clear test reports
- Aim for 100% line coverage on any new code

```python
# Example test
import unittest
from skills.decision import aggregate_risk

class TestMySkill(unittest.TestCase):
    def test_aggregate_risk_with_spoof(self):
        payload = {"validate_spf_dkim": {"is_spoofed": True}}
        result = aggregate_risk(payload)
        self.assertGreater(result["output"]["risk_score"], 0)
```