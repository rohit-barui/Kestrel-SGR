import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import server
from core.auth import AuthManager
from core.replay import ReplayStore


class FakeRuntime:
    def __init__(self, result):
        self._result = result

    def run(self, entry_payload=None):
        return self._result


def make_result(risk_score=20, decision_hint="allow", actions=None):
    return {
        "graph_output": {
            "aggregate_risk": {"risk_score": risk_score},
            "recommend_actions": {"actions": actions or []},
            "deploy_honey_credentials": {"honey_credentials": []},
            "rewrite_links": {"rewritten_urls": {}},
            "containment_actions": {"blocked_ips": [], "quarantined": False, "mfa_reset": False},
            "check_ip_reputation": {"ip_reputation": {}},
            "check_file_reputation": {"file_reputation": {}},
            "owasp_analysis": {"owasp_findings": [], "by_severity": {}},
            "phishing_validation": {"phishing_signals": {}, "phishing_likely": False},
            "threat_intel_lookup": {"threat_intel": []},
            "extract_urls": {"urls": []},
            "extract_archive_password": {"archive_password": ""},
            "validate_spf_dkim": {"is_spoofed": False, "spf_result": "neutral", "dmarc_result": "neutral"},
            "detect_typo_squatting": {"typo_squatting": []},
            "ml_score": {"ml_risk_score": 0, "ml_confidence": 50},
            "detonate_urls": {"detonation": {"malicious_count": 0, "suspicious_count": 0}},
        },
        "aggregated_confidence": 50,
    }


class FakeRequest:
    def __init__(self, path, headers=None, body=b"", method="GET"):
        self.path = path
        self.client_address = ("127.0.0.1", 12345)
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self._cached_body = body
        self._auth_token = None
        self._auth_info = None
        self.command = method

    def handler(self):
        h = server.APIHandler.__new__(server.APIHandler)
        h.path = self.path
        h.client_address = self.client_address
        h.headers = self.headers
        h.rfile = self.rfile
        h.wfile = self.wfile
        h._cached_body = self._cached_body
        h._auth_token = self._auth_token
        h._auth_info = self._auth_info
        h.command = self.command
        h.requestline = f"{self.command} {self.path} HTTP/1.1"
        h.protocol_version = "HTTP/1.1"
        h.request_version = "HTTP/1.1"
        return h

    def json_body(self):
        raw = self.wfile.getvalue()
        _, _, payload = raw.partition(b"\r\n\r\n")
        return json.loads(payload.decode())

    def status(self):
        raw = self.wfile.getvalue()
        first = raw.split(b"\r\n", 1)[0].decode()
        parts = first.split(" ", 2)
        return int(parts[1])


class TestServerEndpoints(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        token_file = os.path.join(self.tmpdir, "tokens.json")
        self.auth = AuthManager(token_file)
        self.admin_token = self.auth.generate_token("admin", role="Admin")
        self.analyst_token = self.auth.generate_token("analyst", role="Analyst")

        db = os.path.join(self.tmpdir, "replay.db")
        self.replay = ReplayStore(db)

        self.patchers = [
            patch.object(server, "auth_manager", self.auth),
            patch.object(server, "replay_store", self.replay),
        ]
        for p in self.patchers:
            p.start()
        self.addCleanup(self._stop_patchers)

    def _stop_patchers(self):
        for p in self.patchers:
            p.stop()

    def _authed(self, headers=None):
        hdrs = {"Authorization": f"Bearer {self.admin_token}"}
        if headers:
            hdrs.update(headers)
        return hdrs

    # ---- GET endpoints -----------------------------------------------------

    def test_get_auth_tokens(self):
        req = FakeRequest("/api/auth/tokens", headers=self._authed())
        req.handler().do_GET()
        self.assertEqual(req.status(), 200)

    def test_get_scenarios(self):
        req = FakeRequest("/api/scenarios", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertIn("ceo_fraud", {s["id"] for s in body})

    def test_get_integrations_admin(self):
        req = FakeRequest("/api/integrations", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertIn("config", body)

    def test_get_integrations_forbidden(self):
        req = FakeRequest("/api/integrations", headers={"Authorization": f"Bearer {self.analyst_token}"})
        req.handler().do_GET()
        self.assertEqual(req.status(), 403)

    def test_get_events_sse(self):
        with patch.object(server.SSEQueue, "get", return_value=None):
            req = FakeRequest("/events", headers=self._authed())
            req.handler().do_GET()
        self.assertEqual(req.status(), 200)

    def test_get_replay_list(self):
        req = FakeRequest("/api/replay", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertIn("scan_ids", body)

    def test_get_stats(self):
        req = FakeRequest("/api/stats", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertIn("total_scans", body)

    def test_get_trend(self):
        req = FakeRequest("/api/trend", headers=self._authed())
        req.handler().do_GET()
        self.assertIsInstance(req.json_body(), list)

    def test_get_replay_detail(self):
        self.replay.store("abc123", {}, {}, "ALLOW", 10, 50, [])
        req = FakeRequest("/api/replay/abc123", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertEqual(body["scan_id"], "abc123")

    def test_get_replay_detail_missing(self):
        req = FakeRequest("/api/replay/nope", headers=self._authed())
        req.handler().do_GET()
        self.assertEqual(req.status(), 404)

    def test_get_red_team(self):
        req = FakeRequest("/api/red-team", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertIsInstance(body, dict)

    def test_get_notifications_config(self):
        config = os.path.join(self.tmpdir, "notify.json")
        with open(config, "w") as f:
            json.dump({"slack_webhook": "x"}, f)
        with patch.dict(os.environ, {"APCS_NOTIFY_CONFIG": config}):
            req = FakeRequest("/api/notifications/config", headers=self._authed())
            req.handler().do_GET()
            self.assertEqual(req.json_body()["slack_webhook"], "x")

    def test_get_notifications_config_missing(self):
        req = FakeRequest("/api/notifications/config", headers=self._authed())
        req.handler().do_GET()
        self.assertEqual(req.json_body(), {})

    def test_get_export_csv(self):
        self.replay.store("abc", {}, {"risk_score": 5}, "ALLOW", 5, 50, [])
        req = FakeRequest("/api/export/csv", headers=self._authed())
        req.handler().do_GET()
        raw = req.wfile.getvalue()
        self.assertIn(b"text/csv", raw)

    def test_get_export_report(self):
        req = FakeRequest("/api/export/report", headers=self._authed())
        req.handler().do_GET()
        self.assertEqual(req.status(), 200)

    def test_get_health(self):
        req = FakeRequest("/api/health")
        req.handler().do_GET()
        body = req.json_body()
        self.assertEqual(body["status"], "ok")

    def test_get_metrics(self):
        req = FakeRequest("/api/metrics")
        req.handler().do_GET()
        body = req.json_body()
        self.assertIn("metrics", body)

    def test_get_policies_admin(self):
        req = FakeRequest("/api/policies", headers=self._authed())
        req.handler().do_GET()
        body = req.json_body()
        self.assertIn("policy", body)

    def test_get_policies_forbidden(self):
        req = FakeRequest("/api/policies", headers={"Authorization": f"Bearer {self.analyst_token}"})
        req.handler().do_GET()
        self.assertEqual(req.status(), 403)

    def test_get_policies_error(self):
        with patch.object(server, "POLICY_FILE", os.path.join(self.tmpdir, "missing.rego")):
            req = FakeRequest("/api/policies", headers=self._authed())
            req.handler().do_GET()
            self.assertEqual(req.status(), 500)

    def test_get_static_file(self):
        req = FakeRequest("/index.html")
        req.handler().do_GET()
        self.assertEqual(req.status(), 200)

    def test_get_static_fallback(self):
        req = FakeRequest("/nonexistent.html", headers=self._authed())
        req.handler().do_GET()
        self.assertEqual(req.status(), 200)

    def test_get_unknown_api(self):
        req = FakeRequest("/api/bogus", headers=self._authed())
        req.handler().do_GET()
        self.assertEqual(req.status(), 200)

    # ---- POST endpoints ----------------------------------------------------

    def test_post_login_valid(self):
        req = FakeRequest(
            "/api/auth/login",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"token": self.admin_token}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        body = req.json_body()
        self.assertTrue(body["valid"])

    def test_post_login_invalid(self):
        req = FakeRequest(
            "/api/auth/login",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"token": "bad"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 401)

    def test_post_generate_token_admin(self):
        req = FakeRequest(
            "/api/auth/token/generate",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"label": "ci"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        body = req.json_body()
        self.assertIn("token", body)

    def test_post_generate_token_forbidden(self):
        req = FakeRequest(
            "/api/auth/token/generate",
            headers={"Authorization": f"Bearer {self.analyst_token}", "Content-Type": "application/json"},
            body=json.dumps({"label": "ci"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 403)

    def test_post_scan_valid(self):
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/scan",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"email": "normal message"}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        body = req.json_body()
        self.assertIn("scan_id", body)
        self.assertIn("decision", body)

    def test_post_scan_with_urls_list(self):
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/scan",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"urls": ["https://example.com"]}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertIn("scan_id", req.json_body())

    def test_post_scan_with_urls_string(self):
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/scan",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"urls": "https://example.com"}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertIn("scan_id", req.json_body())

    def test_post_scan_invalid_body(self):
        req = FakeRequest(
            "/api/scan",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"foo": "bar"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_scan_runtime_error(self):
        class BoomRuntime:
            def run(self, entry_payload=None):
                raise RuntimeError("pipeline exploded")

        with patch.object(server, "build_graph", return_value=BoomRuntime()):
            req = FakeRequest(
                "/api/scan",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"email": "normal message"}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertEqual(req.status(), 500)

    def test_post_webhook_default_event(self):
        req = FakeRequest(
            "/api/webhook",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"email": "phish body"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        body = req.json_body()
        self.assertIn("scan_id", body)
        self.assertIn("decision", body)

    def test_post_webhook_unknown_event(self):
        req = FakeRequest(
            "/api/webhook",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"event": "nope", "email": "x"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.json_body()["status"], "error")

    def test_post_webhook_bad_signature(self):
        with patch.dict(os.environ, {"APCS_WEBHOOK_SECRET": "secret"}, clear=False):
            import core.webhooks as wh
            wh.SECRET = "secret"
            body = json.dumps({"event": "phishing_report", "email": "x"}).encode()
            req = FakeRequest(
                "/api/webhook",
                headers=self._authed({"Content-Type": "application/json", "X-APCS-Signature": "deadbeef"}),
                body=body,
                method="POST",
            )
            req.handler().do_POST()
        self.assertEqual(req.status(), 401)
        wh.SECRET = os.environ.get("APCS_WEBHOOK_SECRET", "")

    def test_post_check_pii(self):
        req = FakeRequest(
            "/api/check-pii",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"text": "SSN: 123-45-6789"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        body = req.json_body()
        self.assertTrue(body["contains_pii"])

    def test_post_detonate(self):
        with patch.object(server, "detonate_urls", return_value={"total_urls": 1}):
            req = FakeRequest(
                "/api/detonate",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"urls": ["https://x.com"]}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertEqual(req.json_body()["total_urls"], 1)

    def test_post_detonate_missing_urls(self):
        req = FakeRequest(
            "/api/detonate",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_scan_upload_text(self):
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/scan/upload",
                headers=self._authed({"Content-Type": "text/plain"}),
                body=b"uploaded phishing email content",
                method="POST",
            )
            req.handler().do_POST()
        self.assertIn("scan_id", req.json_body())

    def test_post_scan_upload_multipart(self):
        boundary = "XYZ"
        part = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"scan.txt\"\r\n\r\n"
            "suspicious email body\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/scan/upload",
                headers=self._authed({"Content-Type": f"multipart/form-data; boundary={boundary}"}),
                body=part,
                method="POST",
            )
            req.handler().do_POST()
        self.assertIn("scan_id", req.json_body())

    def test_post_scan_upload_empty(self):
        req = FakeRequest(
            "/api/scan/upload",
            headers=self._authed({"Content-Type": "text/plain"}),
            body=b"",
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_report_phishing(self):
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/report/phishing",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"email": "phish", "reporter": "a@b.com"}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertEqual(req.status(), 200)

    def test_post_report_phishing_message_id(self):
        with patch.object(server, "build_graph", return_value=FakeRuntime(make_result())):
            req = FakeRequest(
                "/api/report/phishing",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"message_id": "m-1", "auto_remediate": True}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertEqual(req.status(), 200)

    def test_post_report_phishing_missing(self):
        req = FakeRequest(
            "/api/report/phishing",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_reputation_ip(self):
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            req = FakeRequest(
                "/api/reputation/ip",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"ips": ["example.com"]}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertIn("ip_reputation", req.json_body())

    def test_post_reputation_ip_missing(self):
        req = FakeRequest(
            "/api/reputation/ip",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_reputation_file_hash(self):
        req = FakeRequest(
            "/api/reputation/file",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"hash": "abc123"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        body = req.json_body()
        self.assertEqual(body["file_reputation"]["sha256"], "abc123")

    def test_post_reputation_file_multipart(self):
        boundary = "FUBAR"
        part = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.bin\"\r\n\r\n"
            "binary-content"
            f"\r\n--{boundary}--\r\n"
        ).encode()
        req = FakeRequest(
            "/api/reputation/file",
            headers=self._authed({"Content-Type": f"multipart/form-data; boundary={boundary}"}),
            body=part,
            method="POST",
        )
        req.handler().do_POST()
        body = req.json_body()
        self.assertTrue(body["file_reputation"]["sha256"])

    def test_post_reputation_file_missing(self):
        req = FakeRequest(
            "/api/reputation/file",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_owasp_scan(self):
        with patch("skills.owasp.owasp_analysis", return_value={"output": {"owasp_findings": []}}):
            req = FakeRequest(
                "/api/owasp/scan",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"url": "https://example.com"}).encode(),
                method="POST",
            )
            req.handler().do_POST()
        self.assertIn("owasp_findings", req.json_body())

    def test_post_owasp_scan_missing(self):
        req = FakeRequest(
            "/api/owasp/scan",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 400)

    def test_post_reports(self):
        req = FakeRequest("/api/reports", headers=self._authed(), method="POST")
        req.handler().do_POST()
        self.assertIn("reports", req.json_body())

    def test_post_action(self):
        req = FakeRequest(
            "/api/action",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"action": "block", "target": "evil.com"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.json_body()["status"], "executed")

    def test_post_analytics_quality(self):
        req = FakeRequest(
            "/api/analytics/quality",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({"scan_id": "abc"}).encode(),
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.json_body()["status"], "feedback_recorded")

    def test_post_unknown(self):
        req = FakeRequest(
            "/api/bogus",
            headers=self._authed({"Content-Type": "application/json"}),
            body=b"{}",
            method="POST",
        )
        req.handler().do_POST()
        self.assertEqual(req.status(), 404)

    # ---- PUT endpoints -----------------------------------------------------

    def test_put_policies(self):
        with patch.object(server, "policy_engine", MagicMock()):
            req = FakeRequest(
                "/api/policies",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"policy": "allow { true }"}).encode(),
                method="PUT",
            )
            req.handler().do_PUT()
        self.assertEqual(req.json_body()["status"], "updated")

    def test_put_policies_missing_policy(self):
        req = FakeRequest(
            "/api/policies",
            headers=self._authed({"Content-Type": "application/json"}),
            body=json.dumps({}).encode(),
            method="PUT",
        )
        req.handler().do_PUT()
        self.assertEqual(req.status(), 400)

    def test_put_policies_forbidden(self):
        req = FakeRequest(
            "/api/policies",
            headers={"Authorization": f"Bearer {self.analyst_token}", "Content-Type": "application/json"},
            body=json.dumps({"policy": "allow { true }"}).encode(),
            method="PUT",
        )
        req.handler().do_PUT()
        self.assertEqual(req.status(), 403)

    def test_put_integrations(self):
        vault = os.path.join(self.tmpdir, "secrets.json")
        with patch.dict(os.environ, {"VAULT_JSON_PATH": vault}):
            req = FakeRequest(
                "/api/integrations",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"config": {"virustotal": {"key": "k"}}}).encode(),
                method="PUT",
            )
            req.handler().do_PUT()
        self.assertEqual(req.json_body()["status"], "updated")
        with open(vault) as f:
            self.assertEqual(json.load(f)["virustotal"]["key"], "k")

    def test_put_notifications_config(self):
        config = os.path.join(self.tmpdir, "notify.json")
        with patch.dict(os.environ, {"APCS_NOTIFY_CONFIG": config}):
            req = FakeRequest(
                "/api/notifications/config",
                headers=self._authed({"Content-Type": "application/json"}),
                body=json.dumps({"slack_webhook": "w"}).encode(),
                method="PUT",
            )
            req.handler().do_PUT()
        self.assertEqual(req.json_body()["status"], "updated")

    def test_put_unknown(self):
        req = FakeRequest("/api/bogus", headers=self._authed(), body=b"{}", method="PUT")
        req.handler().do_PUT()
        self.assertEqual(req.status(), 404)

    # ---- helper methods ----------------------------------------------------

    def test_check_auth_bearer(self):
        req = FakeRequest("/api/replay", headers=self._authed())
        h = req.handler()
        self.assertTrue(h._check_auth())
        self.assertIsNotNone(h._auth_token)

    def test_check_auth_query_token(self):
        req = FakeRequest(f"/api/replay?token={self.admin_token}")
        h = req.handler()
        self.assertTrue(h._check_auth())

    def test_check_auth_unauthorized(self):
        req = FakeRequest("/api/replay")
        h = req.handler()
        self.assertFalse(h._check_auth())
        self.assertEqual(req.status(), 401)

    def test_check_role_forbidden(self):
        req = FakeRequest("/api/replay")
        h = req.handler()
        h._auth_token = self.analyst_token
        self.assertFalse(h._check_role("Admin"))
        self.assertEqual(req.status(), 403)

    def test_check_rate_limit_exceeded(self):
        with patch.object(server.rate_limiter, "is_allowed", return_value=False):
            req = FakeRequest("/api/health")
            h = req.handler()
            self.assertFalse(h._check_rate_limit())
            self.assertEqual(req.status(), 429)

    def test_verify_hmac_valid(self):
        import hashlib
        import hmac as hmac_mod
        body = b"payload"
        sig = hmac_mod.new(b"secret", body, hashlib.sha256).hexdigest()
        req = FakeRequest("/api/scan", headers={"X-HMAC": sig}, body=body, method="POST")
        req.handler()._cached_body = body
        with patch("core.vault.get_secret", return_value="secret"):
            self.assertTrue(req.handler()._verify_hmac())

    def test_verify_hmac_invalid(self):
        req = FakeRequest("/api/scan", headers={"X-HMAC": "bad"}, body=b"payload", method="POST")
        with patch("core.vault.get_secret", return_value="secret"):
            self.assertFalse(req.handler()._verify_hmac())
        self.assertEqual(req.status(), 401)

    def test_validate_scan_body_non_dict(self):
        h = server.APIHandler.__new__(server.APIHandler)
        self.assertEqual(h._validate_scan_body("nope")[1], "Body must be a JSON object")

    def test_validate_scan_body_missing_fields(self):
        h = server.APIHandler.__new__(server.APIHandler)
        self.assertEqual(h._validate_scan_body({"x": 1})[1], "Body must contain 'email', 'sms', 'voice', or 'urls' field")

    def test_validate_scan_body_non_string(self):
        h = server.APIHandler.__new__(server.APIHandler)
        self.assertEqual(h._validate_scan_body({"email": 5})[1], "'email' must be a string")

    def test_validate_scan_body_too_long(self):
        h = server.APIHandler.__new__(server.APIHandler)
        ok, err = h._validate_scan_body({"email": "x" * 500001})
        self.assertFalse(ok)

    def test_broadcast_removes_dead_queue(self):
        dead = MagicMock()
        dead.put.side_effect = Exception("closed")
        server.sse_clients.append(dead)
        try:
            server.broadcast("evt", {"a": 1})
            self.assertNotIn(dead, server.sse_clients)
        finally:
            server.sse_clients.clear()

    def test_sse_queue_put_get(self):
        q = server.SSEQueue()
        q.put(b"event: x\ndata: {}\n\n")
        self.assertEqual(q.get(timeout=1), b"event: x\ndata: {}\n\n")

    def test_rate_limiter_allowed_then_blocked(self):
        rl = server.RateLimiter(max_requests=1, window=60)
        self.assertTrue(rl.is_allowed("1.1.1.1"))
        self.assertFalse(rl.is_allowed("1.1.1.1"))

    def test_wrap_calls_on_node_done(self):
        calls = []
        wrapped = server._wrap(lambda p: {"output": "o", "confidence": 5}, "node", lambda n, r: calls.append((n, r)))
        result = wrapped({})
        self.assertEqual(calls[0][0], "node")
        self.assertEqual(result["output"], "o")

    def test_build_graph_runs_with_callback(self):
        gateway = MagicMock()
        events = []
        runtime = server.build_graph(gateway, on_node_done=lambda n, r: events.append(n))
        result = runtime.run(entry_payload={"email": "test body"})
        self.assertIn("graph_output", result)
        self.assertIn("ingest", events)


if __name__ == "__main__":
    unittest.main()
