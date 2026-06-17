import json, http.server, socketserver, os, sys, threading, time, uuid, io, ssl, argparse, logging, hmac, hashlib
from urllib.parse import urlparse
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("apcs")

from core.engine import SkillNode, SkillGraphRuntime
from core.gateway import Gateway
from core.policy import SimpleRegoEngine
from core.replay import ReplayStore
from core.export import export_csv, generate_summary_report
from core.notifications import notifier
from core.drift import DriftTracker
from core.auth import auth_manager
from core.webhooks import webhook_handler
from core.logging import setup_logging
from core.ml import ml_score
from config.constants import EXAMPLE_URLS
from core.red_team import generate_all as generate_red_team_payloads
from skills.perception import (
    ingest_payload, extract_urls, scan_qr_codes,
    extract_archive_password, whois_lookup, enrich_dns,
    detect_typo_squatting, extract_entities, enrich_external
)
from skills.decision import (
    aggregate_risk, apply_veto, recommend_actions, validate_spf_dkim
)
from skills.dominance import (
    deploy_honey_credentials, rewrite_links, containment_actions,
    block_ip, quarantine_email, trigger_mfa_reset
)

os.makedirs("data", exist_ok=True)

PORT = 9090
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
POLICY_FILE = os.path.join(os.path.dirname(__file__), "policies", "remediation.rego")

SCENARIOS = {
    "ceo_fraud": {
        "name": "CEO Fraud (Vishing/Email Combo)",
        "payload": {
            "email": "From: ceo@cornpany.com\nSubject: Urgent wire transfer\n\nHi, I need $50K wired ASAP. Password: urgent123"
        }
    },
    "credential_harvester": {
        "name": "Credential Harvester (Lookalike Domain)",
        "payload": {
            "email": f'From: support@secure-login.xyz\nSubject: Verify account\n\nClick here: {EXAMPLE_URLS["secure_login"]}/verify [QR:{EXAMPLE_URLS["phish_qr"]}]\npassword: verify2024'
        }
    },
    "malware_drop": {
        "name": "Malware Drop (Invoice Attachment)",
        "payload": {
            "email": f'From: billing@mycompay.co\nSubject: Overdue invoice\n\nInvoice attached. password: inv123\nDownload: {EXAMPLE_URLS["invoice"]}'
        }
    },
    "clean_alert": {
        "name": "Clean Alert (Normal Internal Email)",
        "payload": {
            "email": "From: hr@company.com\nSubject: Meeting reminder\n\nTeam meeting at 3pm today."
        }
    }
}

sse_clients = []
sse_lock = threading.Lock()

def broadcast(event, data):
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()
    with sse_lock:
        dead = []
        for q in sse_clients:
            try:
                q.put(msg)
            except:
                dead.append(q)
        for q in dead:
            sse_clients.remove(q)

def build_graph(gateway, on_node_done=None):
    return SkillGraphRuntime(nodes=[
        SkillNode(name="ingest", func=_wrap(ingest_payload, "ingest", on_node_done)),
        SkillNode(name="extract_urls", func=_wrap(extract_urls, "extract_urls", on_node_done), deps=["ingest"]),
        SkillNode(name="scan_qr_codes", func=_wrap(scan_qr_codes, "scan_qr_codes", on_node_done), deps=["ingest"]),
        SkillNode(name="extract_archive_password", func=_wrap(extract_archive_password, "extract_archive_password", on_node_done), deps=["ingest"]),
        SkillNode(name="whois_lookup", func=_wrap(whois_lookup, "whois_lookup", on_node_done), deps=["extract_urls"]),
        SkillNode(name="enrich_dns", func=_wrap(enrich_dns, "enrich_dns", on_node_done), deps=["extract_urls"]),
        SkillNode(name="detect_typo_squatting", func=_wrap(detect_typo_squatting, "detect_typo_squatting", on_node_done), deps=["extract_urls"]),
        SkillNode(name="extract_entities", func=_wrap(extract_entities, "extract_entities", on_node_done), deps=["ingest"]),
        SkillNode(name="enrich_external", func=_wrap(enrich_external, "enrich_external", on_node_done), deps=["extract_urls"]),
        SkillNode(name="validate_spf_dkim", func=_wrap(validate_spf_dkim, "validate_spf_dkim", on_node_done), deps=["ingest"]),
        SkillNode(name="ml_score", func=_wrap(ml_score, "ml_score", on_node_done), deps=["extract_urls", "scan_qr_codes", "extract_archive_password", "whois_lookup", "enrich_dns", "detect_typo_squatting", "extract_entities", "enrich_external", "validate_spf_dkim"]),
        SkillNode(name="aggregate_risk", func=_wrap(aggregate_risk, "aggregate_risk", on_node_done), deps=["extract_urls", "scan_qr_codes", "extract_archive_password", "whois_lookup", "enrich_dns", "detect_typo_squatting"]),
        SkillNode(name="apply_veto", func=_wrap(apply_veto, "apply_veto", on_node_done), deps=["aggregate_risk"]),
        SkillNode(name="recommend_actions", func=_wrap(recommend_actions, "recommend_actions", on_node_done), deps=["apply_veto"]),
        SkillNode(name="deploy_honey_credentials", func=_wrap(deploy_honey_credentials, "deploy_honey_credentials", on_node_done), deps=["recommend_actions", "apply_veto"]),
        SkillNode(name="rewrite_links", func=_wrap(rewrite_links, "rewrite_links", on_node_done), deps=["recommend_actions", "extract_urls"]),
        SkillNode(name="containment_actions", func=_wrap(containment_actions, "containment_actions", on_node_done), deps=["recommend_actions", "apply_veto"]),
        SkillNode(name="block_ip", func=_wrap(block_ip, "block_ip", on_node_done), deps=["recommend_actions"]),
        SkillNode(name="quarantine_email", func=_wrap(quarantine_email, "quarantine_email", on_node_done), deps=["recommend_actions"]),
        SkillNode(name="trigger_mfa_reset", func=_wrap(trigger_mfa_reset, "trigger_mfa_reset", on_node_done), deps=["recommend_actions", "apply_veto"]),
    ], gateway=gateway)

def _wrap(fn, name, on_node_done):
    if on_node_done is None:
        return fn
    def wrapper(payload):
        result = fn(payload)
        on_node_done(name, result)
        return result
    return wrapper

class SSEQueue:
    def __init__(self):
        self.queue = []
        self.event = threading.Event()

    def put(self, msg):
        self.queue.append(msg)
        self.event.set()

    def get(self, timeout=30):
        self.event.wait(timeout)
        if not self.queue:
            return None
        msg = self.queue.pop(0)
        if not self.queue:
            self.event.clear()
        return msg

class RateLimiter:
    def __init__(self, max_requests=20, window=60):
        self.max_requests = max_requests
        self.window = window
        self.clients = defaultdict(list)

    def is_allowed(self, client_ip):
        now = time.time()
        cutoff = now - self.window
        self.clients[client_ip] = [t for t in self.clients[client_ip] if t > cutoff]
        if len(self.clients[client_ip]) >= self.max_requests:
            return False
        self.clients[client_ip].append(now)
        return True

rate_limiter = RateLimiter()

class APIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self._auth_token = None
        self._auth_info = None
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        logger = logging.getLogger("apcs")
        logger.info("GET %s from %s", path, self.client_address[0])

        if path == "/api/auth/tokens":
            self._send_json(auth_manager.list_tokens())
            return

        if path == "/api/scenarios":
            self._send_json([{"id": k, "name": v["name"], "payload": v["payload"]} for k, v in SCENARIOS.items()])
            return
        if path == "/api/integrations":
            if not self._check_role("Admin"):
                return
            # Return current vault configuration (all secrets)
            vault_path = os.getenv("VAULT_JSON_PATH", "data/secrets.json")
            try:
                with open(vault_path, "r") as f:
                    config = json.load(f)
            except FileNotFoundError:
                config = {}
            self._send_json({"config": config})
            return
        if path == "/events":
            self._handle_sse()
            return
        if path == "/api/replay":
            self._send_json({"scan_ids": replay_store.list_ids()})
            return
        if path == "/api/stats":
            self._send_json(replay_store.stats())
            return
        if path == "/api/trend":
            self._send_json(replay_store.risk_trend())
            return
        if path.startswith("/api/replay/"):
            scan_id = path.split("/api/replay/")[1]
            trace = replay_store.get(scan_id)
            if trace:
                self._send_json(trace)
            else:
                self._send_json({"error": "not found"}, 404)
            return
        if path == "/api/red-team":
            self._send_json(generate_red_team_payloads())
            return
        if path == "/api/notifications/config":
            config_path = os.environ.get("APCS_NOTIFY_CONFIG", "notify_config.json")
            if os.path.exists(config_path):
                with open(config_path) as f:
                    self._send_json(json.load(f))
            else:
                self._send_json({})
            return
        if path == "/api/export/csv":
            all_ids = replay_store.list_ids()
            traces = []
            for sid in all_ids:
                t = replay_store.get(sid)
                if t:
                    traces.append(t)
            csv_data = export_csv(traces)
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", "attachment; filename=apcs_export.csv")
            self.send_header("Content-Length", str(len(csv_data.encode())))
            self.end_headers()
            self.wfile.write(csv_data.encode())
            return

        if path == "/api/export/report":
            stats = replay_store.stats()
            trend = replay_store.risk_trend()
            report = generate_summary_report(stats, trend)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(report.encode())))
            self.end_headers()
            self.wfile.write(report.encode())
            return

        if path == "/api/health":
            self._send_json({
                "status": "ok",
                "version": "0.4.0",
                "uptime": time.time() - start_time,
                "scans_processed": scan_count,
                "policies_loaded": len(policy_engine.rules) if hasattr(policy_engine, 'rules') else 0,
            })
            return
        if path == "/api/metrics":
            metrics = (
                f"# HELP apcs_scans_total Total scans processed\n"
                f"# TYPE apcs_scans_total counter\n"
                f"apcs_scans_total {scan_count}\n"
                f"# HELP apcs_risk_score_last Last risk score\n"
                f"# TYPE apcs_risk_score_last gauge\n"
                f"apcs_risk_score_last {last_risk_score}\n"
                f"# HELP apcs_up Server uptime in seconds\n"
                f"# TYPE apcs_up gauge\n"
                f"apcs_up {time.time() - start_time}\n"
            )
            self._send_json({"metrics": metrics})
            return

        web_path = os.path.join(WEB_DIR, path.lstrip("/") or "index.html")
        if os.path.isfile(web_path):
            self._serve_static(web_path)
        else:
            self._serve_static(os.path.join(WEB_DIR, "index.html"))

    def do_POST(self):
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return
        if not self._verify_hmac():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        logger = logging.getLogger("apcs")
        logger.info("POST %s from %s", path, self.client_address[0])
        if parsed.path == "/api/auth/login":
            body_bytes = self._read_body()
            body = json.loads(body_bytes) if body_bytes else {}
            token = body.get("token", "")
            info = auth_manager.validate_token(token)
            if info:
                self._send_json({"valid": True, "label": info["label"]})
            else:
                self._send_json({"valid": False, "error": "Invalid token"}, 401)
            return
        if parsed.path == "/api/auth/token/generate":
            if not self._check_role("Admin"):
                return
            body_bytes = self._read_body()
            body = json.loads(body_bytes) if body_bytes else {}
            label = body.get("label", "api-key")
            new_token = auth_manager.generate_token(label)
            self._send_json({"token": new_token, "label": label})
            return
        if path == "/api/scan":
            body_bytes = self._read_body()
            body = json.loads(body_bytes) if body_bytes else {}
            self._run_scan(body)
            return
        if parsed.path == "/api/webhook":
            body_bytes = self._read_body()

            signature = self.headers.get("X-APCS-Signature", "")
            if not webhook_handler.verify_signature(body_bytes, signature):
                self._send_json({"error": "Invalid signature"}, 401)
                return

            body = json.loads(body_bytes) if body_bytes else {}
            event_type = body.get("event", body.get("type", "phishing_report"))
            result = webhook_handler.process(event_type, body)

            if result.get("status") == "accepted":
                scan_payload = result.get("scan_payload", {})
                if scan_payload:
                    self._run_scan(scan_payload)
                    return

            self._send_json(result)
            return
        self._send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return
        if not self._verify_hmac():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        logger = logging.getLogger("apcs")
        logger.info("PUT %s from %s", path, self.client_address[0])
        if path == "/api/integrations":
            if not self._check_role("Admin"):
                return
            body_bytes = self._read_body()
            body = json.loads(body_bytes) if body_bytes else {}
            config = body.get("config", {})
            vault_path = os.getenv("VAULT_JSON_PATH", "data/secrets.json")
            # Ensure directory exists
            os.makedirs(os.path.dirname(vault_path), exist_ok=True)
            with open(vault_path, "w") as f:
                json.dump(config, f, indent=2)
            self._send_json({"status": "updated"})
            return
        if parsed.path == "/api/notifications/config":
            if not self._check_role("Admin"):
                return
            body_bytes = self._read_body()
            body = json.loads(body_bytes) if body_bytes else {}
            with open(config_path, "w") as f:
                json.dump(body, f)
            from core.notifications import notifier
            notifier.config = body
            self._send_json({"status": "updated"})
            return
        self._send_json({"error": "Not found"}, 404)

    def _handle_sse(self):
        q = SSEQueue()
        with sse_lock:
            sse_clients.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            while True:
                msg = q.get(timeout=60)
                if msg is None:
                    break
                try:
                    self.wfile.write(msg)
                    self.wfile.flush()
                except:
                    break
        finally:
            with sse_lock:
                if q in sse_clients:
                    sse_clients.remove(q)

    def _check_auth(self) -> bool:
        # Skip auth for static files, login endpoint, and health/metrics
        path = urlparse(self.path).path
        if path in ("/api/health", "/api/metrics", "/api/auth/login", "/") or path.startswith("/api/auth/"):
            return True

        # Allow if no tokens configured (dev mode)
        if not auth_manager.has_tokens():
            return True

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # Reload token file to catch newly added tokens during runtime
            auth_manager._load()
            info = auth_manager.validate_token(token)
            if info:
                self._auth_token = token
                self._auth_info = info
                return True

        self._send_json({"error": "Unauthorized. Provide Authorization: Bearer <token> header."}, 401)
        return False

    def _check_role(self, required_role: str) -> bool:
        """Check if the authenticated token has the required role."""
        token = getattr(self, '_auth_token', None)
        if token is None:
            return False
        if auth_manager.has_role(token, required_role):
            return True
        self._send_json({"error": f"Forbidden: requires '{required_role}' role"}, 403)
        return False

    def _read_body(self):
        """Read and cache the request body so it can be read only once."""
        if hasattr(self, '_cached_body'):
            return self._cached_body
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self._cached_body = self.rfile.read(length)
        else:
            self._cached_body = b""
        return self._cached_body

    def _verify_hmac(self) -> bool:
        """Verify HMAC signature using a secret from the vault."""
        body_bytes = self._read_body()

        signature = self.headers.get("X-HMAC", "")
        if not signature:
            # HMAC is optional; if not present, skip verification
            return True

        try:
            from core.vault import get_secret
            secret = get_secret("webhook_hmac_secret")
        except Exception:
            secret = ""

        if not secret:
            return True

        expected = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            self._send_json({"error": "Invalid HMAC signature"}, 401)
            return False
        return True

    def _check_rate_limit(self):
        client_ip = self.client_address[0]
        if not rate_limiter.is_allowed(client_ip):
            self._send_json({"error": "Rate limit exceeded. Try again later."}, 429)
            return False
        return True

    def _validate_scan_body(self, body):
        if not isinstance(body, dict):
            return False, "Body must be a JSON object"
        if not any(k in body for k in ("email", "sms", "voice")):
            return False, "Body must contain 'email', 'sms', or 'voice' field"
        for key in ("email", "sms", "voice"):
            val = body.get(key)
            if val is not None:
                if not isinstance(val, str):
                    return False, f"'{key}' must be a string"
                if len(val) > 10000:
                    return False, f"'{key}' exceeds 10000 character limit"
        return True, ""

    def _run_scan(self, body):
        valid, err = self._validate_scan_body(body)
        if not valid:
            self._send_json({"error": err}, 400)
            return
        scan_id = uuid.uuid4().hex[:8]
        broadcast("scan_start", {"scan_id": scan_id})
        gateway = Gateway()
        def on_done(name, result):
            broadcast("skill_done", {"scan_id": scan_id, "node": name, "output": result.get("output", {}), "confidence": result.get("confidence", 0)})
            replay_store.add_event(scan_id, name, result.get("output", {}), result.get("confidence", 0))
        runtime = build_graph(gateway, on_node_done=on_done)
        try:
            global scan_count, last_risk_score
            broadcast("scan_start", {"scan_id": scan_id})
            result = runtime.run(entry_payload=body)
            final_output = result["graph_output"]
            risk_score = final_output.get("aggregate_risk", {}).get("risk_score", 0)
            scan_count += 1
            last_risk_score = risk_score
            actions = final_output.get("recommend_actions", {}).get("actions", [])
            dominance = {
                "honey_credentials": final_output.get("deploy_honey_credentials", {}).get("honey_credentials", []),
                "rewritten_urls": final_output.get("rewrite_links", {}).get("rewritten_urls", {}),
                "blocked_ips": final_output.get("containment_actions", {}).get("blocked_ips", []),
                "quarantined": final_output.get("containment_actions", {}).get("quarantined", False),
                "mfa_reset": final_output.get("containment_actions", {}).get("mfa_reset", False),
            }
            confidence = result["aggregated_confidence"]
            is_allowed = True
            try:
                is_allowed = policy_engine.evaluate({"risk_score": risk_score, "confidence": confidence, "urls": final_output.get("extract_urls", {}).get("urls", []), "archive_password": final_output.get("extract_archive_password", {}).get("archive_password", ""), "is_whitelisted": False})
            except Exception:
                pass
            decision = "ALLOW" if is_allowed else "DENY"
            replay_store.store(scan_id, body, final_output, decision, risk_score, confidence, actions)
            notifier.alert(scan_id, risk_score, decision, actions, dominance)

            # Drift tracking – feedback loop
            if decision == "ALLOW" and risk_score > 70:
                drift_tracker.record_fn("remediation_rule")
                broadcast("drift_update", {"type": "false_negative", "decision": decision, "risk_score": risk_score})
            elif decision == "DENY" and risk_score < 30:
                drift_tracker.record_fp("remediation_rule")
                broadcast("drift_update", {"type": "false_positive", "decision": decision, "risk_score": risk_score})
            elif decision == "ALLOW" and risk_score <= 70:
                drift_tracker.record_tn("remediation_rule")
            elif decision == "DENY" and risk_score >= 30:
                drift_tracker.record_tp("remediation_rule")
            drift_status = drift_tracker.stats("remediation_rule")
            broadcast("drift_status", {"adjusting": drift_tracker.should_adjust("remediation_rule"), "stats": drift_status})

            broadcast("run_complete", {"scan_id": scan_id, "decision": decision, "risk_score": risk_score, "confidence": confidence, "actions": actions, "dominance": dominance})
            self._send_json({"scan_id": scan_id, "decision": decision, "risk_score": risk_score, "confidence": confidence, "actions": actions, "dominance": dominance, "ml_confidence": result.get("graph_output", {}).get("ml_score", {}).get("ml_confidence", None)})
        except Exception as e:
            broadcast("run_error", {"scan_id": scan_id, "error": str(e)})
            self._send_json({"scan_id": scan_id, "error": str(e)}, 500)

    def _send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, path):
        ext = os.path.splitext(path)[1]
        types = {".html": "text/html", ".css": "text/css", ".js": "application/javascript", ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon"}
        ctype = types.get(ext, "application/octet-stream")
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._send_json({"error": "Not found"}, 404)

    def log_message(self, format, *args):
        logger.info("%s - %s", self.client_address[0], format % args)

policy_engine = SimpleRegoEngine(POLICY_FILE)
replay_store = ReplayStore()
drift_tracker = DriftTracker()
start_time = time.time()
scan_count = 0
last_risk_score = 0

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APCS Server")
    parser.add_argument("--port", type=int, default=PORT, help="Port to bind")
    parser.add_argument("--cert", help="Path to SSL certificate file")
    parser.add_argument("--key", help="Path to SSL key file")
    parser.add_argument("--client-ca", help="Path to CA certificate for mTLS client verification")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--json-logs", action="store_true", help="Output logs in JSON format")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose, json_output=args.json_logs)

    server = ThreadedHTTPServer((args.bind, args.port), APIHandler)

    ssl_ctx = None
    if args.cert and args.key:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
        # Optionally require client certificate
        if hasattr(args, 'client_ca') and args.client_ca:
            ssl_ctx.load_verify_locations(cafile=args.client_ca)
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        server.socket = ssl_ctx.wrap_socket(
            server.socket,
            server_side=True
        )
        proto = "HTTPS"
    else:
        proto = "HTTP"

    logger.info(f"Serving {proto} on {args.bind} port {args.port} ...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
