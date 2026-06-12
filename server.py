import json, http.server, socketserver, os, sys, threading, time, uuid, io, ssl, argparse, logging
from urllib.parse import urlparse
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("apcs")

from core.engine import SkillNode, SkillGraphRuntime
from core.gateway import Gateway
from core.policy import SimpleRegoEngine
from core.replay import ReplayStore
from core.drift import DriftTracker
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

PORT = 8080
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
            "email": "From: support@secure-login.xyz\nSubject: Verify account\n\nClick here: https://secure-login.xyz/verify [QR:https://phish.xyz/qr]\npassword: verify2024"
        }
    },
    "malware_drop": {
        "name": "Malware Drop (Invoice Attachment)",
        "payload": {
            "email": "From: billing@mycompay.co\nSubject: Overdue invoice\n\nInvoice attached. password: inv123\nDownload: https://mycompay.co/invoice.exe"
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
    def do_GET(self):
        if not self._check_rate_limit():
            return
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/scenarios":
            self._send_json([{"id": k, "name": v["name"], "payload": v["payload"]} for k, v in SCENARIOS.items()])
            return
        if path == "/api/policies":
            try:
                with open(POLICY_FILE, "r") as f:
                    content = f.read()
                self._send_json({"policy": content})
            except FileNotFoundError:
                self._send_json({"policy": ""}, 404)
            return
        if path == "/events":
            self._handle_sse()
            return
        if path == "/api/replay":
            self._send_json({"scan_ids": replay_store.list_ids()})
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

        web_path = os.path.join(WEB_DIR, path.lstrip("/") or "index.html")
        if os.path.isfile(web_path):
            self._serve_static(web_path)
        else:
            self._serve_static(os.path.join(WEB_DIR, "index.html"))

    def do_POST(self):
        if not self._check_rate_limit():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            self._run_scan(body)
            return
        self._send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        if not self._check_rate_limit():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/policies":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            content = body.get("policy", "")
            with open(POLICY_FILE, "w") as f:
                f.write(content)
            global policy_engine
            policy_engine = SimpleRegoEngine(POLICY_FILE)
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
            broadcast("scan_start", {"scan_id": scan_id})
            result = runtime.run(entry_payload=body)
            final_output = result["graph_output"]
            risk_score = final_output.get("aggregate_risk", {}).get("risk_score", 0)
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
            self._send_json({"scan_id": scan_id, "decision": decision, "risk_score": risk_score, "confidence": confidence, "actions": actions, "dominance": dominance})
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

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APCS Server")
    parser.add_argument("--port", type=int, default=PORT, help="Port to bind")
    parser.add_argument("--cert", help="Path to SSL certificate file")
    parser.add_argument("--key", help="Path to SSL key file")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    server = ThreadedHTTPServer((args.bind, args.port), APIHandler)

    if args.cert and args.key:
        server.socket = ssl.wrap_socket(
            server.socket,
            certfile=args.cert,
            keyfile=args.key,
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
