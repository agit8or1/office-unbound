"""HTTPS listener (bound to ONE configured address). Application-layer mutual authentication on top of TLS:
the agent only acts on Ed25519-signed requests from the enrolled ICS key; the ICS only accepts Ed25519-signed
responses from the agent key it recorded at enrollment (and pins the agent's TLS certificate)."""
import hashlib
import hmac
import http.server
import json
import os
import ssl
import stat
import threading
import time
import socketserver

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__, proto, runbooks
from .proto import Reject
from .state import Journal

MAX_BODY = 16 * 1024
ENROLL_SOURCE_MAX_FAILURES = 5      # wrong guesses per source address within ENROLL_THROTTLE_SECONDS before that source is throttled
ENROLL_GLOBAL_MAX_FAILURES = 60     # same, summed over all sources
ENROLL_THROTTLE_SECONDS = 600
ENROLL_FAIL_DELAY = 0.5             # seconds slept per wrong guess


def load_config(path: str) -> dict:
    """The config must be root-owned and not writable by group/other (the agent user must not be able to widen its allowlist)."""
    st = os.stat(path)
    if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit(f"{path} must be owned by root and not group/world-writable")
    with open(path) as f:
        cfg = json.load(f)
    runbooks.validate_config(cfg)
    return cfg


def b64pub(priv: Ed25519PrivateKey) -> str:
    import base64
    return base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def load_agent_key(state_dir: str) -> Ed25519PrivateKey:
    with open(os.path.join(state_dir, "agent_key.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)


class Agent:
    def __init__(self, cfg: dict, state_dir: str):
        self.cfg, self.state_dir = cfg, state_dir
        self.key = load_agent_key(state_dir)
        self.pub_b64 = b64pub(self.key)
        self.journal = Journal(os.path.join(state_dir, "journal"))
        self.exec_lock = threading.Lock()
        self.enroll_lock = threading.Lock()
        self.enroll_fail_delay = ENROLL_FAIL_DELAY
        self._enroll_fails: dict[str, list[float]] = {}   # source -> recent failure times (review L1)
        self.n = 0

    # ---- persisted trust ----
    def trust(self) -> dict | None:
        try:
            with open(os.path.join(self.state_dir, "trust.json")) as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def _write(self, name: str, obj: dict) -> None:
        p = os.path.join(self.state_dir, name)
        tmp = p + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)

    def signed(self, resp: dict) -> dict:
        return {"resp": resp, "sig": proto.sign(self.key, proto.RESP_PREFIX, resp)}

    # ---- enrollment ----
    def _throttled(self, source: str, now: float) -> bool:
        cut = now - ENROLL_THROTTLE_SECONDS
        for k in list(self._enroll_fails):
            self._enroll_fails[k] = [t for t in self._enroll_fails[k] if t > cut]
            if not self._enroll_fails[k]:
                del self._enroll_fails[k]
        return (len(self._enroll_fails.get(source, ())) >= ENROLL_SOURCE_MAX_FAILURES
                or sum(len(v) for v in self._enroll_fails.values()) >= ENROLL_GLOBAL_MAX_FAILURES)

    def enroll(self, body: dict, source: str = "?") -> dict:
        """Unauthenticated guesses never burn the token (review L1: that let anyone on the network deny enrollment). Instead each
        source address is throttled after repeated wrong guesses, each wrong guess is slowed, and the token expires on its own."""
        with self.enroll_lock:
            if self.trust() is not None:
                raise Reject("already_enrolled", "agent is already enrolled")
            try:
                with open(os.path.join(self.state_dir, "enroll.json")) as f:
                    en = json.load(f)
            except FileNotFoundError:
                raise Reject("no_enrollment_token", "no enrollment token is armed on this node") from None
            if set(body) != {"token", "ics_pubkey", "node_id"} or not all(isinstance(body[k], str) for k in body):
                raise Reject("bad_format")
            if time.time() > en["expires_at"]:
                raise Reject("token_expired", "enrollment token expired; run `ou-agent arm-enroll` on the node")
            if self._throttled(source, time.time()):
                raise Reject("throttled", "too many wrong enrollment guesses from this source; try again later")
            if not hmac.compare_digest(hashlib.sha256(body["token"].encode()).hexdigest(), en["token_sha256"]):
                self._enroll_fails.setdefault(source, []).append(time.time())
                time.sleep(self.enroll_fail_delay)
                raise Reject("bad_token", "enrollment token rejected")
            if not proto.UUID_RE.match(body["node_id"]):
                raise Reject("bad_format", "node_id")
            try:
                proto.pub_from_b64(body["ics_pubkey"])
            except ValueError:
                raise Reject("bad_format", "ics_pubkey") from None
            self._write("trust.json", {"ics_pubkey": body["ics_pubkey"], "node_id": body["node_id"], "enrolled_at": int(time.time())})
            os.unlink(os.path.join(self.state_dir, "enroll.json"))  # single use
            return self.signed({"v": 1, "type": "enroll", "node_id": body["node_id"], "agent_pubkey": self.pub_b64,
                                "capabilities": runbooks.capabilities(self.cfg), "agent_version": __version__, "at": int(time.time())})

    # ---- exec ----
    def exec(self, body: dict, now: int | None = None) -> tuple[int, dict]:
        now = int(time.time()) if now is None else now
        tr = self.trust()
        base = {"v": 1, "type": "exec", "node_id": tr["node_id"] if tr else None, "job_id": None, "nonce": None, "at": now}
        req = body.get("req") if isinstance(body, dict) else None
        # Review L2: nothing is signed, and nothing attacker-chosen is echoed, until the request signature has verified.
        if tr is None:
            return 403, {"error": "not_enrolled"}
        try:
            if set(body) != {"req", "sig"} or not isinstance(body["sig"], str) or not isinstance(req, dict):
                return 403, {"error": "bad_format"}
            if not proto.verify(proto.pub_from_b64(tr["ics_pubkey"]), proto.REQ_PREFIX, req, body["sig"]):
                return 403, {"error": "bad_signature"}
        except Exception:  # noqa: BLE001 - malformed key material / request: still unauthenticated
            return 403, {"error": "bad_format"}
        for k in ("job_id", "nonce"):   # authenticated now
            if isinstance(req.get(k), str) and len(req[k]) <= 64:
                base[k] = req[k]
        try:
            proto.check_envelope(req, now=now, node_id=tr["node_id"])
            self.journal.accept(req["nonce"], req["job_id"])  # before anything else: replays and re-runs are impossible
            params = runbooks.check_allowed(self.cfg, req["action"], req["params"])
            with self.exec_lock:
                try:
                    result = runbooks.execute(req["action"], params)
                except Exception as e:  # noqa: BLE001 - never echo internals
                    return 200, self.signed({**base, "status": "error", "code": "exec_failed", "result": {"error": type(e).__name__}})
            self.n += 1
            if self.n % 200 == 0:
                self.journal.gc()
            return 200, self.signed({**base, "status": "ok", "code": "ok", "result": result})
        except Reject as r:
            return 403, self.signed({**base, "status": "rejected", "code": r.code, "result": {"message": r.msg}})


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """TLS is negotiated per connection in its worker thread, never in the accept loop.
    Review H1 (2026-11-15): wrapping the *listening* socket made accept() perform the handshake,
    so a single idle TCP connection blocked every request. Now: plain accept, per-connection
    handshake under a deadline, and a cap on concurrent connections."""
    daemon_threads = True
    request_queue_size = 16
    handshake_timeout = 10.0
    max_connections = 32

    def __init__(self, addr, handler, ssl_ctx: ssl.SSLContext):
        self.ssl_ctx = ssl_ctx
        self._slots = threading.BoundedSemaphore(self.max_connections)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):  # over capacity: drop instead of queueing unbounded threads
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address):
        request.settimeout(self.handshake_timeout)
        try:
            tls = self.ssl_ctx.wrap_socket(request, server_side=True)  # handshake happens here, in this thread, bounded
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass


def make_handler(agent: Agent):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "ou-agent"
        sys_version = ""
        timeout = 15

        def log_message(self, fmt, *a):  # one short line, no bodies
            print(f"{self.address_string()} {self.command} {self.path.split('?')[0]} -> {fmt % a if a else fmt}", flush=True)

        def _send(self, code: int, obj: dict) -> None:
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/v1/identity":
                return self._send(200, {"v": 1, "agent_pubkey": agent.pub_b64, "enrolled": agent.trust() is not None,
                                        "agent_version": __version__})
            self._send(404, {"error": "not_found"})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                return self._send(413, {"error": "bad_length"})
            try:
                body = json.loads(self.rfile.read(n))
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._send(400, {"error": "bad_json"})
            if self.path == "/v1/exec":
                code, resp = agent.exec(body)
                return self._send(code, resp)
            if self.path == "/v1/enroll":
                try:
                    return self._send(200, agent.enroll(body, self.client_address[0]))
                except Reject as r:
                    return self._send(403, {"error": r.code, "message": r.msg})
            self._send(404, {"error": "not_found"})
    return H


def build_server(cfg: dict, state_dir: str):
    agent = Agent(cfg, state_dir)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(state_dir, "tls.crt"), os.path.join(state_dir, "tls.key"))
    srv = _Server((cfg["listen"]["address"], int(cfg["listen"]["port"])), make_handler(agent), ctx)
    return srv, agent


def serve(cfg_path: str, state_dir: str) -> None:
    cfg = load_config(cfg_path)
    srv, agent = build_server(cfg, state_dir)
    agent.journal.gc()
    print(f"ou-agent {__version__} listening on {cfg['listen']['address']}:{cfg['listen']['port']}", flush=True)
    srv.serve_forever()
