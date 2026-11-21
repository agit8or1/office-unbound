"""Throw-away ICS callback simulator for the independent image boot test (stdlib only; no database, no production code, no secrets of any real deployment).

It speaks the guest bootstrap callback protocol of ics/guest/callback.py (docs/status/bootstrap-v2.md): TLS listener with a freshly generated self-signed
certificate (its SHA-256 is the pin the guest receives through SMBIOS), `POST /api/v1/guest-bootstrap/report` with the HMAC-SHA256 proof over the canonical
string, single use of the bootstrap secret, an HMAC acknowledgement and a MAC'd closed-schema configuration in the answer. The protocol constants are
VENDORED from the specification; ics/tests/test_golden_prod.py pins them against the real `ics.guest.callback` functions so the two cannot drift silently.
Failure modes for the negative boots: mode "badack" answers with an acknowledgement made with the WRONG secret (an impostor who holds the pinned certificate
but not the secret); `hold` delays the answer so the harness can probe the guest while the callback is in flight."""
import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time

PATH = "/api/v1/guest-bootstrap/report"
SKEW = 300
BID = re.compile(r"^[0-9a-f]{16}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


def canonical(bid, nonce, ts, address, port, tls, key, token) -> bytes:
    return "\n".join(["ou-bootstrap-report-v1", bid, nonce, str(ts), address, str(port), tls, key, hashlib.sha256(token.encode()).hexdigest()]).encode()


def proof(secret_hex: str, msg: bytes) -> str:
    return hmac.new(bytes.fromhex(secret_hex), msg, hashlib.sha256).hexdigest()


def ack(secret_hex: str, nonce: str) -> str:
    return hmac.new(bytes.fromhex(secret_hex), f"ou-bootstrap-ack-v1\n{nonce}".encode(), hashlib.sha256).hexdigest()


def canon_json(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def config_mac(secret_hex: str, nonce: str, conf: dict) -> str:
    return hmac.new(bytes.fromhex(secret_hex), ("ou-bootstrap-config-v1\n" + nonce + "\n" + canon_json(conf)).encode(), hashlib.sha256).hexdigest()


def make_cert(workdir: str):
    """returns (certfile, keyfile, pin_sha256_hex)"""
    crt, key = os.path.join(workdir, "ics.crt"), os.path.join(workdir, "ics.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj", "/CN=ics-imgtest.invalid",
                    "-keyout", key, "-out", crt], check=True, capture_output=True)
    os.chmod(key, 0o600)
    der = subprocess.run(["openssl", "x509", "-in", crt, "-outform", "DER"], check=True, capture_output=True).stdout
    return crt, key, hashlib.sha256(der).hexdigest()


class Sim:
    """One bootstrap record (bid + secret) and the listener. Thread-safe counters are read by the harness."""

    def __init__(self, workdir: str, port: int, mode: str = "ok", hold: float = 0.0, pin_override: str | None = None):
        self.bid = os.urandom(8).hex()
        self.secret = os.urandom(32).hex()
        self.mode, self.hold = mode, hold
        self.crt, self.key, self.pin = make_cert(workdir)
        self.port = port
        self.lock = threading.Lock()
        self.handshakes = 0
        self.requests = 0
        self.valid_reports = 0
        self.rejected = 0
        self.replays = 0
        self.report = None           # the last valid report body (dict)
        self.tokens_seen = []
        self.state = "pending"
        self.events = []
        self.t_ack = None
        sim = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                d = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(d)))
                self.end_headers()
                self.wfile.write(d)

            def do_POST(self):
                sim._post(self)

        class S(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                s, a = super().get_request()
                try:
                    s.settimeout(30)
                    ws = ctx.wrap_socket(s, server_side=True)
                    with sim.lock:
                        sim.handshakes += 1
                    return ws, a
                except (ssl.SSLError, OSError):
                    try:
                        s.close()
                    except OSError:
                        pass
                    raise

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.crt, self.key)
        self.httpd = S(("127.0.0.1", port), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def smbios(self, host: str, port: int, pin: str | None = None) -> dict:
        return {"serial": self.bid + self.secret, "sku": f"https://{host}:{port}", "family": "sha256:" + (pin or self.pin)}

    def conf(self) -> dict:
        return {"v": 1, "hostname": "ou-imgtest", "agent_port": 8443, "mgmt_sources": ["10.0.2.2/32"], "ports": [],
                "agent_config": {"listen": {"address": "0.0.0.0", "port": 8443}, "runbooks": {"disk.usage": {"paths": ["/"]}, "guest.facts": {"enabled": True}}},
                "image_registries": [], "insecure_registries": [], "signing_pubkey_pem": None, "signing_key_sha256": None, "enroll_ttl_seconds": 3600}

    def _post(self, h):
        with self.lock:
            self.requests += 1
        try:
            n = int(h.headers.get("Content-Length", "-1"))
            if h.path != PATH or not 0 < n <= 4096:
                return h._send(400, {"error": "bad"})
            b = json.loads(h.rfile.read(n))
            a = b["agent"]
            # `features` (optional, agent >= 0.8.1): the optional runbooks the image knows; the real ICS uses it only to REMOVE runbooks
            if not {"v", "bid", "nonce", "ts", "agent", "enroll_token", "proof"} <= set(b) <= {"v", "bid", "nonce", "ts", "agent", "enroll_token", "proof", "features"} \
                    or not (isinstance(b.get("features", []), list) and all(isinstance(x, str) and len(x) <= 40 for x in b.get("features", []))) or set(a) != {"address", "port", "tls_fingerprint_sha256", "agent_key_fingerprint_sha256"}:
                raise ValueError("schema")
            if (b["v"] != 1 or not BID.match(b["bid"]) or not NONCE.match(b["nonce"]) or not HEX64.match(a["tls_fingerprint_sha256"])
                    or not HEX64.match(a["agent_key_fingerprint_sha256"]) or not TOKEN.match(b["enroll_token"]) or not HEX64.match(b["proof"])):
                raise ValueError("format")
            if b["bid"] != self.bid:
                raise ValueError("unknown bid")
            want = proof(self.secret, canonical(b["bid"], b["nonce"], b["ts"], a["address"], a["port"], a["tls_fingerprint_sha256"],
                                                a["agent_key_fingerprint_sha256"], b["enroll_token"]))
            if not hmac.compare_digest(want, b["proof"]):
                raise ValueError("bad proof")
            if abs(time.time() - b["ts"]) > SKEW:
                raise ValueError("skew")
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            with self.lock:
                self.rejected += 1
            return h._send(401, {"error": "rejected"})
        with self.lock:
            if self.state != "pending":
                self.replays += 1
                return h._send(401, {"error": "rejected"})
            self.state = "reported"
            self.valid_reports += 1
            self.report = {"address": a["address"], "port": a["port"], "tls_fingerprint_sha256": a["tls_fingerprint_sha256"],
                           "agent_key_fingerprint_sha256": a["agent_key_fingerprint_sha256"], "token": b["enroll_token"], "t": time.time()}
            self.tokens_seen.append(b["enroll_token"])
        if self.hold:
            time.sleep(self.hold)
        conf = self.conf()
        sec = self.secret if self.mode != "badack" else os.urandom(32).hex()
        h._send(200, {"ok": True, "ack": ack(sec, b["nonce"]), "config": conf, "config_mac": config_mac(self.secret, b["nonce"], conf)})
        self.t_ack = time.time()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
