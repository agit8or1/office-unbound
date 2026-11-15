"""Local HTTPS mock of the PVE API (GET only) with a self-signed certificate."""
import datetime
import hashlib
import http.server
import ipaddress
import json
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

FIX = Path(__file__).parent / "fixtures" / "pve"
TID, SEC = "ics-ro@pve!inventory", "0123456789abcdef"
TOKEN = f"PVEAPIToken={TID}={SEC}"


def make_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pve-mock")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return cert_pem, key_pem, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.seen.append(("GET", self.path))
        if self.headers.get("Authorization") != TOKEN:
            return self._send(401, {"data": None})
        p = self.path.split("?")[0].removeprefix("/api2/json")
        routes = {"/version": "version", "/cluster/status": "cluster_status", "/nodes": "nodes"}
        if p in routes:
            return self._file(routes[p])
        parts = p.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "nodes" and parts[2] in ("qemu", "lxc", "storage", "network"):
            if parts[1] != "pve1":
                return self._send(500, {"data": None})
            return self._file(parts[2])
        self._send(404, {"data": None})

    def _file(self, n):
        self._send(200, json.loads((FIX / f"{n}.json").read_text()))

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _deny(self):
        self.server.seen.append((self.command, self.path))
        self._send(501, {"data": None})

    do_POST = do_PUT = do_DELETE = _deny


class MockPVE:
    def __init__(self):
        self.cert_pem, key_pem, self.fingerprint = make_cert()
        d = tempfile.mkdtemp()
        cf, kf = Path(d, "c.pem"), Path(d, "k.pem")
        cf.write_text(self.cert_pem)
        kf.write_text(key_pem)
        kf.chmod(0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.srv.seen = []
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def seen(self):
        return self.srv.seen

    def stop(self):
        self.srv.shutdown()
