"""Local fake services for the monitoring tests: HTTPS (configurable), IMAPS, SMTP (plain), webhook receiver. All bind 127.0.0.1."""
import datetime
import hashlib
import http.server
import ipaddress
import json
import socketserver
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert(days: float = 30):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return pem, kp, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def server_ctx(days: float = 30):
    pem, kp, fp = make_cert(days)
    d = Path(tempfile.mkdtemp())
    (d / "c.pem").write_text(pem)
    (d / "k.pem").write_text(kp)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    return ctx, pem, fp


class HttpsMock:
    """routes: {(method, path): (status, body_bytes)}  or a callable(handler)->(status, body). `seen` records requests."""

    def __init__(self, routes=None, days: float = 30):
        self.routes, self.seen = routes or {}, []
        ctx, self.pem, self.fp = server_ctx(days)
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.seen.append((self.command, self.path, dict(self.headers), body))
                r = outer.routes.get((self.command, self.path.split("?")[0]), (404, b"nope"))
                if callable(r):
                    r = r(self, body)
                code, data = r
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _do

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self.base = f"https://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class _Tcp(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ImapMock:
    """IMAP over implicit TLS: LOGIN user/pass, SELECT/EXAMINE, LOGOUT."""

    def __init__(self, user="mon", password="s3cret-pw!", days: float = 30, mailbox_ok=True):
        ctx, self.pem, self.fp = server_ctx(days)
        self.user, self.password, self.mailbox_ok = user, password, mailbox_ok
        self.down = False   # simulate a service outage: accept the TLS connection, then hang up without a greeting
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                if outer.down:
                    return
                self.wfile.write(b"* OK mock IMAP ready\r\n")
                while True:
                    line = self.rfile.readline().decode(errors="replace").strip()
                    if not line:
                        return
                    tag, _, rest = line.partition(" ")
                    cmd = rest.split(" ")[0].upper()
                    if cmd == "CAPABILITY":
                        self.wfile.write(f"* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n".encode())
                    elif cmd == "LOGIN":
                        parts = rest.split(" ", 2)[1:]
                        ok = [p.strip('"') for p in parts] == [outer.user, outer.password]
                        self.wfile.write((f"{tag} OK logged in\r\n" if ok else f"{tag} NO [AUTHENTICATIONFAILED] bad login\r\n").encode())
                    elif cmd in ("SELECT", "EXAMINE"):
                        if outer.mailbox_ok:
                            self.wfile.write(f"* 3 EXISTS\r\n* 0 RECENT\r\n{tag} OK [READ-ONLY] done\r\n".encode())
                        else:
                            self.wfile.write(f"{tag} NO no such mailbox\r\n".encode())
                    elif cmd == "LOGOUT":
                        self.wfile.write(f"* BYE\r\n{tag} OK bye\r\n".encode())
                        return
                    else:
                        self.wfile.write(f"{tag} BAD unknown\r\n".encode())

        self.srv = _Tcp(("127.0.0.1", 0), H)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class SmtpMock:
    def __init__(self, banner="220 mock.example ESMTP ready", reject_rcpt=False):
        self.messages, self.banner, self.reject = [], banner, reject_rcpt
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                w = self.wfile
                w.write((outer.banner + "\r\n").encode())
                rcpts = []
                while True:
                    line = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
                    if not line:
                        return
                    c = line.split(" ")[0].upper()
                    if c in ("EHLO", "HELO"):
                        w.write(b"250-mock.example\r\n250 SIZE 1000000\r\n")
                    elif c == "MAIL":
                        w.write(b"250 ok\r\n")
                    elif c == "RCPT":
                        if outer.reject:
                            w.write(b"550 no such user\r\n")
                        else:
                            rcpts.append(line)
                            w.write(b"250 ok\r\n")
                    elif c == "DATA":
                        w.write(b"354 go\r\n")
                        buf = []
                        while True:
                            l = self.rfile.readline()
                            if l in (b".\r\n", b""):
                                break
                            buf.append(l)
                        outer.messages.append(b"".join(buf).decode(errors="replace"))
                        w.write(b"250 queued\r\n")
                    elif c == "QUIT":
                        w.write(b"221 bye\r\n")
                        return
                    else:
                        w.write(b"250 ok\r\n")

        self.srv = _Tcp(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


EWS_OK = (b'<s:Envelope><s:Body><m:GetFolderResponse><m:ResponseMessages><m:GetFolderResponseMessage ResponseClass="Success">'
          b'<m:ResponseCode>NoError</m:ResponseCode></m:GetFolderResponseMessage></m:ResponseMessages></m:GetFolderResponse></s:Body></s:Envelope>')
