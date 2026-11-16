"""A PVE-simulator HTTPS server whose certificate is issued by a real (test) CA chain: root -> intermediate -> leaf (SAN localhost / 127.0.0.1), served as a
full chain like an ACME certificate. Used to test public-CA / cluster-CA / reverse-proxy trust decisions (ics/sshonboard/trust.py) with genuine chain and host-name
validation; the "public trust store" is replaced by the test root (tests patch ics.sshonboard.trust.system_context)."""
import datetime
import http.server
import ipaddress
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .pve_sim import PveSim, _Handler


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject, issuer, pub, signer, ca: bool, san=None, days=30, path_len=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer)).public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return b.sign(signer, hashes.SHA256())


def pem(c) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


def fp(c) -> str:
    return c.fingerprint(hashes.SHA256()).hex()


class Pki:
    def __init__(self, tag="Test"):
        self.root_key, self.int_key = _key(), _key()
        self.root = _cert(f"{tag} Root CA", f"{tag} Root CA", self.root_key.public_key(), self.root_key, True, path_len=1)
        self.inter = _cert(f"{tag} Intermediate CA", f"{tag} Root CA", self.int_key.public_key(), self.root_key, True, path_len=0)

    def leaf(self, cn="localhost", san=None, days=30):
        k = _key()
        san = san or [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        return k, _cert(cn, f"{self.inter.subject.rfc4514_string().split('=')[1]}", k.public_key(), self.int_key, False, san=san, days=days)

    def fullchain(self, leaf) -> str:
        return pem(leaf) + pem(self.inter)


class CaSimServer:
    """Like pve_sim.SimServer but with a CA-issued leaf (+ intermediate) and the IP 127.0.0.1 as the host name (the ICS SSRF guard rejects ::1, so 'localhost' is not usable)."""

    def __init__(self, pki: Pki, sim: PveSim | None = None, leaf=None):
        self.sim = sim or PveSim(task_delay=0.1)
        self.pki = pki
        self.key, self.leaf = leaf or pki.leaf()
        self.fullchain = pki.fullchain(self.leaf)
        self.cert_pem = pem(self.leaf)
        self.fingerprint = fp(self.leaf)
        d = Path(tempfile.mkdtemp())
        (d / "c.pem").write_text(self.fullchain)
        (d / "k.pem").write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(d / "c.pem", d / "k.pem")
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.srv.sim = self.sim
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
