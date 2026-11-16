"""ou-agent init | arm-enroll | show | serve   (init/arm-enroll/show run on the node console as the agent user)"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from . import server

STATE = "/var/lib/ou-agent"
CONFIG = "/etc/ou-agent/agent.json"


def _w(path: str, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def make_tls(state: str, address: str, hostname: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"ou-agent {hostname}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address)), x509.DNSName(hostname)]), False)
            .sign(key, hashes.SHA256()))
    _w(os.path.join(state, "tls.key"), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _w(os.path.join(state, "tls.crt"), cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def arm_enroll(state: str, ttl: int = 3600, token_sha256: str | None = None) -> str | None:
    """token_sha256 (cloud-init path): the ICS generated the token and supplies only its hash, so the plaintext never touches user-data,
    cloud-init logs or this node's disk; nothing is printed. Without it a fresh token is generated and returned (console path)."""
    token = None
    if token_sha256 is None:
        token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(token.encode()).hexdigest()
    elif not re.fullmatch(r"[0-9a-f]{64}", token_sha256):
        raise SystemExit("--token-sha256 must be 64 lowercase hex characters")
    p = os.path.join(state, "enroll.json")
    if os.path.exists(os.path.join(state, "trust.json")):
        raise SystemExit("already enrolled; remove trust.json deliberately (and re-run init/arm-enroll) to re-enroll")
    with open(p, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump({"token_sha256": token_sha256, "expires_at": int(time.time()) + ttl, "failures": 0}, f)
    return token


def fingerprints(state: str) -> tuple[str, str]:
    with open(os.path.join(state, "tls.crt"), "rb") as f:
        tls = hashlib.sha256(x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)).hexdigest()
    pub = server.load_agent_key(state).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return tls, hashlib.sha256(pub).hexdigest()


def reseed_epoch(state: str, doc_path: str, now: int | None = None) -> int:
    """Review 7 L-2: after the stored epoch became unreadable the agent refuses everything. The operator re-seeds it on the node console with a doc that the
    CURRENT controller signed (`ics-cli epoch-attest --node <id>`): ICS signing key (pinned in trust.json), this node's id, issued at most 1 h ago."""
    from . import proto
    with open(os.path.join(state, "trust.json")) as f:
        trust = json.load(f)
    with open(doc_path) as f:
        doc = json.load(f)
    body, sig = doc["attest"], doc["sig"]
    ok = proto.verify(proto.pub_from_b64(trust["ics_pubkey"]), proto.RESEED_PREFIX, body, sig)
    now = int(time.time()) if now is None else now
    if (not ok or body.get("v") != 1 or body.get("node_id") != trust["node_id"] or type(body.get("epoch")) is not int or not 0 <= body["epoch"] < 2**62
            or type(body.get("issued_at")) is not int or not 0 <= now - body["issued_at"] <= 3600):
        raise SystemExit("the re-seed document is not valid for this node (signature, node id, age)")
    gate = proto.EpochGate(os.path.join(state, "epoch.json"))
    if body["epoch"] < gate.max_epoch:
        raise SystemExit(f"refusing to LOWER the mark ({gate.max_epoch} -> {body['epoch']})")
    gate.reseed(body["epoch"])
    print(f"epoch mark set to {body['epoch']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ou-agent")
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--config", default=CONFIG)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--hostname", required=True)
    for sp in (i, sub.add_parser("arm-enroll")):
        sp.add_argument("--token-sha256")
        sp.add_argument("--ttl", type=int, default=3600)
    sub.add_parser("show")
    sub.add_parser("serve")
    rs = sub.add_parser("reseed-epoch", help="re-seed an unreadable controller epoch from a doc signed by the current controller (ics-cli epoch-attest)")
    rs.add_argument("doc")
    a = ap.parse_args(argv)
    if a.cmd == "reseed-epoch":
        return reseed_epoch(a.state, a.doc)
    if a.cmd == "serve":
        server.serve(a.config, a.state)
        return 0
    if a.cmd == "init":
        cfg = server.load_config(a.config)
        os.makedirs(a.state, mode=0o700, exist_ok=True)
        _w(os.path.join(a.state, "agent_key.pem"), Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        make_tls(a.state, cfg["listen"]["address"], a.hostname)
    if a.cmd in ("init", "arm-enroll"):
        if not 60 <= a.ttl <= 7 * 86400:
            raise SystemExit("--ttl must be 60..604800 seconds")
        token = arm_enroll(a.state, a.ttl, a.token_sha256)
        if token is not None:
            print("ENROLLMENT TOKEN (shown once, valid 1h, single use): " + token)
    tls, key = fingerprints(a.state)
    print(f"tls_fingerprint_sha256={tls}\nagent_key_fingerprint_sha256={key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
