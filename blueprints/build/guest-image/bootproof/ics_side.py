#!/usr/bin/env python3
"""ICS side of the golden-image boot proof (docs/status/golden-image-results.md s3). Runs on the BUILDER next to the emulator, with a THROW-AWAY ICS
runtime (its own local PostgreSQL database, vault/audit keys, TLS certificate). It is never the production ICS.

  1. creates the schema (alembic head) and issues a REAL per-VM-instance bootstrap record (ics.guest.bootsecrets.issue) with a guest configuration;
  2. writes the SMBIOS values for the emulator (-smbios type=1,serial=,sku=,family=) to <workdir>/smbios.json;
  3. serves the REAL callback endpoint (ics.guest.callback via ics.main.create_app) over TLS on 127.0.0.1:<port> (the emulator reaches it as 10.0.2.2);
  4. waits for the guest's report (HMAC verified by the real endpoint), then does the ICS's enrollment step against the guest's agent over TLS PINNED to the
     fingerprint the guest reported (ics.agentclient.identity/enroll, the functions deploy.agentport._enroll uses), then wipes the secrets as _finish does;
  5. prints the evidence (record states, audit events, secrets wiped) as JSON.
Emulator artefact (the only deviation): user-mode networking NATs the guest, so the ICS sees the connection from 127.0.0.1 while the guest reports 10.0.2.15;
the endpoint's `source address == reported address` check is satisfied by patching callback.source_ip to return the guest's slirp address (a routed network
shows the real source). Every other check (HMAC, nonce/ts, TTL, single use, pin, closed schemas) runs unmodified.
Usage: ics_side.py <workdir> <callback_port> <agent_forward_port> <timeout_s>   (env: ICS_PROOF_DB_APP / ICS_PROOF_DB_OWNER sqlalchemy URLs)"""
import datetime
import hashlib
import json
import os
import sys
import threading
import time

sys.path.insert(0, "/opt/ics-src")
W, PORT, AGENT_FWD, TIMEOUT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
os.makedirs(W, mode=0o700, exist_ok=True)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

for n in ("vault.key", "audit.key", "signing.key"):
    p = os.path.join(W, n)
    if not os.path.exists(p):
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, os.urandom(32))
        os.close(fd)
# TLS certificate of the throw-away ICS listener (pinned by the guest through SMBIOS `family`)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ics-bootproof.invalid")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
cert_path, key_path = os.path.join(W, "ics.crt"), os.path.join(W, "ics.key")
open(cert_path, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
os.close(fd)
PIN = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

APP, OWNER = os.environ["ICS_PROOF_DB_APP"], os.environ["ICS_PROOF_DB_OWNER"]
eng = create_engine(OWNER, isolation_level="AUTOCOMMIT")
with eng.connect() as c:
    c.execute(text("DROP SCHEMA public CASCADE"))
    c.execute(text("CREATE SCHEMA public"))
cfg = Config("/opt/ics-src/alembic.ini")
cfg.set_main_option("script_location", "/opt/ics-src/migrations")
cfg.attributes["url"] = OWNER
cfg.attributes["app_role"] = "ics_test_app"
command.upgrade(cfg, "head")

from ics import agentclient, audit  # noqa: E402
from ics.config import Settings  # noqa: E402
from ics.guest import bootsecrets, callback  # noqa: E402
from ics.main import create_app  # noqa: E402
from ics.runtime import Runtime  # noqa: E402

st = Settings(database_url=APP, vault_key_file=os.path.join(W, "vault.key"), audit_key_file=os.path.join(W, "audit.key"), signing_key_file=os.path.join(W, "signing.key"),
              worker_enabled=False, allow_loopback_endpoints=True)
rt = Runtime(st)
DID = "00000000-0000-0000-0000-0000000000d1"
CONFIG = {"v": 1, "hostname": "bootproof", "agent_port": 8443, "mgmt_sources": ["10.0.2.2/32"], "ports": [],
          "agent_config": {"listen": {"address": "0.0.0.0", "port": 8443},
                           "runbooks": {"disk.usage": {"paths": ["/"]}, "guest.facts": {"enabled": True}}},
          "image_registries": [], "insecure_registries": [], "signing_pubkey_pem": None, "signing_key_sha256": None, "enroll_ttl_seconds": 3600}
rec = bootsecrets.issue(rt, DID, "bootproof", 9001, "callback", config=CONFIG)
smbios = {"serial": rec.smbios_serial, "sku": f"https://10.0.2.2:{PORT}", "family": "sha256:" + PIN}
fd = os.open(os.path.join(W, "smbios.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, json.dumps(smbios).encode())
os.close(fd)

callback.source_ip = lambda request, rt_: "10.0.2.15"     # emulator artefact, see the module docstring
import uvicorn  # noqa: E402

app = create_app(runtime=rt)
server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, ssl_keyfile=key_path, ssl_certfile=cert_path, log_level="warning", server_header=False))
server.install_signal_handlers = lambda: None
threading.Thread(target=server.run, daemon=True).start()
print(f"ICS callback endpoint listening on https://127.0.0.1:{PORT} (pin sha256:{PIN[:16]}...), bootstrap record bid={rec.bid} state=pending; waiting for the guest", flush=True)

ev = {"smbios_written": True, "pin": PIN}
deadline = time.time() + TIMEOUT
cur = None
while time.time() < deadline:
    cur = bootsecrets.find(rt, DID, "bootproof", 9001, "callback")
    if cur.state != "pending":
        break
    time.sleep(2)
ev["state_after_wait"] = cur.state
if cur.state != "reported":
    print(json.dumps(ev))
    sys.exit(2)
print("guest reported (HMAC verified by the endpoint); enrolling over pinned TLS", flush=True)
with rt.session() as db:
    rep = db.execute(text("SELECT report FROM guest_bootstrap WHERE id = :i"), {"i": cur.id}).scalar()
ev["report"] = {k: rep[k] for k in ("address", "port", "tls_fingerprint_sha256", "agent_key_fingerprint_sha256", "source_ip")}
ident = enr = None
for _ in range(60):          # the guest opens the agent port only AFTER the callback was acknowledged
    try:
        ident = agentclient.identity("127.0.0.1", AGENT_FWD, rep["tls_fingerprint_sha256"], allow_loopback=True)
        break
    except Exception as e:  # noqa: BLE001
        ev["identity_last_error"] = str(e)[:120]
        time.sleep(5)
if ident is None:
    print(json.dumps(ev))
    sys.exit(3)
ev["agent_key_matches_report"] = agentclient.key_fingerprint(ident["agent_pubkey"]) == rep["agent_key_fingerprint_sha256"]
ev["agent_already_enrolled_before"] = bool(ident.get("enrolled"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

priv = Ed25519PrivateKey.generate()
enr = agentclient.enroll("127.0.0.1", AGENT_FWD, rep["tls_fingerprint_sha256"], token=cur.token, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()),
                         node_id="00000000-0000-0000-0000-0000000000e1", expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
ev["enrolled"] = bool(enr)
ev["agent_version"] = enr.get("agent_version")
bootsecrets.set_state(rt, cur.id, "enrolled")
bootsecrets.delete_secrets(rt, cur.id, "enrolled")
ev["secrets_wiped"] = bootsecrets.secrets_wiped(rt, cur.id)
ev["final_state"] = bootsecrets.find(rt, DID, "bootproof", 9001, "callback").state
with rt.session() as db:
    ev["audit_actions"] = [r[0] for r in db.execute(text("SELECT action FROM audit_events WHERE action LIKE 'guest.%' ORDER BY seq")).all()]
# the one-time report cannot be used again: a second identical report is refused (single use) -- covered by tests/test_guest_callback.py; here: secret is gone
print(json.dumps(ev, indent=1))
