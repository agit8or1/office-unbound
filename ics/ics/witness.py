"""python -m ics.witness  keygen | serve | revoke | status   (security review 7 H-5 lease witness; see ics/lease.py for the protocol)

Runs on the STANDBY ICS host (or any small third host that is not on the primary's side of a partition).
  keygen  --key-file F                       creates the witness key (32 raw bytes, 0600) and prints its public key (base64): put it in the primary's
                                             ICS_LEASE_WITNESS_PUBKEY
  serve   --key-file F --controller-pubkey B64 --state S [--listen 0.0.0.0:8099] [--lease-seconds 30] [--cert C --key K]
                                             --controller-pubkey is the primary's ICS signing PUBLIC key (`ics-cli signing-pubkey` / agentclient.pub_b64)
  revoke  --state S [--wait --margin 10]     promotion step 1+2: stop granting and (with --wait) block until no controller can still hold a lease
  status  --state S
`ics-cli promote` does revoke+wait itself when ICS_WITNESS_STATE_FILE is set on the promoting host."""
import argparse
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .agentclient import load_signing_key, pub_b64, pub_from_b64
from .lease import Witness


def make_handler(w: Witness):
    class H(BaseHTTPRequestHandler):
        server_version = "ou-witness"

        def log_message(self, *a):  # no request logging (no secrets anyway)
            pass

        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            if self.path != "/witness/v1/grant":
                return self._send(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= 4096:
                    raise ValueError("size")
                self._send(200, w.handle(json.loads(self.rfile.read(n))))
            except (ValueError, KeyError, TypeError):
                self._send(400, {"error": "bad request"})

        def do_GET(self):
            self._send(200, {"ok": True}) if self.path == "/healthz" else self._send(404, {"error": "not found"})
    return H


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ics.witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--key-file", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--key-file", required=True)
    s.add_argument("--controller-pubkey", required=True)
    s.add_argument("--state", required=True)
    s.add_argument("--listen", default="0.0.0.0:8099")
    s.add_argument("--lease-seconds", type=float, default=30.0)
    s.add_argument("--cert")
    s.add_argument("--key")
    for n in ("revoke", "status"):
        r = sub.add_parser(n)
        r.add_argument("--state", required=True)
        r.add_argument("--lease-seconds", type=float, default=30.0)
        if n == "revoke":
            r.add_argument("--wait", action="store_true")
            r.add_argument("--margin", type=float, default=10.0)
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        fd = os.open(a.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Ed25519PrivateKey.generate().private_bytes_raw())
        print(pub_b64(load_signing_key(a.key_file).public_key()))
        return 0
    if a.cmd == "serve":
        w = Witness(load_signing_key(a.key_file), pub_from_b64(a.controller_pubkey), lease_seconds=a.lease_seconds, state_path=a.state)
        host, _, port = a.listen.rpartition(":")
        srv = ThreadingHTTPServer((host, int(port)), make_handler(w))
        if a.cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(a.cert, a.key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        srv.serve_forever()
        return 0
    w = Witness(None, None, lease_seconds=a.lease_seconds, state_path=a.state)       # revoke/status need no keys: they only touch the state file
    if a.cmd == "status":
        print(json.dumps({"revoked_epoch": w.revoked_epoch, "max_epoch": w.max_epoch, "seconds_until_proven": round(w.seconds_until_proven(10.0), 1)}))
        return 0
    print(f"revoked epochs <= {w.revoke()}")
    if a.wait:
        w.wait_proven(a.margin, progress=lambda left: print(f"waiting {left:.0f} s for any lease to expire", flush=True))
        print("proven: no controller can hold a valid lease any more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
