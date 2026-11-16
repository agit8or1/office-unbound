"""Controller lease with an external witness (security review 7 H-5, coordinator follow-up).

Why: `epoch.assert_active` reads the controller's OWN database. A primary isolated by a network partition still sees its own epoch and role, so it would keep
running. A LEASE fixes that: the active controller may cause side effects only while it holds a time-bounded grant from a WITNESS it can not forge (the
standby ICS host, or any small third host), renewed every `renew` seconds. If the grant is not renewed within `lease` (T) seconds the controller fences
itself; every side effect asks `Lease.require()` first (via epoch.assert_active / egress.require), so nothing is sent, claimed or committed.

Protocol (Ed25519, canonical JSON; the transport only carries bytes):
  controller -> witness  {"v":1,"op":"grant","epoch":E,"nonce":N,"issued_at":t}  signed by the ICS signing key (witness holds only its public half)
  witness -> controller  {"v":1,"ok":true,"epoch":E,"nonce":N,"lease_s":T}       signed by the witness key (pinned public key in the controller's config)
                         or {"v":1,"ok":false,"reason":"superseded", "nonce":N}  (a promotion revoked this epoch: the controller fences itself for good)
The controller computes valid_until = (monotonic time BEFORE it sent the request) + lease_s, so network delay only shortens its lease. The witness records
the monotonic time of its last grant. PROMOTION (witness.revoke + wait_proven): the witness stops granting for epochs <= E, then waits until
T + margin have elapsed since the last grant it ever made: by then no controller can still hold a valid lease, so bumping the epoch is safe even though the old
primary was unreachable. The margin bounds clock-RATE drift between the two hosts (monotonic clocks are never compared, only elapsed times).

Modes: no witness configured = lease OFF (single-controller installs keep working). Witness configured = lease ON: if the witness (standby) is down the primary
self-fences after T seconds unless an operator sets ICS_LEASE_STANDALONE_OVERRIDE=true (audited at start; the controller then runs unfenced and a partition can
split-brain it: use only while the standby is known to be dead)."""
import base64
import json
import os
import secrets
import threading
import time

from .agentclient import pub_from_b64, sign, verify

REQ_PREFIX = b"ou-lease-req-v1\n"
RESP_PREFIX = b"ou-lease-resp-v1\n"
MAX_REQ_AGE = 120


class Superseded(Exception):
    """the witness revoked this epoch (a promotion happened)"""


class Lease:
    """lives in Runtime. `transport(request_dict) -> response_dict` is injected (HTTP in production, a function in tests); `clock` is time.monotonic."""

    def __init__(self, *, signing_key, witness_pub, transport, epoch_fn, lease_seconds=30.0, renew_seconds=5.0, clock=time.monotonic, wall=time.time, standalone=False, on_superseded=None):
        self.key, self.witness_pub, self.transport, self.epoch_fn = signing_key, witness_pub, transport, epoch_fn
        self.lease_s, self.renew_s, self.clock, self.standalone = float(lease_seconds), float(renew_seconds), clock, standalone
        self.on_superseded, self.wall = on_superseded, wall
        self.valid_until = float("-inf")
        self.superseded = False
        self.last_error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- the check every side effect makes ----
    def valid(self) -> bool:
        return self.standalone or (not self.superseded and self.clock() < self.valid_until)

    def require(self) -> None:
        from .epoch import NotActive
        if self.superseded:
            raise NotActive("the witness revoked this controller's lease (a promotion happened): superseded")
        if not self.valid():
            raise NotActive(f"controller lease expired (no grant from the witness within {self.lease_s:.0f} s{': ' + self.last_error if self.last_error else ''})")

    # ---- renewal ----
    def renew_once(self) -> bool:
        t0 = self.clock()                        # BEFORE sending: the grant can only be shorter than the witness believes
        nonce = secrets.token_urlsafe(16)
        body = {"v": 1, "op": "grant", "epoch": int(self.epoch_fn()), "nonce": nonce, "issued_at": int(self.wall())}
        req = {"req": body, "sig": sign(self.key, REQ_PREFIX, body)}
        try:
            resp = self.transport(req)
            r, sig = resp["resp"], resp["sig"]
            if not verify(self.witness_pub, RESP_PREFIX, r, sig) or r.get("nonce") != nonce or r.get("v") != 1:
                raise ValueError("witness reply is not authentic or not for this request")
        except Exception as e:  # noqa: BLE001  (partition, timeout, forged or replayed reply: no grant)
            self.last_error = f"{type(e).__name__}"
            return False
        if not r.get("ok"):
            if r.get("reason") == "superseded":
                self.superseded = True
                if self.on_superseded:
                    self.on_superseded()
            self.last_error = str(r.get("reason"))[:60]
            return False
        if r.get("epoch") != body["epoch"] or not isinstance(r.get("lease_s"), (int, float)):
            self.last_error = "bad grant"
            return False
        self.valid_until = max(self.valid_until, t0 + min(float(r["lease_s"]), self.lease_s))
        self.last_error = None
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.renew_once()
            self._stop.wait(self.renew_s)

    def start(self) -> None:
        if self.standalone or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ics-lease")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(5)


# ---------------------------------------------------------------------------------------------------------------------------- the witness
class Witness:
    """The witness's state machine (runs on the standby host or any third host). State file (fsync'd, 0600): {"revoked_epoch": n, "max_epoch": n, "last_grant_age_ref": ...}.
    `clock` is monotonic; `last_grant` is kept in memory AND persisted as wall-clock so a restarted witness assumes the worst (a grant might have been made a moment ago)."""

    def __init__(self, key, controller_pub, *, lease_seconds=30.0, state_path=None, clock=time.monotonic, wall=time.time, witness_id="witness"):
        self.key, self.controller_pub = key, controller_pub
        self.lease_s, self.clock, self.wall, self.state_path, self.id = float(lease_seconds), clock, wall, state_path, witness_id
        self.lock = threading.Lock()
        self.revoked_epoch = 0
        self.max_epoch = 0
        self.last_grant: float | None = None     # monotonic
        self.seen: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        """merge the state file into memory (a `revoke` CLI process writes the same file the serving process uses): epochs only go up, the grant time
        is the most recent one; a restart must not shorten the proof (the persisted grant counts as made `wall - last_grant_wall` seconds ago)"""
        if not self.state_path or not os.path.exists(self.state_path):
            return
        d = json.load(open(self.state_path))
        self.revoked_epoch, self.max_epoch = max(self.revoked_epoch, int(d.get("revoked_epoch", 0))), max(self.max_epoch, int(d.get("max_epoch", 0)))
        lw = d.get("last_grant_wall")
        if lw is not None:
            g = self.clock() - max(0.0, self.wall() - float(lw))
            self.last_grant = g if self.last_grant is None else max(self.last_grant, g)

    def _save(self) -> None:
        if not self.state_path:
            return
        self._load()
        lw = None if self.last_grant is None else self.wall() - (self.clock() - self.last_grant)
        tmp = self.state_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"revoked_epoch": self.revoked_epoch, "max_epoch": self.max_epoch, "last_grant_wall": lw}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    def _reply(self, body: dict) -> dict:
        return {"resp": body, "sig": sign(self.key, RESP_PREFIX, body)}

    def handle(self, req: dict) -> dict:
        """the request of Lease.renew_once; raises ValueError for anything not authentic (the HTTP layer answers 400)"""
        b, sig = req["req"], req["sig"]
        if not verify(self.controller_pub, REQ_PREFIX, b, sig) or b.get("v") != 1 or b.get("op") != "grant":
            raise ValueError("not signed by the controller")
        e, nonce = b.get("epoch"), b.get("nonce")
        if type(e) is not int or not isinstance(nonce, str) or not 8 <= len(nonce) <= 64 or type(b.get("issued_at")) is not int:
            raise ValueError("malformed")
        if abs(self.wall() - b["issued_at"]) > MAX_REQ_AGE:
            raise ValueError("stale request")
        with self.lock:
            self._load()
            now = self.clock()
            self.seen = {k: v for k, v in self.seen.items() if now - v < 2 * MAX_REQ_AGE}
            if nonce in self.seen:
                raise ValueError("replayed request")
            self.seen[nonce] = now
            if e <= self.revoked_epoch or e < self.max_epoch:
                return self._reply({"v": 1, "ok": False, "reason": "superseded", "nonce": nonce})
            self.max_epoch = max(self.max_epoch, e)
            self.last_grant = now
            self._save()
            return self._reply({"v": 1, "ok": True, "epoch": e, "nonce": nonce, "lease_s": self.lease_s, "witness": self.id})

    # ---- promotion ----
    def revoke(self, epoch: int | None = None) -> int:
        """stop granting for every epoch up to the highest seen (or `epoch`): called by the promotion CLI FIRST"""
        with self.lock:
            self.revoked_epoch = max(self.revoked_epoch, self.max_epoch if epoch is None else int(epoch))
            self._save()
            return self.revoked_epoch

    def seconds_until_proven(self, margin: float) -> float:
        """0 when no controller can still hold a valid lease: T + margin have passed since the last grant (or none was ever made)"""
        with self.lock:
            self._load()
            if self.last_grant is None:
                return 0.0
            return max(0.0, self.lease_s + float(margin) - (self.clock() - self.last_grant))

    def wait_proven(self, margin: float, sleep=time.sleep, progress=None) -> None:
        """blocks until seconds_until_proven() == 0 (the promotion CLI waits here; it must have revoked first)"""
        if self.revoked_epoch < self.max_epoch:
            raise RuntimeError("revoke() first: the witness would still grant")
        while True:
            left = self.seconds_until_proven(margin)
            if left <= 0:
                return
            if progress:
                progress(left)
            sleep(min(left, 2.0))


# ---------------------------------------------------------------------------------------------------------------------------- HTTP glue
def http_transport(url: str, *, timeout=3.0, fingerprint_sha256: str | None = None):
    import httpx
    from .proxmox import build_ssl_context
    verify_ = build_ssl_context(ca_pem=None, fingerprint_sha256=fingerprint_sha256) if url.startswith("https://") and fingerprint_sha256 else True

    def send(req: dict) -> dict:
        r = httpx.post(url.rstrip("/") + "/witness/v1/grant", json=req, timeout=timeout, verify=verify_, follow_redirects=False, trust_env=False)
        if r.status_code != 200:
            raise RuntimeError(f"witness answered HTTP {r.status_code}")
        return r.json()
    return send


def build(rt):
    """Lease for a Runtime, or None (lease OFF: single-controller install)."""
    s = rt.settings
    if not s.lease_witness_url or s.role != "primary":
        return None
    from . import agentclient, epoch
    key = agentclient.load_signing_key(s.signing_key_file)
    pub = pub_from_b64(s.lease_witness_pubkey or "")
    ls = Lease(signing_key=key, witness_pub=pub, transport=http_transport(s.lease_witness_url, fingerprint_sha256=s.lease_witness_tls_fp),
               epoch_fn=lambda: epoch.current_db_epoch(rt), lease_seconds=s.lease_seconds, renew_seconds=s.lease_renew_seconds, standalone=s.lease_standalone_override,
               on_superseded=lambda: setattr(rt, "fenced_reason", rt.fenced_reason or "superseded: the witness revoked this controller's lease"))
    return ls
