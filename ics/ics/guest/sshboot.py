"""LAB-ONLY (ICS_LAB_SSH_BOOTSTRAP=true and ICS_ENVIRONMENT=lab): ICS-driven first boot of a fresh guest over SSH. NOT a production path
(docs/status/review-ssh-bootstrap-2026-11-15.md; ADR-0002 addendum "lab-only exception"). The production path is the golden image + authenticated
callback (guest/callback.py, docs/status/bootstrap-v2.md): no inbound SSH at any point.

Why it exists. The real cluster's stock Debian template has no QEMU guest agent and no code of ours, and `cicustom` needs snippets the Proxmox API
cannot upload. The only authenticated ICS -> guest channel is what the Proxmox API writes into the cloud-init drive and the VM config
(`ciuser`, `sshkeys`, SMBIOS).

  * per VM INSTANCE the ICS draws random material (guest/bootsecrets.py: SSH key, proof secret, enrollment token; vault-encrypted, deleted after
    the seal); the public key goes into `sshkeys`, the proof secret into the SMBIOS serial (root-readable in the guest only, never on a command line);
  * the ICS reaches the booted guest on its IPv6 link-local address (EUI-64 from the MAC Proxmox reports) and logs in with the key. The GUEST must
    prove it is the VM Proxmox created BEFORE the ICS sends anything (review M4): every session first prints HMAC(proof secret, nonce) and only then
    reads its stdin, which carries the payload (the rendered user-data); the output carries a second HMAC (so no host-key TOFU is needed);
  * the FIRST thing done in a proven session is arming a persistent seal (script + timer + boot check) that disables SSH and locks the account
    after `seal_minutes` regardless of the ICS (review H1); nothing else is installed before that;
  * the seal is synchronous and verified (review H2): masked units, locked account, no keys, and a port-22 probe from the ICS.

Every remote command is a fixed script from this file (`Guest.run` takes an operation NAME; only validated, charset-restricted values are
interpolated); there is no API that lets a caller choose a command."""
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass

BOOT_USER = "ou-boot"
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
OUT_LIMIT = 256 * 1024
STATE_DIR = "/var/lib/ou-bootstrap"


class BootstrapError(Exception):
    """Operator-readable, secret-free."""


class NotReady(BootstrapError):
    """The guest cannot be reached (yet): safe to retry."""


class ProofFailed(BootstrapError):
    """An answering host failed the SMBIOS proof: NEVER retry blindly, never send it anything."""


class SealUnverified(BootstrapError):
    """The seal ran (or was attempted) but its effect could not be verified."""


@dataclass(frozen=True)
class BootIdentity:
    ssh_private_openssh: bytes
    ssh_public: str
    psk: str                 # the SMBIOS serial value (bid + random secret), [0-9a-f]{64}; the HMAC key of every proof
    enroll_token: str        # one-time agent enrollment token; only its sha256 reaches the guest
    enroll_token_sha256: str


def identity(rec) -> BootIdentity:
    """From a bootsecrets.BootRecord (random per VM instance)."""
    if rec.mode != "ssh-lab" or not rec.secret or not rec.ssh_private_openssh or not rec.token:
        raise BootstrapError("the bootstrap material of this VM instance is gone or not an SSH-lab record")
    return BootIdentity(rec.ssh_private_openssh, rec.ssh_public, rec.smbios_serial, rec.token, rec.token_sha256)


def link_local(mac: str, iface: str) -> str:
    """fe80:: EUI-64 address of a NIC with this MAC (what a Debian/Ubuntu cloud image configures by default), scoped to our interface."""
    if not MAC_RE.match(mac) or not IFACE_RE.match(iface):
        raise BootstrapError("invalid MAC or interface")
    b = bytearray(int(x, 16) for x in mac.split(":"))
    b[0] ^= 2
    addr = ipaddress.IPv6Address(bytes([0xfe, 0x80] + [0] * 6 + [b[0], b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]]))
    return f"{addr.compressed}%{iface}"


def default_iface() -> str:
    """Interface of the IPv4 default route (the LAN the guests share with this host)."""
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                return f[0]
    except OSError:
        pass
    raise BootstrapError("cannot determine the LAN interface (no default route)")


def mac_of(psk: str, nonce: str, body: str) -> str:
    return hmac.new(psk.encode(), f"{nonce}\n{body}".encode(), hashlib.sha256).hexdigest()


def proof_of(psk: str, nonce: str) -> str:
    return hmac.new(psk.encode(), f"proof\n{nonce}".encode(), hashlib.sha256).hexdigest()


# The fixed outer script. $1 = nonce (hex), $2 = base64 of the operation body. The key is read from sysfs INSIDE python3 (never on a command line,
# review M2). First line out = the proof; then the operation runs with stdin = the payload; the last line is an HMAC over nonce + output.
OUTER = r'''set -eu
N="$1"
python3 -c 'import sys,hmac,hashlib;k=open("/sys/class/dmi/id/product_serial","rb").read().rstrip(b"\n");print("OU-PROOF "+hmac.new(k,("proof\n"+sys.argv[1]).encode(),hashlib.sha256).hexdigest(),flush=True)' "$N"
OUT=$(eval "$(printf %s "$2" | base64 -d)")
printf '%s\n' "$OUT"
printf '%s\n%s' "$N" "$OUT" | python3 -c 'import sys,hmac,hashlib;k=open("/sys/class/dmi/id/product_serial","rb").read().rstrip(b"\n");print("OU-MAC "+hmac.new(k,sys.stdin.buffer.read(),hashlib.sha256).hexdigest())'
'''


# ---- the fixed bodies (run as root through sudo) ---------------------------------------------------------------------

PROBE = """echo "proven=1"
echo "addr=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
echo "done=$([ -f /var/lib/ou-bootstrap/done ] && echo 1 || echo 0)"
echo "armed=$([ -f /var/lib/ou-bootstrap/seal-deadline ] && echo 1 || echo 0)"
echo "sealed=$([ -f /var/lib/ou-bootstrap/sealed ] && echo 1 || echo 0)"
echo "running=$(systemctl is-active ou-bootstrap-run.service 2>/dev/null || true)"
echo "os=$(. /etc/os-release; echo $ID-$VERSION_ID)\""""

SEAL_SCRIPT = f"""#!/bin/sh
# generated: ends the ICS-driven bootstrap. SSH is disabled and masked, the bootstrap account is locked and loses its key and sudo rule.
# Run synchronously by the ICS after enrollment, by a timer N minutes after it was armed, and at every boot once the deadline passed. Idempotent.
set -u
systemctl disable --now ssh.socket ssh.service 2>/dev/null || true
systemctl mask ssh.socket ssh.service 2>/dev/null || true
passwd -l {BOOT_USER} >/dev/null 2>&1 || true
usermod --expiredate 1 {BOOT_USER} 2>/dev/null || true
rm -f "$(getent passwd {BOOT_USER} | cut -d: -f6)/.ssh/authorized_keys"
for f in /etc/sudoers.d/*; do [ -f "$f" ] && sed -i '/^{BOOT_USER}[[:space:]]/d' "$f"; done
install -d -m 0755 {STATE_DIR}
date +%s > {STATE_DIR}/sealed
exit 0
"""

SEAL_BOOT_CHECK = f"""#!/bin/sh
# at boot: seal at once when the deadline recorded by the ICS has passed (the transient timers do not survive a reboot)
[ -f {STATE_DIR}/sealed ] && exit 0
[ -f {STATE_DIR}/seal-deadline ] || exit 0
[ "$(date +%s)" -ge "$(cat {STATE_DIR}/seal-deadline)" ] && exec /usr/local/sbin/ou-bootstrap-seal
exit 0
"""


def arm_body(seal_minutes: int) -> str:
    if not isinstance(seal_minutes, int) or not 5 <= seal_minutes <= 1440:
        raise BootstrapError("invalid seal delay")
    unit_svc = ("[Unit]\nDescription=Office Unbound bootstrap seal\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/ou-bootstrap-seal\n")
    unit_tim = (f"[Unit]\nDescription=Office Unbound bootstrap dead-man seal\n[Timer]\nOnActiveSec={seal_minutes}min\nOnBootSec={seal_minutes}min\nUnit=ou-bootstrap-seal.service\n"
                "[Install]\nWantedBy=timers.target\n")
    unit_boot = ("[Unit]\nDescription=Office Unbound bootstrap seal check\nAfter=local-fs.target\n[Service]\nType=oneshot\n"
                 "ExecStart=/usr/local/sbin/ou-bootstrap-seal-check\n[Install]\nWantedBy=multi-user.target\n")
    return f"""install -d -m 0755 {STATE_DIR}
cat > /usr/local/sbin/ou-bootstrap-seal <<'OU_SEAL_END'
{SEAL_SCRIPT}OU_SEAL_END
cat > /usr/local/sbin/ou-bootstrap-seal-check <<'OU_CHECK_END'
{SEAL_BOOT_CHECK}OU_CHECK_END
chmod 0750 /usr/local/sbin/ou-bootstrap-seal /usr/local/sbin/ou-bootstrap-seal-check
cat > /etc/systemd/system/ou-bootstrap-seal.service <<'OU_U1'
{unit_svc}OU_U1
cat > /etc/systemd/system/ou-bootstrap-seal.timer <<'OU_U2'
{unit_tim}OU_U2
cat > /etc/systemd/system/ou-bootstrap-seal-check.service <<'OU_U3'
{unit_boot}OU_U3
echo $(( $(date +%s) + {seal_minutes * 60} )) > {STATE_DIR}/seal-deadline
systemctl daemon-reload
systemctl enable ou-bootstrap-seal-check.service >/dev/null 2>&1 || true
systemctl enable --now ou-bootstrap-seal.timer >/dev/null 2>&1
echo "armed=$([ -f {STATE_DIR}/seal-deadline ] && systemctl is-active ou-bootstrap-seal.timer >/dev/null 2>&1 && echo 1 || echo 0)\""""


RUNNER = """set -u
exec >/var/log/ou-bootstrap-run.log 2>&1
rm -f /var/log/ou-bootstrap-run.rc
cloud-init clean --logs
cloud-init init --local && cloud-init init && cloud-init modules --mode=config && cloud-init modules --mode=final
echo $? > /var/log/ou-bootstrap-run.rc
"""


def install_body(instance_id: str, hostname: str) -> str:
    """The user-data itself arrives on STDIN (after the guest proved itself), not inside the script."""
    if not re.match(r"^[a-z0-9-]{8,64}$", instance_id) or not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", hostname):
        raise BootstrapError("invalid instance id or hostname")
    return f"""if [ -f /var/lib/ou-bootstrap/done ]; then cat >/dev/null; echo "state=done"; exit 0; fi
if systemctl is-active --quiet ou-bootstrap-run.service; then cat >/dev/null; echo "state=running"; exit 0; fi
D=/var/lib/cloud/seed/nocloud
install -d -m 0700 $D
cat > $D/user-data
printf 'instance-id: {instance_id}\\nlocal-hostname: {hostname}\\n' > $D/meta-data
# the seed must be the ONLY NoCloud source: the first-boot cloud-init drive (Proxmox's, no workload config) is consumed already
printf 'datasource:\\n  NoCloud:\\n    fs_label: null\\n' > /etc/cloud/cloud.cfg.d/99-ou-bootstrap.cfg
cat > /usr/local/sbin/ou-bootstrap-run <<'OU_RUN_END'
{RUNNER}OU_RUN_END
chmod 0750 /usr/local/sbin/ou-bootstrap-run
systemd-run --quiet --no-block --unit=ou-bootstrap-run /bin/sh /usr/local/sbin/ou-bootstrap-run
echo "state=started\""""


WAIT_CI = 'timeout 240 cloud-init status --wait >/dev/null 2>&1 || true\necho "proven=1"'

STATUS = """echo "running=$(systemctl is-active ou-bootstrap-run.service 2>/dev/null || true)"
echo "rc=$(cat /var/log/ou-bootstrap-run.rc 2>/dev/null || echo none)"
echo "done=$([ -f /var/lib/ou-bootstrap/done ] && echo 1 || echo 0)"
echo "log=$(tail -n 6 /var/log/ou-bootstrap-run.log 2>/dev/null | tr -c '[:print:]\\n' '?' | tr '\\n' '|' | cut -c1-600)\""""

FINGERPRINTS = "cat /var/lib/ou-bootstrap/fingerprints.json | sed 's/^/json=/'"

# the synchronous seal: run the seal script IN this session (stopping sshd does not end the session: KillMode=process) and report what is true now
SEAL = f"""/usr/local/sbin/ou-bootstrap-seal
echo "ssh_enabled=$(systemctl is-enabled ssh.service 2>/dev/null || true)/$(systemctl is-enabled ssh.socket 2>/dev/null || true)"
echo "ssh_active=$(systemctl is-active ssh.service 2>/dev/null || true)/$(systemctl is-active ssh.socket 2>/dev/null || true)"
echo "locked=$(passwd -S {BOOT_USER} 2>/dev/null | awk '{{print $2}}')"
echo "keys=$([ -s "$(getent passwd {BOOT_USER} | cut -d: -f6)/.ssh/authorized_keys" ] && echo 1 || echo 0)"
echo "sudo=$(grep -rl '^{BOOT_USER}[[:space:]]' /etc/sudoers.d 2>/dev/null | wc -l)"
echo "sealed=$([ -f {STATE_DIR}/sealed ] && echo 1 || echo 0)\""""

OPERATIONS = {"probe": lambda: PROBE, "wait_ci": lambda: WAIT_CI, "status": lambda: STATUS, "fingerprints": lambda: FINGERPRINTS, "seal": lambda: SEAL,
              "arm": arm_body, "install": install_body}


def seal_effective(r: dict[str, str]) -> bool:
    """Interpretation of the SEAL operation's (MAC-authenticated) report: masked units, inactive sshd, locked account, no key, no sudo rule."""
    enabled = r.get("ssh_enabled", "").split("/")
    active = r.get("ssh_active", "").split("/")
    return (r.get("sealed") == "1" and r.get("keys") == "0" and r.get("sudo") == "0" and r.get("locked", "") in ("L", "LK")
            and enabled[0] == "masked" and all(x in ("masked", "not-found", "") for x in enabled[1:])
            and "active" not in active)


def port_closed(addr: str, port: int = 22, timeout: float = 4.0) -> bool:
    """True when nothing accepts TCP connections at addr:port (refused or filtered). `addr` may be a scoped IPv6 link-local ("fe80::1%eth0")."""
    try:
        infos = socket.getaddrinfo(addr, port, type=socket.SOCK_STREAM)
        for fam, typ, proto, _c, sa in infos:
            with socket.socket(fam, typ, proto) as s:
                s.settimeout(timeout)
                if s.connect_ex(sa) == 0:
                    return False
        return True
    except OSError:
        return True


class Guest:
    """One guest reached over SSH on its link-local address; every session is proof-first and MAC-authenticated against the proof secret."""

    def __init__(self, ident: BootIdentity, address: str, user: str = BOOT_USER, ssh_bin: str | None = None):
        self.ident, self.address, self.user = ident, address, user
        self.ssh = ssh_bin or shutil.which("ssh") or "/usr/bin/ssh"

    def _session(self, op: str, payload: bytes = b"", timeout: float = 60.0, **params) -> dict[str, str]:
        """`op` is a NAME from OPERATIONS; the body is this module's constant (or its validated builder), never caller-supplied text."""
        if op not in OPERATIONS:
            raise BootstrapError("unknown bootstrap operation")
        body = OPERATIONS[op](**params)
        nonce = secrets.token_hex(16)
        b64 = base64.b64encode(body.encode()).decode()
        remote = f"sudo -n /bin/sh -c {shlex.quote(OUTER)} sh {nonce} {b64}"
        with tempfile.TemporaryDirectory(prefix="ou-boot-") as d:
            os.chmod(d, 0o700)
            kf = os.path.join(d, "k")
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self.ident.ssh_private_openssh)
            argv = [self.ssh, "-6", "-i", kf, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                    "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}", "-o", "LogLevel=ERROR",   # guest authenticity: HMAC below
                    "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-o", "ClearAllForwardings=yes",
                    "-o", "ForwardAgent=no", "-o", "RequestTTY=no", f"{self.user}@{self.address}", remote]
            try:
                p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env={"PATH": "/usr/bin:/bin", "HOME": d, "LANG": "C"})
            except OSError:
                raise BootstrapError("cannot run the ssh client") from None
            try:
                first = self._read_line(p, min(timeout, 30.0))
                want = "OU-PROOF " + proof_of(self.ident.psk, nonce)
                if not hmac.compare_digest(first.strip(), want):
                    raise ProofFailed("the answering host could not prove it is the VM Proxmox created (SMBIOS proof mismatch); nothing was sent to it")
                try:
                    if payload:
                        p.stdin.write(payload)
                    p.stdin.close()
                except OSError:
                    pass
                out, _ = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise NotReady("the guest did not answer in time") from None
            except BaseException:
                p.kill()
                p.wait()
                raise
        if p.returncode != 0 or len(out) > OUT_LIMIT:
            raise NotReady("the guest refused the command or dropped the connection")   # stderr deliberately not echoed
        text = out.decode("utf-8", "replace")
        body_txt, _, last = text.rstrip("\n").rpartition("\nOU-MAC ")
        if not last or not hmac.compare_digest(last.strip(), mac_of(self.ident.psk, nonce, body_txt.rstrip("\n"))):
            raise ProofFailed("the answering host's output failed the SMBIOS proof; refusing to continue")
        return dict(l.partition("=")[::2] for l in body_txt.splitlines() if "=" in l and re.match(r"^[a-z_]+=", l))

    @staticmethod
    def _read_line(p, timeout: float) -> str:
        buf = b""
        end = time.monotonic() + timeout
        while b"\n" not in buf:
            left = end - time.monotonic()
            if left <= 0:
                raise NotReady("the guest did not answer in time")
            r, _, _ = select.select([p.stdout], [], [], left)
            if not r:
                raise NotReady("the guest did not answer in time")
            chunk = os.read(p.stdout.fileno(), 4096)
            if not chunk:
                raise NotReady("the guest is not reachable over SSH yet or refused the command")
            buf += chunk
            if len(buf) > 4096:
                raise ProofFailed("the answering host sent garbage instead of a proof")
        return buf.split(b"\n", 1)[0].decode("utf-8", "replace")

    # typed operations ----------------------------------------------------------------------------------------------
    def probe(self) -> dict[str, str]:
        return self._session("probe", timeout=60)

    def arm(self, seal_minutes: int) -> dict[str, str]:
        r = self._session("arm", timeout=60, seal_minutes=seal_minutes)
        if r.get("armed") != "1":
            raise BootstrapError("the guest could not arm its seal timer")
        return r

    def wait_cloud_init(self) -> dict[str, str]:
        return self._session("wait_ci", timeout=300)

    def install(self, user_data: str, instance_id: str, hostname: str) -> dict[str, str]:
        return self._session("install", payload=user_data.encode(), timeout=120, instance_id=instance_id, hostname=hostname)

    def status(self) -> dict[str, str]:
        return self._session("status")

    def fingerprints(self) -> str:
        return self._session("fingerprints").get("json", "")

    def seal_verified(self) -> dict[str, str]:
        """Seal synchronously; raise SealUnverified unless the guest's own report AND a port-22 probe from here show it took effect."""
        try:
            r = self._session("seal", timeout=90)
        except NotReady:
            r = None   # the connection may drop while sshd is stopped; the probe below decides
        if r is not None and not seal_effective(r):
            raise SealUnverified("the guest's seal report shows SSH or the bootstrap account is still usable")
        if not port_closed(self.address):
            raise SealUnverified("TCP port 22 of the guest still accepts connections after the seal")
        if r is None:
            raise SealUnverified("the guest did not confirm the seal; port 22 is closed but the account state is unverified")
        return r
