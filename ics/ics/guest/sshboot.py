"""ICS-driven first boot of a fresh guest (ADR-0009 section 5 addendum; docs/status/first-real-deployment.md has the evaluation).

Why this exists. The real cluster's storage has no `snippets` content and the Proxmox API cannot upload snippets, so `cicustom` is not an
option; the stock Debian 12 template has no QEMU guest agent and no code of ours. The only authenticated ICS -> guest channel left is what the
Proxmox API itself writes into the cloud-init drive and the VM config: `ciuser`, `sshkeys`, `ipconfig`, SMBIOS. So:

  * the ICS derives (HMAC of its signing key, nothing stored) a per-VM Ed25519 SSH key and a per-VM secret PSK;
    the public key goes into `sshkeys`, the PSK into the SMBIOS serial (readable by root in the guest only);
  * the ICS reaches the freshly booted guest on its IPv6 link-local address (EUI-64 from the MAC Proxmox reports: no scan, no DHCP guessing),
    authenticates to the GUEST with the key (nobody else can log in), and authenticates the GUEST to itself by an HMAC over a fresh nonce
    and over every output, keyed with the PSK that only Proxmox could have given it (no host-key TOFU);
  * it uploads the rendered cloud-init user-data (guest/cloudinit.py, unchanged) as a NoCloud seed and re-runs cloud-init from it;
  * it reads the agent's TLS/agent-key fingerprints (MAC-authenticated), enrolls the agent over the pinned TLS channel (one-time token whose
    HASH is in the user-data), then runs the seal script (SSH disabled and masked, bootstrap account locked).

Every remote command is a fixed script from this file (only validated, charset-restricted values are interpolated); there is no API that lets a
caller choose a command. The key and PSK exist only in memory/a 0700 temp dir for the duration of one call."""
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BOOT_USER = "ou-boot"
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
OUT_LIMIT = 256 * 1024


class BootstrapError(Exception):
    """Operator-readable, secret-free."""


class NotReady(BootstrapError):
    """The guest cannot be reached (yet): safe to retry."""


class ProofFailed(BootstrapError):
    """An answering host failed the SMBIOS-PSK proof: NEVER retry blindly, never send it anything else."""


def derive(master: bytes, purpose: str, slug: str, vm: str) -> bytes:
    return hmac.new(master, f"ou-guest-bootstrap-v1|{purpose}|{slug}|{vm}".encode(), hashlib.sha256).digest()


@dataclass(frozen=True)
class BootIdentity:
    ssh_private_openssh: bytes
    ssh_public: str
    psk: str                 # SMBIOS serial value, [0-9a-f]{48}
    enroll_token: str        # one-time agent enrollment token ([A-Za-z0-9_-]{43}); only its sha256 reaches the guest
    enroll_token_sha256: str


def identity(signing_key: Ed25519PrivateKey, slug: str, vm: str) -> BootIdentity:
    master = signing_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    k = Ed25519PrivateKey.from_private_bytes(derive(master, "ssh", slug, vm))
    token = base64.urlsafe_b64encode(derive(master, "enroll", slug, vm)).decode().rstrip("=")
    return BootIdentity(
        k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()),
        k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + " ou-bootstrap",
        derive(master, "psk", slug, vm)[:24].hex(), token, hashlib.sha256(token.encode()).hexdigest())


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


def _wrap(nonce: str, body: str) -> str:
    """The fixed envelope: output of BODY plus an HMAC (keyed with the SMBIOS serial) over nonce+output."""
    return f"""set -eu
S=$(cat /sys/class/dmi/id/product_serial)
OUT=$({{
{body}
}})
printf '%s\\n' "$OUT"
printf 'OU-MAC %s\\n' "$(printf '%s\\n%s' '{nonce}' "$OUT" | openssl dgst -sha256 -hmac "$S" -r | cut -d' ' -f1)"
"""


# ---- the fixed bodies (run as root through sudo) ---------------------------------------------------------------------

PROBE = """timeout 240 cloud-init status --wait >/dev/null 2>&1 || true
echo "addr=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
echo "done=$([ -f /var/lib/ou-bootstrap/done ] && echo 1 || echo 0)"
echo "running=$(systemctl is-active ou-bootstrap-run.service 2>/dev/null || true)"
echo "os=$(. /etc/os-release; echo $ID-$VERSION_ID)\""""

RUNNER = """set -u
exec >/var/log/ou-bootstrap-run.log 2>&1
rm -f /var/log/ou-bootstrap-run.rc
cloud-init clean --logs
cloud-init init --local && cloud-init init && cloud-init modules --mode=config && cloud-init modules --mode=final
echo $? > /var/log/ou-bootstrap-run.rc
"""


def install_body(user_data: str, instance_id: str, hostname: str) -> str:
    if not re.match(r"^[a-z0-9-]{8,64}$", instance_id) or not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", hostname):
        raise BootstrapError("invalid instance id or hostname")
    b64 = base64.encodebytes(user_data.encode()).decode()
    return f"""if [ -f /var/lib/ou-bootstrap/done ]; then echo "state=done"; exit 0; fi
if systemctl is-active --quiet ou-bootstrap-run.service; then echo "state=running"; exit 0; fi
D=/var/lib/cloud/seed/nocloud
install -d -m 0700 $D
base64 -d > $D/user-data <<'OU_SEED_END'
{b64}OU_SEED_END
printf 'instance-id: {instance_id}\\nlocal-hostname: {hostname}\\n' > $D/meta-data
# the seed must be the ONLY NoCloud source: the first-boot cloud-init drive (Proxmox's, no workload config) is consumed already
printf 'datasource:\\n  NoCloud:\\n    fs_label: null\\n' > /etc/cloud/cloud.cfg.d/99-ou-bootstrap.cfg
cat > /usr/local/sbin/ou-bootstrap-run <<'OU_RUN_END'
{RUNNER}OU_RUN_END
chmod 0750 /usr/local/sbin/ou-bootstrap-run
systemd-run --quiet --no-block --unit=ou-bootstrap-run /bin/sh /usr/local/sbin/ou-bootstrap-run
echo "state=started\""""


STATUS = """echo "running=$(systemctl is-active ou-bootstrap-run.service 2>/dev/null || true)"
echo "rc=$(cat /var/log/ou-bootstrap-run.rc 2>/dev/null || echo none)"
echo "done=$([ -f /var/lib/ou-bootstrap/done ] && echo 1 || echo 0)"
echo "log=$(tail -n 6 /var/log/ou-bootstrap-run.log 2>/dev/null | tr -c '[:print:]\\n' '?' | tr '\\n' '|' | cut -c1-600)\""""

FINGERPRINTS = "cat /var/lib/ou-bootstrap/fingerprints.json"
SEAL = """systemd-run --quiet --no-block --on-active=4 --unit=ou-bootstrap-seal /usr/local/sbin/ou-bootstrap-seal
echo sealing"""


class Guest:
    """One guest reached over SSH on its link-local address; every call is MAC-authenticated against the PSK."""

    def __init__(self, ident: BootIdentity, address: str, user: str = BOOT_USER, ssh_bin: str | None = None):
        self.ident, self.address, self.user = ident, address, user
        self.ssh = ssh_bin or shutil.which("ssh") or "/usr/bin/ssh"

    def call(self, body: str, timeout: float = 60.0, stdin_extra: bytes = b"") -> dict[str, str]:
        nonce = secrets.token_hex(16)
        script = _wrap(nonce, body)
        with tempfile.TemporaryDirectory(prefix="ou-boot-") as d:
            kf = os.path.join(d, "k")
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self.ident.ssh_private_openssh)
            argv = [self.ssh, "-6", "-i", kf, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                    "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}", "-o", "LogLevel=ERROR",   # guest authenticity: HMAC below
                    "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-o", "ClearAllForwardings=yes",
                    "-o", "ForwardAgent=no", "-o", "RequestTTY=no", f"{self.user}@{self.address}", "sudo -n /bin/sh -s"]
            try:
                r = subprocess.run(argv, input=script.encode() + stdin_extra, capture_output=True, timeout=timeout,
                                   env={"PATH": "/usr/bin:/bin", "HOME": d, "LANG": "C"})
            except subprocess.TimeoutExpired:
                raise NotReady("the guest did not answer in time") from None
            except OSError:
                raise BootstrapError("cannot run the ssh client") from None
        if r.returncode != 0 or len(r.stdout) > OUT_LIMIT:
            raise NotReady("the guest is not reachable over SSH yet or refused the command")   # stderr deliberately not echoed
        out = r.stdout.decode("utf-8", "replace")
        body_txt, _, last = out.rstrip("\n").rpartition("\nOU-MAC ")
        if not last or not hmac.compare_digest(last.strip(), mac_of(self.ident.psk, nonce, body_txt.rstrip("\n"))):
            raise ProofFailed("the answering host could not prove it is the VM Proxmox created (SMBIOS proof mismatch); refusing to continue")
        return dict(l.partition("=")[::2] for l in body_txt.splitlines() if "=" in l and re.match(r"^[a-z_]+=", l))

    # typed operations ----------------------------------------------------------------------------------------------
    def probe(self) -> dict[str, str]:
        return self.call(PROBE, timeout=300)

    def install(self, user_data: str, instance_id: str, hostname: str) -> dict[str, str]:
        return self.call(install_body(user_data, instance_id, hostname), timeout=120)

    def status(self) -> dict[str, str]:
        return self.call(STATUS)

    def fingerprints(self) -> str:
        nonce_free = self.call(FINGERPRINTS + " | sed 's/^/json=/'")
        return nonce_free.get("json", "")

    def seal(self) -> None:
        try:
            self.call(SEAL)
        except BootstrapError:
            pass   # the guest may drop the connection while it seals; the timer seals it anyway
