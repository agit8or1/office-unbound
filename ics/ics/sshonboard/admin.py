"""Admin facades over the SSH templates (duck-typed like providers.proxmox.admin.ProxmoxAdminClient so the EXISTING permission-plan generator,
apply_plan, rollback_created and collect_facts are reused unchanged), the dry-run twin that renders the approvers' command list, the ICS's own
node identity (ed25519 key, forced-command authorized_keys line, helper + config + sudoers) and the client for that identity."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from urllib.parse import parse_qsl, urlparse  # noqa: F401

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..providers.base import require_job_execution
from ..proxmox import ProxmoxError
from . import templates as T
from .client import HostKey, SshError, SshSession, fingerprint_of

MAX_JSON = 8 * 1024 * 1024
FORCED = "sudo -n " + T.HELPER_PATH


def _fail(c: T.Cmd, r) -> ProxmoxError:
    tail = re.sub(r"\s+", " ", r.err.strip())[-160:]
    return ProxmoxError(f"node command '{c.name}' failed (exit {r.rc}){': ' + tail if tail else ''}")


class SshAdmin:
    """Executes ONLY templates.* commands over a pinned SSH session. `executed` lists template names (never arguments' secrets, never output)."""

    def __init__(self, sess: SshSession):
        self.s = sess
        self.executed: list[str] = []
        self.discarded = False

    def run(self, c: T.Cmd, *, write: bool = True) -> bytes:
        if write:
            require_job_execution()
        if self.discarded:
            raise ProxmoxError("SSH credential was already discarded")
        r = self.s.run(c)
        self.executed.append(c.name)
        if r.rc != 0:
            raise _fail(c, r)
        return r.out

    def run_rc(self, c: T.Cmd) -> int:
        """For probes where a non-zero exit is an answer (e.g. getent), not an error."""
        r = self.s.run(c)
        self.executed.append(c.name)
        return r.rc

    # ---- reads (discovery) ----
    def get(self, path: str):
        out = self.run(T.pvesh_get(path), write=False)
        if len(out) > MAX_JSON:
            raise ProxmoxError("discovery output exceeded the size limit")
        try:
            data = json.loads(out.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ProxmoxError(f"node returned invalid JSON for {path.split('?')[0]}") from None
        if not isinstance(data, (list, dict)):
            raise ProxmoxError("unexpected discovery result type")
        return data

    def optional_text(self, c: T.Cmd, limit: int = 2 * 1024 * 1024) -> str | None:
        """Read-only probe whose absence is an answer (no LVM / no ZFS on this node): None when the tool is missing or fails."""
        r = self.s.run(c)
        self.executed.append(c.name)
        return r.out.decode("utf-8", "replace") if r.rc == 0 and len(r.out) <= limit else None

    def raw_text(self, c: T.Cmd, limit: int = 256 * 1024) -> str:
        out = self.run(c, write=False)
        if len(out) > limit:
            raise ProxmoxError("output exceeded the size limit")
        return out.decode("utf-8", "replace")

    # ---- the same typed helpers ProxmoxAdminClient has, each a fixed template ----
    def user_add(self, userid, comment):
        self.run(T.user_add(userid, comment))

    def user_delete(self, userid):
        self.run(T.user_delete(userid))

    def token_add(self, userid, name, comment, privsep=1) -> dict:
        out = self.run(T.token_add(userid, name, comment, privsep))
        try:
            d = json.loads(out.decode())
            if not isinstance(d, dict) or not isinstance(d.get("value"), str) or not isinstance(d.get("info"), dict):
                raise ValueError
        except ValueError:
            raise ProxmoxError("node returned an unexpected token response (the secret was not captured)") from None
        return d

    def token_delete(self, userid, name):
        self.run(T.token_delete(userid, name))

    def role_add(self, name, privs):
        self.run(T.role_add(name, privs))

    def role_set(self, name, privs):
        self.run(T.role_set(name, privs))

    def role_delete(self, name):
        self.run(T.role_delete(name))

    def acl_set(self, path, role, *, user=None, token=None, propagate=1, delete=False):
        self.run(T.acl_set(path, role, user=user, token=token, propagate=propagate, delete=delete))

    def pool_add(self, pool, comment=""):
        self.run(T.pool_add(pool, comment))

    def pool_delete(self, pool):
        self.run(T.pool_delete(pool))

    def discard(self) -> None:
        self.discarded = True
        self.s.close()


class DryAdmin:
    """Renders what SshAdmin would run (same builders) without connecting: the command list approvers see and the plan hash binds."""

    def __init__(self, sudo: bool):
        self.sudo, self.cmds = sudo, []

    def _r(self, c: T.Cmd):
        self.cmds.append(c)

    def user_add(self, userid, comment):
        self._r(T.user_add(userid, comment))

    def user_delete(self, userid):
        self._r(T.user_delete(userid))

    def token_add(self, userid, name, comment, privsep=1):
        self._r(T.token_add(userid, name, comment, privsep))
        return {"info": {"privsep": "1"}, "value": "<token secret: captured into the vault, never shown>", "full-tokenid": f"{userid}!{name}"}

    def token_delete(self, userid, name):
        self._r(T.token_delete(userid, name))

    def role_add(self, name, privs):
        self._r(T.role_add(name, privs))

    def role_set(self, name, privs):
        self._r(T.role_set(name, privs))

    def role_delete(self, name):
        self._r(T.role_delete(name))

    def acl_set(self, path, role, *, user=None, token=None, propagate=1, delete=False):
        self._r(T.acl_set(path, role, user=user, token=token, propagate=propagate, delete=delete))

    def pool_add(self, pool, comment=""):
        self._r(T.pool_add(pool, comment))

    def lines(self) -> list[str]:
        return [c.line(self.sudo) for c in self.cmds]


# ------------------------------------------------------------------------------------------------ the ICS's own node identity
def helper_source() -> bytes:
    return resources.files("ics.sshonboard").joinpath("ou_pve_helper.py").read_bytes()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass
class NodeIdentity:
    account: str
    home: str
    node: str
    pub_line: str                 # "ssh-ed25519 AAAA..."
    key_fp: str                   # SHA256:... of the public key
    authorized_line: str
    helper: bytes = field(repr=False)
    conf: bytes = field(repr=False)
    sudoers: bytes = field(repr=False)

    def summary(self) -> dict:
        return {"account": self.account, "home": self.home, "node": self.node, "key_fingerprint": self.key_fp, "authorized_keys_line": self.authorized_line,
                "helper_path": T.HELPER_PATH, "helper_sha256": sha(self.helper), "conf_sha256": sha(self.conf), "conf": json.loads(self.conf),
                "sudoers_path": T.SUDOERS_PATH, "sudoers": self.sudoers.decode(), "sudoers_sha256": sha(self.sudoers)}


def generate_keypair() -> tuple[str, str, str]:
    """-> (OpenSSH private key PEM, public key line, SHA256 fingerprint). The private key goes to the vault and nowhere else."""
    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return pem, pub, fingerprint_of(__import__("base64").b64decode(pub.split()[1]))


def conf_for(userid: str, tokens: list[str], roles: list[str]) -> bytes:
    return (json.dumps({"version": 1, "user": userid, "tokens": sorted(tokens), "roles": sorted(roles)}, sort_keys=True, indent=1) + "\n").encode()


def sudoers_for(account: str) -> bytes:
    T._v(T.ACCOUNT, account, "account")
    return (f"# Office Unbound ICS (managed): exactly the helper, no arguments, no wildcards\n"
            f'Defaults:{account} env_keep += "SSH_ORIGINAL_COMMAND"\n'
            f'{account} ALL=(root) NOPASSWD: {T.HELPER_PATH} ""\n').encode()


def authorized_line(pub: str, from_addr: str | None) -> str:
    opts = []
    if from_addr:
        if not re.fullmatch(r"[0-9A-Fa-f:.]{3,45}", from_addr):
            raise T.TemplateError("invalid from= address")
        opts.append(f'from="{from_addr}"')
    opts += ["restrict", f'command="{FORCED}"']
    return ",".join(opts) + " " + pub + " ou-ics@office-unbound"


def build_identity(account: str, node: str, pub: str, key_fp: str, userid: str, tokens: list[str], roles: list[str], from_addr: str | None) -> NodeIdentity:
    T._v(T.ACCOUNT, account, "account")
    T._v(T.NODE, node, "node")
    return NodeIdentity(account=account, home=f"/var/lib/{account}", node=node, pub_line=pub, key_fp=key_fp, authorized_line=authorized_line(pub, from_addr),
                        helper=helper_source(), conf=conf_for(userid, tokens, roles), sudoers=sudoers_for(account))


def install_commands(i: NodeIdentity) -> list[T.Cmd]:
    return [T.sudo_present(), T.account_add(i.account, i.home), T.account_lock(i.account), T.ssh_dir(i.account, i.home), T.authorized_keys(i.account, i.home, i.authorized_line),
            T.conf_dir(), T.install_helper(i.helper), T.install_conf(i.conf), T.sudoers_stage(i.sudoers), T.sudoers_check(), T.sudoers_commit()]


def remove_commands(account: str) -> list[T.Cmd]:
    return [T.remove_file("sudoers"), T.sudoers_discard(), T.remove_file("helper"), T.remove_file("conf"), T.account_delete(account)]


def install_identity(adm: SshAdmin, i: NodeIdentity) -> None:
    """Idempotent: an existing account is reused (and its key/helper/config/sudoers replaced); anything missing is created."""
    exists = adm.run_rc(T.account_exists(i.account)) == 0
    for c in install_commands(i):
        if c.name == "sudo.present" and adm.run_rc(c) != 0:
            raise ProxmoxError("sudo is not installed on the node (the ICS's restricted SSH account needs it): install it with 'apt install sudo' and retry")
        if exists and c.name in ("account.add", "account.lock"):
            continue
        if c.name == "sudo.present":
            continue
        try:
            adm.run(c)
        except ProxmoxError:
            if c.name.startswith("sudoers"):
                try:
                    adm.run(T.sudoers_discard())
                except ProxmoxError:
                    pass
            raise


def verify_files(adm: SshAdmin, i: NodeIdentity) -> None:
    for which, blob in (("helper", i.helper), ("conf", i.conf), ("sudoers", i.sudoers)):
        out = adm.run(T.sha256_of(which), write=False).decode().split()
        if not out or out[0] != sha(blob):
            raise ProxmoxError(f"installed {which} does not match the approved content")


def remove_identity(adm: SshAdmin, account: str) -> list[str]:
    left = []
    for c in remove_commands(account):
        try:
            adm.run(c)
        except ProxmoxError as e:
            left.append(str(e)[:120])
    return left


class HelperClient:
    """Connects with the ICS's OWN key and sends only the fixed operations of ou-pve-helper. Nothing else can be expressed by this class."""

    def __init__(self, host: str, port: int, account: str, pinned: HostKey, pem: str, timeout: float = 10.0):
        self.s = SshSession(host, port, account, pinned, pem=pem, timeout=timeout)

    def _op(self, line: str) -> str:
        r = self.s.run_raw(line)
        if r.rc != 0:
            raise ProxmoxError(f"helper refused or failed (exit {r.rc})")
        return r.out.decode("utf-8", "replace")

    def self_check(self) -> dict:
        return json.loads(self._op("self-check"))

    NODE_KINDS = ("network", "fw-options", "fw-rules")
    KINDS = ("version", "cluster-status", "nodes", "storage", "pools", "resources", "roles", "users", "acl", "fw-cluster", "storage-lvm")

    def discover(self, kind: str, node: str | None = None):
        if kind in self.NODE_KINDS:
            return json.loads(self._op(f"discover {kind} {T._v(T.NODE, node or '', 'node')}"))
        if kind == "storage-zfs":
            return self._op("discover storage-zfs")
        if kind not in self.KINDS:
            raise ValueError("unknown discovery kind")
        return json.loads(self._op(f"discover {kind}"))

    def cert(self) -> str:
        return self._op("cert-read")

    def drift(self) -> list[dict]:
        return [json.loads(x) for x in self._op("drift").splitlines() if x.strip()]

    def token_rotate(self, name: str) -> dict:
        require_job_execution()
        return json.loads(self._op(f"token-rotate {T._v(T.NAME, name, 'token')}"))

    def acl_narrow(self, path: str, role: str, subject: str) -> dict:
        require_job_execution()
        return json.loads(self._op(f"acl-narrow {T._v(T.ACLPATH, path, 'path')} {T._v(T.ROLE, role, 'role')} "
                                   f"{T._v(T.USERID if '!' not in subject else T.TOKENID, subject, 'subject')}"))

    def close(self):
        self.s.close()


def leaf_fingerprint(pem: str) -> str:
    """SHA-256 (hex) of the DER of the FIRST certificate in a PEM bundle: the format the ICS pins for HTTPS."""
    from cryptography import x509
    m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem, re.S)
    if not m:
        raise ProxmoxError("no certificate found on the node")
    der = x509.load_pem_x509_certificate(m.group(0).encode()).public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def known_host_key(text: str, names: list[str]) -> list[tuple[str, str]]:
    """From the cluster's /etc/pve/priv/known_hosts: (algo, fingerprint) pairs for a node name or address. Not used for the first node (that one is
    confirmed by the admin on its console)."""
    out = []
    for ln in text.splitlines():
        parts = ln.split()
        if len(parts) >= 3 and any(n in parts[0].split(",") for n in names):
            try:
                out.append((parts[1], fingerprint_of(__import__("base64").b64decode(parts[2]))))
            except Exception:  # noqa: BLE001
                continue
    return out
