"""The closed set of commands the ICS may run on a Proxmox node during onboarding (ADR-0014).

Every command is a `Cmd`: a template name, an argv built ONLY by the builder functions below, and optional stdin. Every interpolated value
is validated against a strict regex before it is placed in argv; the argv is then rendered with `shlex.join`, so even a value that slipped through
could not be interpreted by the remote shell. Nothing here accepts a caller-supplied command string. The same builders produce the command list
shown to approvers (DryAdmin) and the commands the job executes (SshAdmin)."""
from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass

NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
USERID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}@[A-Za-z0-9._-]{1,32}$")
TOKENID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}@[A-Za-z0-9._-]{1,32}![A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
ROLE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
PRIV = re.compile(r"^[A-Za-z][A-Za-z0-9.]{0,40}$")
ACLPATH = re.compile(r"^(?!.*/\.\.?(?:/|$))/(?:[A-Za-z0-9._:@+][A-Za-z0-9._:@+-]{0,62}(?:/[A-Za-z0-9._:@+][A-Za-z0-9._:@+-]{0,62})*)?$")   # no segment may start with "-"; no "//"
COMMENT = re.compile(r"^[A-Za-z0-9 ._:()/,=+-]{0,120}$")
ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

GET_ALLOWED = (
    re.compile(r"^/version$"), re.compile(r"^/cluster/status$"), re.compile(r"^/nodes$"), re.compile(r"^/storage$"), re.compile(r"^/pools$"),
    re.compile(r"^/cluster/resources(\?type=vm)?$"), re.compile(r"^/cluster/sdn/vnets$"),
    re.compile(r"^/nodes/[A-Za-z0-9][A-Za-z0-9.-]{0,62}/network$"),
    re.compile(r"^/cluster/firewall/options$"), re.compile(r"^/nodes/[A-Za-z0-9][A-Za-z0-9.-]{0,62}/firewall/(options|rules)$"),
    re.compile(r"^/access/users(\?full=1)?$"), re.compile(r"^/access/roles$"), re.compile(r"^/access/acl$"),
    re.compile(r"^/pools/[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$"),   # members of an Office Unbound pool (leftover cleanup: only an empty pool is offered)
)
_QUERY = {"type=vm": ["--type", "vm"], "full=1": ["--full", "1"]}

# fixed absolute paths on the node (never taken from input)
HELPER_PATH = "/usr/local/sbin/ou-pve-helper"
CONF_DIR = "/etc/office-unbound"
CONF_PATH = CONF_DIR + "/ou-pve-helper.json"
SUDOERS_PATH = "/etc/sudoers.d/ou-ics"
SUDOERS_TMP = "/etc/sudoers.d/.ou-ics.tmp"
CERT_PATHS = ("/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pve-ssl.pem")
KNOWN_HOSTS = "/etc/pve/priv/known_hosts"
CLUSTER_CA = "/etc/pve/pve-root-ca.pem"
MARK = "Office Unbound"


class TemplateError(ValueError):
    pass


@dataclass(frozen=True)
class Cmd:
    name: str
    argv: tuple[str, ...]
    stdin: bytes | None = None
    secret_out: bool = False      # stdout holds a secret (token value): never recorded or logged

    def render(self, sudo: bool = False) -> str:
        return shlex.join((("sudo", "-n", "--") if sudo else ()) + self.argv)

    def line(self, sudo: bool = False) -> str:
        s = self.render(sudo)
        if self.stdin is not None:
            s += f"   < [{len(self.stdin)} bytes, sha256 {hashlib.sha256(self.stdin).hexdigest()[:16]}]"
        return s


def _v(rx: re.Pattern, val: str, what: str) -> str:
    if not isinstance(val, str) or not rx.fullmatch(val) or ".." in val:
        raise TemplateError(f"invalid {what}")
    return val


# ------------------------------------------------------------------------------------------------ read-only discovery
def pvesh_get(path: str) -> Cmd:
    if not any(rx.fullmatch(path) for rx in GET_ALLOWED):
        raise TemplateError("path is not an allowed read-only discovery path")
    p, _, q = path.partition("?")
    extra = _QUERY[q] if q else []
    return Cmd("pvesh.get", ("pvesh", "get", p, "--output-format", "json", *extra))


def lvs_report() -> Cmd:
    """LVM thin-pool usage, bytes, JSON. Read-only."""
    return Cmd("lvs.report", ("lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "lv_name,vg_name,lv_size,data_percent,metadata_percent,pool_lv,lv_attr"))


def zfs_list() -> Cmd:
    """ZFS dataset usage (bytes, tab separated). Read-only."""
    return Cmd("zfs.list", ("zfs", "list", "-Hp", "-t", "filesystem,volume", "-o", "name,used,avail,volsize,refreservation"))


def read_cert(i: int) -> Cmd:
    return Cmd("cert.read", ("cat", CERT_PATHS[i]))


def read_cluster_ca() -> Cmd:
    return Cmd("cluster_ca.read", ("cat", CLUSTER_CA))


def read_known_hosts() -> Cmd:
    return Cmd("known_hosts.read", ("cat", KNOWN_HOSTS))


# ------------------------------------------------------------------------------------------------ pveum (PVE-internal accounts, ACLs)
def user_add(userid: str, comment: str) -> Cmd:
    return Cmd("pveum.user.add", ("pveum", "user", "add", _v(USERID, userid, "user id"), "--comment", _v(COMMENT, comment, "comment"), "--enable", "1"))


def user_delete(userid: str) -> Cmd:
    return Cmd("pveum.user.delete", ("pveum", "user", "delete", _v(USERID, userid, "user id")))


def token_add(userid: str, name: str, comment: str, privsep: int = 1) -> Cmd:
    if privsep != 1:
        raise TemplateError("tokens are always privilege-separated")
    return Cmd("pveum.token.add", ("pveum", "user", "token", "add", _v(USERID, userid, "user id"), _v(NAME, name, "token name"), "--privsep", "1",
                                   "--comment", _v(COMMENT, comment, "comment"), "--output-format", "json"), secret_out=True)


def token_delete(userid: str, name: str) -> Cmd:
    return Cmd("pveum.token.remove", ("pveum", "user", "token", "remove", _v(USERID, userid, "user id"), _v(NAME, name, "token name")))


def _privs(privs) -> str:
    return ",".join(sorted(_v(PRIV, p, "privilege") for p in privs))


def role_add(name: str, privs) -> Cmd:
    return Cmd("pveum.role.add", ("pveum", "role", "add", _v(ROLE, name, "role"), "--privs", _privs(privs)))


def role_set(name: str, privs) -> Cmd:
    return Cmd("pveum.role.modify", ("pveum", "role", "modify", _v(ROLE, name, "role"), "--privs", _privs(privs)))


def role_delete(name: str) -> Cmd:
    return Cmd("pveum.role.delete", ("pveum", "role", "delete", _v(ROLE, name, "role")))


def acl_set(path: str, role: str, *, user: str | None = None, token: str | None = None, propagate: int = 1, delete: bool = False) -> Cmd:
    if bool(user) == bool(token):
        raise TemplateError("exactly one of user / token")
    a = ["pveum", "acl", "modify", _v(ACLPATH, path, "ACL path"), "--roles", _v(ROLE, role, "role")]
    a += ["--users", _v(USERID, user, "user id")] if user else ["--tokens", _v(TOKENID, token, "token id")]
    a += ["--propagate", "1" if propagate else "0"]
    if delete:
        a += ["--delete", "1"]
    return Cmd("pveum.acl.delete" if delete else "pveum.acl.modify", tuple(a))


def pool_add(pool: str, comment: str = "") -> Cmd:
    return Cmd("pveum.pool.add", ("pveum", "pool", "add", _v(NAME, pool, "pool"), "--comment", _v(COMMENT, comment, "comment")))


def pool_delete(pool: str) -> Cmd:
    return Cmd("pveum.pool.delete", ("pveum", "pool", "delete", _v(NAME, pool, "pool")))


# ------------------------------------------------------------------------------------------------ the ICS's own node identity (ADR-0014)
def account_exists(account: str) -> Cmd:
    return Cmd("account.exists", ("getent", "passwd", _v(ACCOUNT, account, "account")))


def account_add(account: str, home: str) -> Cmd:
    return Cmd("account.add", ("useradd", "--system", "--create-home", "--home-dir", _v(ACLPATH, home, "home"), "--shell", "/bin/sh",
                               "--comment", "Office Unbound ICS (forced command only)", _v(ACCOUNT, account, "account")))


SUDO_BIN = "/usr/bin/sudo"
_APT = ("env", "DEBIAN_FRONTEND=noninteractive", "apt-get")


def install_present() -> Cmd:
    """review 8 M-1: an Office Unbound node identity (fixed paths) is already installed on this node"""
    return Cmd("install.present", ("test", "-e", SUDOERS_PATH))


def sudo_present() -> Cmd:
    return Cmd("sudo.present", ("test", "-x", SUDO_BIN))


def sudo_install() -> Cmd:
    """Proxmox VE does not ship sudo. Installed from the node's own configured repositories, only when missing."""
    return Cmd("sudo.install", _APT + ("install", "-y", "--no-install-recommends", "sudo"))


def apt_update() -> Cmd:
    """Only run when the install above failed (stale package lists); a failing enterprise repository without subscription does not stop the retry."""
    return Cmd("sudo.apt_update", _APT + ("update",))


def sudo_remove() -> Cmd:
    """Rollback of a sudo this run installed (configuration is kept)."""
    return Cmd("sudo.remove", _APT + ("remove", "-y", "sudo"))


def account_lock(account: str) -> Cmd:
    """No password can ever match ('*'); key login still works (UsePAM or not: unlike '!', '*' is not treated as a locked account by sshd)."""
    return Cmd("account.lock", ("usermod", "--password", "*", _v(ACCOUNT, account, "account")))


def account_delete(account: str) -> Cmd:
    return Cmd("account.delete", ("userdel", "--remove", _v(ACCOUNT, account, "account")))


def ssh_dir(account: str, home: str) -> Cmd:
    a = _v(ACCOUNT, account, "account")
    return Cmd("ssh.dir", ("install", "-d", "-m", "0700", "-o", a, "-g", a, _v(ACLPATH, home + "/.ssh", "home")))


def authorized_keys(account: str, home: str, line: str) -> Cmd:
    a = _v(ACCOUNT, account, "account")
    return Cmd("ssh.authorized_keys", ("install", "-m", "0600", "-o", a, "-g", a, "/dev/stdin", _v(ACLPATH, home + "/.ssh/authorized_keys", "home")),
               stdin=(line.rstrip("\n") + "\n").encode())


def conf_dir() -> Cmd:
    return Cmd("conf.dir", ("install", "-d", "-m", "0755", "-o", "root", "-g", "root", CONF_DIR))


def install_helper(source: bytes) -> Cmd:
    return Cmd("helper.install", ("install", "-m", "0755", "-o", "root", "-g", "root", "/dev/stdin", HELPER_PATH), stdin=source)


def install_conf(conf: bytes) -> Cmd:
    return Cmd("helper.conf", ("install", "-m", "0644", "-o", "root", "-g", "root", "/dev/stdin", CONF_PATH), stdin=conf)


def sudoers_stage(text: bytes) -> Cmd:
    return Cmd("sudoers.stage", ("install", "-m", "0440", "-o", "root", "-g", "root", "/dev/stdin", SUDOERS_TMP), stdin=text)


def sudoers_check() -> Cmd:
    return Cmd("sudoers.check", ("visudo", "-cf", SUDOERS_TMP))


def sudoers_commit() -> Cmd:
    return Cmd("sudoers.commit", ("mv", "-f", SUDOERS_TMP, SUDOERS_PATH))


def sudoers_discard() -> Cmd:
    return Cmd("sudoers.discard", ("rm", "-f", SUDOERS_TMP))


def remove_file(which: str) -> Cmd:
    p = {"helper": HELPER_PATH, "conf": CONF_PATH, "sudoers": SUDOERS_PATH}[which]
    return Cmd(f"remove.{which}", ("rm", "-f", p))


def sha256_of(which: str) -> Cmd:
    p = {"helper": HELPER_PATH, "conf": CONF_PATH, "sudoers": SUDOERS_PATH}[which]
    return Cmd(f"sha256.{which}", ("sha256sum", p))
