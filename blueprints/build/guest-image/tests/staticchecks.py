"""Offline hardening checks over an EXTRACTED image tree (a directory produced by `debugfs rdump`). Pure functions, no network, no execution of anything
from the image. The tree is untrusted: every read refuses symlinks on the path and anything that is not a regular file, so a hostile image cannot make the
tester read host files. Each check returns (id, ok, detail). Used by tests/image-first-boot (on the pristine image, and again on the disk after the boots)
and by ics/tests/test_golden_prod.py (against synthetic good and bad trees)."""
import os
import re
import stat

DENY_PACKAGES = ("openssh-server", "openssh-sftp-server", "qemu-guest-agent", "telnetd", "inetutils-telnetd", "rsh-server", "vsftpd", "proftpd-basic", "dropbear",
                 "dropbear-bin", "tightvncserver", "x11vnc", "sudo", "cloud-init-ssh")
MAXREAD = 8 * 1024 * 1024


def _safe(root: str, rel: str):
    """absolute path of rel below root, or None if any component is a symlink / missing"""
    p = root
    for part in [x for x in rel.split("/") if x]:
        p = os.path.join(p, part)
        try:
            st = os.lstat(p)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            return None
    return p


def read(root: str, rel: str) -> str | None:
    p = _safe(root, rel)
    if p is None:
        return None
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, MAXREAD).decode("utf-8", "replace")
    finally:
        os.close(fd)


def exists(root: str, rel: str) -> bool:
    parent, _, name = rel.rstrip("/").rpartition("/")
    d = _safe(root, parent or "/") if parent else root
    return d is not None and os.path.lexists(os.path.join(d, name))


def link(root: str, rel: str) -> str | None:
    parent, _, name = rel.rstrip("/").rpartition("/")
    d = _safe(root, parent or "/") if parent else root
    if d is None:
        return None
    try:
        return os.readlink(os.path.join(d, name))
    except OSError:
        return None


def listdir(root: str, rel: str) -> list[str]:
    p = _safe(root, rel)
    try:
        return sorted(os.listdir(p)) if p else []
    except OSError:
        return []


def installed_packages(root: str) -> dict:
    st = read(root, "/var/lib/dpkg/status") or ""
    out = {}
    for blk in st.split("\n\n"):
        m = re.search(r"^Package: (\S+)$", blk, re.M)
        s = re.search(r"^Status: (.*)$", blk, re.M)
        v = re.search(r"^Version: (\S+)$", blk, re.M)
        if m and s and s.group(1).strip().endswith(" installed") and not s.group(1).startswith(("deinstall", "purge")):
            out[m.group(1)] = v.group(1) if v else ""
    return out


def enabled_units(root: str) -> set:
    """names of every unit with a *.wants/*.requires symlink in the usual systemd directories (= enabled)"""
    out = set()
    for base in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        for d in listdir(root, base):
            if d.endswith((".wants", ".requires")):
                for u in listdir(root, base + "/" + d):
                    out.add(u)
    return out


def masked(root: str, unit: str) -> bool:
    return link(root, "/etc/systemd/system/" + unit) == "/dev/null"


def check_tree(root: str) -> list:
    """Checks of the shipped (pristine) image tree. Returns [(id, ok, detail)]."""
    R = []

    def add(i, ok, d=""):
        R.append((i, bool(ok), d))

    pk = installed_packages(root)
    add("S01-packages-present", len(pk) > 100, f"{len(pk)} packages installed")
    bad = sorted(set(DENY_PACKAGES) & set(pk))
    add("S02-no-sshd-or-remote-shell-packages", not bad, "denied packages installed: %s" % bad if bad else "none of %d denied packages installed" % len(DENY_PACKAGES))
    add("S03-no-sshd-binary-or-config", not any(exists(root, p) for p in ("/usr/sbin/sshd", "/etc/ssh/sshd_config", "/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/ssh.service",
                                                                           "/usr/lib/systemd/system/sshd.service")), "no sshd binary, config or unit")
    hk = [f for f in listdir(root, "/etc/ssh") if f.startswith("ssh_host_")]
    add("S04-no-ssh-host-keys", not hk, str(hk))
    keys = []
    for base in ("/root", "/home", "/var/lib/ou-svc", "/etc/ssh", "/var/lib"):
        for dp, dns, fns in os.walk(os.path.join(root, base.lstrip("/")), followlinks=False):
            for f in fns:
                if f in ("authorized_keys", "authorized_keys2") or f.startswith("id_") and not f.endswith(".pub"):
                    keys.append(os.path.relpath(os.path.join(dp, f), root))
    add("S05-no-authorized-keys-or-private-ssh-keys", not keys, str(keys))
    ssh_units_ok = all(u not in enabled_units(root) for u in ("ssh.service", "sshd.service", "ssh.socket"))
    add("S06-no-ssh-unit-enabled", ssh_units_ok, "")
    sh = read(root, "/etc/shadow") or ""
    rows = [l.split(":") for l in sh.splitlines() if l.strip()]
    rootrow = next((r for r in rows if r[0] == "root"), None)
    add("S07-root-locked", rootrow is not None and rootrow[1][:1] in ("!", "*"), "root password field: %s" % ("locked" if rootrow and rootrow[1][:1] in ("!", "*") else "NOT LOCKED"))
    open_ = [r[0] for r in rows if len(r) > 1 and r[1][:1] not in ("!", "*")]
    add("S08-no-account-has-a-password-or-an-empty-password", bool(rows) and not open_, "accounts with a usable password field: %s" % open_ if open_ else "all %d accounts locked" % len(rows))
    pw = read(root, "/etc/passwd") or ""
    uid0 = [l.split(":")[0] for l in pw.splitlines() if l.split(":")[2:3] == ["0"]]
    add("S09-only-root-has-uid-0", uid0 == ["root"], str(uid0))
    pamnull = [l.strip() for f in listdir(root, "/etc/pam.d") for l in (read(root, "/etc/pam.d/" + f) or "").splitlines()
               if re.match(r"\s*auth\s+(sufficient|\[success=\d+[^\]]*\])\s+pam_permit\.so", l)]
    add("S10-no-pam-permit-auth-backdoor", not pamnull, str(pamnull))
    nft = read(root, "/etc/nftables.conf") or ""
    add("S11-nftables-default-deny-input-and-forward", bool(re.search(r"hook input[^;]*;\s*policy drop", nft)) and bool(re.search(r"hook forward[^;]*;\s*policy drop", nft)), "shipped ruleset")
    add("S12-nftables-has-no-tcp-service-rule", not re.search(r"\b(tcp|sctp)\s+dport\b|\bdport\s*[{0-9]", re.sub(r"udp\s+sport\s+\d+\s+udp\s+dport\s+\d+", "", nft)), "only DHCP/ICMP/established in the shipped file")
    add("S13-nftables-service-enabled", "nftables.service" in enabled_units(root), "loaded at boot")
    add("S14-agent-not-enabled-before-enrollment", "ou-agent.service" not in enabled_units(root) and not link(root, "/etc/systemd/system/ou-agent.service"), "no wants symlink for ou-agent.service")
    add("S15-no-agent-state-or-keys-in-image", not listdir(root, "/etc/ou-agent") and not listdir(root, "/var/lib/ou-agent"), "/etc/ou-agent=%s /var/lib/ou-agent=%s" % (listdir(root, "/etc/ou-agent"), listdir(root, "/var/lib/ou-agent")))
    add("S16-bootstrap-unit-enabled-and-unsealed", "ou-bootstrap.service" in enabled_units(root) and not any(exists(root, "/var/lib/ou-bootstrap/" + m) for m in ("done", "failed", "sealed")), "first boot is pending")
    unit = read(root, "/etc/systemd/system/ou-bootstrap.service") or ""
    add("S17-bootstrap-unit-refuses-rerun-and-seals", "ConditionPathExists=!/var/lib/ou-bootstrap/sealed" in unit and "ConditionPathExists=!/var/lib/ou-bootstrap/done" in unit
        and "ExecStartPost=/usr/local/sbin/ou-seal" in unit and "Restart=no" in unit, "Condition*=!sealed/done, ExecStartPost=ou-seal, Restart=no")
    seal = read(root, "/usr/local/sbin/ou-seal") or ""
    add("S18-ou-seal-present", "systemctl disable ou-bootstrap.service" in seal and ": > " in seal, "")
    ci = pk.get("cloud-init")
    add("S19-cloud-init-absent-or-disabled", ci is None or (exists(root, "/etc/cloud/cloud-init.disabled") and not any(u.startswith("cloud-") for u in enabled_units(root))),
        "absent" if ci is None else "installed %s but disabled" % ci)
    add("S20-no-qemu-guest-agent-channel", "qemu-guest-agent" not in pk and not exists(root, "/usr/sbin/qemu-ga"), "no host-to-guest exec channel")
    add("S21-machine-id-empty-for-per-vm-generation", (lambda v: v is not None and v.strip() == "")(read(root, "/etc/machine-id")), "")
    add("S22-no-secret-material-in-image", not [p for p in ("/etc/ou-agent/agent_key.pem", "/var/lib/ou-agent/agent_key.pem", "/var/lib/ou-agent/enroll.json", "/var/lib/ou-agent/trust.json") if exists(root, p)], "")
    pol = re.findall(r"^PermitRootLogin\s+(\S+)", read(root, "/etc/ssh/sshd_config") or "", re.M)
    add("S23-no-permissive-sshd-config", not pol, "")
    return R
