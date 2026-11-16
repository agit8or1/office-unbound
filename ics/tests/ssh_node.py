"""A REAL OpenSSH server (sshd, random localhost port, run as the test user) standing in for a Proxmox node: pvesh/pveum/sudo/install/... are the faithful
fakes of tests/fake_pve_tool.py talking to the PVE simulator. Everything the ICS does reaches it through real SSH sessions (host key, auth, exec, stdin,
forced commands are all genuine sshd behaviour)."""
import getpass
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

TOOLS = ("pvesh", "pveum", "sudo", "install", "mv", "rm", "cat", "sha256sum", "visudo", "useradd", "userdel", "usermod", "getent")
HERE = Path(__file__).parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SshNode:
    def __init__(self, sim_server, local_node="pve06", passphrase: str | None = None, pveproxy_pem: str | None = None, cluster_ca: str | None = None, node_pem: str | None = None):
        self.api_url = sim_server.url
        sim_server.sim.local_node = local_node
        self.dir = Path(tempfile.mkdtemp(prefix="ou-sshnode-"))
        d = self.dir
        self.user = getpass.getuser()
        self.root = d / "root"
        (self.root / "etc/pve/local").mkdir(parents=True)
        (self.root / "etc/office-unbound").mkdir(parents=True)
        (self.root / "usr/local/sbin").mkdir(parents=True)
        (self.root / "var/lib").mkdir(parents=True)
        (self.root / "etc/sudoers.d").mkdir(parents=True)
        (self.root / "state").mkdir()
        (self.root / "etc/pve/local/pve-ssl.pem").write_text(node_pem or sim_server.cert_pem)
        if pveproxy_pem:
            (self.root / "etc/pve/local/pveproxy-ssl.pem").write_text(pveproxy_pem)
        if cluster_ca:
            (self.root / "etc/pve/pve-root-ca.pem").write_text(cluster_ca)
        bindir = d / "bin"
        bindir.mkdir()
        tool = HERE / "fake_pve_tool.py"
        for t in TOOLS:
            (bindir / t).symlink_to(tool)
        # keys: host key, admin key, admin key with passphrase
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "host_ed25519")], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "admin")], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase or "unused-pass", "-f", str(d / "admin_pp")], check=True)
        auth = d / "authorized_admin"
        auth.write_text((d / "admin.pub").read_text() + (d / "admin_pp.pub").read_text())
        self.admin_key = (d / "admin").read_text()
        self.admin_key_pp = (d / "admin_pp").read_text()
        self.passphrase = passphrase or "unused-pass"
        self.port = free_port()
        self.ics_ak = self.root / "var/lib/ou-ics/.ssh/authorized_keys"
        self.account_ak = {}
        env = {
            "PATH": f"{bindir}:/usr/bin:/bin", "OU_FAKE_ROOT": str(self.root), "OU_HELPER_ROOT": str(self.root), "SIM_URL": sim_server.url,
            "SIM_ROOT_PW": sim_server.sim.ROOT_PW, "FAKE_LOCAL_NODE": local_node,
        }
        cfg = d / "sshd_config"
        cfg.write_text("\n".join([
            f"Port {self.port}", "ListenAddress 127.0.0.1", "ListenAddress 127.0.0.2", f"HostKey {d / 'host_ed25519'}", f"PidFile {d / 'sshd.pid'}",
            "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "StrictModes no",
            f"AuthorizedKeysFile {auth} {self.root}/var/lib/%u/.ssh/authorized_keys", "PermitRootLogin yes", f"AllowUsers {self.user}",
            "LogLevel INFO", f"SetEnv {' '.join(f'{k}={v}' for k, v in env.items())}", "PrintMotd no",
        ]) + "\n")
        self.log = open(d / "sshd.log", "w")
        self.proc = subprocess.Popen([shutil.which("sshd") or "/usr/sbin/sshd", "-D", "-e", "-f", str(cfg)], stdout=self.log, stderr=self.log)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("sshd did not start: " + (d / "sshd.log").read_text()[-500:])
        self.host_fp = subprocess.run(["ssh-keygen", "-lf", str(d / "host_ed25519.pub")], capture_output=True, text=True).stdout.split()[1]

    # ---- inspection helpers for tests ----
    def executed(self) -> list[list[str]]:
        p = self.root / "executed.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def set_lvs(self, rows: list[dict]):
        (self.root / "state" / "lvs.json").write_text(json.dumps({"report": [{"lv": rows}]}))

    def set_zfs(self, text: str):
        (self.root / "state" / "zfs.txt").write_text(text)

    def clear_log(self):
        (self.root / "executed.log").unlink(missing_ok=True)

    def file(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def has_account(self, name: str) -> bool:
        return (self.root / "state" / f"user-{name}").exists()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()
        shutil.rmtree(self.dir, ignore_errors=True)
