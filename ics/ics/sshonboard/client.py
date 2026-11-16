"""SSH transport for onboarding (paramiko, LGPL-2.1). Strict host-key pinning (no TOFU, no known_hosts, no auto-add), no agent, no key lookup,
no pty, no shell: only `exec` of a rendered fixed template. The ssh binary is never invoked."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import socket
import threading
import time
from dataclasses import dataclass

import paramiko

from .templates import Cmd

KEY_ALGOS = ("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512")
KEYFILE = {"ssh-ed25519": "ssh_host_ed25519_key.pub", "ecdsa-sha2-nistp256": "ssh_host_ecdsa_key.pub", "rsa-sha2-512": "ssh_host_rsa_key.pub"}
MAX_OUT = 8 * 1024 * 1024
MAX_ERR = 64 * 1024
MAX_KEY_PEM = 16 * 1024


class SshError(Exception):
    """Messages are safe to show to operators (no credentials, no remote text beyond a short stderr tail)."""


@dataclass(frozen=True)
class HostKey:
    algo: str
    fingerprint: str      # "SHA256:<base64 without padding>", the format of `ssh-keygen -lf`

    def verify_command(self) -> str:
        return f"ssh-keygen -lf /etc/ssh/{KEYFILE[self.algo]}"


@dataclass
class Result:
    rc: int
    out: bytes
    err: str


def fingerprint_of(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _transport(host: str, port: int, timeout: float, algo: str) -> paramiko.Transport:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        raise SshError("could not connect to the SSH port") from None
    t = paramiko.Transport(sock)
    t.set_log_channel("ics.ssh.transport")
    t.banner_timeout = timeout
    t.get_security_options().key_types = [algo]
    try:
        t.start_client(timeout=timeout)
    except (paramiko.SSHException, EOFError, OSError):
        try:
            t.close()
        except Exception:  # noqa: BLE001
            pass
        raise SshError(f"the server did not offer a {algo} host key") from None
    return t


def fetch_host_key(host: str, port: int, timeout: float = 8.0) -> HostKey:
    """Unauthenticated: read the host key the server presents (strongest algorithm first). Nothing is sent but the SSH handshake."""
    last = "no supported host key"
    for algo in KEY_ALGOS:
        try:
            t = _transport(host, port, timeout, algo)
        except SshError as e:
            last = str(e)
            continue
        try:
            k = t.get_remote_server_key()
            return HostKey(algo=algo, fingerprint=fingerprint_of(k.asbytes()))
        finally:
            t.close()
    raise SshError(last)


def load_pkey(pem: str, passphrase: str | None) -> paramiko.PKey:
    if len(pem) > MAX_KEY_PEM:
        raise SshError("private key is too large")
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise SshError("the private key is encrypted: a passphrase is required") from None
        except paramiko.SSHException:
            continue
    raise SshError("the private key could not be read (wrong passphrase or unsupported format)")


class SshSession:
    """One authenticated SSH connection to a node whose host key is pinned. `run` executes one rendered Cmd; nothing else."""

    def __init__(self, host: str, port: int, username: str, pinned: HostKey, *, password: str | None = None, pem: str | None = None,
                 passphrase: str | None = None, timeout: float = 10.0, sudo: bool = False):
        self.host, self.port, self.username, self.sudo, self.timeout = host, port, username, sudo, timeout
        self.t: paramiko.Transport | None = None
        t = _transport(host, port, timeout, pinned.algo)
        seen = fingerprint_of(t.get_remote_server_key().asbytes())
        if not hmac.compare_digest(seen, pinned.fingerprint):
            t.close()
            raise SshError("the node's SSH host key does not match the key that was confirmed: nothing was sent (possible man-in-the-middle, "
                           "or the node was reinstalled)")
        try:
            if pem is not None:
                t.auth_publickey(username, load_pkey(pem, passphrase))
            elif password is not None:
                t.auth_password(username, password)
            else:
                raise SshError("no credential")
        except paramiko.AuthenticationException:
            t.close()
            raise SshError("SSH authentication failed") from None
        except paramiko.SSHException:
            t.close()
            raise SshError("SSH authentication could not be completed") from None
        except SshError:
            t.close()
            raise
        self.t = t

    def run_raw(self, command: str, stdin: bytes | None = None, timeout: float = 60.0) -> Result:
        """Execute ONE already-rendered command string. Private to this package: callers use `run` (a Cmd) or the helper client's fixed ops."""
        if self.t is None or not self.t.is_active():
            raise SshError("SSH connection is closed")
        ch = self.t.open_session(timeout=self.timeout)
        ch.settimeout(timeout)
        out, err = bytearray(), bytearray()
        try:
            ch.exec_command(command)
            if stdin is not None:
                ch.sendall(stdin)
            ch.shutdown_write()
            end = time.monotonic() + timeout
            while True:
                if ch.recv_ready():
                    out += ch.recv(65536)
                if ch.recv_stderr_ready():
                    err += ch.recv_stderr(8192)
                if len(out) > MAX_OUT:
                    raise SshError("command output exceeded the size limit")
                if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
                    break
                if time.monotonic() > end:
                    raise SshError("command timed out")
                if not (ch.recv_ready() or ch.recv_stderr_ready()):
                    time.sleep(0.01)
            rc = ch.recv_exit_status()
        finally:
            ch.close()
        return Result(rc, bytes(out), bytes(err[:MAX_ERR]).decode("utf-8", "replace"))

    def run(self, cmd: Cmd, timeout: float = 60.0) -> Result:
        return self.run_raw(cmd.render(sudo=self.sudo), cmd.stdin, timeout)

    def close(self) -> None:
        t, self.t = self.t, None
        if t is not None:
            t.close()


_lock = threading.Lock()
