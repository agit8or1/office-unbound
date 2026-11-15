"""Read-only Proxmox VE client.

Only GET is implemented: the class has no method that can send POST/PUT/DELETE.
Inventory call set adapted from Depl0y backend/app/services/proxmox.py (MIT, (c) agit8or1);
transport is httpx with real TLS verification (CA bundle) or leaf-certificate SHA-256 pinning
(performed on the very connection used for the request; the TLS stack never runs with an
unverified peer that we do not then check).
"""
import hashlib
import hmac
import re
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

_FP_RE = re.compile(r"^[0-9a-f]{64}$")


class ProxmoxError(Exception):
    pass


def normalize_fingerprint(fp: str) -> str:
    n = fp.replace(":", "").strip().lower()
    if not _FP_RE.match(n):
        raise ValueError("fingerprint must be 64 hex chars (SHA-256), colons optional")
    return n


class _PinnedContext(ssl.SSLContext):
    """TLS context that accepts exactly one leaf certificate (by SHA-256 of its DER)."""

    def __new__(cls, pin: str):
        return super().__new__(cls, ssl.PROTOCOL_TLS_CLIENT)

    def __init__(self, pin: str):
        super().__init__()
        self._pin = pin
        self.minimum_version = ssl.TLSVersion.TLSv1_2
        # Chain/hostname validation is replaced by the pin check below (PVE certs are self-signed).
        self.check_hostname = False
        self.verify_mode = ssl.CERT_NONE

    def wrap_socket(self, sock, *args, **kwargs):  # type: ignore[override]
        s = super().wrap_socket(sock, *args, **kwargs)
        try:
            der = s.getpeercert(binary_form=True)
            if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self._pin):
                raise ssl.SSLError("server certificate does not match the pinned SHA-256 fingerprint")
        except BaseException:
            s.close()
            raise
        return s


def build_ssl_context(*, ca_pem: str | None, fingerprint_sha256: str | None) -> ssl.SSLContext:
    if bool(ca_pem) == bool(fingerprint_sha256):
        raise ValueError("exactly one of ca_pem or fingerprint_sha256 is required")
    if fingerprint_sha256:
        return _PinnedContext(normalize_fingerprint(fingerprint_sha256))
    ctx = ssl.create_default_context(cadata=ca_pem)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class ProxmoxReadClient:
    def __init__(self, base_url: str, token_id: str, token_secret: str, *, ca_pem: str | None = None,
                 fingerprint_sha256: str | None = None, timeout: float = 10.0):
        u = urlparse(base_url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("base_url must be https://host[:port]")
        self._base = f"https://{u.netloc}/api2/json"
        self._client = httpx.Client(
            verify=build_ssl_context(ca_pem=ca_pem, fingerprint_sha256=fingerprint_sha256),
            headers={"Authorization": f"PVEAPIToken={token_id}={token_secret}"},
            timeout=timeout, follow_redirects=False, trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str) -> Any:
        try:
            r = self._client.get(self._base + path)
        except (httpx.HTTPError, ssl.SSLError) as e:
            raise ProxmoxError(f"GET {path} failed: {type(e).__name__}: {e}") from None
        if r.status_code != 200:
            raise ProxmoxError(f"GET {path} returned HTTP {r.status_code}")
        try:
            return r.json()["data"]
        except (ValueError, KeyError):
            raise ProxmoxError(f"GET {path}: unexpected response body") from None

    def version(self) -> dict: return self._get("/version")
    def cluster_status(self) -> list: return self._get("/cluster/status")
    def nodes(self) -> list: return self._get("/nodes")
    def qemu(self, node: str) -> list: return self._get(f"/nodes/{_seg(node)}/qemu")
    def lxc(self, node: str) -> list: return self._get(f"/nodes/{_seg(node)}/lxc")
    def storage(self, node: str) -> list: return self._get(f"/nodes/{_seg(node)}/storage")
    def network(self, node: str) -> list: return self._get(f"/nodes/{_seg(node)}/network")

    def inventory(self) -> dict:
        """Full read-only snapshot. A node that fails is recorded with an error, not fatal."""
        out: dict[str, Any] = {"version": self.version(), "cluster_status": self.cluster_status(), "nodes": []}
        for n in self.nodes():
            name = n["node"]
            entry: dict[str, Any] = {"node": name, "status": n.get("status", "unknown"), "info": n}
            if entry["status"] == "online":
                try:
                    entry.update(qemu=self.qemu(name), lxc=self.lxc(name), storage=self.storage(name), network=self.network(name))
                except ProxmoxError as e:
                    entry["error"] = str(e)
            out["nodes"].append(entry)
        return out


def _seg(node: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node):
        raise ProxmoxError("invalid node name")
    return node
