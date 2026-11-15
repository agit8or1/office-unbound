"""Read-only Proxmox VE client.

Only GET is implemented: the class has no method that can send POST/PUT/DELETE.
Inventory call set adapted from Depl0y backend/app/services/proxmox.py (MIT, (c) agit8or1);
transport is httpx with real TLS verification (CA bundle) or leaf-certificate SHA-256 pinning
(performed on the very connection used for the request; the TLS stack never runs with an
unverified peer that we do not then check).
"""
import hashlib
import hmac
import json
import ipaddress
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import httpx

_FP_RE = re.compile(r"^[0-9a-f]{64}$")


class ProxmoxError(Exception):
    pass


def _clean_reason(v: str | None) -> str:
    """Server-supplied reason phrase (PVE puts the permission/validation message there). Printable ASCII only, bounded."""
    return re.sub(r"[^\x20-\x7e]", "", v or "")[:200]


class ProxmoxHTTPError(ProxmoxError):
    """Non-200 answer; keeps the status and PVE's own message so providers can map it to an operator-readable error."""

    def __init__(self, method: str, path: str, status: int, reason: str):
        super().__init__(f"{method} {path} returned HTTP {status}" + (f" ({reason})" if reason else ""))
        self.status, self.reason = status, reason


_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{8,200}$")
_TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$")


def check_destination(host: str, allow_loopback: bool = False) -> list[str]:
    """SSRF guard: resolve the host and refuse loopback, link-local (incl. cloud metadata), unspecified, multicast, reserved.
    RFC1918 stays allowed (management networks). Returns the resolved addresses (shown to the approver)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        raise ProxmoxError("endpoint host does not resolve") from None
    ips = sorted({i[4][0].split("%")[0] for i in infos})
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            a = a.ipv4_mapped
        if a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved or (a.is_loopback and not allow_loopback):
            raise ProxmoxError(f"endpoint address {ip} is not an allowed destination")
    return ips


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
                 fingerprint_sha256: str | None = None, timeout: float = 5.0, deadline: float = 30.0,
                 max_bytes: int = 16 * 1024 * 1024, allow_loopback: bool = False):
        u = urlparse(base_url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("base_url must be https://host[:port]")
        # never put unvalidated bytes into a header, and never echo them in an error
        if not _SECRET_RE.match(token_secret) or not _TOKEN_ID_RE.match(token_id):
            raise ValueError("token id/secret has an invalid format")
        check_destination(u.hostname, allow_loopback)
        self._deadline, self._max_bytes = deadline, max_bytes
        self._base = f"https://{u.netloc}/api2/json"
        self._client = httpx.Client(
            verify=build_ssl_context(ca_pem=ca_pem, fingerprint_sha256=fingerprint_sha256),
            headers={"Authorization": f"PVEAPIToken={token_id}={token_secret}"},
            timeout=httpx.Timeout(timeout), follow_redirects=False, trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _request(self, method: str, path: str, data: dict | None = None) -> Any:
        """Request with an overall wall-clock deadline and a response size cap. Errors never include transport text
        (it can echo request headers); only the exception class name is reported. Only ProxmoxWriteClient exposes
        non-GET methods; this class's public surface is read-only."""
        end = time.monotonic() + self._deadline
        buf = bytearray()
        try:
            with self._client.stream(method, self._base + path, data=data) as r:
                if r.status_code != 200:
                    reason = _clean_reason(r.reason_phrase)
                    raise ProxmoxHTTPError(method, path, r.status_code, reason)
                if int(r.headers.get("content-length", "0") or 0) > self._max_bytes:
                    raise ProxmoxError(f"{method} {path}: response too large")
                for chunk in r.iter_bytes():  # decoded (PVE gzips larger bodies); cap applies to DECOMPRESSED size (bomb guard)
                    if time.monotonic() > end:
                        raise ProxmoxError(f"{method} {path}: overall deadline of {self._deadline:g}s exceeded")
                    buf += chunk
                    if len(buf) > self._max_bytes:
                        raise ProxmoxError(f"{method} {path}: response exceeds {self._max_bytes} bytes")
                if time.monotonic() > end:
                    raise ProxmoxError(f"{method} {path}: overall deadline of {self._deadline:g}s exceeded")
        except ProxmoxError:
            raise
        except (httpx.ConnectError, ssl.SSLError) as e:  # TLS/connect layer: no request headers involved
            raise ProxmoxError(f"{method} {path} failed: {type(e).__name__}: {str(e)[:200]}") from None
        except (httpx.HTTPError, OSError, ValueError) as e:
            raise ProxmoxError(f"{method} {path} failed: {type(e).__name__}") from None
        try:
            return json.loads(bytes(buf))["data"]
        except (ValueError, KeyError, TypeError):
            raise ProxmoxError(f"{method} {path}: unexpected response body") from None

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
                    entry["error"] = str(e)[:300]
            out["nodes"].append(entry)
        return out


def _seg(node: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node):
        raise ProxmoxError("invalid node name")
    return node


def fetch_peer_certificate(base_url: str, *, ca_pem: str | None = None, fingerprint_sha256: str | None = None, timeout: float = 5.0,
                           allow_loopback: bool = False) -> dict:
    """TLS-ONLY setup stage: read the certificate the server presents (so an admin can compare it out of band) and report whether it
    satisfies the supplied trust anchor. The handshake is the only traffic: no HTTP request, no credential. This connection is never
    used for anything else; every real request goes through ProxmoxReadClient/ProxmoxWriteClient with full verification/pinning."""
    import datetime as _dt
    from cryptography import x509 as _x509
    u = urlparse(base_url)
    if u.scheme != "https" or not u.hostname:
        return {"ok": False, "error": "base_url must be https://host[:port]"}
    try:
        check_destination(u.hostname, allow_loopback)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # read-only look at the certificate; nothing is sent over it
        with socket.create_connection((u.hostname, u.port or 443), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=u.hostname) as t:
            der = t.getpeercert(binary_form=True)
    except ProxmoxError as e:
        return {"ok": False, "error": str(e)}
    except (OSError, ssl.SSLError) as e:
        return {"ok": False, "error": f"could not complete a TLS handshake ({type(e).__name__})"}
    fp = hashlib.sha256(der).hexdigest()
    cert = _x509.load_der_x509_certificate(der)
    out: dict = {"ok": False, "presented_fingerprint_sha256": fp, "subject": cert.subject.rfc4514_string()[:200],
                 "not_after": cert.not_valid_after_utc.isoformat()}
    if cert.not_valid_after_utc < _dt.datetime.now(_dt.timezone.utc):
        out["error"] = "the presented certificate has expired"
        return out
    if fingerprint_sha256:
        out["verified_by"] = "fingerprint"
        out["ok"] = hmac.compare_digest(fp, normalize_fingerprint(fingerprint_sha256))
        if not out["ok"]:
            out["error"] = "the presented certificate does not match the supplied fingerprint"
    elif ca_pem:
        out["verified_by"] = "ca"
        try:
            vctx = ssl.create_default_context(cadata=ca_pem)
            vctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((u.hostname, u.port or 443), timeout=timeout) as raw, vctx.wrap_socket(raw, server_hostname=u.hostname):
                out["ok"] = True
        except (OSError, ssl.SSLError):
            out["error"] = "the certificate is not trusted by the supplied CA bundle (or does not match the host name)"
    else:
        out["error"] = "no trust anchor supplied: compare the presented fingerprint out of band, then supply it"
    return out


class ProxmoxWriteClient(ProxmoxReadClient):
    """Same transport, TLS trust and limits as the read client, plus POST/PUT/DELETE. Constructed only by the provisioning
    provider (providers/proxmox) with the `provision` credential; never handed to request handlers."""

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, data: dict | None = None) -> Any:
        return self._request("POST", path, data or {})

    def put(self, path: str, data: dict | None = None) -> Any:
        return self._request("PUT", path, data or {})

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)
