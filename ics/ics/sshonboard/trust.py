"""TLS trust decision for the Proxmox API during SSH onboarding (ADR-0014). No verification is ever weakened.

The node's own certificate is read over the pinned SSH session (/etc/pve/local/pveproxy-ssl.pem when present, else pve-ssl.pem) and compared with the
leaf the ICS itself sees on the API address. Outcomes:

  public_ca    the API address presents the node's certificate AND its chain validates against the public trust store with host-name validation
               (e.g. Let's Encrypt). Pinned: the issuing ROOT (chain + host name), NOT the leaf: ACME leaves rotate every 60-90 days. The leaf is information only.
  cluster_ca   the address presents the node's certificate, it is not publicly trusted, and it validates (with host name) against /etc/pve/pve-root-ca.pem.
               Pinned: that cluster CA.
  fingerprint  the address presents the node's certificate, validated by neither: the leaf is pinned (SHA-256).
  proxy_public the address presents a DIFFERENT leaf (a reverse proxy in between) that validates publicly with host-name validation. Nothing continues until the
               administrator confirms the proxy's leaf fingerprint; trust is then the public root + host name (still a valid chain).
  (error)      a different leaf that is not publicly valid: stop, nothing to confirm.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..proxmox import ProxmoxError, check_destination, fetch_peer_certificate


def system_context() -> ssl.SSLContext:
    """The public trust store. Tests replace this function; production uses the operating system's roots."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


@dataclass
class Trust:
    mode: str                      # public_ca | cluster_ca | fingerprint | proxy_public
    ca_pem: str | None
    leaf_pin: str | None           # hex SHA-256: only for mode=fingerprint
    seen_leaf: str                 # what the ICS sees on the API address (hex)
    node_leaf: str                 # what the node says it serves (hex)
    needs_confirmation: bool = False
    explanation: str = ""

    def ca_sha256(self) -> str | None:
        return hashlib.sha256(self.ca_pem.encode()).hexdigest() if self.ca_pem else None


def pem_blocks(text: str) -> list[str]:
    return re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)


def der_of(pem: str) -> bytes:
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)


def leaf_fp(pem_bundle: str) -> str:
    b = pem_blocks(pem_bundle)
    if not b:
        raise ProxmoxError("no certificate found on the node")
    return hashlib.sha256(der_of(b[0])).hexdigest()


def _public_root(host: str, port: int, timeout: float = 6.0) -> tuple[bool, str | None]:
    """(chain + host name valid against the public store?, PEM of the root that anchored it)."""
    ctx = system_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            chain = s._sslobj.get_verified_chain()      # type: ignore[attr-defined]  # leaf ... root (Python >= 3.10, private accessor)
            root = chain[-1]
            if hasattr(root, "public_bytes"):                 # Python 3.12: _ssl.Certificate objects; 3.13+: DER bytes
                import _ssl
                pem = root.public_bytes(_ssl.ENCODING_PEM)
            else:
                pem = ssl.DER_cert_to_PEM_cert(bytes(root))
            return True, pem if isinstance(pem, str) else pem.decode()
    except (OSError, ssl.SSLError, AttributeError, ValueError):
        return False, None


def _verifies(url: str, ca_pem: str, allow_loopback: bool) -> bool:
    return bool(fetch_peer_certificate(url, ca_pem=ca_pem, allow_loopback=allow_loopback).get("ok"))


def decide(url: str, node_bundle_pem: str, cluster_ca_pem: str | None, allow_loopback: bool) -> Trust:
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        raise ProxmoxError("the API address must be https://host[:port]")
    host, port = u.hostname, u.port or 443
    try:
        check_destination(host, allow_loopback)
    except ProxmoxError as e:
        raise ProxmoxError(str(e)) from None
    node_leaf = leaf_fp(node_bundle_pem)
    res = fetch_peer_certificate(url, allow_loopback=allow_loopback)
    seen = res.get("presented_fingerprint_sha256")
    if not seen:
        raise ProxmoxError("the ICS could not read the certificate presented on the API address: " + str(res.get("error", ""))[:120])
    pub_ok, root = _public_root(host, port)
    if seen == node_leaf:
        if pub_ok and root:
            return Trust("public_ca", root, None, seen, node_leaf,
                         explanation="The API address presents this node's certificate and its chain is publicly trusted for the host name. The issuing root and host name "
                                     "are pinned, not the leaf, so certificate renewals keep working.")
        if cluster_ca_pem and _verifies(url, cluster_ca_pem, allow_loopback):
            return Trust("cluster_ca", cluster_ca_pem, None, seen, node_leaf, explanation="The certificate validates against this cluster's own CA for the host name; that CA is pinned.")
        return Trust("fingerprint", None, seen, seen, node_leaf, explanation="The certificate is neither publicly trusted nor valid for this host name under the cluster CA; its SHA-256 fingerprint is pinned.")
    if pub_ok and root:
        return Trust("proxy_public", root, None, seen, node_leaf, needs_confirmation=True,
                     explanation="The API address does NOT present the certificate this node serves: something in between (a reverse proxy or load balancer) terminates TLS. "
                                 "Its certificate is publicly valid for the host name. Continue only if you know about this proxy and confirm its fingerprint.")
    raise ProxmoxError("API certificate MISMATCH: the certificate on the node (read over SSH) differs from the one presented on the API address, and the presented one is not "
                       f"valid for the host name under any public CA. Stopping: something other than this node may be answering. Node: {node_leaf}  API address: {seen}")


def trust_args(t: Trust) -> tuple[str | None, str | None]:
    """(ca_pem, fingerprint_sha256) as the endpoint/TLS layer expects them: exactly one is set."""
    return (t.ca_pem, None) if t.ca_pem else (None, t.leaf_pin)
