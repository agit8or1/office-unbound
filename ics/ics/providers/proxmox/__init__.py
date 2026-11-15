"""Proxmox provider: build providers from stored endpoints.

`open_read_provider` is safe anywhere (read-only client). `open_mutations` raises MutationNotAllowed unless called from job
execution (see providers.base.job_execution) and refuses endpoints that have no `provision` credential.
"""
from __future__ import annotations

from ...proxmox import ProxmoxReadClient, ProxmoxWriteClient
from ...runtime import Runtime
from ..base import MutationNotAllowed, ProviderError, require_job_execution
from .provider import EndpointScope, ProxmoxMutations, ProxmoxProvider, map_error

__all__ = ["probe_connection", "EndpointScope", "ProxmoxMutations", "ProxmoxProvider", "open_mutations", "open_read_provider", "scope_of", "provision_aad"]


def scope_of(ep) -> EndpointScope:
    return EndpointScope(tuple(ep.allowed_pools or ()), tuple(ep.allowed_storage or ()), tuple(ep.allowed_networks or ()),
                         tuple(getattr(ep, "allowed_templates", None) or ()), bool(ep.allow_cicustom))


def provision_aad(ep, binding: str) -> str:
    return f"endpoint-provision:{ep.id}:{binding}:{ep.provision_token_id}"


def _binding(ep) -> str:
    from ...actions import endpoint_binding  # late import: actions imports this package
    return endpoint_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem)


def _kw(rt: Runtime, ep) -> dict:
    s = rt.settings
    return dict(ca_pem=ep.ca_pem, fingerprint_sha256=ep.fingerprint_sha256, deadline=s.pve_request_deadline_seconds,
                max_bytes=s.pve_max_response_bytes, allow_loopback=s.allow_loopback_endpoints)


def open_read_provider(rt: Runtime, ep, known: list[str] | None = None, *, with_provision_probe: bool = False) -> ProxmoxProvider:
    """Inventory credential (PVEAuditor). `with_provision_probe` additionally opens a READ-ONLY client with the provision
    token so the permission probe can report on it (never used to mutate)."""
    known = known if known is not None else []
    b = _binding(ep)
    secret = rt.vault.decrypt(ep.token_secret_enc, f"endpoint-token:{ep.id}:{b}").decode()
    known.append(secret)
    inv = ProxmoxReadClient(ep.base_url, ep.token_id, secret, **_kw(rt, ep))
    prov = None
    if with_provision_probe and ep.provision_token_id:
        ps = rt.vault.decrypt(ep.provision_secret_enc, provision_aad(ep, b)).decode()
        known.append(ps)
        prov = ProxmoxReadClient(ep.base_url, ep.provision_token_id, ps, **_kw(rt, ep))
    return ProxmoxProvider(inv, scope=scope_of(ep), trust="fingerprint" if ep.fingerprint_sha256 else "ca_bundle",
                           inventory_token_id=ep.token_id, provision_probe=prov, provision_token_id=ep.provision_token_id,
                           allow_simulator=rt.settings.allow_loopback_endpoints)


def open_mutations(rt: Runtime, ep, known: list[str] | None = None) -> ProxmoxMutations:
    require_job_execution()
    known = known if known is not None else []
    if not ep.provision_token_id or ep.provision_secret_enc is None:
        raise MutationNotAllowed("this endpoint has only an inventory credential; mutations are refused (register a provision credential)")
    if getattr(ep, "enabled", True) is False or getattr(ep, "detached_at", None) is not None:
        raise MutationNotAllowed("this endpoint is disabled or detached")
    ps = rt.vault.decrypt(ep.provision_secret_enc, provision_aad(ep, _binding(ep))).decode()
    known.append(ps)
    w = ProxmoxWriteClient(ep.base_url, ep.provision_token_id, ps, **_kw(rt, ep))
    return ProxmoxMutations(w, scope=scope_of(ep), token_id=ep.provision_token_id, allow_simulator=rt.settings.allow_loopback_endpoints)


def probe_connection(rt: Runtime, *, base_url: str, token_id: str, token_secret: str, ca_pem: str | None = None,
                     fingerprint_sha256: str | None = None, provision_token_id: str | None = None,
                     provision_token_secret: str | None = None, scope: EndpointScope | None = None):
    """Dry probe of connection details (setup wizard, endpoint.register/update). Persists nothing. Raises ValueError on malformed
    input and ProxmoxError when the destination is not allowed (SSRF guard); transport problems come back inside the result."""
    s = rt.settings
    kw = dict(ca_pem=ca_pem, fingerprint_sha256=fingerprint_sha256, deadline=s.pve_request_deadline_seconds,
              max_bytes=s.pve_max_response_bytes, allow_loopback=s.allow_loopback_endpoints)
    inv = ProxmoxReadClient(base_url, token_id, token_secret, **kw)
    prov = ProxmoxReadClient(base_url, provision_token_id, provision_token_secret, **kw) if provision_token_id else None
    try:
        return ProxmoxProvider(inv, scope=scope, trust="fingerprint" if fingerprint_sha256 else "ca_bundle", inventory_token_id=token_id,
                               provision_probe=prov, provision_token_id=provision_token_id,
                               allow_simulator=s.allow_loopback_endpoints).probe()
    finally:
        inv.close()
        if prov:
            prov.close()
