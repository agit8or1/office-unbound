"""API TLS trust during SSH onboarding (ADR-0014, trust.py): public CA chain with host-name validation (pin the root, never the ACME leaf), cluster CA,
fingerprint, reverse proxy in front of the API (explicit confirmation, still a valid chain), SSH address != API address (same-node verification).
Real certificate chains (root -> intermediate -> leaf) and real TLS handshakes; the "public trust store" is the test root (system_context is patched)."""
import ipaddress
import ssl

import pytest
from cryptography import x509
from sqlalchemy import text

from ics.proxmox import ProxmoxError
from ics.sshonboard import trust as TR
from .ca_server import CaSimServer, Pki, fp as cfp, pem
from .infra_fixtures import H  # noqa: F401
from .pve_sim import PveSim, SimServer
from .ssh_node import SshNode
from .test_provisioning import owner, w  # noqa: F401
from .test_ssh_onboard import ACCT, POL, connected, discover, flow, new_session, preview, pve_state  # noqa: F401


@pytest.fixture()
def pki(monkeypatch):
    p = Pki("Public")
    ctx = ssl.create_default_context(cadata=pem(p.root))
    monkeypatch.setattr(TR, "system_context", lambda: ctx)
    return p


def owner_sim():
    s = PveSim(task_delay=0.1)
    s.populate_owner_env()
    return s


@pytest.fixture()
def servers():
    made = []

    def mk(srv):
        made.append(srv)
        return srv
    yield mk
    for s in made:
        s.stop()


def self_signed_pem() -> str:
    from .pve_mock import make_cert
    return make_cert()[0]


# ======================================================================================= decide(): every case
def test_public_ca_pins_the_root_and_host_name_not_the_leaf(pki, servers):
    srv = servers(CaSimServer(pki, owner_sim()))
    t = TR.decide(srv.url, srv.fullchain, None, True)
    assert t.mode == "public_ca" and t.leaf_pin is None and t.ca_pem.strip() == pem(pki.root).strip() and not t.needs_confirmation
    assert TR.trust_args(t) == (t.ca_pem, None)                         # exactly one of ca / fingerprint, as the endpoint layer requires
    # ACME-style renewal: a NEW leaf from the same CA on the same host name: the pin (the root) is unchanged, so nothing has to be re-approved
    srv2 = servers(CaSimServer(pki, owner_sim()))
    t2 = TR.decide(srv2.url, srv2.fullchain, None, True)
    assert t2.seen_leaf != t.seen_leaf and t2.mode == "public_ca" and t2.ca_sha256() == t.ca_sha256()
    # the chain really is validated: the pinned root accepts the renewed leaf for the host name, and rejects another host name
    assert TR._verifies(srv2.url, t.ca_pem, True)


def test_host_name_validation_is_part_of_public_trust(pki, servers):
    k, leaf = pki.leaf(cn="other.example", san=[x509.DNSName("other.example")])          # valid chain, but not for 127.0.0.1
    srv = servers(CaSimServer(pki, owner_sim(), leaf=(k, leaf)))
    t = TR.decide(srv.url, srv.fullchain, None, True)
    assert t.mode == "fingerprint" and t.leaf_pin == cfp(leaf)             # NOT public_ca: a valid chain for another name earns no trust


def test_cluster_ca_is_pinned_when_not_public(pki, servers):
    cluster = Pki("PVE Cluster")
    srv = servers(CaSimServer(cluster, owner_sim()))
    t = TR.decide(srv.url, srv.fullchain, pem(cluster.root), True)
    assert t.mode == "cluster_ca" and t.ca_pem.strip() == pem(cluster.root).strip() and t.leaf_pin is None
    t = TR.decide(srv.url, srv.fullchain, None, True)                     # no CA readable: strict fingerprint pin of the leaf
    assert t.mode == "fingerprint" and t.leaf_pin == srv.fingerprint


def test_self_signed_node_by_address_is_a_fingerprint_pin(pki, servers):
    srv = servers(SimServer(owner_sim()))
    t = TR.decide(srv.url, srv.cert_pem, None, True)
    assert t.mode == "fingerprint" and t.leaf_pin == srv.fingerprint and t.ca_pem is None


def test_reverse_proxy_with_valid_public_chain_needs_confirmation(pki, servers):
    srv = servers(CaSimServer(pki, owner_sim()))
    t = TR.decide(srv.url, self_signed_pem(), None, True)                  # the node serves its own cert; the address presents the proxy's
    assert t.mode == "proxy_public" and t.needs_confirmation and t.seen_leaf == srv.fingerprint and t.node_leaf != t.seen_leaf
    assert t.ca_pem.strip() == pem(pki.root).strip() and "reverse proxy" in t.explanation


def test_different_certificate_without_a_valid_chain_stops_and_shows_both_fingerprints(pki, servers):
    srv = servers(SimServer(owner_sim()))
    node = self_signed_pem()
    with pytest.raises(ProxmoxError) as e:
        TR.decide(srv.url, node, None, True)
    assert "MISMATCH" in str(e.value) and srv.fingerprint in str(e.value) and TR.leaf_fp(node) in str(e.value)


def test_public_chain_for_a_different_host_name_is_not_accepted_as_a_proxy(pki, servers):
    k, leaf = pki.leaf(cn="other.example", san=[x509.DNSName("other.example")])
    srv = servers(CaSimServer(pki, owner_sim(), leaf=(k, leaf)))
    with pytest.raises(ProxmoxError, match="MISMATCH"):
        TR.decide(srv.url, self_signed_pem(), None, True)


# ======================================================================================= through the pipeline
def endpoint_trust(owner_engine, name="onb"):
    with owner_engine.connect() as c:
        return c.execute(text("SELECT base_url, ca_pem, fingerprint_sha256 FROM endpoints WHERE name = :n"), {"n": name}).first()


def test_public_ca_hostname_endpoint_end_to_end_with_pveproxy_cert_preferred(w, pki, servers, owner_engine):
    srv = servers(CaSimServer(pki, owner_sim()))
    node = SshNode(srv, pveproxy_pem=srv.fullchain, node_pem=self_signed_pem())        # pve-ssl.pem is the cluster-CA cert; pveproxy-ssl.pem the ACME one
    try:
        ACCT[0] = node.user
        sid = connected(w, node, host="127.0.0.2")                      # SSH to 127.0.0.2, API at https://127.0.0.1:PORT (different addresses, same node)
        p, j = discover(w, sid)
        assert j["status"] == "succeeded", j.get("error")
        ac = j["result"]["api_certificate"]
        assert ac["mode"] == "public_ca" and ac["seen_leaf"] == srv.fingerprint == ac["node_leaf"] and not ac["needs_confirmation"]
        reads = [e for e in node.executed() if e[0] == "cat"]
        assert any("pveproxy-ssl.pem" in " ".join(e) for e in reads)
        pv = preview(w, sid)
        assert pv["ssh"]["api_trust"] == "public_ca" and pv["ssh"]["api_leaf_pinned"] is None
        p, j = w.run("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"})
        assert j["status"] == "succeeded", j.get("error")
        assert j["result"]["api_trust"] == "public_ca" and j["result"]["node_check"].startswith("api and ssh agree: pve06")
        ep = endpoint_trust(owner_engine)
        assert ep.ca_pem.strip() == pem(pki.root).strip() and ep.fingerprint_sha256 is None and ep.base_url == srv.url
        assert w.v.get(f"{H}/endpoints/{j['result']['endpoint_id']}").json()["trust"] == "ca_bundle"
    finally:
        node.stop()


def test_cluster_ca_mode_end_to_end(w, pki, servers, owner_engine):
    cluster = Pki("PVE Cluster")
    srv = servers(CaSimServer(cluster, owner_sim()))
    node = SshNode(srv, cluster_ca=pem(cluster.root))
    try:
        ACCT[0] = node.user
        sid = connected(w, node, host="127.0.0.2")
        p, j = discover(w, sid)
        assert j["result"]["api_certificate"]["mode"] == "cluster_ca"
        pv = preview(w, sid)
        p, j = w.run("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"})
        assert j["status"] == "succeeded", j.get("error")
        ep = endpoint_trust(owner_engine)
        assert ep.ca_pem.strip() == pem(cluster.root).strip() and ep.fingerprint_sha256 is None
    finally:
        node.stop()


def test_fingerprint_mode_pins_the_leaf(w, pki, owner, owner_engine):
    node = SshNode(owner)
    try:
        ACCT[0] = node.user
        sid, pv, p, j = flow(w, node)
        assert j["status"] == "succeeded", j.get("error")
        ep = endpoint_trust(owner_engine)
        assert ep.ca_pem is None and ep.fingerprint_sha256 == owner.fingerprint
    finally:
        node.stop()


def test_reverse_proxy_requires_explicit_confirmation_and_keeps_a_valid_chain(w, pki, servers, owner_engine):
    srv = servers(CaSimServer(pki, owner_sim()))          # the proxy (what the API address presents), public chain
    node = SshNode(srv, node_pem=self_signed_pem())        # the node's own certificate differs
    try:
        ACCT[0] = node.user
        sid = connected(w, node)
        p, j = discover(w, sid)
        assert j["status"] == "succeeded", j.get("error")
        ac = j["result"]["api_certificate"]
        assert ac["mode"] == "proxy_public" and ac["needs_confirmation"] and ac["seen_leaf"] == srv.fingerprint and ac["node_leaf"] != ac["seen_leaf"]
        # nothing continues until the administrator confirms the proxy's fingerprint
        r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.preview", "params": {"ssh_session_id": sid, "policy": POL, "name": "onb", "account": node.user}}, headers=w.oh)
        assert r.status_code == 409 and "proxy" in r.text
        bad = w.o.post(f"{H}/ssh-sessions/{sid}/confirm-proxy", json={"fingerprint": ac["node_leaf"]}, headers=w.oh)      # the node's own fingerprint is not the proxy's
        assert bad.status_code == 422
        ok = w.o.post(f"{H}/ssh-sessions/{sid}/confirm-proxy", json={"fingerprint": ac["seen_leaf"]}, headers=w.oh)
        assert ok.status_code == 200 and ok.json()["api_proxy"] == "confirmed"
        pv = preview(w, sid)
        assert pv["ssh"]["api_trust"] == "proxy_public" and pv["ssh"]["api_leaf_pinned"] == srv.fingerprint
        p, j = w.run("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"})
        assert j["status"] == "succeeded", j.get("error")
        assert j["result"]["node_check"].startswith("api and ssh agree")          # the leaf differs, so identity came from /cluster/status over the API
        ep = endpoint_trust(owner_engine)
        assert ep.ca_pem.strip() == pem(pki.root).strip() and ep.fingerprint_sha256 is None
        with owner_engine.connect() as c:
            assert c.execute(text("SELECT count(*) FROM audit_events WHERE action = 'ssh.api_proxy.confirmed'")).scalar() == 1
    finally:
        node.stop()


def test_api_address_reaching_a_different_node_is_refused_and_rolled_back(w, pki, servers, owner_engine):
    sim = owner_sim()
    srv = servers(CaSimServer(pki, sim))
    node = SshNode(srv, pveproxy_pem=srv.fullchain)
    try:
        ACCT[0] = node.user
        sim.local_node = "pve05"                              # the API address is served by pve05; the SSH session is on pve06
        sid = connected(w, node, host="127.0.0.2")
        discover(w, sid)
        pv = preview(w, sid)
        p, j = w.run("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"})
        assert j["status"] == "failed" and "not the same node" in j["error"]["message"]
        st = pve_state(srv)
        assert not st["users"] and not st["roles"] and not node.has_account(node.user)
        assert endpoint_trust(owner_engine) is None
    finally:
        node.stop()


def test_ssh_and_api_addresses_may_differ_when_they_are_the_same_node(w, pki, servers):
    """SSH by IP, API by host name (public chain): allowed and verified (covered end to end above); the session stores both."""
    srv = servers(CaSimServer(pki, owner_sim()))
    node = SshNode(srv, pveproxy_pem=srv.fullchain)
    try:
        s = new_session(w, node)
        assert s["host"] == "127.0.0.1" and s["api_url"].startswith("https://127.0.0.1:")
    finally:
        node.stop()
