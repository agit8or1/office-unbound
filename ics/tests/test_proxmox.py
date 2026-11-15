import json
import ssl

import pytest

from ics.proxmox import ProxmoxError, ProxmoxReadClient
from .pve_mock import FIX, SEC, TID



def client(pve, **kw):
    kw.setdefault('allow_loopback', True)
    return ProxmoxReadClient(pve.url, TID, SEC, **kw)


def test_pinned_fingerprint_success_and_colon_format(pve):
    c = client(pve, fingerprint_sha256=pve.fingerprint)
    assert c.version()["version"] == "8.2.4"
    c.close()
    fp = ":".join(pve.fingerprint[i:i + 2] for i in range(0, 64, 2)).upper()
    c = client(pve, fingerprint_sha256=fp)
    assert c.version()["release"] == "8.2"


def test_wrong_fingerprint_fails_before_any_request(pve):
    before = len(pve.seen)
    c = client(pve, fingerprint_sha256="ab" * 32)
    with pytest.raises(ProxmoxError, match="pinned"):
        c.version()
    assert len(pve.seen) == before  # no HTTP request (and no token) reached the server


def test_ca_bundle_mode(pve):
    assert client(pve, ca_pem=pve.cert_pem).version()["version"] == "8.2.4"
    from .pve_mock import make_cert
    other_pem, _, _ = make_cert()
    with pytest.raises(ProxmoxError):
        client(pve, ca_pem=other_pem).version()


def test_unverified_construction_rejected(pve):
    with pytest.raises(ValueError):
        client(pve)
    with pytest.raises(ValueError):
        client(pve, ca_pem=pve.cert_pem, fingerprint_sha256=pve.fingerprint)
    with pytest.raises(ValueError):
        ProxmoxReadClient("http://127.0.0.1:8006", TID, SEC, fingerprint_sha256=pve.fingerprint)
    with pytest.raises(ValueError):
        client(pve, fingerprint_sha256="nothex")


def test_bad_token_is_error_not_data(pve):
    c = ProxmoxReadClient(pve.url, TID, "wrong-secret-xx", fingerprint_sha256=pve.fingerprint, allow_loopback=True)
    with pytest.raises(ProxmoxError, match="401"):
        c.version()


def test_read_only_surface(pve):
    c = client(pve, fingerprint_sha256=pve.fingerprint)
    public = {n for n in dir(c) if not n.startswith("_")}
    assert public == {"close", "version", "cluster_status", "nodes", "qemu", "lxc", "storage", "network", "inventory"}
    with pytest.raises(ProxmoxError):
        c.qemu("../../access/users")


def test_inventory_parsing_matches_fixtures(pve):
    c = client(pve, fingerprint_sha256=pve.fingerprint)
    inv = c.inventory()
    assert inv["version"]["version"] == "8.2.4"
    assert [n["type"] for n in inv["cluster_status"]] == ["cluster", "node", "node"]
    assert inv["cluster_status"][0]["quorate"] == 1
    nodes = {n["node"]: n for n in inv["nodes"]}
    assert nodes["pve1"]["status"] == "online" and nodes["pve2"]["status"] == "offline"
    p1 = nodes["pve1"]
    assert {v["vmid"] for v in p1["qemu"]} == {100, 9000} and p1["qemu"][1]["template"] == 1
    assert p1["lxc"][0]["name"] == "ct-dns" and p1["lxc"][0]["type"] == "lxc"
    assert [s["storage"] for s in p1["storage"]] == ["local", "local-lvm"]
    assert {i["iface"]: i["type"] for i in p1["network"]} == {"eno1": "eth", "vmbr0": "bridge"}
    assert "qemu" not in nodes["pve2"]  # offline node is not queried
    assert json.loads((FIX / "qemu.json").read_text())["data"] == p1["qemu"]
    assert all(m == "GET" for m, _ in pve.seen)
