"""Shared fixtures for the provider / inventory tests. The Proxmox simulator is a TEST DOUBLE (see pve_sim.py)."""
import pytest

from ics import worker
from ics.providers import base
from ics.providers.proxmox.provider import EndpointScope, ProxmoxMutations, ProxmoxProvider
from ics.proxmox import ProxmoxReadClient, ProxmoxWriteClient

from .pve_sim import PveSim, SimServer

H = "/api/v1"
INV = ("ics-inv@pve!inventory", "invsecret0123456789")
LAB = ("ics-lab@pve!lab", "labsecret0123456789")
SCOPE = EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1",))


@pytest.fixture()
def sim():
    s = PveSim(task_delay=0.15)
    s.populate_default()
    srv = SimServer(s)
    yield srv
    srv.stop()


@pytest.fixture()
def real_sim():
    s = PveSim(task_delay=0.15)
    s.populate_realworld()
    srv = SimServer(s)
    yield srv
    srv.stop()


def ro(srv, cred=INV, **kw):
    kw.setdefault("fingerprint_sha256", srv.fingerprint)
    return ProxmoxReadClient(srv.url, *cred, allow_loopback=True, **kw)


def rw(srv, cred=LAB, **kw):
    kw.setdefault("fingerprint_sha256", srv.fingerprint)
    return ProxmoxWriteClient(srv.url, *cred, allow_loopback=True, **kw)


def read_provider(srv, scope=SCOPE, with_prov=True, **kw):
    return ProxmoxProvider(ro(srv), scope=scope, inventory_token_id=INV[0], provision_probe=ro(srv, LAB) if with_prov else None,
                           provision_token_id=LAB[0], allow_simulator=True, sleep=lambda s: __import__("time").sleep(0.02), **kw)


def mutations(srv, scope=SCOPE, **kw):
    """Only valid inside job execution (the structural guard)."""
    return ProxmoxMutations(rw(srv), scope=scope, token_id=LAB[0], allow_simulator=True, sleep=lambda s: __import__("time").sleep(0.02), **kw)


@pytest.fixture()
def job():
    with base.job_execution("test-job"):
        yield
