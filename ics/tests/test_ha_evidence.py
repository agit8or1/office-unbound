"""HA proof support (docs/status/ha-partition-results.md): the evidence a central recorder relies on, and the fencing check on the one egress path the H-5 commit missed.
- every provider / notification client (incl. the PROVISIONING admin client) asks the epoch guard first and names controller + epoch + job on each request
- the node agent writes one secret-free exec-log line per request (peer, controller epoch, decision), also for refusals"""
import json
import os
import uuid

import httpx
import pytest

from ics import egress
from ics.epoch import NotActive
from ics.providers import base
from ics.providers.proxmox.admin import ProxmoxAdminClient

from .infra_fixtures import ro, sim  # noqa: F401  (fixture)
from .pve_sim import PveSim, SimServer
from .test_agent import NODE, enrolled  # noqa: F401  (fixture)
from .test_agent_epoch import _req
from .test_review7_fencing import primary, supersede  # noqa: F401  (fixture + helper)


def test_request_hook_names_controller_epoch_and_job_and_asks_the_guard(primary):
    rt = primary
    req = httpx.Request("GET", "https://127.0.0.1/api2/json/version")
    with base.job_execution("job-123"):
        egress._request_hook(req)
    assert req.headers["x-ou-epoch"] == str(rt.own_epoch) and req.headers["x-ou-controller"] and req.headers["x-ou-job"] == "job-123"
    egress._request_hook(r2 := httpx.Request("GET", "https://127.0.0.1/"))
    assert "x-ou-job" not in r2.headers                               # outside job execution there is no job to name
    supersede(rt, "epoch")
    with pytest.raises(NotActive):
        egress._request_hook(httpx.Request("GET", "https://127.0.0.1/"))


def test_provisioning_admin_client_is_fenced_and_sends_nothing(primary):
    """the Mode-A admin client (ticket / admin token: the most powerful provider call) is under the same guard, from its very first (login) request"""
    s = PveSim(task_delay=0.05)
    s.populate_owner_env()
    srv = SimServer(s)
    try:
        supersede(primary, "epoch")
        with base.job_execution("t"):
            with pytest.raises(NotActive):
                ProxmoxAdminClient(srv.url, username="root@pam", password=s.ROOT_PW, fingerprint_sha256=srv.fingerprint, allow_loopback=True)
        assert s.seen == []                                           # not a single request reached the provider
    finally:
        srv.stop()


def test_read_client_request_is_fenced_and_stamped(primary, sim):
    c = ro(sim)
    c._get("/version")                                                # active primary: the request goes out
    n = len(sim.sim.seen)
    assert n >= 1
    supersede(primary, "epoch")
    with pytest.raises(NotActive):
        c._get("/version")
    assert len(sim.sim.seen) == n                                     # fenced: nothing more reached the provider


def _lines(fa):
    p = os.path.join(fa.state, "exec.log")
    return [json.loads(x) for x in open(p).read().splitlines()] if os.path.exists(p) else []


def test_agent_exec_log_records_every_request_with_epoch_and_decision(enrolled, monkeypatch):
    from ics import agentclient
    monkeypatch.setattr(agentclient, "stale_epoch_hook", lambda seen: None)      # do not fence the session-wide Runtime with the deliberate stale request
    fa = enrolled[0]
    assert _req(enrolled, 3)["status"] == "ok"
    assert _req(enrolled, 2)["code"] == "stale_epoch"                 # a fenced controller's attempt is evidence too
    ls = [l for l in _lines(fa) if l.get("action") == "service.status"]
    assert [(l["req_epoch"], l["status"], l["code"], l["agent_epoch"]) for l in ls] == [(3, "ok", "ok", 3), (2, "rejected", "stale_epoch", 3)]
    assert all(uuid.UUID(l["job_id"]) and l["peer"] == "127.0.0.1" for l in ls)
    raw = open(os.path.join(fa.state, "exec.log")).read()
    assert "gromox-imap" not in raw                                   # no parameters, no secrets in the log
    assert oct(os.stat(os.path.join(fa.state, "exec.log")).st_mode & 0o777) == "0o640"


def test_agent_exec_log_failure_never_blocks_a_request(enrolled, monkeypatch):
    fa = enrolled[0]
    monkeypatch.setattr(fa.agent, "_log_line", lambda d: (_ for _ in ()).throw(OSError("disk full")))
    assert _req(enrolled, 1)["status"] == "ok"
