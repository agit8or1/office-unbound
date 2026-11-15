"""Identity lifecycle gaps: OpenCloud app-token revocation, Gromox session kill, ActiveSync remote wipe (ICS side, agent helpers, EAS test client)."""
import json
import os
import subprocess
import sys
import time

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import easprobe, identity
from .test_identity import H, add_stack, create_user, env, world  # noqa: F401  (fixtures)

DEPLOY = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks")


def disable(env, **kw):
    return env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, **kw}))


# ---- gap 1: OpenCloud app tokens ---------------------------------------------------------------------------------------------------------
def test_disable_revokes_app_tokens_before_the_lock_and_reports_it(env, rt, world):
    add_stack(rt)
    create_user(env)
    world.app_tokens["alice"] = 3
    n0 = len(world.calls)
    job = disable(env)
    assert job["status"] == "succeeded", job.get("error")
    calls = [c[0] for c in world.calls[n0:]]
    assert calls.index("opencloud.revoke_app_tokens") < calls.index("gromox.sync_user")            # revoked while OpenCloud can still resolve the user
    assert world.app_tokens["alice"] == 0
    v = job["result"]["verification"]
    assert v["oc_app_tokens"]["revoked"] == 3 and v["oc_app_tokens"]["remaining"] == 0 and v["oc_app_tokens"]["ok"] is True and "oc_app_tokens" not in v["not_revoked"]
    step = [s for s in job["result"]["steps"] if s["step"] == "opencloud.revoke_app_tokens"][0]
    assert step["revoked"] == 3 and step["remaining"] == 0
    # enable does not bring them back
    assert env.run(env.plan("idm.user.enable", {"stack": "acme", "uid": "alice"}))["status"] == "succeeded"
    assert world.app_tokens["alice"] == 0


def test_incomplete_token_revocation_fails_verify_loudly(env, rt, world):
    add_stack(rt)
    create_user(env)
    world.app_tokens["alice"] = 2
    world.revoke_ok = False
    job = disable(env)
    assert job["status"] == "failed" and "oc_app_tokens" in job["error"]["message"]
    assert world.ldap["alice"]["locked"]                                      # the lock itself is never skipped


def test_stack_without_files_node_skips_token_revocation(env, rt, world):
    add_stack(rt, files_node_id=None)
    create_user(env)
    job = disable(env)
    assert job["status"] == "succeeded" and job["result"]["verification"]["oc_app_tokens"] is None
    assert not [c for c in world.calls if c[0] == "opencloud.revoke_app_tokens"]


# ---- gap 2: session kill ------------------------------------------------------------------------------------------------------------------
def test_disable_kills_sessions_after_suspension_and_before_quarantine(env, rt, world):
    add_stack(rt)
    create_user(env)
    n0 = len(world.calls)
    job = disable(env)
    assert job["status"] == "succeeded"
    order = [c[0] for c in world.calls[n0:] if c[0].startswith("gromox")]
    assert order[:4] == ["gromox.sync_user", "gromox.kill_sessions", "gromox.kick_user", "gromox.user_state"]
    assert world.kicked == ["alice"]
    step = [s for s in job["result"]["steps"] if s["step"] == "gromox.kill_sessions"][0]
    assert step["kick_sent"] is True


# ---- gap 3: device wipe -------------------------------------------------------------------------------------------------------------------
def test_wipe_devices_is_high_risk_and_validated(env, rt, world):
    add_stack(rt)
    create_user(env)
    d = env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "wipe_devices": True}, approvers=[])
    assert d["risk"] == "high" and d["approvals_required"] == 2
    assert env.plan("idm.user.disable", {"stack": "acme", "uid": "alice"}, approvers=[])["risk"] == "normal"
    assert env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "wipe_wait_seconds": 30}, expect=422)    # wait without wipe
    assert env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "wipe_devices": True, "wipe_wait_seconds": 301}, expect=422)
    with pytest.raises(ValidationError):
        identity.UserDisable.model_validate({"stack": "acme", "uid": "alice", "wipe_devices": True, "extra": 1})


def test_wipe_requested_before_lock_waits_for_delivery_and_reports_devices(env, rt, world):
    add_stack(rt)
    create_user(env)
    world.devices["alice"] = {"phone1": 0, "tablet2": 0}
    world.picks_up_after = 2
    n0 = len(world.calls)
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "wipe_devices": True, "wipe_wait_seconds": 60}))
    assert job["status"] == "succeeded", job.get("error")
    calls = [c[0] for c in world.calls[n0:]]
    assert calls.index("gromox.wipe_devices") < calls.index("gromox.sync_user")                    # BEFORE suspension
    w = job["result"]["verification"]["device_wipe"]
    assert w["requested"] == 2 and w["delivered"] == 2 and w["undelivered_devices"] == []
    assert {d["device"]: d["status"] for d in w["devices"]} == {"phone1": "wipe_delivered", "tablet2": "wipe_delivered"}


def test_undelivered_wipe_is_reported_not_hidden(env, rt, world):
    add_stack(rt)
    create_user(env)
    world.devices["alice"] = {"phone1": 0}
    world.picks_up_after = None
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "wipe_devices": True, "wipe_wait_seconds": 10}))
    assert job["status"] == "succeeded"                                        # the disable is never held hostage by an offline phone
    w = job["result"]["verification"]["device_wipe"]
    assert w["delivered"] == 0 and w["undelivered_devices"] == ["phone1"] and w["devices"][0]["status"] == "wipe_pending"
    assert world.ldap["alice"]["locked"]


def test_user_without_devices_and_no_wipe_flag(env, rt, world):
    add_stack(rt)
    create_user(env)
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "wipe_devices": True}))
    assert job["result"]["verification"]["device_wipe"]["requested"] == 0
    j2 = create_user(env, "bob")[1]
    job2 = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "bob", "verify_timeout_seconds": 5}))
    assert job2["result"]["verification"]["device_wipe"] is None
    assert not [c for c in world.calls if c[0] == "gromox.wipe_devices" and c[1] == "bob"]


def test_devices_action_lists_devices_read_only(env, rt, world):
    add_stack(rt)
    create_user(env)
    world.devices["alice"] = {"phone1": 0}
    j = env.plan("idm.user.devices", {"stack": "acme", "uid": "alice"}, approvers=[])
    assert j["risk"] == "low"
    j["job_id"] = j.get("job_id") or env.op.get(f"{H}/plans/{j['plan_id']}").json().get("job_id")
    job = env.run(j)
    assert job["status"] == "succeeded" and job["result"]["devices"][0]["device"] == "phone1"
    assert env.plan("idm.user.devices", {"stack": "acme", "uid": "ghost"}, expect=404)


# ---- EAS test client (WBXML) ----------------------------------------------------------------------------------------------------------------
def _wbxml_provision_response(wipe: bool, account_only: bool = False) -> bytes:
    body = bytes([0x03, 0x01, 0x6A, 0x00, 0x00, 0x0E, 0x45, 0x4B, 0x03]) + b"1\0" + bytes([0x01])
    body += bytes([0x46, 0x47, 0x48, 0x03]) + b"MS-EAS-Provisioning-WBXML\0" + bytes([0x01, 0x4B, 0x03]) + b"1\0" + bytes([0x01, 0x49, 0x03]) + b"123456789\0" + bytes([0x01, 0x01, 0x01])
    if wipe:
        body += bytes([0x0C])
    if account_only:
        body += bytes([0x3B])
    return body + bytes([0x01])


def test_eas_provision_response_parsing_detects_remote_wipe():
    r = easprobe.parse_provision(200, _wbxml_provision_response(False))
    assert r.status == 1 and r.policy_status == 1 and r.policy_key == "123456789" and not r.remote_wipe and not r.account_only_wipe
    assert easprobe.parse_provision(200, _wbxml_provision_response(True)).remote_wipe is True
    assert easprobe.parse_provision(200, _wbxml_provision_response(False, True)).account_only_wipe is True
    with pytest.raises(ValueError):
        easprobe.parse_provision(200, b"<html>")


def test_eas_requests_are_wellformed():
    assert easprobe.provision_request() == bytes.fromhex("03016a00 000e 45 46 47 48 03") + b"MS-EAS-Provisioning-WBXML\0" + bytes.fromhex("01 01 01 01")
    assert easprobe.provision_request(ack_wipe=True) == bytes.fromhex("03016a00 000e 45 4c 4b 03") + b"1\0" + bytes.fromhex("01 01 01")
    assert easprobe.foldersync_request()[-5:] == b"0\0\x01\x01"[-5:] or easprobe.foldersync_request().endswith(b"\x030\0\x01\x01")
    ph2 = easprobe.provision_request("987", with_policy_ack=True)
    assert b"987\0" in ph2 and ph2.count(b"1\0") == 1


# ---- helper scripts: validation without touching a real system ------------------------------------------------------------------------------
def _run(script, *args):
    return subprocess.run([sys.executable, os.path.join(DEPLOY, script), *args], capture_output=True, text=True, timeout=20)


@pytest.mark.parametrize("script", ["ou-oc-revoke", "ou-gw-user"])
def test_helpers_reject_malformed_uids(script):
    for bad in ("Alice", "a", "al;ice", "../x", "alice\n", "-h"):
        args = (bad,) if script == "ou-oc-revoke" else ("devices", bad)
        r = _run(script, *args)
        assert r.returncode == 2 and "usage" in r.stderr, (bad, r.stderr)
    r = _run("ou-gw-user", "rm", "alice")
    assert r.returncode == 2


def test_new_runbooks_are_registered_with_fixed_template_units():
    from ou_agent import runbooks
    for action, tmpl in (("opencloud.revoke_app_tokens", "ou-rb-opencloud-revoke"), ("gromox.kill_sessions", "ou-rb-gromox-kill"),
                         ("gromox.wipe_devices", "ou-rb-gromox-wipe"), ("gromox.devices", "ou-rb-gromox-devices")):
        assert runbooks.USER_RUNBOOKS[action][0] == tmpl
        assert os.path.exists(os.path.join(DEPLOY, tmpl + "@.service"))
        cfg = {"runbooks": {action: {"enabled": True}}}
        assert runbooks.check_allowed(cfg, action, {"user": "alice"}) == {"user": "alice"}
        for bad in ({"user": "alice", "device": "x"}, {"user": "Alice"}, {}):
            with pytest.raises(Exception):
                runbooks.check_allowed(cfg, action, bad)
    p = subprocess.run([sys.executable, os.path.join(DEPLOY, "..", "render_polkit.py"), os.path.join(DEPLOY, "..", "agent.json")], capture_output=True, text=True, check=True).stdout
    for t in ("ou-rb-gromox-kill", "ou-rb-gromox-wipe", "ou-rb-gromox-devices"):
        assert t in p
    p2 = subprocess.run([sys.executable, os.path.join(DEPLOY, "..", "render_polkit.py"), os.path.join(DEPLOY, "..", "agent-files.json")], capture_output=True, text=True, check=True).stdout
    assert "ou-rb-opencloud-revoke" in p2 and "ou-rb-gromox" not in p2


def test_wipe_api_only_accepts_device_acknowledgements():
    """The HTTP surface of ou-wipe-api can never CREATE a wipe request (status 2/16): only the root helper writes those."""
    src = open(os.path.join(DEPLOY, "ou-wipe-api")).read()
    assert "ACK = {4, 8, 32, 64}" in src and "status not in ACK | {POLICY_OK}" in src
    assert "if dev is None or int(dev[1]) < 2" in src                         # an ack for a device without a pending wipe is refused


def test_wipe_happens_before_the_canary_credential_replaces_the_password(env, rt, world, monkeypatch):
    """A device must still authenticate with the user's real credential: the wipe request (and wait) precede the canary rotation and the lock."""
    from .test_identity import patch_probes
    add_stack(rt, probe_client_id="probe")
    patch_probes(monkeypatch, world)
    create_user(env)
    world.passwords["alice"] = "users-own-password"
    world.devices["alice"] = {"phone1": 0}
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "wipe_devices": True, "wipe_wait_seconds": 5,
                                                "rotate_credentials": True}))
    assert job["status"] == "succeeded", job.get("error")
    assert world.pw_at_wipe == "users-own-password" and world.passwords["alice"] != "users-own-password"
