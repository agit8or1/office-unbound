"""SSH onboarding (ADR-0014). The node is a REAL OpenSSH server (tests/ssh_node.py) whose pvesh/pveum/sudo/install/... are faithful fakes driven by the PVE
simulator (tests/pve_sim.py); the ICS reaches it only through real SSH sessions (host key, auth, exec, stdin, forced command). Passing here proves the ICS
logic and the allowlist against that model, NOT that a real Proxmox node behaves identically (docs/status/ssh-onboard-results.md has the real-target checklist)."""
import json
import re
import time

import pytest
from sqlalchemy import text

from ics import worker
from ics.providers import base
from ics.sshonboard import admin as A, client as C, session as S, templates as T
from .infra_fixtures import H  # noqa: F401
from .pve_sim import PveSim, SimServer
from .ssh_node import SshNode
from .test_provisioning import owner, w  # noqa: F401

POL = {"preset": "deploy", "scope_mode": "single_node",
       "scope": {"nodes": ["pve06"], "storages": ["PVE06-Storage"], "pools": ["officeunbound"], "networks": ["vmbr0"], "template_vmids": [9612, 131],
                 "protected_vmids": [126], "vmid_ranges": [[2000, 2999]]}}
TIB = 1 << 40
LVS_ROWS = [  # the owner's real shape: a 10.91 TiB thin pool carrying 15.17 TiB of thin volumes
    {"lv_name": "PVE06data", "vg_name": "pve06vg", "lv_size": str(int(10.91 * TIB)), "data_percent": "62.50", "metadata_percent": "4.10", "pool_lv": "", "lv_attr": "twi-aotz--"},
    {"lv_name": "vm-126-disk-0", "vg_name": "pve06vg", "lv_size": str(int(7.0 * TIB)), "data_percent": "50.00", "metadata_percent": "", "pool_lv": "PVE06data", "lv_attr": "Vwi-aotz--"},
    {"lv_name": "vm-131-disk-0", "vg_name": "pve06vg", "lv_size": str(int(8.17 * TIB)), "data_percent": "10.00", "metadata_percent": "", "pool_lv": "PVE06data", "lv_attr": "Vwi---tz-k"},
    {"lv_name": "root", "vg_name": "pve06vg", "lv_size": str(100 << 30), "data_percent": "", "metadata_percent": "", "pool_lv": "", "lv_attr": "-wi-ao----"},
]
ZFS_TEXT = "\n".join(["rpool\t300000000000\t700000000000\t-\t-", "rpool/data\t200000000000\t700000000000\t-\t-", "rpool/data/vm-9-disk-0\t150000000000\t700000000000\t2000000000000\t0"]) + "\n"
ALLOWED_TOOLS = {"lvs", "zfs", "pvesh", "pveum", "sudo", "install", "mv", "rm", "cat", "sha256sum", "visudo", "useradd", "usermod", "getent", "userdel", "usermod", "test", "apt-get", "env"}
PVEUM_OK = {("user", "add"), ("user", "delete"), ("user", "token", "add"), ("user", "token", "remove"), ("role", "add"), ("role", "modify"), ("role", "delete"),
            ("acl", "modify"), ("pool", "add"), ("pool", "delete")}


ACCT = ["ou-ics"]       # the sshd runs as the test user, so the ICS's "own account" must be that user in these tests


@pytest.fixture()
def node(owner):
    n = SshNode(owner)
    ACCT[0] = n.user
    yield n
    n.stop()


def new_session(w, node, **over):
    body = {"host": "127.0.0.1", "port": node.port, "username": node.user, "private_key": node.admin_key, "api_url": node.api_url, **over}
    r = w.o.post(f"{H}/ssh-sessions", json=body, headers=w.oh)
    assert r.status_code == 201, r.text
    return r.json()


def pin(w, node, sid):
    r = w.o.post(f"{H}/ssh-sessions/{sid}/hostkey", headers=w.oh)
    assert r.status_code == 200, r.text
    assert r.json()["hostkey_candidate"] == node.host_fp
    r = w.o.post(f"{H}/ssh-sessions/{sid}/confirm", json={"fingerprint": node.host_fp}, headers=w.oh)
    assert r.status_code == 200 and r.json()["state"] == "pinned", r.text


def connected(w, node, **over):
    s = new_session(w, node, **over)
    pin(w, node, s["id"])
    return s["id"]


def discover(w, sid):
    return w.run("provider.ssh.discover", {"ssh_session_id": sid})


def preview(w, sid, policy=None, name="onb", **extra):
    p, j = w.run("provider.ssh.preview", {"ssh_session_id": sid, "policy": policy or POL, "account": ACCT[0], **({"name": name} if "endpoint_id" not in extra else {}), **extra})
    assert j["status"] == "succeeded", j.get("error")
    return j["result"]


def flow(w, node, policy=None, name="onb", **session_over):
    sid = connected(w, node, **session_over)
    p, j = discover(w, sid)
    assert j["status"] == "succeeded", j.get("error")
    pv = preview(w, sid, policy, name)
    p, j = w.run("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": name})
    return sid, pv, p, j


def dump_db(engine) -> str:
    with engine.connect() as c:
        parts = [c.execute(text(q)).all() for q in (
            "SELECT params::text, coalesce(secret_enc::text,'') FROM plans", "SELECT coalesce(result::text,''), coalesce(error::text,'') FROM jobs",
            "SELECT details_canon FROM audit_events", "SELECT data::text FROM provision_artifacts", "SELECT * FROM ssh_sessions",
            "SELECT policy::text, design::text, coalesce(last_verification::text,'') FROM endpoint_policy")]
    return json.dumps([[str(x) for x in r] for rows in parts for r in rows])


def body_of(pem: str) -> str:
    return "".join(l for l in pem.splitlines() if "-----" not in l)[:60]


def pve_state(srv):
    s = srv.sim
    return {"users": {u for u in s.users if u.startswith("officeunbound@pve")}, "tokens": {t for t in s.tokens if t.startswith("officeunbound@pve!")},
            "roles": {r for r in s.roles if r.startswith("OfficeUnbound")}, "acl": [e for e in s.acl_entries if e["ugid"].startswith("officeunbound@pve")]}


# ======================================================================================= host key / TOFU
def test_host_key_fingerprint_matches_ssh_keygen_and_nothing_runs_before_confirmation(w, node, owner):
    s = new_session(w, node)
    r = w.o.post(f"{H}/ssh-sessions/{s['id']}/hostkey", headers=w.oh).json()
    assert r["hostkey_candidate"] == node.host_fp and r["hostkey_verify_command"] == "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
    assert node.executed() == []                                       # the handshake ran nothing
    pl = w.o.post(f"{H}/plans", json={"action": "provider.ssh.discover", "params": {"ssh_session_id": s["id"]}}, headers=w.oh)
    assert pl.status_code == 409 and "not been confirmed" in pl.text   # no TOFU: nothing else runs until the fingerprint is confirmed
    bad = w.o.post(f"{H}/ssh-sessions/{s['id']}/confirm", json={"fingerprint": "SHA256:" + "A" * 43}, headers=w.oh)
    assert bad.status_code == 422
    assert w.o.post(f"{H}/ssh-sessions/{s['id']}/confirm", json={"fingerprint": node.host_fp}, headers=w.oh).status_code == 200
    # a pinned key can not be re-pinned
    assert w.o.post(f"{H}/ssh-sessions/{s['id']}/hostkey", headers=w.oh).status_code == 409
    assert node.executed() == []


def test_pinned_key_mismatch_sends_nothing(node):
    with pytest.raises(C.SshError, match="host key does not match"):
        C.SshSession("127.0.0.1", node.port, node.user, C.HostKey("ssh-ed25519", "SHA256:" + "B" * 43), pem=node.admin_key)
    assert "Accepted" not in (node.dir / "sshd.log").read_text()      # sshd never saw an authentication


def test_host_key_changed_after_confirmation_stops_the_job(w, node, rt, owner):
    sid = connected(w, node)
    with rt.session() as db:
        db.execute(text("UPDATE ssh_sessions SET hk_pinned = :f WHERE id = :i"), {"f": "SHA256:" + "C" * 43, "i": sid})
        db.commit()
    p, j = discover(w, sid)
    assert j["status"] == "failed" and "host key does not match" in j["error"]["message"]
    assert node.executed() == []


# ======================================================================================= API certificate pin / cross-check
def test_wrong_api_certificate_stops_discovery(w, node, owner):
    other = SimServer(PveSim(task_delay=0.1))
    try:
        sid = connected(w, node, api_url=other.url)                    # the node says cert A (pve-ssl.pem); :8006 presents cert B
        p, j = discover(w, sid)
        assert j["status"] == "failed" and "MISMATCH" in j["error"]["message"] and "Node:" in j["error"]["message"]
        r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.preview", "params": {"ssh_session_id": sid, "policy": POL, "name": "x"}}, headers=w.oh)
        assert r.status_code == 409 and "discovery first" in r.text   # no trust decision was recorded
    finally:
        other.stop()


def test_discovery_overview_and_only_read_templates_ran(w, node, owner):
    sid = connected(w, node)
    p, j = discover(w, sid)
    assert j["status"] == "succeeded", j.get("error")
    ov = j["result"]["overview"]
    assert ov["cluster_name"] == "agit"+"8or" and ov["connected_node"] == "pve06" and ov["pve_version"] == "9.2.21"
    assert {n["name"] for n in ov["nodes"]} >= {"pve06", "pve05"} and any(s["name"] == "PVE06-Storage" for s in ov["storages"])
    assert any(n["name"] == "vmbr0" for n in ov["networks"]) and ov["guests"]["total"] >= 3 and ov["guests"]["templates"] >= 1
    assert j["result"]["api_certificate"]["seen_leaf"] == owner.fingerprint and j["result"]["api_certificate"]["mode"] == "fingerprint"
    ex = node.executed()
    assert ex and {e[0] for e in ex} <= {"sudo", "pvesh", "cat", "lvs", "zfs"}
    for e in ex:
        if e[0] == "pvesh":
            assert e[1] == "get" and "--output-format" in e
    assert not owner.sim.write_calls                                    # discovery changed nothing


# ======================================================================================= the full flow
def test_end_to_end_onboarding(w, node, owner, rt, owner_engine):
    sid, pv, p, j = flow(w, node)
    assert p["risk"] == "normal" and p["approvals_required"] == 1            # owner decision 2026-11-16: one approver (not the requester)
    assert pv["risk"] == "normal" and pv["approvals_required"] == 1 and pv["widening"] is False
    ob = p["onboard"]
    assert any("pveum user add officeunbound@pve" in c for c in ob["commands"]) and any("useradd" in c for c in ob["commands"])
    assert ob["identity"]["key_fingerprint"].startswith("SHA256:") and "restrict" in ob["identity"]["authorized_keys_line"]
    assert ob["identity"]["sudoers"].count("ALL=(root) NOPASSWD:") == 1 and "*" not in ob["identity"]["sudoers"].replace("# ", "")
    assert j["status"] == "succeeded", j.get("error")
    res = j["result"]
    # --- Proxmox: its OWN user, role(s), pool, ACLs, privsep tokens; exactly what was planned
    st = pve_state(owner)
    assert st["users"] == {"officeunbound@pve"} and st["tokens"] and st["roles"] and "officeunbound" in owner.sim.pools
    assert all(not e["path"] == "/" for e in st["acl"])
    assert res["verification"]["ok"] is True
    # --- the node: a locked system account, key with restrict+forced command, root-owned helper, config, sudoers
    acct = node.user
    assert node.has_account(acct) and (node.root / "state" / f"locked-{acct}").exists()
    ak = node.ics_ak.read_text() if node.ics_ak.exists() else (node.root / "var/lib" / acct / ".ssh/authorized_keys").read_text()
    assert ak.startswith("restrict,command=\"sudo -n /usr/local/sbin/ou-pve-helper\" ssh-ed25519 ")
    assert node.file("/usr/local/sbin/ou-pve-helper").read_bytes() == A.helper_source()
    assert json.loads(node.file("/etc/office-unbound/ou-pve-helper.json").read_text())["user"] == "officeunbound@pve"
    assert "NOPASSWD: /usr/local/sbin/ou-pve-helper \"\"" in node.file("/etc/sudoers.d/ou-ics").read_text()
    assert not node.file("/etc/sudoers.d/.ou-ics.tmp").exists()
    assert res["helper_verification"]["probes_refused"] >= 8 and res["admin_ssh_credential"] == "wiped"
    # --- only templates ran
    for e in node.executed():
        assert e[0] in ALLOWED_TOOLS, e
        if e[0] == "pveum":
            a = tuple(e[1:4]) if e[1:3] == ["user", "token"] else tuple(e[1:3])
            assert a in PVEUM_OK, e
        if e[0] == "sudo":
            assert e[1:3] == ["-n", "--"] or e[1] == "-n"
    names = [e[0] for e in node.executed()]
    assert "sh" not in names and "bash" not in names
    # --- the endpoint works with the captured token; the secret is only in the vault
    ep = w.v.get(f"{H}/endpoints/{res['endpoint_id']}").json()
    assert ep["credentials"]["inventory"]["present"] is True
    with owner_engine.connect() as c:
        ses = c.execute(text("SELECT state FROM ssh_sessions WHERE id = :i"), {"i": sid}).scalar()
        cred = c.execute(text("SELECT status, purged_at, length(secret_enc) FROM credentials WHERE id = :i"), {"i": sid}).first()
        idn = c.execute(text("SELECT account, node, key_fp, removed_at FROM ssh_identities")).first()
        keyc = c.execute(text("SELECT purpose, status, expires_at, host FROM credentials WHERE credential_type = 'ssh_key' AND provider = 'pve-ssh' AND id <> :i"), {"i": sid}).all()
    assert ses == "used" and cred.status == "revoked" and cred.purged_at is not None and cred.length == 0      # admin credential wiped
    assert idn.account == acct and idn.node == "pve06" and idn.key_fp == ob["identity"]["key_fingerprint"] and idn.removed_at is None
    assert [(k.purpose, k.status, k.expires_at) for k in keyc if k.status == "active"] == [("provision", "active", None)]
    dumped = dump_db(owner_engine)
    secrets = [t["secret"] for k, t in owner.sim.tokens.items() if k.startswith("officeunbound@pve!")]
    assert secrets and not any(s in dumped for s in secrets)
    assert body_of(node.admin_key) not in dumped and "PRIVATE KEY" not in dumped
    aud = json.dumps(res)
    assert node.admin_key.split()[1][:20] not in aud


def test_session_api_never_returns_the_credential(w, node):
    s = new_session(w, node)
    blob = json.dumps(s) + w.o.get(f"{H}/ssh-sessions/{s['id']}", headers=w.oh).text
    assert body_of(node.admin_key) not in blob and "private_key" not in blob and "password" not in blob
    assert w.v.get(f"{H}/ssh-sessions/{s['id']}", headers=w.vh).status_code in (403, 404)
    assert w.a1.get(f"{H}/ssh-sessions/{s['id']}", headers=w.a1h).status_code == 404            # bound to its creator
    bad = w.o.post(f"{H}/ssh-sessions", json={"host": "127.0.0.1", "username": "BAD USER", "password": "hunter2-secret-pass"}, headers=w.oh)
    assert bad.status_code == 422 and "hunter2" not in bad.text


def test_passphrase_protected_key_works(w, node, owner):
    sid = connected(w, node, private_key=node.admin_key_pp, passphrase=node.passphrase)
    p, j = discover(w, sid)
    assert j["status"] == "succeeded", j.get("error")
    sid2 = connected(w, node, private_key=node.admin_key_pp)         # missing passphrase
    p, j = discover(w, sid2)
    assert j["status"] == "failed" and "passphrase" in j["error"]["message"]


def test_root_login_does_not_use_sudo_and_user_does(w, node):
    s = new_session(w, node, username="root")
    s2 = new_session(w, node)
    with w.rt.session() as db:              # (was .__enter__() without exit: the leaked sessions held locks and made the next test's TRUNCATE time out)
        assert S.row(db, s["id"]).use_sudo is False
        assert S.row(db, s2["id"]).use_sudo is True
    ex = node.executed()
    assert ex == []


def test_sudo_user_path_runs_every_command_through_sudo_n(w, node, owner):
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    ex = node.executed()
    # the fake sudo re-execs the inner tool, which logs itself too: every bare privileged entry must be the target of the sudo entry right before it
    privileged = [e for i, e in enumerate(ex) if e[0] in {"pveum", "useradd", "install"}
                  and not (i and ex[i - 1][0] == "sudo" and ex[i - 1][1:3] == ["-n", "--"] and ex[i - 1][3:] == e)]
    assert not privileged                                              # every privileged tool was reached via sudo -n --
    assert all(e[1] == "-n" and e[2] == "--" for e in ex if e[0] == "sudo" and e[3:4] and e[3] != "/usr/local/sbin/ou-pve-helper")


# ======================================================================================= injection
BAD = ["a'b", 'a"b', "a;id", "a$(id)", "a`id`", "a\nid", "a b", "../x", "a|b", "a&b", "-rf", "a>b"]


@pytest.mark.parametrize("v", BAD)
def test_templates_refuse_injection_in_every_field(v):
    calls = [lambda: T.pvesh_get(f"/nodes/{v}/network"), lambda: T.user_add(v + "@pve", "c"), lambda: T.user_add("u@pve", v + "\u0001"),
             lambda: T.token_add("u@pve", v, "c"), lambda: T.token_delete("u@pve", v), lambda: T.role_add(v, ["VM.Audit"]), lambda: T.role_add("R", [v]),
             lambda: T.role_delete(v), lambda: T.acl_set("/pool/" + v, "R", user="u@pve"), lambda: T.acl_set("/", v, user="u@pve"), lambda: T.acl_set("/", "R", token=v),
             lambda: T.pool_add(v), lambda: T.account_add(v, "/var/lib/x"), lambda: T.account_exists(v), lambda: T.ssh_dir("ou", "/var/lib/" + v),
             lambda: A.authorized_line("ssh-ed25519 AAAA", v)]
    for c in calls:
        with pytest.raises((T.TemplateError, ValueError)):
            c()


def test_render_round_trips_through_shlex_for_every_template():
    import shlex
    cmds = [T.pvesh_get("/nodes/pve06/network"), T.pvesh_get("/cluster/resources?type=vm"), T.user_add("officeunbound@pve", "ICS-managed Office Unbound service account"),
            T.token_add("officeunbound@pve", "ics-inv", "ICS-managed inventory"), T.acl_set("/pool/officeunbound", "OfficeUnboundDeploy", token="officeunbound@pve!ics-prov"),
            T.role_add("OfficeUnboundDeploy", ["VM.Audit", "VM.Clone"]), T.pool_add("officeunbound", "ICS-managed")]
    for c in cmds:
        assert shlex.split(c.render(True)) == ["sudo", "-n", "--", *c.argv]


def test_pvesh_get_is_an_allowlist():
    for p in ("/nodes/pve06/qemu/100/config", "/access/permissions", "/cluster/config", "/version?x=1", "/nodes/pve06/network/../../x", "/storage/x", "/access/users/x@pve"):
        with pytest.raises(T.TemplateError):
            T.pvesh_get(p)


@pytest.mark.parametrize("field,val", [("nodes", ["pve06;id"]), ("storages", ["a'b"]), ("pools", ["a$(id)"]), ("networks", ["a\nb"])])
def test_injection_in_policy_fields_is_refused_at_plan_time(w, node, owner, field, val):
    sid = connected(w, node)
    discover(w, sid)
    pol = json.loads(json.dumps(POL))
    pol["scope"][field] = val
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.preview", "params": {"ssh_session_id": sid, "policy": pol, "name": "x"}}, headers=w.oh)
    assert r.status_code == 422
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.preview", "params": {"ssh_session_id": sid, "policy": POL, "name": "x';id"}}, headers=w.oh)
    assert r.status_code == 422
    assert node.executed() and all(e[0] in {"sudo", "pvesh", "cat", "lvs", "zfs"} for e in node.executed())


@pytest.mark.parametrize("body", [{"host": "a;id"}, {"host": "$(id)"}, {"username": "root;id"}, {"username": "a b"}, {"port": 0}, {"port": 70000}, {"api_url": "http://x"}])
def test_session_fields_are_validated(w, node, body):
    r = w.o.post(f"{H}/ssh-sessions", json={"host": "127.0.0.1", "port": node.port, "username": node.user, "private_key": node.admin_key, **body}, headers=w.oh)
    assert r.status_code == 422


def test_ssrf_guard_refuses_link_local_and_metadata(w):
    r = w.o.post(f"{H}/ssh-sessions", json={"host": "169.254.169.254", "username": "root", "password": "x" * 9}, headers=w.oh)
    assert r.status_code == 422


# ======================================================================================= approvals / binding
def test_changed_cluster_after_preview_refuses_and_changes_nothing(w, node, owner):
    sid = connected(w, node)
    discover(w, sid)
    pv = preview(w, sid)
    owner.sim.pools.add("officeunbound")                 # someone created the pool meanwhile: the planned commands differ
    p, j = w.run("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"})
    assert j["status"] == "failed" and "commands differ" in j["error"]["message"]
    assert not pve_state(owner)["users"] and not node.has_account(node.user)


def test_wrong_hash_or_foreign_session_is_refused(w, node, owner):
    sid = connected(w, node)
    discover(w, sid)
    pv = preview(w, sid)
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh_onboard", "params": {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": "0" * 64, "name": "onb"}}, headers=w.oh)
    assert r.status_code == 409
    sid2 = connected(w, node)
    discover(w, sid2)
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh_onboard", "params": {"ssh_session_id": sid2, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"}}, headers=w.oh)
    assert r.status_code == 409


def test_single_node_scope_blocks_when_connected_to_another_node(owner, w):
    n = SshNode(owner, local_node="pve05")
    try:
        sid = connected(w, n)
        discover(w, sid)
        pv = preview(w, sid)
        assert any("not the selected node" in b for b in pv["blocked"])
        r = w.o.post(f"{H}/plans", json={"action": "provider.ssh_onboard", "params": {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"}}, headers=w.oh)
        assert r.status_code == 409
    finally:
        n.stop()


# ======================================================================================= the ICS's own identity: allowlist and escapes
def ics_session(rt, node, owner):
    with rt.session() as db:
        i = db.execute(text("SELECT * FROM ssh_identities")).first()
    from ics.credentials import service as cs
    pem = cs.get_secret(rt, i.credential_id, use="test", actor="test")
    return C.SshSession("127.0.0.1", node.port, i.account, C.HostKey(i.hostkey_algo, i.hostkey_fp), pem=pem)


def test_forced_command_allows_only_the_helper_operations_and_refuses_every_escape(w, node, owner, rt):
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    s = ics_session(rt, node, owner)
    ok = {"self-check": 0, "discover nodes": 0, "discover version": 0, "discover network pve06": 0, "cert-read": 0, "drift": 0}
    for cmd, rc in ok.items():
        r = s.run_raw(cmd)
        assert r.rc == rc, (cmd, r.err)
    assert json.loads(s.run_raw("discover nodes").out)[0]["node"]
    escapes = ["id", "sh", "bash -i", "sh -c id", "/bin/sh", "cat /etc/shadow", "ls", "discover nodes; id", "discover nodes && id", "discover nodes | cat", "discover $(id)",
               "discover `id`", "discover nodes\nid", "discover ../../etc/passwd", "discover network ../x", "discover -h", "discover storage --help", "self-check extra",
               "pveum user add x@pve", "pveum acl modify / --roles Administrator --users officeunbound@pve", "pvesh get /access/users", "acl-narrow / Administrator root@pam",
               "acl-narrow /pool/x OfficeUnboundDeploy root@pam", "acl-narrow /pool/x Administrator officeunbound@pve", "acl-narrow ../x OfficeUnboundDeploy officeunbound@pve",
               "token-rotate root", "token-rotate ../x", "sudo -n id", "sudo id", "scp -t /tmp", "rsync --server .", "sftp", "internal-sftp", "ou-pve-helper", "", " ", "DISCOVER nodes",
               "discover  nodes", "x" * 400, "discover nodes #", "env", "export", "python3 -c 1", "su -", "OU_HELPER_ROOT=/ discover nodes"]
    for cmd in escapes:
        r = s.run_raw(cmd)
        assert r.rc != 0, (cmd, r.out)
        assert b"root:" not in r.out and b"uid=" not in r.out, cmd
    # no pty, no shell channel: restrict forbids them
    ch = s.t.open_session()
    with pytest.raises(Exception):
        ch.get_pty()
    ch.close()
    # no port forwarding
    with pytest.raises(Exception):
        s.t.open_channel("direct-tcpip", ("127.0.0.1", 22), ("127.0.0.1", 0)).close()
    # the command log shows only helper invocations after the key logged in
    bad = [e for e in node.executed() if e[0] in ("id", "sh", "bash", "ls", "env")]
    assert not bad
    s.close()


def test_helper_token_rotation_and_narrowing_are_limited_to_its_own_identity(w, node, owner, rt):
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    st = pve_state(owner)
    tok = sorted(st["tokens"])[0]
    s = ics_session(rt, node, owner)
    with base.job_execution("t"):
        h = A.HelperClient.__new__(A.HelperClient)
        h.s = s
        out = h.token_rotate(tok.split("!")[1])
    assert out["full-tokenid"] == tok and out["info"]["privsep"] == "1" and out["value"] != owner.sim.tokens[tok].get("old")
    # narrowing: one of its own ACL entries goes away; an entry of another subject can not be touched
    mine = [e for e in owner.sim.acl_entries if e["ugid"] == "officeunbound@pve" or e["ugid"].startswith("officeunbound@pve!")]
    assert mine
    e0 = mine[0]
    root_before = [e for e in owner.sim.acl_entries if e["ugid"] == "root@pam"]
    with base.job_execution("t"):
        h.acl_narrow(e0["path"], e0["roleid"], e0["ugid"])
        with pytest.raises(Exception):
            h.acl_narrow("/", "Administrator", "root@pam")
    assert [e for e in owner.sim.acl_entries if e["ugid"] == "root@pam"] == root_before
    assert not any((e["path"], e["roleid"], e["ugid"]) == (e0["path"], e0["roleid"], e0["ugid"]) for e in owner.sim.acl_entries)
    # widening is not expressible: there is no op that adds an ACL entry
    r = s.run_raw("acl-add / Administrator officeunbound@pve")
    assert r.rc == 126
    s.close()


def test_helper_actions_through_the_pipeline(w, node, owner, rt):
    sid, pv, p, j = flow(w, node)
    eid = j["result"]["endpoint_id"]
    p, j2 = w.run("provider.ssh.helper", {"endpoint_id": eid, "op": "self-check"})
    assert j2["status"] == "succeeded" and j2["result"]["helper_sha256"] == A.sha(A.helper_source())
    p, j2 = w.run("provider.ssh.helper", {"endpoint_id": eid, "op": "discover", "kind": "storage"})
    assert j2["status"] == "succeeded" and any(x["storage"] == "PVE06-Storage" for x in j2["result"]["result"])
    p, j2 = w.run("provider.ssh.helper", {"endpoint_id": eid, "op": "cert-read"})
    assert j2["result"]["certificate_sha256"] == owner.fingerprint
    p, j2 = w.run("provider.ssh.helper", {"endpoint_id": eid, "op": "drift"})
    assert j2["status"] == "succeeded" and {x["subject"] for x in j2["result"]["permissions"]} >= {"officeunbound@pve"}
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.helper", "params": {"endpoint_id": eid, "op": "discover", "kind": "x; id"}}, headers=w.oh)
    assert r.status_code == 422


# ======================================================================================= failure / rollback / wipe
def test_extra_privileges_fail_verification_and_roll_everything_back(w, node, owner, rt, owner_engine, monkeypatch):
    orig = A.SshAdmin.token_add

    def evil(self, userid, name, comment, privsep=1):
        out = orig(self, userid, name, comment, privsep)
        for t, ug in (("user", userid), ("token", f"{userid}!{name}")):   # Proxmox gives MORE than planned (privsep: effective = user AND token, so both)
            owner.sim.acl_entries.append({"path": "/", "type": t, "ugid": ug, "roleid": "PVEAuditor", "propagate": 1})
        return out
    monkeypatch.setattr(A.SshAdmin, "token_add", evil)
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "failed" and "verification" in j["error"]["message"]
    st = pve_state(owner)
    assert not st["users"] and not st["tokens"] and not st["roles"] and not [e for e in st["acl"]]
    assert not node.has_account(node.user) and not node.file("/usr/local/sbin/ou-pve-helper").exists() and not node.file("/etc/sudoers.d/ou-ics").exists()
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM endpoints WHERE name = 'onb'")).scalar() == 0
        assert c.execute(text("SELECT state FROM ssh_sessions WHERE id = :i"), {"i": sid}).scalar() == "used"
        assert c.execute(text("SELECT purged_at IS NOT NULL FROM credentials WHERE id = :i"), {"i": sid}).scalar()
    assert body_of(node.admin_key) not in dump_db(owner_engine)


def test_failed_node_command_rolls_back_and_wipes(w, node, owner, owner_engine, monkeypatch):
    def boom(self, i):
        raise A.ProxmoxError("simulated install failure")
    monkeypatch.setattr(A, "install_identity", boom)
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "failed"
    assert not pve_state(owner)["users"] and not pve_state(owner)["roles"]
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT purged_at IS NOT NULL FROM credentials WHERE id = :i"), {"i": sid}).scalar()


def test_credential_wiped_on_cancel(w, node, owner_engine):
    s = new_session(w, node)
    assert w.o.delete(f"{H}/ssh-sessions/{s['id']}", headers=w.oh).status_code == 200
    with owner_engine.connect() as c:
        r = c.execute(text("SELECT status, purged_at, length(secret_enc) FROM credentials WHERE id = :i"), {"i": s["id"]}).first()
        assert c.execute(text("SELECT state FROM ssh_sessions WHERE id = :i"), {"i": s["id"]}).scalar() == "cancelled"
    assert r.status == "revoked" and r.purged_at and r.length == 0
    assert w.o.post(f"{H}/ssh-sessions/{s['id']}/hostkey", headers=w.oh).status_code == 409


def test_credential_wiped_on_expiry_and_unusable_after(w, node, rt, owner_engine):
    from ics import actions
    sid = connected(w, node)
    with rt.session() as db:
        db.execute(text("UPDATE ssh_sessions SET expires_at = now() - interval '1 minute' WHERE id = :i"), {"i": sid})
        db.execute(text("UPDATE credentials SET expires_at = now() - interval '1 minute' WHERE id = :i"), {"i": sid})
        db.commit()
    actions.reap_expired(rt)
    with owner_engine.connect() as c:
        r = c.execute(text("SELECT status, purged_at, length(secret_enc) FROM credentials WHERE id = :i"), {"i": sid}).first()
        assert c.execute(text("SELECT state FROM ssh_sessions WHERE id = :i"), {"i": sid}).scalar() == "expired"
    assert r.purged_at and r.length == 0
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.discover", "params": {"ssh_session_id": sid}}, headers=w.oh)
    assert r.status_code == 409
    assert node.executed() == []


def test_session_is_30_minutes_and_wipe_after_failed_discovery_is_not_required_but_expiry_applies(w, node, owner_engine):
    s = new_session(w, node)
    with owner_engine.connect() as c:
        d = c.execute(text("SELECT extract(epoch FROM expires_at - created_at) FROM ssh_sessions WHERE id = :i"), {"i": s["id"]}).scalar()
    assert 1790 <= d <= 1810


def test_session_credential_is_bound_to_its_customer_and_creator(w, node, rt, owner_engine, mk_user, login):
    s = new_session(w, node)
    with owner_engine.connect() as c:
        cred = c.execute(text("SELECT customer_id, provider, purpose, credential_type FROM credentials WHERE id = :i"), {"i": s["id"]}).first()
    assert (cred.provider, cred.purpose, cred.credential_type) == ("pve-ssh", "temporary_provisioning", "ssh_key")
    # envelope AAD binds the customer: re-pointing the row to another customer makes it undecryptable
    from ics.credentials import service as cs
    with rt.session() as db:
        db.execute(text("INSERT INTO customers (id, name, msp_owned, provisioning_mode) VALUES (gen_random_uuid(), 'other', false, 'auto')"))
        other = db.execute(text("SELECT id FROM customers WHERE name = 'other'")).scalar()
        db.execute(text("UPDATE credentials SET customer_id = :c WHERE id = :i"), {"c": str(other), "i": s["id"]})
        db.commit()
    with pytest.raises(Exception):
        cs.get_secret(rt, s["id"], use="t", actor="t")


# ======================================================================================= idempotence, rotation, offboarding
def test_rerun_rotates_the_token_reuses_the_account_and_offboard_removes_everything(w, node, owner, rt, owner_engine):
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    eid = j["result"]["endpoint_id"]
    first = {k: v["secret"] for k, v in owner.sim.tokens.items() if k.startswith("officeunbound@pve!")}
    node.clear_log()
    sid2 = connected(w, node)
    discover(w, sid2)
    pv2 = preview(w, sid2, endpoint_id=eid)
    assert pv2["rotates"] and any("token remove" in c for c in pv2["commands"])
    p2, j2 = w.run("provider.ssh_onboard", {"ssh_session_id": sid2, "preview_id": pv2["preview_id"], "bind_hash": pv2["bind_hash"], "endpoint_id": eid})
    assert j2["status"] == "succeeded", j2.get("error")
    second = {k: v["secret"] for k, v in owner.sim.tokens.items() if k.startswith("officeunbound@pve!")}
    assert set(first) == set(second) and all(first[k] != second[k] for k in first)           # rotated, same ids
    assert not any(e[0] == "useradd" for e in node.executed())                                  # account reused
    assert len(pve_state(owner)["users"]) == 1
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM endpoints WHERE name = 'onb'")).scalar() == 1
        assert c.execute(text("SELECT count(*) FROM ssh_identities WHERE removed_at IS NULL")).scalar() == 1
    # ---- offboard (needs the admin's credentials again: the ICS identity cannot remove itself)
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh_offboard", "params": {"ssh_session_id": (abandoned := connected(w, node)), "endpoint_id": eid, "confirm_name": "nope"}}, headers=w.oh)
    assert r.status_code == 422
    sid3 = connected(w, node)
    p3, j3 = w.run("provider.ssh_offboard", {"ssh_session_id": sid3, "endpoint_id": eid, "confirm_name": "onb", "delete_pool": True})
    assert p3["risk"] == "high" and j3["status"] == "succeeded", j3
    st = pve_state(owner)
    assert not st["users"] and not st["tokens"] and not st["roles"] and not st["acl"] and "officeunbound" not in owner.sim.pools
    assert not node.has_account(node.user) and not node.file("/usr/local/sbin/ou-pve-helper").exists() and not node.file("/etc/sudoers.d/ou-ics").exists()
    assert not node.file(f"/var/lib/{node.user}").exists()
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT enabled FROM endpoints WHERE id = :i"), {"i": eid}).scalar() is False
        assert c.execute(text("SELECT removed_at IS NOT NULL FROM ssh_identities WHERE endpoint_id = :i"), {"i": eid}).scalar()
        # nothing usable is left: no ICS SSH key (also not the one replaced by the re-run) and no admin credential except the never-used session's
        assert c.execute(text("SELECT count(*) FROM credentials WHERE provider = 'pve-ssh' AND purged_at IS NULL AND id <> :a"), {"a": abandoned}).scalar() == 0


def test_offboard_keeps_a_pool_that_still_has_guests(w, node, owner):
    sid, pv, p, j = flow(w, node)
    eid = j["result"]["endpoint_id"]
    owner.sim.add_vm(5000, "pve06", "guest", pool="officeunbound")
    sid3 = connected(w, node)
    p3, j3 = w.run("provider.ssh_offboard", {"ssh_session_id": sid3, "endpoint_id": eid, "confirm_name": "onb", "delete_pool": True})
    assert j3["status"] == "succeeded" and any("not empty" in x for x in j3["result"]["not_removed"])
    assert "officeunbound" in owner.sim.pools and not pve_state(owner)["users"]


def test_helper_script_ignores_the_test_root_override_when_euid_is_zero():
    src = A.helper_source().decode()
    assert 'ROOT = os.environ.get("OU_HELPER_ROOT", "") if TEST else ""' in src and "TEST = os.geteuid() != 0" in src
    assert "shell=True" not in src and "os.system" not in src and "eval(" not in src
    assert A.sudoers_for("ou-ics").decode().count("NOPASSWD") == 1


def test_authorized_keys_line_carries_from_when_the_ics_address_is_known():
    _, pub, fp = A.generate_keypair()
    line = A.authorized_line(pub, "192.168.22.167")
    assert line.startswith('from="192.168.22.167",restrict,command="sudo -n /usr/local/sbin/ou-pve-helper" ssh-ed25519 ')
    assert fp.startswith("SHA256:") and len(fp) == 50


# ======================================================================================= discovery extras: thin-pool usage and firewall state (display only)
def test_storageinfo_parsing_owner_shaped_thin_pool_and_zfs():
    from ics.sshonboard import storageinfo as SI
    cfg = [{"storage": "PVE06-Storage", "type": "lvmthin", "vgname": "pve06vg", "thinpool": "PVE06data"}, {"storage": "zp", "type": "zfspool", "pool": "rpool/data"}]
    tp = SI.thin_pools(LVS_ROWS, cfg)
    assert len(tp) == 1 and tp[0]["storages"] == ["PVE06-Storage"] and tp[0]["thin_volumes"] == 2
    assert tp[0]["overprovision_ratio"] == 1.39 and tp[0]["data_percent"] == 62.5 and tp[0]["metadata_percent"] == 4.1
    assert tp[0]["provisioned_bytes"] > tp[0]["physical_bytes"] and any("over-provisioned 1.39x" in w for w in tp[0]["warnings"])
    z = SI.zfs_pools(ZFS_TEXT, cfg)
    assert z[0]["storage"] == "zp" and z[0]["physical_bytes"] == 1000000000000 and z[0]["provisioned_bytes"] == 2000000000000 and z[0]["overprovision_ratio"] == 2.0
    with pytest.raises(Exception):
        SI.parse_lvs("not json")
    assert SI.thin_pools([], cfg) == []


def test_discovery_shows_thin_pool_usage_and_firewall_state_without_touching_anything(w, node, owner):
    owner.sim.storages["PVE06-Storage"].update(vgname="pve06vg", thinpool="PVE06data")
    node.set_lvs(LVS_ROWS)
    owner.sim.fw_nodes = {"pve01": {"options": {"enable": 1}, "rules": [{"pos": 0, "type": "in", "action": "ACCEPT", "enable": 1, "dport": "22"}, {"pos": 1, "type": "in", "action": "DROP"}]},
                          "pve2": {"options": {"enable": 0}, "rules": [{"pos": 0, "type": "in", "action": "ACCEPT", "enable": 1}]}, "pve05": {"options": {}, "rules": []}}
    sid = connected(w, node)
    p, j = discover(w, sid)
    assert j["status"] == "succeeded", j.get("error")
    ov = j["result"]["overview"]
    tp = ov["storage_usage"]["thin_pools"]
    assert tp and tp[0]["pool"] == "PVE06data" and float(tp[0]["overprovision_ratio"]) == 1.39 and tp[0]["storages"] == ["PVE06-Storage"] and ov["storage_usage"]["zfs"] == []
    fw = ov["firewall"]
    by = {n["name"]: n for n in fw["nodes"]}
    assert fw["datacenter_enabled"] is False and len(fw["nodes"]) == len(ov["nodes"])
    assert by["pve01"]["rules"] == 2 and by["pve01"]["rules_enabled"] == 1 and by["pve2"]["rules"] == 1 and by["pve05"]["rules"] == 0
    assert fw["nodes_with_rules"] == ["pve01", "pve2"] and fw["rules_would_become_active_on"] == ["pve01"]      # pve2's node firewall option is off
    assert "OFF" in fw["note"] and not owner.sim.write_calls
    ex = node.executed()
    assert {e[0] for e in ex} <= {"sudo", "pvesh", "cat", "lvs", "zfs"}
    assert any(e[:2] == ["lvs", "--reportformat"] for e in ex) and any("firewall" in " ".join(e) for e in ex if e[0] == "pvesh")
    assert all(e[0] != "ssh" for e in ex)                # only the connected node is ever logged in to; the other nodes are read through the cluster API paths


def test_missing_lvm_and_zfs_degrade_to_empty_not_failure(w, node, owner):
    sid = connected(w, node)            # no lvs.json / zfs.txt on this fake node: the tools exit 127
    p, j = discover(w, sid)
    assert j["status"] == "succeeded", j.get("error")
    assert j["result"]["overview"]["storage_usage"]["thin_pools"] == []


def test_helper_reads_thin_pool_and_firewall_for_later_drift_checks(w, node, owner, rt):
    node.set_lvs(LVS_ROWS)
    node.set_zfs(ZFS_TEXT)
    owner.sim.fw_nodes = {"pve01": {"options": {"enable": 1}, "rules": [{"type": "in", "action": "ACCEPT", "enable": 1}]}}
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    s = ics_session(rt, node, owner)
    for cmd in ("discover fw-cluster", "discover fw-options pve01", "discover fw-rules pve01", "discover storage-lvm", "discover storage-zfs"):
        r = s.run_raw(cmd)
        assert r.rc == 0, (cmd, r.err)
    assert json.loads(s.run_raw("discover fw-rules pve01").out)[0]["action"] == "ACCEPT"
    assert json.loads(s.run_raw("discover storage-lvm").out)["report"][0]["lv"][0]["lv_name"] == "PVE06data"
    for bad in ("discover fw-options", "discover fw-rules ../x", "discover fw-rules pve01 extra", "discover storage-lvm x", "discover storage-lvm; id", "discover fw-options pve01;id"):
        assert s.run_raw(bad).rc != 0, bad
    s.close()
    p, j2 = w.run("provider.ssh.helper", {"endpoint_id": j["result"]["endpoint_id"], "op": "discover", "kind": "fw-rules", "pve_node": "pve01"})
    assert j2["status"] == "succeeded" and j2["result"]["result"][0]["type"] == "in"
    r = w.o.post(f"{H}/plans", json={"action": "provider.ssh.helper", "params": {"endpoint_id": j["result"]["endpoint_id"], "op": "discover", "kind": "fw-rules"}}, headers=w.oh)
    assert r.status_code == 422


# ======================================================================================= sudo is not shipped by Proxmox VE: an explicit, approved plan step
def test_missing_sudo_is_installed_from_the_nodes_repositories_and_shown_in_the_plan(w, node, owner):
    assert not node.has_sudo_package()
    sid, pv, p, j = flow(w, node)
    cmds = p["onboard"]["commands"]
    assert any("sudo.install" in c or "apt-get install -y --no-install-recommends sudo" in c for c in cmds)     # approvers see it
    assert any("apt-get update" in c for c in cmds)
    assert j["status"] == "succeeded", j.get("error")
    assert j["result"]["sudo_installed"] is True and node.has_sudo_package()
    ex = [e for e in node.executed() if e[0] == "apt-get"]
    assert [e[1] for e in ex] == ["install"]                          # no update needed when the first install works


def test_present_sudo_is_not_touched(w, node, owner):
    sudo = node.root / "usr/bin/sudo"
    sudo.parent.mkdir(parents=True, exist_ok=True)
    sudo.write_text("#!/bin/sh\n")
    sudo.chmod(0o755)
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    assert j["result"]["sudo_installed"] is False and not [e for e in node.executed() if e[0] == "apt-get"]


def test_stale_package_lists_are_refreshed_once_and_the_install_retried(w, node, owner):
    (node.root / "state" / "apt-fail-once").write_text("1")
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "succeeded", j.get("error")
    assert [e[1] for e in node.executed() if e[0] == "apt-get"] == ["install", "update", "install"] and node.has_sudo_package()


def test_apt_failure_stops_with_a_clear_message_and_rolls_everything_back(w, node, owner, owner_engine):
    (node.root / "state" / "apt-fail").write_text("1")
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "failed" and "sudo is not installed on the node" in j["error"]["message"] and "apt install sudo" in j["error"]["message"]
    st = pve_state(owner)
    assert not st["users"] and not st["tokens"] and not st["roles"] and not st["acl"]
    assert not node.has_account(node.user) and not node.has_sudo_package()
    assert not node.file("/usr/local/sbin/ou-pve-helper").exists() and not node.file("/etc/sudoers.d/ou-ics").exists()
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT purged_at IS NOT NULL FROM credentials WHERE id = :i"), {"i": sid}).scalar()


def test_rollback_after_a_later_failure_removes_the_sudo_this_run_installed(w, node, owner, monkeypatch):
    orig = A.verify_files

    def boom(adm, i):
        raise A.ProxmoxError("simulated verify failure")
    monkeypatch.setattr(A, "verify_files", boom)
    sid, pv, p, j = flow(w, node)
    assert j["status"] == "failed"
    assert not node.has_sudo_package() and not node.has_account(node.user)       # the sudo installed by THIS run is removed again
    assert not pve_state(owner)["users"]


# ======================================================================================= approval level (owner decision 2026-11-16)
def test_onboarding_is_normal_risk_with_one_approver_who_is_not_the_requester(w, node, owner):
    sid = connected(w, node)
    discover(w, sid)
    pv = preview(w, sid)
    pl = w.plan("provider.ssh_onboard", {"ssh_session_id": sid, "preview_id": pv["preview_id"], "bind_hash": pv["bind_hash"], "name": "onb"})
    assert pl["risk"] == "normal" and pl["approvals_required"] == 1 and pl["status"] == "pending_approval"
    r = w.o.post(f"{H}/plans/{pl['plan_id']}/approve", headers=w.oh)          # the requester can never approve their own plan
    assert r.status_code in (403, 409), r.text
    assert w.a1.post(f"{H}/plans/{pl['plan_id']}/approve", headers=w.a1h).status_code == 200      # one other approver is enough


def test_widening_an_existing_integration_is_high_risk_and_needs_two(w, node, owner):
    narrow = json.loads(json.dumps(POL))
    narrow["scope"]["template_vmids"] = [9612]
    sid, pv, p, j = flow(w, node, policy=narrow)
    assert j["status"] == "succeeded", j.get("error")
    eid = j["result"]["endpoint_id"]
    sid2 = connected(w, node)
    discover(w, sid2)
    same = preview(w, sid2, narrow, endpoint_id=eid)
    assert same["risk"] == "normal" and same["widening"] is False            # a re-run that grants nothing new stays normal
    sid3 = connected(w, node)
    discover(w, sid3)
    wide = preview(w, sid3, POL, endpoint_id=eid)                               # adds template 131
    assert wide["risk"] == "high" and wide["widening"] is True and wide["approvals_required"] == 2
    pl = w.plan("provider.ssh_onboard", {"ssh_session_id": sid3, "preview_id": wide["preview_id"], "bind_hash": wide["bind_hash"], "endpoint_id": eid})
    assert pl["risk"] == "high" and pl["approvals_required"] == 2


def test_is_widening_rules():
    from ics.provisioning.model import Policy
    from ics.sshonboard.actions import is_widening
    base = Policy.model_validate(POL)
    assert is_widening(None, base) is False and is_widening(base, base) is False
    more = json.loads(json.dumps(POL))
    more["scope"]["networks"] = ["vmbr0", "vmbr1"]
    assert is_widening(base, Policy.model_validate(more)) is True
    less = json.loads(json.dumps(POL))
    less["scope"]["template_vmids"] = [131]
    assert is_widening(base, Policy.model_validate(less)) is False
    whole = Policy.model_validate({**POL, "scope_mode": "whole_cluster", "scope": {**POL["scope"], "nodes": []}})
    assert is_widening(base, whole) is True and is_widening(whole, base) is False
