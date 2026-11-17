"""Conflict choices and leftover cleanup in the Proxmox connection wizard's dry run (ADR-0016 amendment). Proxmox is the simulator
(tests/pve_sim.py). Every choice is a typed parameter of provider.provision.plan_preview, appears as plan steps BEFORE apply, is bound into
the plan hash and is re-checked against the cluster at apply. Nothing that is not provably Office Unbound's is offered for removal/overwrite."""
import pytest
from pydantic import ValidationError

from ics.providers import base
from ics.providers.proxmox import provisioning as pp
from ics.provisioning.model import ConflictChoices, Policy
from .test_provisioning import POLICY, admin, owner, w  # noqa: F401  (fixtures)

MARK = pp.MARK
DEPLOY = sorted(pp.role_privileges("deploy", Policy.model_validate(POLICY), 9))
NONE: dict = {"users": [], "tokens": [], "roles": [], "pools": []}


def facts(srv):
    with admin(srv) as a:
        return pp.collect_facts(a)


def plan(srv, choices=None, owned=NONE, policy=None, **kw):
    pol = Policy.model_validate(policy or POLICY)
    ch = ConflictChoices.model_validate(choices) if choices is not None else None
    return pol, pp.plan_for(pol, facts(srv), choices=ch, owned=owned, **kw)


def apply(srv, pol, pl):
    assert not pl.blocked, pl.blocked
    with base.job_execution("t"), admin(srv) as a:
        return pp.apply_plan(a, pl, pp.design_from_plan(pl, pol))


def opt(pl, kind, target):
    e = next(x for x in pl.facts["conflict_options"] if x["kind"] == kind and x["target"] == target)
    return e, {o["action"]: o for o in e["options"]}


def steps(pl, op=None):
    return {(s.kind, s.op, s.target) for s in pl.steps if op is None or s.op == op}


def sim_token(sim, uid, t, comment):
    sim.users[uid]["tokens"][t] = {"privsep": 1, "comment": comment, "expire": 0, "secret": f"{t}-secret-0123456789"}
    sim.tokens[f"{uid}!{t}"] = {"secret": f"{t}-secret-0123456789", "acl": [], "user": uid, "privsep": 1}


def acl(sim, path, ugid, role):
    sim.acl_entries.append({"path": path, "type": "token" if "!" in ugid else "user", "ugid": ugid, "roleid": role, "propagate": 1})


def failed_attempt(sim):
    """What a failed earlier wizard run leaves behind: the marked service user, a marked token with an ACL, a role."""
    sim.add_user("ics-svc@pve", comment=f"{MARK} Office Unbound service account")
    sim_token(sim, "ics-svc@pve", "ics-inv", f"{MARK} inventory")
    acl(sim, "/nodes/pve01", "ics-svc@pve!ics-inv", "PVEAuditor")
    acl(sim, "/nodes/pve01", "ics-svc@pve", "PVEAuditor")


# ======================================================================================= model
def test_choices_are_typed_and_strict():
    with pytest.raises(ValidationError):
        ConflictChoices.model_validate({"items": [{"kind": "role", "target": "X", "action": "use_existing", "extra": 1}]})
    with pytest.raises(ValidationError):
        ConflictChoices.model_validate({"items": [{"kind": "role", "target": "X", "action": "delete_everything"}]})
    with pytest.raises(ValidationError):
        ConflictChoices.model_validate({"items": [{"kind": "role", "target": "X", "action": "overwrite"}, {"kind": "role", "target": "X", "action": "recreate"}]})
    with pytest.raises(ValidationError):
        ConflictChoices.model_validate({"cleanup": ["user:a; rm -rf /"]})
    with pytest.raises(ValidationError):
        ConflictChoices.model_validate({"items": [{"kind": "group", "target": "X", "action": "overwrite"}]})


# ======================================================================================= roles
def test_role_conflict_lists_every_option_and_defaults_to_a_new_role(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit", "VM.PowerMgmt"})
    _, pl = plan(owner)
    e, o = opt(pl, "role", "OfficeUnboundDeploy")
    assert e["default"] == "create_new" and e["chosen"] == "create_new" and all(o[a]["available"] for a in pp.CHOICE_ACTIONS)
    assert e["existing"]["would_add"] and not e["existing"]["would_remove"]
    assert pl.facts["roles"]["deploy"] == "OfficeUnboundDeploy-2" and not pl.blocked and pl.choices == {}


def test_role_use_existing_only_for_a_safe_subset(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit", "VM.PowerMgmt"})
    pol, pl = plan(owner, {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "use_existing"}]})
    assert pl.facts["roles"]["deploy"] == "OfficeUnboundDeploy" and ("role", "noop", "OfficeUnboundDeploy") in steps(pl)
    st = next(s for s in pl.steps if s.target == "OfficeUnboundDeploy")
    assert st.detail["choice"] == "use_existing" and "VM.Allocate" in st.detail["withheld"]
    assert any("used as is" in x and "VM.Allocate" in x for x in pl.warnings)
    d = pp.design_from_plan(pl, pol)
    assert d.roles["deploy"][1] == frozenset({"VM.Audit", "VM.PowerMgmt"}) and "VM.Allocate" in d.withheld
    apply(owner, pol, pl)
    assert owner.sim.roles["OfficeUnboundDeploy"] == {"VM.Audit", "VM.PowerMgmt"}            # untouched
    assert any(e["roleid"] == "OfficeUnboundDeploy" and e["ugid"] == "ics-svc@pve!ics-prov" for e in owner.sim.acl_entries)
    # a role that grants MORE than needed is never offered "as is"
    owner.sim.roles["OfficeUnboundDeploy"] = {"VM.Audit", "Sys.Console"}
    _, pl2 = plan(owner, {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "use_existing"}]})
    _, o = opt(pl2, "role", "OfficeUnboundDeploy")
    assert not o["use_existing"]["available"] and "Sys.Console" in o["use_existing"]["why_not"]
    assert any("'use_existing' is not possible" in b for b in pl2.blocked)


def test_role_overwrite_shows_the_exact_change_and_applies_it(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit", "VM.Console"})
    pol, pl = plan(owner, {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "overwrite"}]})
    st = next(s for s in pl.steps if s.kind == "role" and s.target == "OfficeUnboundDeploy")
    assert st.op == "modify" and st.detail["removed"] == ["VM.Console"] and "VM.Allocate" in st.detail["added"] and st.risk == "normal"
    res = apply(owner, pol, pl)
    assert owner.sim.roles["OfficeUnboundDeploy"] == set(DEPLOY) and "OfficeUnboundDeploy" in res.created["adopted_roles"]


def test_role_overwrite_with_foreign_acl_users_needs_acknowledgement_and_recreate_is_refused(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit"})
    acl(owner.sim, "/pool/other-team", "officeunbound@pam", "OfficeUnboundDeploy")          # someone else uses this role
    ch = {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "overwrite"}]}
    _, pl = plan(owner, ch)
    e, o = opt(pl, "role", "OfficeUnboundDeploy")
    assert e["existing"]["used_by_others"] == ["officeunbound@pam on /pool/other-team"]
    assert any("did not create" in b and "officeunbound@pam" in b for b in pl.blocked)
    assert not o["recreate"]["available"] and "take their rights away" in o["recreate"]["why_not"]
    ch["items"][0]["acknowledge_shared"] = True
    pol, pl2 = plan(owner, ch)
    st = next(s for s in pl2.steps if s.kind == "role" and s.target == "OfficeUnboundDeploy")
    assert not pl2.blocked and st.op == "modify" and st.risk == "high" and st.detail["affects"] and pl2.risk == "high"
    _, pl3 = plan(owner, {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "recreate"}]})
    assert any("'recreate' is not possible" in b for b in pl3.blocked)


def test_builtin_role_is_never_overwritten_or_removed(owner):  # noqa: F811
    pol = {**POLICY, "role_names": {"monitor": "PVEAuditor"}}
    for act in ("overwrite", "recreate", "use_existing"):
        _, pl = plan(owner, {"items": [{"kind": "role", "target": "PVEAuditor", "action": act}]}, policy=pol)
        assert any(f"'{act}' is not possible" in b for b in pl.blocked), act
    _, o = opt(pl, "role", "PVEAuditor")
    assert "built-in" in o["overwrite"]["why_not"] and "built-in" in o["recreate"]["why_not"] and o["create_new"]["available"]
    _, pl = plan(owner, policy=pol)
    assert pl.facts["roles"]["monitor"] == "PVEAuditor-2" and not pl.blocked
    assert owner.sim.roles["PVEAuditor"] == {"Sys.Audit", "VM.Audit", "Datastore.Audit", "Pool.Audit", "SDN.Audit", "Mapping.Audit"}


def test_role_of_a_connected_integration_or_unknown_ownership_is_not_overwritten(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit"})
    _, pl = plan(owner, owned={**NONE, "roles": ["OfficeUnboundDeploy"]})
    _, o = opt(pl, "role", "OfficeUnboundDeploy")
    assert "connected Office Unbound integration" in o["overwrite"]["why_not"] and not o["recreate"]["available"]
    _, pl = plan(owner, owned=None)
    _, o = opt(pl, "role", "OfficeUnboundDeploy")
    assert "could not be checked" in o["overwrite"]["why_not"] and "could not be checked" in o["recreate"]["why_not"]
    assert pl.facts.get("leftovers") == []


def test_role_recreate_removes_first_then_creates(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit"})
    pol, pl = plan(owner, {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "recreate"}]})
    assert {("role", "remove", "OfficeUnboundDeploy"), ("role", "create", "OfficeUnboundDeploy")} <= steps(pl)
    assert any("removed BEFORE" in c for c in pl.consequences)
    res = apply(owner, pol, pl)
    assert owner.sim.roles["OfficeUnboundDeploy"] == set(DEPLOY) and res.removed == ["role OfficeUnboundDeploy"]


# ======================================================================================= user and tokens
def test_foreign_user_blocks_by_default_and_create_new_uses_a_new_account(owner):  # noqa: F811
    owner.sim.add_user("ics-svc@pve", comment="someone else's")
    _, pl = plan(owner)
    e, o = opt(pl, "user", "ics-svc@pve")
    assert pl.blocked and e["default"] is None and not o["use_existing"]["available"] and not o["recreate"]["available"]
    pol, pl = plan(owner, {"items": [{"kind": "user", "target": "ics-svc@pve", "action": "create_new"}]})
    assert not pl.blocked and pl.facts["service_user"] == "ics-svc-2@pve" and pl.policy["service_user"] == "ics-svc-2"
    # apply recomputes with the plan's effective policy and the same choices: same hash (the user choice is then reported as not needed)
    pol2 = Policy.model_validate(pl.policy)
    again = pp.plan_for(pol2, facts(owner), choices=ConflictChoices.model_validate({"items": [{"kind": "user", "target": "ics-svc@pve", "action": "create_new"}]}),
                        owned=NONE)
    assert again.hash() == pl.hash() and any("was not needed" in x for x in again.warnings)
    apply(owner, pol2, pl)
    assert "ics-svc-2@pve" in owner.sim.users and owner.sim.users["ics-svc@pve"]["comment"] == "someone else's"


def test_failed_attempt_token_conflict_recreate_or_create_new(owner):  # noqa: F811
    failed_attempt(owner.sim)
    _, pl = plan(owner)
    e, o = opt(pl, "token", "ics-svc@pve!ics-inv")
    assert pl.blocked and not o["use_existing"]["available"] and o["recreate"]["available"] and o["create_new"]["available"]
    eu, ou = opt(pl, "user", "ics-svc@pve")
    assert eu["default"] == "use_existing" and ou["recreate"]["available"]
    pol, pl = plan(owner, {"items": [{"kind": "token", "target": "ics-svc@pve!ics-inv", "action": "recreate"}]})
    assert not pl.blocked and {("token", "remove", "ics-svc@pve!ics-inv"), ("token", "create", "ics-svc@pve!ics-inv"),
                               ("acl", "remove", "/nodes/pve01|ics-svc@pve!ics-inv|PVEAuditor")} <= steps(pl)
    old = owner.sim.tokens["ics-svc@pve!ics-inv"]["secret"]
    res = apply(owner, pol, pl)
    assert res.secrets["inventory"][1] != old and owner.sim.tokens["ics-svc@pve!ics-inv"]["secret"] == res.secrets["inventory"][1]
    assert not any(e["ugid"] == "ics-svc@pve!ics-inv" and e["path"] == "/nodes/pve01" for e in owner.sim.acl_entries)


def test_token_create_new_alongside(owner):  # noqa: F811
    failed_attempt(owner.sim)
    pol, pl = plan(owner, {"items": [{"kind": "token", "target": "ics-svc@pve!ics-inv", "action": "create_new"}]})
    assert not pl.blocked and pl.facts["tokens"]["inventory"] == "ics-inv-2"
    apply(owner, pol, pl)
    assert "ics-svc@pve!ics-inv" in owner.sim.tokens and "ics-svc@pve!ics-inv-2" in owner.sim.tokens


def test_user_recreate_removes_its_tokens_and_permissions_first(owner):  # noqa: F811
    failed_attempt(owner.sim)
    pol, pl = plan(owner, {"items": [{"kind": "user", "target": "ics-svc@pve", "action": "recreate"}]})
    assert not pl.blocked
    assert {("user", "remove", "ics-svc@pve"), ("user", "create", "ics-svc@pve"), ("token", "remove", "ics-svc@pve!ics-inv"),
            ("acl", "remove", "/nodes/pve01|ics-svc@pve|PVEAuditor")} <= steps(pl)
    apply(owner, pol, pl)
    assert not any(e["path"] == "/nodes/pve01" and e["ugid"].startswith("ics-svc@pve") for e in owner.sim.acl_entries)
    assert owner.sim.users["ics-svc@pve"]["comment"].startswith(MARK)


def test_user_of_a_connected_integration_or_with_foreign_tokens_is_never_recreated(owner):  # noqa: F811
    failed_attempt(owner.sim)
    _, pl = plan(owner, {"items": [{"kind": "user", "target": "ics-svc@pve", "action": "recreate"}]},
                 owned={**NONE, "users": ["ics-svc@pve"], "tokens": ["ics-svc@pve!ics-inv"]})
    assert any("connected Office Unbound integration" in b for b in pl.blocked)
    _, o = opt(pl, "token", "ics-svc@pve!ics-inv")
    assert not o["recreate"]["available"]
    sim_token(owner.sim, "ics-svc@pve", "personal", "made by an admin")
    _, pl = plan(owner, {"items": [{"kind": "user", "target": "ics-svc@pve", "action": "recreate"}]})
    assert any("tokens Office Unbound did not create" in b for b in pl.blocked)


# ======================================================================================= leftovers
def leftovers_world(sim):
    sim.add_user("ics-old@pve", comment=f"{MARK} Office Unbound service account")
    sim_token(sim, "ics-old@pve", "ics-inv", f"{MARK} inventory")
    sim.add_role("OfficeUnboundBackup-3", {"VM.Backup"})
    acl(sim, "/pool/ou-old", "ics-old@pve!ics-inv", "OfficeUnboundBackup-3")
    sim.add_role("OfficeUnboundOperate-2", {"VM.PowerMgmt"})
    acl(sim, "/vms/300", "officeunbound@pam", "OfficeUnboundOperate-2")                          # used by someone else: kept
    sim.pools |= {"ou-old", "ou-full", "team-pool"}
    sim.pool_comments.update({"ou-old": MARK, "ou-full": MARK})
    sim.add_vm(990, "pve06", "in-full-pool", pool="ou-full")
    sim.add_user("bob@pve", comment="a person")                                                   # no marker: never listed
    sim.add_user("ics-conn@pve", comment=f"{MARK} Office Unbound service account")                # a connected integration's
    sim_token(sim, "ics-conn@pve", "ics-inv", f"{MARK} inventory")
    sim.add_role("OfficeUnboundMonitor-7", {"VM.Audit"})
    acl(sim, "/", "ics-conn@pve!ics-inv", "OfficeUnboundMonitor-7")


CONN = {"users": ["ics-conn@pve"], "tokens": ["ics-conn@pve!ics-inv"], "roles": ["OfficeUnboundMonitor-7"], "pools": []}


def test_leftovers_are_detected_and_only_provable_ones_are_removable(owner):  # noqa: F811
    leftovers_world(owner.sim)
    _, pl = plan(owner, owned=CONN)
    lo = {x["id"]: x for x in pl.facts["leftovers"]}
    assert lo["user:ics-old@pve"]["removable"] and "token ics-old@pve!ics-inv" in lo["user:ics-old@pve"]["removes"]
    assert lo["role:OfficeUnboundBackup-3"]["removable"]
    assert not lo["role:OfficeUnboundOperate-2"]["removable"] and "officeunbound@pam" in lo["role:OfficeUnboundOperate-2"]["kept_because"]
    assert lo["pool:ou-old"]["removable"] and not lo["pool:ou-full"]["removable"] and "not empty" in lo["pool:ou-full"]["kept_because"]
    for never in ("user:bob@pve", "user:ics-conn@pve", "token:ics-conn@pve!ics-inv", "role:OfficeUnboundMonitor-7", "pool:team-pool",
                  "pool:other-team", "role:PVEAuditor", "user:root@pam", "user:officeunbound@pam"):
        assert never not in lo, never
    assert not any(s.op == "remove" for s in pl.steps)                       # detection alone removes nothing


def test_cleanup_removes_exactly_the_chosen_leftovers(owner):  # noqa: F811
    leftovers_world(owner.sim)
    ch = {"cleanup": ["user:ics-old@pve", "role:OfficeUnboundBackup-3", "pool:ou-old"]}
    pol, pl = plan(owner, ch, owned=CONN)
    assert not pl.blocked and pl.choices["cleanup"] == sorted(ch["cleanup"])
    assert {("user", "remove", "ics-old@pve"), ("token", "remove", "ics-old@pve!ics-inv"), ("role", "remove", "OfficeUnboundBackup-3"),
            ("pool", "remove", "ou-old"), ("acl", "remove", "/pool/ou-old|ics-old@pve!ics-inv|OfficeUnboundBackup-3")} <= steps(pl)
    res = apply(owner, pol, pl)
    s = owner.sim
    assert "ics-old@pve" not in s.users and "OfficeUnboundBackup-3" not in s.roles and "ou-old" not in s.pools
    assert {"bob@pve", "ics-conn@pve", "officeunbound@pam"} <= set(s.users) and {"OfficeUnboundOperate-2", "OfficeUnboundMonitor-7", "PVEAuditor"} <= set(s.roles)
    assert {"ou-full", "team-pool", "other-team"} <= s.pools and s.vms[990]["pool"] == "ou-full"
    assert "ics-conn@pve!ics-inv" in s.tokens and len(res.removed) >= 4


def test_cleanup_refuses_non_removable_or_unknown_ids(owner):  # noqa: F811
    leftovers_world(owner.sim)
    for bad in ("pool:ou-full", "role:OfficeUnboundOperate-2", "user:bob@pve", "user:ics-conn@pve", "role:PVEAuditor", "pool:team-pool"):
        _, pl = plan(owner, {"cleanup": [bad]}, owned=CONN)
        assert any(b.startswith(f"cleanup {bad}") for b in pl.blocked), bad
        assert not any(s.op == "remove" for s in pl.steps)


def test_stale_permissions_of_a_reused_leftover_account_are_offered(owner):  # noqa: F811
    failed_attempt(owner.sim)
    _, pl = plan(owner, {"items": [{"kind": "token", "target": "ics-svc@pve!ics-inv", "action": "create_new"}]})
    lo = {x["id"]: x for x in pl.facts["leftovers"]}
    assert "acl:/nodes/pve01|ics-svc@pve|PVEAuditor" in lo and "token:ics-svc@pve!ics-inv" in lo
    pol, pl = plan(owner, {"items": [{"kind": "token", "target": "ics-svc@pve!ics-inv", "action": "create_new"}],
                           "cleanup": ["acl:/nodes/pve01|ics-svc@pve|PVEAuditor", "token:ics-svc@pve!ics-inv"]})
    apply(owner, pol, pl)
    assert "ics-svc@pve!ics-inv" not in owner.sim.tokens and not any(e["path"] == "/nodes/pve01" and e["ugid"] == "ics-svc@pve" for e in owner.sim.acl_entries)


# ======================================================================================= hash binding
def test_plan_hash_changes_with_the_choices(owner):  # noqa: F811
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit"})
    leftovers_world(owner.sim)
    h = {}
    for label, ch in (("none", None), ("new", {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "create_new"}]}),
                      ("over", {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "overwrite"}]}),
                      ("rec", {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "recreate"}]}),
                      ("clean", {"cleanup": ["pool:ou-old"]})):
        h[label] = plan(owner, ch, owned=CONN)[1].hash()
        assert h[label] == plan(owner, ch, owned=CONN)[1].hash()           # deterministic for the same choices and cluster
    assert len(set(h.values())) == len(h)
    # no choices: the hash is computed exactly as before this feature (no 'choices' key in the hashed body)
    _, pl = plan(owner, owned=CONN)
    assert pl.choices == {} and pl.hash() == pp.plan_for(Policy.model_validate(POLICY), facts(owner)).hash()


# ======================================================================================= through the typed actions (preview -> approval -> apply)
def conn(owner):  # noqa: F811
    return {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW}


def test_preview_and_apply_with_choices_end_to_end(w, owner):  # noqa: F811
    leftovers_world(owner.sim)
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit", "VM.Console"})
    owner.sim.add_role("OfficeUnboundMonitor", {"Sys.Audit", "VM.Audit", "Datastore.Audit"})       # a subset: used as is
    ch = {"items": [{"kind": "role", "target": "OfficeUnboundDeploy", "action": "overwrite"},
                    {"kind": "role", "target": "OfficeUnboundMonitor", "action": "use_existing"}],
          "cleanup": ["pool:ou-old", "user:ics-old@pve", "role:OfficeUnboundBackup-3"]}
    p, j = w.run("provider.provision.plan_preview", {**conn(owner), "policy": POLICY, "choices": ch})
    assert j["status"] == "succeeded", j
    pv = j["result"]
    pd = pv["plan"]
    assert not pd["blocked"] and pd["choices"]["cleanup"] == sorted(ch["cleanup"])
    assert "OfficeUnboundDeploy" in [s["target"] for s in pd["steps"] if s["op"] == "modify"]
    assert {o["target"] for o in pd["facts"]["conflict_options"]} == {"OfficeUnboundDeploy", "OfficeUnboundMonitor"}
    assert "ou-old" in owner.sim.pools and owner.sim.roles["OfficeUnboundDeploy"] == {"VM.Audit", "VM.Console"}   # the dry run changed nothing
    p2, j2 = w.run("provider.provision.apply", {**conn(owner), "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert p2["risk"] == "high" and any("remove pool ou-old" in s for s in p2["plan_summary"]["steps"])
    assert j2["status"] == "succeeded", j2
    assert j2["result"]["verification"]["ok"] is True
    s = owner.sim
    assert s.roles["OfficeUnboundDeploy"] == set(DEPLOY) and s.roles["OfficeUnboundMonitor"] == {"Sys.Audit", "VM.Audit", "Datastore.Audit"}
    assert "ou-old" not in s.pools and "ics-old@pve" not in s.users and "OfficeUnboundBackup-3" not in s.roles
    assert "ics-conn@pve" in s.users and "OfficeUnboundOperate-2" in s.roles and "ou-full" in s.pools


def test_connected_integration_objects_are_never_offered_as_leftovers(w, owner):  # noqa: F811
    p, j = w.run("provider.provision.plan_preview", {**conn(owner), "policy": POLICY})
    pv = j["result"]
    _, j2 = w.run("provider.provision.apply", {**conn(owner), "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert j2["status"] == "succeeded", j2
    pol2 = {**POLICY, "service_user": "ics-two"}
    _, j3 = w.run("provider.provision.plan_preview", {**conn(owner), "name": "owner-two", "policy": pol2, "choices": {"cleanup": ["user:ics-svc@pve"]}})
    assert j3["status"] == "succeeded", j3
    pd = j3["result"]["plan"]
    ids = {x["id"] for x in pd["facts"]["leftovers"]}
    assert not any("ics-svc@pve" in i or i.startswith("role:OfficeUnbound") for i in ids), ids
    assert any(b.startswith("cleanup user:ics-svc@pve") for b in pd["blocked"])


def test_apply_refuses_when_the_cluster_changed_under_the_choices(w, owner):  # noqa: F811
    leftovers_world(owner.sim)
    _, j = w.run("provider.provision.plan_preview", {**conn(owner), "policy": POLICY, "choices": {"cleanup": ["pool:ou-old"]}})
    pv = j["result"]
    owner.sim.add_vm(991, "pve06", "moved-in", pool="ou-old")                 # the pool is no longer empty
    _, j2 = w.run("provider.provision.apply", {**conn(owner), "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert j2["status"] == "failed" and "changed since the plan was previewed" in j2["error"]["message"]
    assert "ou-old" in owner.sim.pools and owner.sim.vms[991]["pool"] == "ou-old"


def test_choices_only_on_a_provisioning_preview_with_credentials(w, owner):  # noqa: F811
    c = conn(owner)
    w.plan("provider.provision.plan_preview", {"name": "x", "pve_major": 9, "policy": POLICY, "choices": {"cleanup": []}}, expect=422)
    w.plan("provider.provision.plan_preview", {**c, "policy": POLICY, "choices": {"items": [], "bogus": 1}}, expect=422)
