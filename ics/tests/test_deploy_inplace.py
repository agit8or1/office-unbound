"""In-place upgrades (owner 2026-11-23: "only the apps are updated so we dont need to redeploy the entire images and wipe configs"):
deployment.change steps that upgrade the node agent, grow its allowlists, add a component to an existing VM and reconfigure what depends on
the deployment's component set; the executor's agent.update handler; the agent's cfg.agent_allow / cfg.keycloak_realm contracts."""
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from ics.deploy import executor
from ics.deploy.plan import generate_plan
from ics.deploy.ports import ExecEnv, StepFailed
from ics.deploy.state import diff_plans
from tests.test_deploy_plan import cap, inp, pinned

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from ou_agent import cfgspec, runbooks as agent_runbooks  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

OB8 = [{"name": "gateway", "components": ["identity", "edge", "portal"]}, {"name": "files", "components": ["files", "office"]},
       {"name": "mail", "components": ["groupware"]}]


def _layout(**extra):
    return [{**v, "components": v["components"] + extra.get(v["name"], [])} for v in OB8]


def _plan(c, layout):
    p = generate_plan(inp(profile="custom", users=20, custom_layout=layout), cap(), c)
    assert p["errors"] == [], p["errors"]
    return p


def _keys(diff):
    return {s["key"]: s for s in diff["steps"]}


def _set_agent(c, version):
    c.components["monitoring-agent"].artifacts[0].version = version


def test_adding_chat_to_the_existing_files_vm_installs_it_in_place_and_reconfigures_what_depends_on_it():
    c = pinned()
    old, new = _plan(c, _layout()), _plan(c, _layout(files=["chat"]))
    d = diff_plans(old, new, c)
    k = _keys(d)
    vm = lambda n: f"acme-prod-{n}"   # noqa: E731
    assert not [a for a in d["added"] if a["kind"] == "vm"] and not [s for s in k if s.startswith(("vm.clone", "vm.destroy", "agent.enroll"))]
    # the files VM's agent may install what it never had (postgresql-16, the chat images): its allowlists grow first
    up = k[f"agent.update:{vm('files')}"]
    assert up["params"]["allow"] is True and "version" not in up["params"]
    inst = k[f"comp.install:{vm('files')}:chat"]
    assert f"agent.update:{vm('files')}" in inst["depends_on"] and not any(x.startswith("agent.enroll:") for x in inst["depends_on"])
    assert f"checks.register:{vm('files')}:chat" in k and f"health.verify:{vm('files')}:chat" in k
    # the files VM holds data: snapshotted before anything runs there
    assert f"vm.snapshot:{vm('files')}" in up["depends_on"]
    # sign-in clients, edge sites/certificate names and portal apps follow the new component; configuration only, so not disruptive,
    # and only once chat is healthy
    for comp in ("identity", "edge", "portal"):
        s = k[f"comp.upgrade:{vm('gateway')}:{comp}"]
        assert s["disruptive"] is False and s["downtime_seconds"] == 0
        assert f"health.verify:{vm('files')}:chat" in s["depends_on"]
    # files/office keep running untouched (no artifact or configuration change of their own) ...
    assert f"comp.upgrade:{vm('files')}:files" not in k and f"comp.upgrade:{vm('files')}:office" not in k
    # ... the mail VM only refreshes name resolution and VM-to-VM firewall
    assert k[f"comp.upgrade:{vm('mail')}:@node"]["params"]["component"] == "@node"
    assert f"comp.upgrade:{vm('mail')}:groupware" not in k
    assert not d["requires_maintenance"]


def test_a_new_agent_pin_upgrades_every_agent_in_place_before_anything_else_on_its_vm():
    c = pinned()
    _set_agent(c, "0.10.0-ou19")
    old = _plan(c, _layout())
    _set_agent(c, "0.10.1-ou20")
    new = _plan(c, _layout(files=["chat"]))
    k = _keys(diff_plans(old, new, c))
    for n in ("gateway", "files", "mail"):
        s = k[f"agent.update:acme-prod-{n}"]
        assert s["kind"] == "agent_update" and s["params"]["version"] == "0.10.1-ou20" and s["params"]["package"] == "ou-node-agent"
        assert not any(x.startswith(f"comp.upgrade:acme-prod-{n}:monitoring") for x in k)   # never an empty comp.upgrade for the agent
    for key, s in k.items():
        if s["kind"] == "agent_runbook":
            assert f"agent.update:{s['target']}" in s["depends_on"], key   # the new agent's runbooks/capabilities are used, never the old ones


def test_a_configuration_revision_reconfigures_only_that_component():
    c = pinned()
    old = _plan(c, _layout())
    c.components["groupware"].config_revision += 1
    new = _plan(c, _layout())
    d = diff_plans(old, new, c)
    k = _keys(d)
    assert set(k) == {"vm.snapshot:acme-prod-mail", "comp.upgrade:acme-prod-mail:groupware", "health.verify:acme-prod-mail:groupware:upgrade"}
    assert k["comp.upgrade:acme-prod-mail:groupware"]["disruptive"] is False and not d["empty"]


def test_a_skin_or_palette_change_reconfigures_exactly_the_apps_that_carry_the_brand(monkeypatch):
    """0.13.0 changed the palette and the webmail skin but no config_revision, so a running deployment would never have got them: the
    brand digest on identity, files, groupware and chat does it. Office, edge and portal carry nothing from the brand sources."""
    from ics.deploy import brand
    c = pinned()
    old = _plan(c, _layout())
    assert all(x.get("brand") for x in old["containers"] + old["services"] if x["component"] in brand.BRAND_COMPONENTS)
    assert not any("brand" in x for x in old["containers"] + old["services"] if x["component"] not in brand.BRAND_COMPONENTS)
    monkeypatch.setattr(brand, "digest", lambda: "0" * 16)
    k = _keys(diff_plans(old, _plan(c, _layout()), c))
    ups = {x for x in k if x.startswith("comp.upgrade:")}
    assert ups == {"comp.upgrade:acme-prod-gateway:identity", "comp.upgrade:acme-prod-files:files", "comp.upgrade:acme-prod-mail:groupware"}
    assert all(not k[x]["disruptive"] for x in ups)


def test_an_unchanged_plan_has_no_steps_and_old_plans_without_revisions_compare_equal():
    c = pinned()
    old = _plan(c, _layout())
    legacy = json.loads(json.dumps(old))
    for x in legacy["containers"] + legacy["services"]:
        x.pop("config_revision", None)   # applied before 0.11.0
    for x in legacy["containers"] + legacy["services"]:
        x.pop("brand", None)             # and before 0.13.1: the first change after the upgrade rolls the current brand out once
    k = _keys(diff_plans(legacy, _plan(c, _layout()), c))
    assert {x for x in k if x.startswith("comp.upgrade:")} == {"comp.upgrade:acme-prod-gateway:identity", "comp.upgrade:acme-prod-files:files",
                                                             "comp.upgrade:acme-prod-mail:groupware", "comp.upgrade:acme-prod-gateway:portal"}
    current = _plan(c, _layout())
    assert diff_plans(current, _plan(c, _layout()), c)["steps"] == []


# ---- executor: agent.update ---------------------------------------------------------------------------------------------------------

class _Db:
    def __init__(self, log, on_update=None):
        self.log, self.on_update = log, on_update

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def begin(self):
        return self

    def execute(self, stmt, params=None):
        self.log.append((str(stmt), params))
        if self.on_update and str(stmt).startswith("UPDATE nodes SET capabilities"):
            self.on_update(json.loads(params["c"]))

        class R:
            def scalar(self):
                return None
        return R()


class _Rt:
    def __init__(self, on_update=None):
        self.sql, self.on_update = [], on_update

    def session(self):
        return _Db(self.sql, self.on_update)


@dataclass
class _Ctx(executor.StepCtx):
    logs: list = field(default_factory=list)
    resources: list = field(default_factory=list)

    def log(self, msg, progress=None):
        self.logs.append(msg)

    def resource(self, kind, name, **kw):
        self.resources.append((kind, name, kw))


class _Agent:
    """A node agent that restarts as the new version ~2 polls after pkg.install_pinned and restarts after cfg.agent_allow."""
    def __init__(self, version="0.9.4", caps=None):
        self.version, self.caps, self.started, self.calls, self.pending = version, caps, 100, [], None
        # what the ICS recorded at enrollment (nodes.capabilities); like agentcall.execute, a runbook outside it is never sent
        self.recorded = set(caps or ()) | {"guest.facts", "pkg.install_pinned"}

    def run_runbook(self, node, rb, params):
        if rb not in self.recorded:
            raise ValueError("node does not offer this runbook")
        self.calls.append((rb, params))
        if rb == "guest.facts":
            if self.pending:
                self.pending[0] -= 1
                if self.pending[0] < 0:
                    raise StepFailed("guest.facts: connection refused", "", retryable=True)   # restarting
                if self.pending[0] == 0:
                    self.pending[1](); self.pending = None
            f = {"agent_version": self.version, "started": self.started}
            return {**f, "capabilities": self.caps} if self.caps is not None else f
        if rb == "pkg.install_pinned":
            # like the real agent: guest.facts' helper process imports the agent from disk, so it reports the new version at once while the
            # OLD server (same `started`, no capabilities if it predates 0.10.1) still answers until the deferred restart
            self.version = "0.10.1"

            def done():
                self.version, self.started = "0.10.1", self.started + 50
                self.caps = {"guest.facts": {"enabled": True}, "cfg.agent_allow": {"enabled": True}, "cfg.keycloak_realm": {"enabled": True}}
            self.pending = [2, done]
            return {"installed": params["packages"]}
        if rb == "cfg.agent_allow":
            def restarted():
                self.started += 10
            self.pending = [2, restarted]
            return {"packages": ["postgresql-16"], "image_repos": ["ou/synapse"], "restart_scheduled": True}
        raise AssertionError(rb)

    def registry_prefix(self):
        return "registry.ou.invalid"


def _ctx(agent, params, plan=None):
    t = [0.0]
    env = ExecEnv(agent=agent, sleep=lambda s: t.__setitem__(0, t[0] + s), clock=lambda: t[0], poll_interval=5)
    return _Ctx(rt=_Rt(lambda caps: setattr(agent, "recorded", set(caps))), env=env, job_id="j", deployment_id="d", slug="s", created_by="u", row_id=1, plan=plan or {"services": [], "containers": []},
                step={"target": "vm1", "params": params}, outputs={"agent.enroll:vm1": {"node_id": "n1"}})


def test_agent_update_upgrades_waits_for_the_new_agent_and_records_its_capabilities():
    a = _Agent()
    plan = {"services": [{"vm": "vm1", "name": "vm1-ou-agent", "package": "ou-node-agent", "version": "0.10.1-ou20"}], "containers": []}
    ctx = _ctx(a, {"package": "ou-node-agent", "version": "0.10.1-ou20", "timeout_seconds": 300}, plan)
    out = executor.h_agent_update(ctx)
    assert out["agent_version"] == "0.10.1" and "cfg.agent_allow" in out["runbooks"]
    assert [c[0] for c in a.calls].count("pkg.install_pinned") == 1
    upd = [p for s, p in ctx.rt.sql if s.startswith("UPDATE nodes SET capabilities")]
    assert upd and json.loads(upd[0]["c"])["cfg.keycloak_realm"] == {"enabled": True} and upd[0]["v"] == "0.10.1" and upd[0]["i"] == "n1"
    assert ctx.resources[0][2]["actual"]["version"] == "0.10.1-ou20"


def test_agent_update_waits_for_the_restarted_server_not_the_new_files_on_disk():
    # officeunbound8, 2026-11-23: the 0.9.4 agent's guest.facts said 0.10.1 right after apt, before the restart; the step went on with the
    # old server's (absent) capabilities and refused cfg.agent_allow
    a = _Agent()
    plan = {"services": [{"vm": "vm1", "package": "postgresql-16"}], "containers": []}
    out = executor.h_agent_update(_ctx(a, {"package": "ou-node-agent", "version": "0.10.1-ou20", "allow": True, "timeout_seconds": 300}, plan))
    assert a.started == 160 and "cfg.agent_allow" in out["runbooks"] and out["allowed"]["packages"] == ["postgresql-16"]


def test_agent_update_is_idempotent_when_the_agent_already_runs_the_pin():
    a = _Agent(version="0.10.1", caps={"guest.facts": {"enabled": True}})
    executor.h_agent_update(_ctx(a, {"package": "ou-node-agent", "version": "0.10.1-ou20"}))
    assert [c[0] for c in a.calls] == ["guest.facts"]


def test_agent_update_grows_the_allowlists_from_the_plan_and_waits_for_the_restart():
    a = _Agent(version="0.10.1", caps={"guest.facts": {"enabled": True}, "cfg.agent_allow": {"enabled": True}})
    plan = {"services": [{"vm": "vm1", "package": "postgresql-16"}, {"vm": "vm1", "package": "nginx"}, {"vm": "other", "package": "slapd"}],
            "containers": [{"vm": "vm1", "image": "registry.ou.invalid/ou/synapse"}, {"vm": "other", "image": "registry.ou.invalid/ou/keycloak"}]}
    out = executor.h_agent_update(_ctx(a, {"allow": True}, plan))
    allow = next(p for rb, p in a.calls if rb == "cfg.agent_allow")
    assert allow == {"packages": ["nginx", "postgresql-16"], "image_repos": ["ou/synapse"]}   # this VM's only, never another VM's
    assert a.started == 110 and out["allowed"]["image_repos"] == ["ou/synapse"]


def test_agent_update_on_an_agent_upgraded_earlier_records_its_runbooks_before_using_them():
    # officeunbound8-files, job 66c48b4a: the agent already ran 0.10.1 (an earlier attempt), the ICS record still said 0.9.4
    caps = {"guest.facts": {"enabled": True}, "cfg.agent_allow": {"enabled": True}}
    a = _Agent(version="0.10.1", caps=caps)
    a.recorded = {"guest.facts", "pkg.install_pinned"}
    plan = {"services": [{"vm": "vm1", "package": "postgresql-16"}], "containers": []}
    out = executor.h_agent_update(_ctx(a, {"package": "ou-node-agent", "version": "0.10.1-ou20", "allow": True, "timeout_seconds": 300}, plan))
    assert [c[0] for c in a.calls].count("pkg.install_pinned") == 0 and out["allowed"]["packages"] == ["postgresql-16"]


def test_agent_update_refuses_to_grow_allowlists_on_an_agent_without_the_runbook():
    a = _Agent(version="0.10.0", caps={"guest.facts": {"enabled": True}})
    with pytest.raises(StepFailed, match="cannot extend its allowlists"):
        executor.h_agent_update(_ctx(a, {"allow": True}))


def test_agent_update_gives_up_when_the_agent_never_comes_back():
    a = _Agent()
    a.run_runbook = lambda node, rb, params: (_ for _ in ()).throw(StepFailed("refused", "", retryable=True)) if rb == "guest.facts" else {}
    with pytest.raises(StepFailed, match="did not come back"):
        executor.h_agent_update(_ctx(a, {"package": "ou-node-agent", "version": "0.10.1-ou20", "timeout_seconds": 30}))


# ---- agent contracts ----------------------------------------------------------------------------------------------------------------

def test_agent_allow_takes_only_package_names_and_signed_repositories():
    ok = cfgspec.CHECKS["cfg.agent_allow"]({"packages": ["postgresql-16", "nginx"], "image_repos": ["ou/synapse"]}, {})
    assert ok == {"packages": ["nginx", "postgresql-16"], "image_repos": ["ou/synapse"]}
    for bad in ({"packages": ["x; rm -rf /"], "image_repos": []}, {"packages": [], "image_repos": ["docker.io/library/nginx"]},
                {"packages": [], "image_repos": ["other/x"]}, {"packages": [], "image_repos": [], "registries": ["x"]},
                {"packages": ["a"] * 0 + [f"p{i:02d}x" for i in range(65)], "image_repos": []}):
        with pytest.raises(Reject):
            cfgspec.CHECKS["cfg.agent_allow"](bad, {})


def test_keycloak_realm_takes_one_closed_realm_document_never_master():
    pw = "A" * 24
    ok = cfgspec.CHECKS["cfg.keycloak_realm"]({"realm_json": json.dumps({"realm": "ou", "clients": [{"clientId": "portal"}]}), "admin_password": pw}, {})
    assert json.loads(ok["realm_json"])["realm"] == "ou"
    for rj in ("not json", json.dumps({"realm": "master"}), json.dumps({"clients": []}), json.dumps({"realm": "ou", "clients": [{"id": 1}]})):
        with pytest.raises(Reject):
            cfgspec.CHECKS["cfg.keycloak_realm"]({"realm_json": rj, "admin_password": pw}, {})
    with pytest.raises(Reject):
        cfgspec.CHECKS["cfg.keycloak_realm"]({"realm_json": json.dumps({"realm": "ou"}), "admin_password": pw, "url": "http://x"}, {})


def test_an_upgraded_agent_enables_the_new_runbooks_its_role_implies():
    """The allowlist in agent.json was written at creation: after an in-place upgrade the identity VM's agent offers the realm reconcile and
    every configurable VM the allowlist growth, without rewriting agent.json; a VM without configuration runbooks gets neither."""
    ident = agent_runbooks.validate_config({"runbooks": {"cfg.hosts": {"enabled": True}, "cfg.ldap_list": {"enabled": True}, "guest.facts": {"enabled": True}}})
    assert {"cfg.keycloak_realm", "cfg.agent_allow"} <= set(agent_runbooks.capabilities(ident))
    other = agent_runbooks.validate_config({"runbooks": {"cfg.hosts": {"enabled": True}, "guest.facts": {"enabled": True}}})
    assert "cfg.agent_allow" in other["runbooks"] and "cfg.keycloak_realm" not in other["runbooks"]
    bare = agent_runbooks.validate_config({"runbooks": {"guest.facts": {"enabled": True}}})
    assert set(bare["runbooks"]) == {"guest.facts"}
