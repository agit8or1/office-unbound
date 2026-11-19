"""guest.remove: Office Unbound can delete exactly the guests/templates it provably left behind (owner request 2026-11-19), nothing else."""
import pytest

from ics.providers.base import ProviderError, ScopeViolation
from ics.provisioning.leftovers import NotALeftover, leftover_reason
from .infra_fixtures import job, mutations, sim  # noqa: F401

TPL = "ou-tpl-ubuntu-2404"


def tpl(vmid, rel, name=TPL, tags=None):
    return {"vmid": vmid, "name": name, "tags": tags if tags is not None else ["ou-image", "ou-managed", f"ou-rel-ubuntu-24.04-{rel}"]}


def guest(vmid, name, tags, status="stopped"):
    return {"vmid": vmid, "name": name, "tags": tags, "status": status}


TPLS = [tpl(136, "20261116"), tpl(137, "20261118"), tpl(147, "20261119"), tpl(148, "20261119")]
DEPS = {"e2e-small": "destroyed", "e2e-small2": "active", "prod": "active", "old": "destroyed"}


def why(g, is_tpl=False, templates=TPLS, deps=DEPS, recorded=frozenset()):
    return leftover_reason(g, is_tpl, templates, deps, set(recorded))


def test_superseded_golden_templates_are_leftovers_and_the_current_one_is_not():
    for v in (136, 137, 147):    # older release, or same release with a lower VM id: pick_template never clones them again
        assert "superseded" in why(next(t for t in TPLS if t["vmid"] == v), True) and "148" in why(next(t for t in TPLS if t["vmid"] == v), True)
    with pytest.raises(NotALeftover, match="current"):
        why(TPLS[-1], True)
    with pytest.raises(NotALeftover, match="golden image"):
        why(tpl(149, "20261101", tags=["ou-managed"]), True, TPLS + [tpl(149, "20261101", tags=["ou-managed"])])
    with pytest.raises(NotALeftover, match="not created by Office Unbound"):          # e.g. a template someone made by hand (no ou-managed)
        why(tpl(131, "", name="ou-debian12-template", tags=[]), True)


def test_guests_of_destroyed_deployments_are_leftovers_live_ones_never():
    assert "destroyed" in why(guest(150, "c-0-old-id", ["ou-managed", "ou-deployment-old"]))
    assert "unknown" in why(guest(151, "c-0-gone-id", ["ou-managed", "ou-deployment-gone"]))
    # a clone that never got its deployment tag (kept the template's tags), named like a VM of a destroyed deployment (real: e2e-small, VMs 138/143)
    assert "never received" in why(guest(143, "c-000000000000-e2e-small-id", ["ou-image", "ou-managed", "ou-rel-ubuntu-24.04-20261116"]))
    refused = [
        (guest(152, "c-0-prod-id", ["ou-managed", "ou-deployment-prod"]), "belongs to deployment prod"),
        (guest(153, "c-0-e2e-small2-id", ["ou-managed"]), "e2e-small2, which is not destroyed"),        # longer live slug wins over e2e-small
        (guest(154, "c-0-old-id", ["ou-managed", "ou-deployment-old"], status="running"), "only a stopped guest"),
        (guest(155, "c-0-old-id", ["ou-deployment-old"]), "not created by Office Unbound"),
        (guest(156, "random", ["ou-managed"]), "not named like a VM of a destroyed deployment"),
    ]
    for g, msg in refused:
        with pytest.raises(NotALeftover, match=msg):
            why(g)
    with pytest.raises(NotALeftover, match="not destroyed"):                          # a live deployment still records the VM id
        why(guest(150, "c-0-old-id", ["ou-managed", "ou-deployment-old"]), recorded={150})


def test_provider_fence_is_independent_of_the_ics_decision(sim, job):
    s = sim.sim
    s.add_vm(300, "pve1", "c-0-old-id", pool="ou-lab", tags="ou-managed;ou-deployment-old")
    s.add_vm(301, "pve1", "mine-running", pool="ou-lab", tags="ou-managed", status="running")
    s.add_vm(302, "pve1", "hand-made", pool="ou-lab", tags="")
    s.add_vm(303, "pve1", "ou-tpl-x", pool="ou-lab", tags="ou-managed;ou-image", template=True)
    m = mutations(sim)
    with pytest.raises(ScopeViolation, match="pools/nodes|not visible"):   # wrong pool: invisible to the pool-scoped token, refused if visible
        m.remove_leftover(200, template=False)
    with pytest.raises(ScopeViolation, match="ou-managed"):
        m.remove_leftover(302, template=False)
    with pytest.raises(ProviderError, match="stopped"):
        m.remove_leftover(301, template=False)
    with pytest.raises(ScopeViolation, match="template"):
        m.remove_leftover(303, template=False)                       # the approval said "guest"
    with pytest.raises(ScopeViolation, match="template"):
        m.remove_leftover(300, template=True)
    m.wait(m.remove_leftover(300, template=False), timeout=5)
    m.wait(m.remove_leftover(303, template=True), timeout=5)
    assert 300 not in s.vms and 303 not in s.vms and {301, 302, 150, 200} <= set(s.vms)


# ---------------------------------------------------------------- plan time (inventory snapshot) and execution (live view) on a real DB
from sqlalchemy import text  # noqa: E402

from ics import actions  # noqa: E402
from ics.actions import ActionType, PlanError  # noqa: E402
from ics.provisioning import leftovers  # noqa: E402
from .infra_fixtures import SCOPE  # noqa: E402


def _setup(rt):
    with rt.session() as db:
        eid = str(db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) "
                                  "VALUES ('pve06', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f) RETURNING id"),
                             {"s": b"x", "f": "ab" * 32}).scalar())
        for slug, st in (("old", "destroyed"), ("prod", "active")):
            db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                            "VALUES (:s, 'c', 'small', '1', :st, '{}'::jsonb)"), {"s": slug, "st": st})
        for vmid, name, tags in ((300, "c-0-old-id", ["ou-managed", "ou-deployment-old"]), (301, "c-0-prod-id", ["ou-managed", "ou-deployment-prod"])):
            db.execute(text("INSERT INTO infra_guests (endpoint_id, vmid, kind, node, name, status, tags, pool, observed_at) "
                            "VALUES (:e, :v, 'vm', 'pve1', :n, 'stopped', :t, 'ou-lab', now())"), {"e": eid, "v": vmid, "n": name, "t": tags})
        db.commit()
    return eid


def test_catalog_entry_is_high_risk_admin_only():
    spec = actions.CATALOG[ActionType.guest_remove]
    assert spec["risk"] == "high" and spec["admin_only"] is True and spec["secrets"] == ()
    assert ActionType.guest_remove in actions._EXEC and ActionType.guest_remove in actions._PRECHECK


def test_precheck_and_execution_remove_only_a_provable_leftover(rt, sim, job, monkeypatch):
    eid = _setup(rt)
    sim.sim.add_vm(300, "pve1", "c-0-old-id", pool="ou-lab", tags="ou-managed;ou-deployment-old")
    sim.sim.add_vm(301, "pve1", "c-0-prod-id", pool="ou-lab", tags="ou-managed;ou-deployment-prod")
    m = lambda vmid, name: leftovers.GuestRemove.model_validate({"endpoint_id": eid, "vmid": vmid, "confirm": name})  # noqa: E731
    with rt.session() as db:
        pre = leftovers.precheck(db, rt, m(300, "c-0-old-id"))
        assert "destroyed" in pre["why"] and pre["template"] is False
        with pytest.raises(PlanError, match="belongs to deployment prod"):
            leftovers.precheck(db, rt, m(301, "c-0-prod-id"))
        with pytest.raises(PlanError, match="confirm"):
            leftovers.precheck(db, rt, m(300, "wrong"))
    import ics.providers.proxmox as pmx
    monkeypatch.setattr(pmx, "open_mutations", lambda rt_, ep, known: mutations(sim, scope=SCOPE))
    with rt.session() as db:
        r = leftovers.exec_remove(rt, db, m(300, "c-0-old-id"), None, [])
    assert r["state"] == "ok" and 300 not in sim.sim.vms and 301 in sim.sim.vms
    # the live view decides at execution: a guest re-tagged to a live deployment after approval is not removed
    sim.sim.add_vm(302, "pve1", "c-0-old-db", pool="ou-lab", tags="ou-managed;ou-deployment-prod")
    with rt.session() as db, pytest.raises(LookupError, match="nothing was removed"):
        leftovers.exec_remove(rt, db, m(302, "c-0-old-db"), None, [])
    assert 302 in sim.sim.vms


def test_the_leftover_listing_shows_verdicts_and_reasons(rt):
    _setup(rt)
    with rt.session() as db:
        rows = {r["vmid"]: r for r in leftovers.list_leftovers(db)}
    assert rows[300]["removable"] is True and "destroyed" in rows[300]["why"]
    assert rows[301]["removable"] is False and "prod" in rows[301]["why"]
