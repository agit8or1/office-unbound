"""Security review 7 H-4 regression tests: a plan's customer is derived server-side from EVERY referenced resource."""
import pytest
from sqlalchemy import text

from ics import actions
from ics.tenancy import resolve

from .test_review5 import DEF, H, world  # noqa: F401


@pytest.fixture()
def scoped_a_op(rt, mk_user, login, world):  # noqa: F811
    u = mk_user("scoped-a-op", "operator")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE id = :u"), {"u": u["id"]})
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": u["id"], "c": world["ca"]})
        db.commit()
    return login(u)


def post(c, h, action, params):
    return c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)


# --------------------------------------------------------------------------------------------------- the PoCs of the review
def test_h4_scoped_operator_cannot_silence_or_remediate_another_customers_objects(rt, world, scoped_a_op):
    c, h = scoped_a_op
    ids, ca, cb = world["ids"], world["ca"], world["cb"]
    # maintenance.create {customer_id: A, check_id: <B's check>}: was 201 + auto-approved (silences B's alerting)
    assert post(c, h, "maintenance.create", {"customer_id": ca, "name": "mute", "check_id": ids["check_b"], "duration_minutes": 60}).status_code == 404
    # check.bind_remediation {A's check, remediation.node_id: <B's node>}: was 201 + auto-approved
    rem = {"node_id": ids["node_b"], "runbook": "service.restart", "unit": "nginx.service"}
    assert post(c, h, "check.bind_remediation", {"check_id": ids["check_a"], "remediation": rem}).status_code == 404
    rr = post(c, h, "check.create", {"customer_id": ca, "name": "zz-new", "kind": "tcp_tls", "config": {"host": "10.0.0.9", "port": 443, "fingerprint_sha256": "ab" * 32}, "remediation": rem})
    assert rr.status_code == 404, rr.text
    # runbook.execute {B's node, A's check}: was 201 + auto-approved
    assert post(c, h, "runbook.execute", {"node_id": ids["node_b"], "runbook": "service.restart", "unit": "nginx.service", "check_id": ids["check_a"]}).status_code == 404
    # the customer the caller states can not move the plan to A either
    assert post(c, h, "runbook.execute", {"node_id": ids["node_b"], "runbook": "service.restart", "unit": "nginx.service"}).status_code == 404
    # A's own objects still work
    r = post(c, h, "maintenance.create", {"customer_id": ca, "name": "mine", "check_id": ids["check_a"], "duration_minutes": 30})
    assert r.status_code == 201, r.text
    with rt.session() as db:
        pid = r.json()["plan_id"]
        assert str(db.execute(text("SELECT customer_id FROM plans WHERE id = :i"), {"i": pid}).scalar()) == ca


def test_h4_all_customers_operator_mixed_or_disagreeing_plans_are_refused(client, rt, world, login):
    c, h = world["sessions"]["all"]
    ids, ca, cb = world["ids"], world["ca"], world["cb"]
    rem = {"node_id": ids["node_b"], "runbook": "service.restart", "unit": "nginx.service"}
    r = post(c, h, "check.bind_remediation", {"check_id": ids["check_a"], "remediation": rem})
    assert r.status_code == 409 and "different customers" in r.text                        # A's check, B's node
    assert post(c, h, "maintenance.create", {"customer_id": ca, "name": "m", "check_id": ids["check_b"], "duration_minutes": 5}).status_code == 409   # caller says A, check is B's
    assert post(c, h, "runbook.execute", {"node_id": ids["node_b"], "runbook": "service.restart", "unit": "x.service", "check_id": ids["check_a"]}).status_code == 409
    ok = post(c, h, "maintenance.create", {"customer_id": cb, "name": "m", "check_id": ids["check_b"], "duration_minutes": 5})
    assert ok.status_code == 201, ok.text
    pid = ok.json()["plan_id"]
    with rt.session() as db:
        assert str(db.execute(text("SELECT customer_id FROM plans WHERE id = :i"), {"i": pid}).scalar()) == cb   # the DERIVED customer is what the plan carries


def test_h4_maintenance_window_without_check_mutes_only_its_own_customer(rt, world):
    from ics import monitor
    ids, ca, cb = world["ids"], world["ca"], world["cb"]
    with rt.session() as db:
        db.execute(text("DELETE FROM maintenance_windows"))
        db.execute(text("INSERT INTO maintenance_windows (name, check_id, starts_at, ends_at, reason, customer_id) VALUES ('all-a', NULL, now(), now() + interval '1 hour', 'r', :c)"), {"c": ca})
        db.commit()
        assert monitor.in_maintenance(db, ids["check_a"]) is True
        assert monitor.in_maintenance(db, ids["check_b"]) is False        # was True: a window without check_id muted EVERY customer


def test_h4_alerts_go_to_the_checks_own_customer_channels(rt, world):
    from ics import monitor
    ids = world["ids"]
    with rt.session() as db:
        db.execute(text("UPDATE alert_channels SET enabled = true"))
        db.commit()
        check = db.execute(text("SELECT * FROM checks WHERE id = :i"), {"i": ids["check_a"]}).first()
        monitor.enqueue_notifications(db, check, None, "opened", "x")
        got = {str(r.channel_id) for r in db.execute(text("SELECT channel_id FROM notifications WHERE detail IS NOT DISTINCT FROM 'x' OR detail = 'maintenance window'")).all()}
        assert ids["chan_a"] in got and ids["chan_b"] not in got


# --------------------------------------------------------------------------------------------------- the resolvers themselves
def test_h4_every_referenced_kind_resolves_to_the_owner(rt, world):
    ids = world["ids"]
    with rt.session() as db:
        mid = str(db.execute(text("SELECT id FROM maintenance_windows WHERE customer_id = :c LIMIT 1"), {"c": world["cb"]}).scalar())
        for kind, val in (("endpoint", world["eb"]), ("check", ids["check_b"]), ("node", ids["node_b"]), ("channel", ids["chan_b"]), ("incident", ids["inc_b"]),
                          ("maintenance", mid), ("policy", "zz-b-policy"), ("customer", world["cb"])):
            assert resolve.lookup(db, kind, val) == world["cb"], kind
        assert resolve.lookup(db, "check", "not-a-uuid") is None
        assert resolve.lookup(db, "node", "00000000-0000-0000-0000-000000000000") is None


# --------------------------------------------------------------------------------------------------- the catalog enumeration
def test_h4_every_action_has_a_customer_resolver_or_is_explicitly_msp_global():
    names = {a.value for a in actions.CATALOG}
    covered = set(resolve.REFS) | set(resolve.MSP_GLOBAL)
    assert not (names - covered), f"actions without a customer resolver: {sorted(names - covered)}"
    assert not (covered - names), f"resolver entries for unknown actions: {sorted(covered - names)}"
    assert not (set(resolve.REFS) & set(resolve.MSP_GLOBAL))
    for a, why in resolve.MSP_GLOBAL.items():
        assert why and actions.CATALOG[actions.ActionType(a)].get("admin_only"), f"{a}: an MSP-global action must be admin_only"


def _fields(model, pre=""):
    for k, f in model.model_fields.items():
        yield pre + k
        for cand in (f.annotation, *getattr(f.annotation, "__args__", ())):
            if isinstance(cand, type) and hasattr(cand, "model_fields"):
                yield from _fields(cand, pre + k + ".")


# model fields that look like references but are not resources of a customer (each with the reason)
NOT_REFS = {"admin_token_id": "the operator's own Proxmox token id (secret input)", "token_id": "provider token name", "provision_token_id": "provider token name",
            "inventory_token_id": "provider token name", "kc_client_id": "OIDC client name", "probe_client_id": "OIDC client name", "mas_client_id": "OIDC client name",
            "spec.deployment_id": "slug inside a not-yet-existing deployment spec", "attempt_id": "remediation attempt counter of the same check",
            "policy.scope": "provisioning policy scope (names/ids at the provider)", "policy.scope.nodes": "provider node names", "policy.provider": "provider name",
            "changes.allowed_nodes": "provider node names", "spec.allowed_nodes": "provider node names", "allowed_nodes": "provider node names",
            "policy.preset": "preset name", "policy.capabilities": "capability names", "policy.scope.storages": "provider names", "policy.scope.pools": "provider names",
            "policy.scope.networks": "provider names", "policy.scope.template_vmids": "provider vmids", "policy.scope.vmid_range": "provider vmids",
            "protected_vmids": "provider vmids", "defaults.bridge": "provider bridge", "defaults.resource_policy": "resource policy", "spec.bridge": "provider bridge",
            "spec.endpoint": "endpoint NAME inside a deployment spec: checked by the deployment executor against the customer", "host": "network host",
            "mail_host": "dns name", "display_name": "label", "name": "label", "confirm_name": "confirmation text", "contact_name": "label", "username": "operator account name",
            "uid": "user inside the already-derived stack", "identity": "credential label", "identity_ca_pem": "certificate", "admin_username": "provider login",
            "policy": "(backup.* actions: a REF; provider.* actions: a provisioning policy object)"}


def test_h4_every_reference_looking_model_field_is_covered_by_the_actions_resolver():
    """A model that gains a *_id / stack / policy / node field must be added to resolve.REFS (or to NOT_REFS above with a reason)."""
    problems = []
    for a, spec in actions.CATALOG.items():
        refs = {p for p, _ in resolve.REFS.get(a.value, [])}
        if a.value in resolve.MSP_GLOBAL:
            continue
        for f in _fields(spec["model"]):
            leaf = f.split(".")[-1]
            looks = leaf.endswith("_id") or leaf in ("stack", "policy", "deployment", "node", "endpoint") or leaf.endswith("_node_id")
            if looks and f not in refs and f not in NOT_REFS and leaf not in NOT_REFS and not (leaf == "policy" and a.value.startswith("provider.")):
                problems.append(f"{a.value}: {f}")
    assert not problems, problems


def test_l6_backup_runner_node_must_be_the_customers_or_the_msps_own(rt, world):  # noqa: F811
    ids, ca, cb = world["ids"], world["ca"], world["cb"]
    with rt.session() as db:
        msp = str(db.execute(text("INSERT INTO nodes (name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, customer_id) VALUES ('zz-msp-runner', '10.0.0.9', 8443, :f, 'k', :f, :c) RETURNING id"),
                             {"f": "cd" * 32, "c": DEF}).scalar())
        with pytest.raises(resolve.CustomerConflict):
            resolve.derive(db, "backup.policy.create", {"customer_id": ca, "runner_node_id": ids["node_b"]})        # another customer's node as the runner
        assert resolve.derive(db, "backup.policy.create", {"customer_id": ca, "runner_node_id": ids["node_a"]}) == ca
        assert resolve.derive(db, "backup.policy.create", {"customer_id": cb, "runner_node_id": msp}) == cb         # the MSP's shared runner serves any customer
        db.rollback()
