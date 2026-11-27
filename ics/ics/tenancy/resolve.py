"""Server-side customer derivation for plans (security review 7 H-4).

A plan's customer is NOT what the caller says. It is derived from EVERY resource the parameters reference (node, check, alert channel, incident,
maintenance window, stack, backup policy, deployment, endpoint, credential, provisioning artifact ...):
  * all referenced resources must belong to ONE customer, otherwise the plan is refused (409);
  * an explicit `customer_id` (or `spec.customer_id`) must equal that customer, otherwise the plan is refused (409);
  * the approval policy, the scope check and the job all use the derived customer.
Every action of the catalog has an entry in REFS (what it references) or in MSP_GLOBAL (with the reason it has no customer); tests/test_review7_tenancy.py
fails when an action is added without one, or when a model gets a reference field the entry does not cover."""
from uuid import UUID

from sqlalchemy import text

# kind -> (SQL returning customer_id for :i, how the id is validated)
_SQL = {
    "endpoint": "SELECT customer_id FROM endpoints WHERE id = :i",
    "credential": "SELECT customer_id FROM credentials WHERE id = :i",
    "check": "SELECT customer_id FROM checks WHERE id = :i",
    "node": "SELECT customer_id FROM nodes WHERE id = :i",
    "runner_node": "SELECT customer_id FROM nodes WHERE id = :i",     # a backup runner: the MSP's own runner (default customer) may serve any customer's policy
    "channel": "SELECT customer_id FROM alert_channels WHERE id = :i",
    "maintenance": "SELECT customer_id FROM maintenance_windows WHERE id = :i",
    "incident": "SELECT c.customer_id FROM incidents i JOIN checks c ON c.id = i.check_id WHERE i.id = :i",
    "artifact": "SELECT customer_id FROM provision_artifacts WHERE id = :i",
    "plan": "SELECT customer_id FROM plans WHERE id = :i",
    "stack": "SELECT customer_id FROM idm_stacks WHERE name = :i",     # idm_stacks.customer_id is NOT NULL (MSP-internal default), migration 0012a
    "policy": "SELECT customer_id FROM backup_policies WHERE name = :i",
    # deployments.customer_id is the customer's SLUG text (tenant-msp, migration 0012b): join to the customer row. A legacy value that is itself a UUID still resolves.
    "deployment": "SELECT COALESCE(c.id::text, CASE WHEN d.customer_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN d.customer_id END) AS customer_id "
                  "FROM deployments d LEFT JOIN customers c ON c.slug = d.customer_id WHERE d.slug = :i",
    "customer_ref": "SELECT id::text AS customer_id FROM customers WHERE slug = :i",
    "ssh_session": "SELECT customer_id FROM ssh_sessions WHERE id = :i",   # SSH onboarding session (ADR-0014): bound to one customer at creation
}
DEFAULT_CUSTOMER = "00000000-0000-0000-0000-00000000a001"
_UUID_KINDS = {"endpoint", "credential", "check", "node", "runner_node", "channel", "maintenance", "incident", "artifact", "plan", "ssh_session"}

# action -> [(dotted param path, kind)]; kind "customer" = an explicit customer id the caller states
REFS: dict[str, list[tuple[str, str]]] = {
    "alert_channel.create": [("customer_id", "customer")],
    "alert_channel.delete": [("channel_id", "channel")],
    "alert_channel.test": [("channel_id", "channel")],
    "backup.policy.create": [("customer_id", "customer"), ("runner_node_id", "runner_node"), ("deployment", "deployment")],
    "backup.policy.update": [("policy", "policy")],
    "backup.prune": [("policy", "policy")],
    "backup.run": [("policy", "policy")],
    "backup.verify": [("policy", "policy")],
    "check.bind_remediation": [("check_id", "check"), ("remediation.node_id", "node")],
    "check.create": [("customer_id", "customer"), ("remediation.node_id", "node"), ("config.endpoint_id", "endpoint")],
    "check.delete": [("check_id", "check")],
    "check.set_enabled": [("check_id", "check")],
    "image.import": [("endpoint_id", "endpoint")],
    "guest.power": [("endpoint_id", "endpoint")],
    "guest.remove": [("endpoint_id", "endpoint")],
    "credential.create": [("customer_id", "customer"), ("endpoint_id", "endpoint")],
    "credential.replace": [("credential_id", "credential")],
    "credential.revoke": [("credential_id", "credential")],
    "credential.rotate": [("credential_id", "credential")],
    "credential.test": [("credential_id", "credential")],
    "deployment.change": [("deployment_id", "deployment"), ("maintenance_window_id", "maintenance")],
    "deployment.create": [("spec.customer_id", "customer_ref")],
    "deployment.destroy": [("deployment_id", "deployment")],
    "deployment.snapshots.prune": [("deployment_id", "deployment")],
    "gateway.certificates.issue": [("deployment", "deployment")],
    "directory.account.set": [("deployment", "deployment")],
    "directory.account.lock": [("deployment", "deployment")],
    "directory.account.delete": [("deployment", "deployment")],
    "demo.deployment.mark": [("deployment", "deployment")],
    "endpoint.disable": [("endpoint_id", "endpoint")],
    "endpoint.enable": [("endpoint_id", "endpoint")],
    "endpoint.register": [("customer_id", "customer")],
    "endpoint.remove": [("endpoint_id", "endpoint")],
    "endpoint.update": [("endpoint_id", "endpoint")],
    "idm.reconcile": [("stack", "stack")],
    "idm.stack.register": [("customer_id", "customer"), ("files_node_id", "node"), ("gromox_node_id", "node"), ("pbx_node_id", "node")],
    "idm.user.create": [("stack", "stack")],
    "idm.user.delete": [("stack", "stack")],
    "idm.user.devices": [("stack", "stack")],
    "idm.user.disable": [("stack", "stack")],
    "idm.user.enable": [("stack", "stack")],
    "idm.user.issue_sip_credential": [("stack", "stack")],
    "idm.user.set_extension": [("stack", "stack")],
    "idm.user.update_groups": [("stack", "stack")],
    "idm.user.reset_credentials": [("stack", "stack")],
    "idm.user.set_aliases": [("stack", "stack")],
    "idm.user.set_mail_quota": [("stack", "stack")],
    "idm.user.set_storage_quota": [("stack", "stack")],
    "idm.shared_mailbox.create": [("stack", "stack")],
    "idm.shared_mailbox.delete": [("stack", "stack")],
    "idm.shared_mailbox.grant": [("stack", "stack")],
    "idm.shared_mailbox.revoke": [("stack", "stack")],
    "incident.ack": [("incident_id", "incident")],
    "inventory.refresh": [("endpoint_id", "endpoint")],
    "maintenance.cancel": [("maintenance_id", "maintenance")],
    "maintenance.create": [("customer_id", "customer"), ("check_id", "check")],
    "maintenance.delete": [("maintenance_id", "maintenance")],
    "node.decommission": [("node_id", "node")],
    "node.enroll": [("customer_id", "customer")],
    "plan.archive": [("plan_id", "plan")],
    "provider.credential.import": [("endpoint_id", "endpoint"), ("customer_id", "customer"), ("package_id", "artifact")],
    "provider.permissions.reconcile": [("endpoint_id", "endpoint"), ("preview_id", "artifact")],
    "provider.provision.apply": [("endpoint_id", "endpoint"), ("customer_id", "customer"), ("preview_id", "artifact")],
    "provider.provision.package": [("endpoint_id", "endpoint"), ("customer_id", "customer")],
    "provider.provision.plan_preview": [("endpoint_id", "endpoint"), ("customer_id", "customer")],
    "provider.scope.change": [("endpoint_id", "endpoint"), ("preview_id", "artifact"), ("package_id", "artifact")],
    "provider.scope.package": [("endpoint_id", "endpoint"), ("preview_id", "artifact")],
    "provider.ssh.discover": [("ssh_session_id", "ssh_session")],
    "provider.ssh.preview": [("ssh_session_id", "ssh_session"), ("endpoint_id", "endpoint")],
    "provider.ssh_onboard": [("ssh_session_id", "ssh_session"), ("preview_id", "artifact"), ("endpoint_id", "endpoint"), ("customer_id", "customer")],
    "provider.ssh_offboard": [("ssh_session_id", "ssh_session"), ("endpoint_id", "endpoint")],
    "provider.ssh.helper": [("endpoint_id", "endpoint")],
    "provider.ssh.narrow": [("endpoint_id", "endpoint")],
    "provider.token.revoke": [("endpoint_id", "endpoint")],
    "provider.cleanup": [("endpoint_id", "endpoint")],
    "provider.token.rotate": [("endpoint_id", "endpoint")],
    "runbook.execute": [("node_id", "node"), ("check_id", "check")],
}

# actions without a customer: MSP-wide administration. Scoped operators are refused for these (create_plan: cust is None -> 404).
MSP_GLOBAL: dict[str, str] = {
    "settings.tenancy.set": "the installation's tenancy mode (single / multi tenant): MSP-wide, admin_only",
    "settings.network.update": "the installation's public address (Settings -> Network & domains): MSP-wide infrastructure, admin_only",
    "settings.management.update": "who may reach the ICS console under its public name (Settings -> Network & domains): the ICS host itself, admin_only",
    "customer.create": "creates a customer: the MSP's own administration",
    "customer.update": "edits a customer record: MSP administration (admin_only)",
    "msp.client.create": "MSP API client administration: which customers a key may reach is decided here (admin_only, high risk)",
    "msp.client.revoke": "MSP API client administration (admin_only, high risk)",
    "msp.client.rotate": "MSP API client administration (admin_only, high risk)",
    "msp.client.set_permissions": "MSP API client administration (admin_only, high risk)",
    "msp.stack.link": "(re)binds an identity stack to a customer: the stack's CURRENT customer and the target differ by design (admin_only, high risk)",
    "operator.set_scope": "changes which customers an operator sees: MSP administration (admin_only)",
    "release.promote": "ICS-wide package channel promotion (admin_only)",
    "user.create": "ICS operator accounts are MSP-wide (admin_only)",
    "user.disable": "ICS operator accounts are MSP-wide (admin_only)",
    "user.enable": "ICS operator accounts are MSP-wide (admin_only)",
    "user.invite": "ICS operator accounts are MSP-wide (admin_only)",
    "user.revoke_invite": "ICS operator accounts are MSP-wide (admin_only)",
    "user.revoke_sessions": "ICS operator accounts are MSP-wide (admin_only)",
    "user.set_role": "ICS operator accounts are MSP-wide (admin_only)",
}


NOT_FOUND = {"policy": "backup policy not found"}      # the wording of the "missing" answer per kind (a scoped operator must not tell the two cases apart)


class CustomerConflict(Exception):
    """referenced resources belong to different customers, or the caller's customer_id disagrees with them"""


def _get(params, path):
    cur = params
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur or cur[part] in (None, ""):
            return None
        cur = cur[part]
    return cur


def _norm(c) -> str | None:
    """customers are UUIDs; a free-text customer label (deployments.customer_id is text) can not be scoped and is not a derivation input"""
    try:
        return str(UUID(str(c).strip()))
    except ValueError:
        return None


def lookup(db, kind: str, value) -> str | None:
    """customer id of one referenced resource (None when it does not exist or has no customer)"""
    if kind == "customer":
        return _norm(value)
    if kind == "customer_ref":      # a customer UUID or its slug (deployment specs carry the slug)
        return _norm(value) or _norm(db.execute(text(_SQL["customer_ref"]), {"i": str(value)}).scalar())
    if kind in _UUID_KINDS:
        try:
            value = str(UUID(str(value)))
        except ValueError:
            return None
    r = db.execute(text(_SQL[kind]), {"i": str(value)}).first()
    c = _norm(r.customer_id) if r and r.customer_id is not None else None
    return None if kind == "runner_node" and c == DEFAULT_CUSTOMER else c      # MSP-owned runner: infrastructure, not a customer binding (L-6 still refuses another customer's node)


def references(db, action: str, params: dict) -> list[tuple[str, str, str | None]]:
    """[(path, kind, customer or None)] for every reference the params actually carry"""
    out = []
    for path, kind in REFS.get(action, []):
        v = _get(params, path)
        if v is None:
            continue
        out.append((path, kind, lookup(db, kind, v)))
    return out


def derive(db, action: str, params: dict) -> str | None:
    """The single customer of a plan, or None for an MSP-global action / one that references nothing. Raises CustomerConflict."""
    if action in MSP_GLOBAL:
        return None
    if action not in REFS:
        raise CustomerConflict(f"action {action} has no customer resolver")
    seen: dict[str, list[str]] = {}
    for path, kind, cust in references(db, action, params):
        if cust:
            seen.setdefault(cust, []).append(path)
    if len(seen) > 1:
        raise CustomerConflict("the plan references resources of different customers (%s)" % "; ".join(f"{', '.join(v)}" for v in seen.values()))
    return next(iter(seen)) if seen else None
