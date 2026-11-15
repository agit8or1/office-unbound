"""Per-customer provisioning policy. Evaluated server-side at plan creation; the result is stored on the plan (extra approvals,
customer approval reference) and re-checked before execution.

provisioning_mode
  auto               MSP-owned infrastructure only: provisioning follows the normal risk-tiered ICS approvals.
  customer_approval  customer-owned infrastructure: every provisioning/permission-expanding plan also needs the customer's
                     approval through the external approval link (no ICS account for the customer).
  monitoring_only    inventory/monitoring only: all mutating actions are refused.
extra_approvals     {category: n} additional distinct ICS approvers for sensitive operations."""
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

CATEGORIES = ("delete_guest", "remove_storage", "network_change", "expand_permissions", "revoke_credential")

# action -> category (sensitive operations that may need extra approvals)
CATEGORY_OF = {
    "credential.revoke": "revoke_credential",
    "deployment.destroy": "delete_guest", "guest.destroy": "delete_guest", "guest.delete": "delete_guest",
    "storage.remove": "remove_storage", "storage.delete": "remove_storage",
    "network.change": "network_change", "network.update": "network_change", "network.create": "network_change",
    "network.delete": "network_change",
    # provider provisioning (agent L). preview is read-only: no category, not mutating.
    "provider.provision.apply": "expand_permissions", "provider.provision.package": "expand_permissions",
    "provider.credential.import": "expand_permissions", "provider.permissions.reconcile": "expand_permissions",
    "provider.token.rotate": "revoke_credential",   # deletes the previous token at the provider
    "provider.token.revoke": "revoke_credential",
}
# actions that change infrastructure (blocked for monitoring_only, gated by customer approval for customer-owned infra)
# provider.provision.package and provider.credential.import are decided in classify(): they are monitoring-compatible unless the policy /
# token set goes beyond the inventory (monitor) role. Mode A actions use ADMIN credentials on the customer's cluster: always mutating.
MUTATING_PREFIXES = ("deployment.", "guest.", "storage.", "network.", "provider.provision.apply", "provider.permissions.", "provider.token.")
READ_ONLY = ("provider.provision.plan_preview",)
EXPANDING_ENDPOINT_FIELDS = {"allowed_pools", "allowed_nodes", "allowed_storage", "allowed_networks", "allowed_templates", "provision_token_id",
                             "provision_token_secret", "allow_cicustom"}


class PolicyDenied(Exception):
    pass


@dataclass
class Decision:
    extra_approvals: int = 0
    customer_approval: bool = False
    category: str | None = None
    mutating: bool = False


def classify(action: str, p) -> tuple[bool, str | None]:
    """-> (mutating, category)"""
    cat = CATEGORY_OF.get(action)
    mut = action.startswith(MUTATING_PREFIXES) and action not in READ_ONLY
    if action == "endpoint.update" and getattr(p, "changed", None) and p.changed() & EXPANDING_ENDPOINT_FIELDS:
        mut, cat = True, "expand_permissions"
    if action == "credential.create" and getattr(p, "purpose", "inventory") != "inventory":
        mut, cat = True, "expand_permissions"
    if action == "endpoint.register" and getattr(p, "provision_token_id", None):
        mut, cat = True, "expand_permissions"
    if action == "provider.credential.import":
        mut = bool(getattr(p, "provision_token_id", None))
        cat = "expand_permissions" if mut else None
    if action == "provider.provision.package":
        from ..providers.proxmox import provisioning as pp   # lazy: tenancy must not import providers at module load
        mut = set(pp.capabilities(p.policy)) != {"monitor"}
        cat = "expand_permissions" if mut else None
    return mut, cat


def evaluate(db: Session, customer_id, action: str, p) -> Decision:
    c = db.execute(text("SELECT * FROM customers WHERE id = :i"), {"i": str(customer_id)}).first()
    if c is None or c.disabled_at is not None:
        raise PolicyDenied("customer not found or disabled")
    mut, cat = classify(action, p)
    d = Decision(category=cat, mutating=mut)
    if mut and c.provisioning_mode == "monitoring_only":
        raise PolicyDenied("this customer is monitoring-only: infrastructure changes are not permitted")
    if mut and c.provisioning_mode == "customer_approval" and not c.msp_owned:
        d.customer_approval = True
    if cat:
        d.extra_approvals = int((c.extra_approvals or {}).get(cat, 0))
    return d


def validate_policy(msp_owned: bool, mode: str, extra: dict) -> None:
    if mode == "auto" and not msp_owned:
        raise ValueError("automatic provisioning is only available for MSP-owned infrastructure")
    for k, v in (extra or {}).items():
        if k not in CATEGORIES or not isinstance(v, int) or not 0 <= v <= 3:
            raise ValueError(f"extra_approvals keys must be one of {CATEGORIES} with values 0-3")
