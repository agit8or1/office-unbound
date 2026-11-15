"""Registers the Proxmox provisioning generator as the customer-approval `plan_provider` builder (tenancy/plan_provider.py contract).

The customer approval link must show what will REALLY be requested: the same design (roles, ACL paths, privileges) that Mode A would apply
or that the Mode B package would create, and must offer the real package (scripts + report) for download. Deterministic for the same
input, contains no secrets (policy, paths, privileges, scripts only)."""
from __future__ import annotations

from sqlalchemy import text

from ..providers.proxmox import provisioning as pp
from ..proxmox import ProxmoxError
from ..tenancy import plan_provider
from .model import Policy


def _major_for(db, request: dict, plan_dict: dict | None) -> int | None:
    if plan_dict:
        return plan_dict.get("facts", {}).get("pve_major")
    if request.get("pve_major"):
        return int(request["pve_major"])
    eid = request.get("endpoint_id")
    if eid:
        r = db.execute(text("SELECT last_probe FROM endpoints WHERE id = :i"), {"i": str(eid)}).first()
        try:
            return pp.major_of(str(((r.last_probe or {}) if r else {}).get("version") or ""))
        except ProxmoxError:
            return None
    return None


def build(db, rt, customer: dict, params: dict) -> plan_provider.PermissionPlan:
    action = params.get("action")
    req = params.get("request") or {}
    if action not in ("provider.provision.package", "provider.provision.apply"):
        return plan_provider.stub_builder(db, rt, customer, params)
    plan_dict = None
    if action == "provider.provision.apply":
        art = db.execute(text("SELECT data FROM provision_artifacts WHERE id = :i AND kind = 'plan'"), {"i": str(req.get("preview_id"))}).first()
        if art is None:
            raise ValueError("preview not found")
        plan_dict = art.data["plan"]
        policy = Policy.model_validate(plan_dict["policy"])
    else:
        policy = Policy.model_validate(req["policy"])
    major = _major_for(db, req, plan_dict)
    if not major:
        raise ValueError("the Proxmox VE major version is required to describe the permissions")
    pl = pp.plan_for(policy, None, pve_major=major, mode="B")
    if pl.blocked:
        raise ValueError("the permission plan is blocked: " + "; ".join(pl.blocked))
    d = pp.design_from_plan(pl, policy)
    perms: list[dict] = []
    for a in d.acl:
        role, privs = d.roles[a.cap]
        for priv in sorted(privs):
            perms.append({"path": a.path, "privilege": priv, "reason": f"role {role} ({', '.join(a.tokens)} token)"})
    elevated = [e["privilege"] for e in pl.to_dict().get("elevated", [])]
    files = pp.ProxmoxPackageGenerator(policy).generate(pl, {"package_id": "proposal"})
    summary = (f"Proxmox service account {d.userid} with {len(d.tokens)} API token(s): " + ", ".join(sorted(d.tokens.values()))
               + f"; {len(d.roles)} role(s); {len(perms)} privilege grants" + (f"; elevated: {', '.join(elevated)}" if elevated else ""))
    md = (f"# Provisioning instructions for {customer['name']}\n\n{summary}\n\nRun `provision.sh` (included in the package) as root on one cluster node,\n"
          "review it first. `rollback.sh` removes only what the script created. The generated report follows.\n\n" + files["report.md"])
    return plan_provider.PermissionPlan(summary=summary, permissions=perms, instructions_md=md, package_files=files)


def register() -> None:
    plan_provider.register("proxmox", build)
