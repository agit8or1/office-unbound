"""Per-customer usage / metering. Every figure has a precise, documented definition (see DEFINITIONS and docs/api/msp-v1.yaml).

Sources: ICS identity tables (users, mailboxes), the deployment engine's desired state (provisioned resources) and the newest inventory
snapshot of the deployment's endpoint (observed resources). Nothing is estimated; anything ICS cannot measure is reported as null."""
from datetime import datetime, timezone

from sqlalchemy import text

MiB, GiB = 1024 ** 2, 1024 ** 3

DEFINITIONS = {
    "users.active": "idm_users in state 'active' in identity stacks linked to the customer, at the time of the request",
    "users.disabled": "idm_users in state 'disabled' (login refused, account and mailbox retained)",
    "users.deleted": "idm_users in state 'deleted' (directory entry removed; mailbox data retained by policy)",
    "mailboxes.active": "active or disabled users that hold the stack's mailbox entitlement group (a mailbox exists and consumes storage)",
    "mailboxes.retained": "deleted users whose groups at deletion held the entitlement group: mailbox data is kept, there is no purge action",
    "vm.provisioned": "sum over the customer's deployments (status not 'destroyed') of deployment resources of kind 'vm' in state present/changing: "
                      "count, vCPUs, memory (MiB) and the total of ALL desired virtual disks (GiB). This is allocated, not used, capacity",
    "vm.observed": "from the newest inventory snapshot of each deployment's endpoint, VMs matched by provider vmid: count, running count, vCPUs, "
                   "memory (MiB) and boot-disk size (GiB, Proxmox maxdisk). null when no snapshot exists",
    "storage.provisioned_gb": "same as vm.provisioned.disk_gb",
    "storage.mailbox_used_bytes": "not metered: ICS has no mailbox-usage runbook yet (null)",
}


def usage(db, customer) -> dict:
    stacks = db.execute(text("SELECT id, name, config FROM idm_stacks WHERE customer_id = :c ORDER BY name"), {"c": str(customer.id)}).all()
    users = {"active": 0, "disabled": 0, "deleted": 0}
    mbx_active = mbx_retained = 0
    per_stack = []
    for s in stacks:
        ent = s.config.get("entitlement_group", "mail-users")
        rows = db.execute(text("SELECT state, count(*) AS n, count(*) FILTER (WHERE groups @> to_jsonb(CAST(:g AS text))) AS m FROM idm_users WHERE stack_id = :s GROUP BY state"),
                          {"s": str(s.id), "g": ent}).all()
        cur = {"active": 0, "disabled": 0, "deleted": 0}
        ma = mr = 0
        for r in rows:
            cur[r.state] = r.n
            if r.state in ("active", "disabled"):
                ma += r.m
            elif r.state == "deleted":
                mr += r.m
        for k in users:
            users[k] += cur[k]
        mbx_active += ma
        mbx_retained += mr
        per_stack.append({"stack": s.name, "users": cur, "mailboxes": {"active": ma, "retained": mr}})
    deps = db.execute(text("SELECT id, slug, endpoint_id FROM deployments WHERE customer_id = :s AND status <> 'destroyed' ORDER BY slug"),
                      {"s": customer.slug}).all()
    prov = {"vms": 0, "vcpus": 0, "memory_mb": 0, "disk_gb": 0}
    obs = {"vms": 0, "running": 0, "vcpus": 0, "memory_mb": 0, "boot_disk_gb": 0}
    observed_any = False
    out_deps = []
    for d in deps:
        res = db.execute(text("SELECT desired, provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' AND state IN ('present','changing')"),
                         {"d": str(d.id)}).all()
        dp = {"vms": len(res), "vcpus": 0, "memory_mb": 0, "disk_gb": 0}
        for r in res:
            dp["vcpus"] += int(r.desired.get("cores", 0))
            dp["memory_mb"] += int(r.desired.get("memory_mb", 0))
            dp["disk_gb"] += sum(int(x.get("size_gb", 0)) for x in r.desired.get("disks", []))
        snap = db.execute(text("SELECT data, collected_at FROM inventory_snapshots WHERE endpoint_id = :e ORDER BY collected_at DESC LIMIT 1"),
                          {"e": str(d.endpoint_id)}).first() if d.endpoint_id else None
        do = None
        if snap:
            guests = {int(g["vmid"]): g for n in snap.data.get("nodes", []) for g in n.get("qemu", []) if isinstance(g, dict) and "vmid" in g}
            do = {"vms": 0, "running": 0, "vcpus": 0, "memory_mb": 0, "boot_disk_gb": 0, "inventory_at": snap.collected_at.isoformat()}
            for r in res:
                vmid = (r.provider_ref or {}).get("vmid")
                g = guests.get(int(vmid)) if vmid is not None else None
                if g:
                    do["vms"] += 1
                    do["running"] += 1 if g.get("status") == "running" else 0
                    do["vcpus"] += int(g.get("cpus", 0) or 0)
                    do["memory_mb"] += int(g.get("maxmem", 0) or 0) // MiB
                    do["boot_disk_gb"] += int(g.get("maxdisk", 0) or 0) // GiB
            observed_any = True
            for k in obs:
                obs[k] += do[k]
        for k in prov:
            prov[k] += dp[k]
        out_deps.append({"deployment": d.slug, "provisioned": dp, "observed": do})
    return {"customer_id": str(customer.id), "as_of": datetime.now(timezone.utc).isoformat(),
            "users": {**users, "total_live": users["active"] + users["disabled"]},
            "mailboxes": {"active": mbx_active, "retained": mbx_retained},
            "vm": {"provisioned": prov, "observed": obs if observed_any else None},
            "storage": {"provisioned_gb": prov["disk_gb"], "mailbox_used_bytes": None},
            "stacks": per_stack, "deployments": out_deps, "definitions": DEFINITIONS}
