# Sizing engine and API (backend for the new deployment wizard)

Status (ADR-0009 section 8): **Implemented & tested** (unit + API tests, `ics/tests/test_deploy_sizing.py`, fake provider/agent, real DB).
**Not validated on real load**: every user-scaling number is an estimate except the ones marked `measured` below. Nothing here provisions.

Code: `ics/ics/deploy/sizing.py` (workload -> drivers -> per-component resources; used by `plan.py`), `sizer.py` (pure engine: layouts per
architecture, qualification, capacity analysis, recommendation, resize proposals), `sizeops.py` (read-only DB glue), routes in `api.py`.
Catalog data: `sizing:` block in every `blueprints/catalog/components/*.yaml` (schema: `blueprints/catalog/README.md`).

## Flow (provisioning is unchanged)
1. `POST /api/v1/deployments/size` (operator; dry run, writes nothing) -> response with `plan_input`, `plan_hash`.
2. Operator adjusts (`overrides`, `architecture`, services, workload) and calls `/size` again as often as needed (still writes nothing).
3. Optional: `POST /api/v1/deployments/plan` with `plan_input` -> identical plan and `plan_hash` (same plan function and inventory).
4. `POST /api/v1/plans {action: "deployment.create", params: {spec: plan_input, plan_hash}}` -> approvals -> job (unchanged ADR-0009 path).

`plan_input` is an ordinary `PlanInput`: `profile: "custom"`, `custom_layout`, plus the new optional `sizing` object (below). Legacy
profile-based `PlanInput`s (no `sizing`) produce byte-identical plans and hashes as before.

## POST /api/v1/deployments/size
Request (`SizeRequest`, unknown keys -> 422):
```json
{
  "deployment_type": "evaluation | production | msp | custom",
  "customer_id": "acme", "deployment_id": "prod", "domain": "acme.example", "endpoint": "lab",
  "workload": {
    "users": 100,                      // MSP: users PER TENANT
    "tenants": 1,                      // MSP only (>1 needs deployment_type msp)
    "concurrent_users": null,          // default users * concurrent_pct/100
    "concurrent_pct": 30, "mailbox_gb_per_user": 2, "file_gb_per_user": 5, "growth_pct": 0,
    "office_editor_pct": 20, "meeting_participant_pct": 20, "concurrent_call_pct": 10   // % of concurrent users (advanced)
  },
  "services": ["mail", "calendar", "contacts", "files", "office", "chat", "meetings", "telephony"],
  "architecture": null,                // consolidated | balanced | isolated | ha | dedicated; null = take the recommendation
  "placement": {"allowed_nodes": null, "storage": null, "bridge": null, "vlan": null, "pool": null},
  "backup": {"destination": "pbs-store", "retention_days": 14, "rpo_hours": 24, "rto_hours": null, "offsite": false},
  "updates": {"mode": "manual | maintenance_window", "window": "sun 02:00-04:00"},
  "overrides": {"estimate_margin_pct": null, "tier": null /* minimum|recommended */,
                "vm": {"groupware": {"cores": 4, "memory_mb": 8192, "disks": {"groupware-mailstore": 500}}}},
  "os_image": null
}
```
Defaults: `placement.pool` = endpoint `allowed_pools[0]`; `storage` = the approved storage (`allowed_storage`) with most free space (none set =
planner picks per node); `bridge`/`vlan` = first `allowed_networks` entry (`vmbr1/42`), else `vmbr0`. `allowed_nodes` must be within the
endpoint's approved nodes (capacity is only ever counted there). `overrides.vm` keys: full VM name or logical layout name.
Service ids come from the catalog (`service_catalog` in the response). `identity` + `edge` are always deployed; dependencies are closed
automatically (`office` pulls in `files`).

Response (200; 404 unknown endpoint; 403 viewer; 422 bad input):
```text
deployment_type, services[], components[]          resolved component set (core + providers + dependency closure)
service_catalog[{id, components[]}]
architectures[{id, available, why_not, vms, cores, memory_mb, disk_gb, fits, capacity_errors[], why_not_fit?}]
recommended {architecture, vms, text} | null       "Recommended: N VMs (balanced) based on ..." (N = generated plan VM count)
selected                                           architecture used for the detail below (request or recommendation) | null
alternatives[{architecture, vms, fits}]
errors[{code, severity, message}]                  unknown_service, tenants_need_msp, architecture_not_available
writes: "none"
--- present when `selected` is set:
plan_input (PlanInput), plan_hash, plan_executable, plan_blocking[]   (plan errors that are not capacity, e.g. artifact_unpinned)
vms[{name, logical, tenant, replica, services[], components[], cores, memory_mb, disk_gb, disks[{name,size_gb,storage,purpose}], node,
     anti_affinity, depends_on[], sizing{drivers{...}, components{comp:{cores,memory_mb,disk_gb,volumes,estimated[],floor_applied[]}}, override?}}]
totals{vms, cores, memory_mb, disk_gb}
fits, production_ready, production_ready_blockers[]
capacity{available{vcpu,memory_mb,storage_gb}, requested{vms,cores,memory_mb,disk_gb}, headroom{vcpu,memory_mb,storage_gb,memory_pct},
         nodes[{name, physical_cores, memory_mb, existing_vcpus, existing_memory_mb, foreign_guests, available{}, requested{}, headroom{}, vcpu_allocation_pct}],
         storage[{name, key, shared, nodes, thin, type, available_gb, requested_gb_all_pools_of_name}],
         failure_domains{nodes_used[], count}, warnings[], policy{...}, growth?{fits_with_growth, fits_today, growth_pct}}
validated (bool), evidence[{component, validated{total_users,concurrent,concurrent_metric,reference}, within_validated, exceeds[], no_load_validation}]
estimated_supported_workload{capacity_bound_users, estimate: true, basis}
backup{destination, retention_days, rpo_hours, rto_hours, protected_gb, estimated_backup_gb, estimate, issues[], valid}
backup_destinations[{name, avail_gb, shared, type}]     backup-capable storages in the approved scope
updates{mode, window, note}
recovery{application_ha, host_failure, backups[]}
scaling_recommendations[{kind, message}]
risks[{code, severity: info|warning|error, message}]
assumptions[]  (plain-language list), estimates_flags[]  ("component.field" sized from estimates)
--- present when nothing fits:
shortfall{message, alternatives[{kind: architecture|drop_service|add_capacity|minimum_floors, ...}]}
```
Warning/risk codes: `cpu_overcommit` (vCPU > physical cores), `cpu_contention_high` (> 200 %), `local_storage_no_redundancy`, `thin_storage`,
`single_failure_domain`, `consolidated_production`, `workload_exceeds_validation`, `no_load_validation`, `component_limitation`,
`no_backup_destination`, `backup_destination_unknown`, `backup_space_insufficient`, `backup_on_vm_storage`, `rpo_not_achievable`,
`offsite_not_configured`, `rto_unverified`.

## POST /api/v1/deployments/{slug}/resize-plan
Request: `{"window": "24h" | "7d" | "30d"}` (optional; default 7d). Operator. 404 unknown, 409 no applied revision / executor running.
Writes nothing. Reads `metric_samples` (guest scope, VMID from `deployment_resources.provider_ref`; finest resolution present).
```text
deployment_id, window, applied_revision, writes: "none", note
usage{vm: {samples, resolution, cpu_avg_pct, cpu_peak_pct, mem_peak_mb, disk_used_pct?}}
recommendations[{kind: increase_resources|decrease_resources|expand_storage|no_data|upgrade_ha|add_capacity, vm?, from?, to?, evidence?,
                 automatic: false, requires_downtime, requires_data_migration, message, available?/why_not? (upgrade_ha)}]
model_drift{differs, changed[], note}               current catalog/sizing models vs the applied plan
proposed_change: null | {changes (ChangeSet), plan_hash, executable, errors[], diff{added,changed,removed,capacity_impact,downtime_seconds,
                 disruptive_steps,snapshot_required,risk,risk_reasons,requires_maintenance}, requires_downtime, requires_data_migration, moved_vms[],
                 submit_as{action: "deployment.change", params{deployment_id, changes, plan_hash}}}
```
Rules: memory peak >= 85 % -> raise to peak/0.70 (256 MB steps); CPU average >= 70 % -> cores x avg/50; disks >= 80 % used -> expand
suggestion; idle (memory < 30 %, CPU peak < 10 %) -> decrease suggestion only (never auto-proposed). CPU/memory changes are flagged as
needing a restart (no live resize assumed); node moves as data migration. `submit_as` must still go through `POST /plans`
(`maintenance: window|override` when disruptive) and approvals. `ChangeSet` gained an optional `sizing` (SizingSpec) field.

## PlanInput.sizing (SizingSpec)
`{workload: Workload|null, tier: minimum|recommended, estimate_margin_pct, tenancy: single|multi (custom profile only), dedicated_nodes,
vm_overrides{name|logical: {cores, memory_mb, disks{}}}}`. `workload` null = legacy per-user formulas + overrides only (used by
resize-plan on profile-based deployments). Overrides below the components' documented minimum (CPU/RAM) or below the sized volume size are
blocking errors (`override_below_minimum`); below the sized value but above the minimum is a warning (`override_below_sizing`).
Engine plans carry a `sizing` section (per-VM drivers and per-component breakdown) and the warning `sizing_estimates`.

## How the recommendation is computed
1. Services -> components (core + providers + `depends_on` closure). Disabled services contribute nothing.
2. Drivers per VM: `total_user = users x (1+growth)`, `concurrent_user` (given or %), `office_editor`, `meeting_participant`,
   `concurrent_call` (% of concurrent), `mailbox_gb`, `file_gb` (per-user GB x users).
3. Per component and resource: `base + sum(factor x driver)`; parts with `evidence: estimate` are multiplied by `1 + safety_margin_pct`
   (catalog default 30 %, `overrides.estimate_margin_pct` replaces it); then `max(value, floor)` with floor = `minimum` (evaluation) or
   `recommended` (production/msp/custom). VM = catalog `vm_overhead` + components + node agent.
4. Layout per architecture: consolidated (greedy packing respecting `isolation: required`, `never_with` and port conflicts), balanced
   (catalog `consolidation.group`), isolated (one component per VM), ha (isolated + `min_replicas`, anti-affinity), dedicated (balanced on
   nodes without foreign guests). MSP: one shared edge VM, everything else per tenant.
5. Qualification: ha only when EVERY selected component has an implemented application replication strategy AND enough approved online
   nodes; dedicated only with an approved node without foreign guests. Today no component qualifies for ha (see `why_not`).
6. Each available architecture is planned with the real plan function against the latest inventory (approved nodes only); `fits` = no
   capacity error. Recommendation = first fitting architecture in the preference order: evaluation: consolidated, balanced, isolated;
   msp: balanced, isolated, consolidated; production/custom: ha, balanced, isolated (isolated first above 500 users), dedicated, consolidated.
7. `capacity_bound_users` = binary search for the largest user count whose layout still fits (estimate, not a validated figure).

## Evidence: measured vs estimated
Measured (lab, cited in the catalog `source`): base memory of identity (ou-id1 0.87 GB idle), groupware (idle stack ~1.3 GB), files (0.57 GB
peak), office (0.29 GB idle) and **office per open document (~85 MB, 30 concurrent documents, docs-reliability-results.md)**, chat (0.49 GiB
idle), meetings (0.94 GiB idle), telephony (0.21-0.29 GiB idle); groupware root disk and MariaDB base. Everything else - all CPU figures,
all per-user/per-concurrent-user factors, all volume growth, edge, agent - is an ESTIMATE with the safety margin and is listed in
`estimates_flags`. Validated workloads (`validated` per component): identity/files 5 users, groupware 8 mailboxes, office 30 concurrent
documents, meetings 2 participants, telephony 2 calls, chat functional only, edge none. Anything above is reported as
`workload_exceeds_validation`; the engine never states that a user count is supported, only that it fits the capacity under the models.

## Profiles (legacy path)
Profiles stay a fixed, legacy layout path (existing deployments unchanged). Their titles no longer carry hand-written VM counts (they
contradicted the layouts: Small 3 vs 6, Medium 5 vs 8, Large 6 vs 8 with every option); `GET /catalog/profiles` now returns derived
`vm_counts{default, all_optional, minimum, per_tenant}` that equal the generated plan, and `sizing_preset{deployment_type, architecture}`
mapping each profile onto the engine.

## Not validated / open
- No load test exists for any component; CPU sizing is entirely estimated. Bandwidth and disk IOPS are not modelled.
- Backup space uses an estimated 2 %/day change rate; restore time (RTO) is not estimated. The plan declares the custom profile's daily
  schedule; offsite copies are not configured by the plan.
- Resize thresholds are heuristics; Proxmox reports 0 disk usage for qemu guests without the guest agent (then no disk recommendation).
- HA: no component has implemented application replication, so `ha` is never offered with the stock catalog.
