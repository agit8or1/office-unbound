# Proxmox provider, inventory and endpoint settings (ADR-0009 sections 2, 3, 7)

Status labels per ADR-0009 section 8. "Simulator" = `ics/tests/pve_sim.py`, a stateful **test double** (HTTPS, self-signed cert, per-token ACLs, UPID tasks,
gzip like pveproxy, failure injection). It lives under `tests/`, binds 127.0.0.1 only, reports `repoid: pve-sim-test-double` and the provider refuses
that marker unless loopback endpoints are allowed (tests/lab only) - it cannot be registered as a real endpoint in production. **Passing simulator tests is not
evidence about a real cluster**; the rows below say which parts have had real contact (read-only probe of pve06 by the lead, see `provider-proxmox-real.md`).

## Status
| Area | State |
|---|---|
| Provider interface `ics/providers/base.py` (Provider/ReadProvider protocols, value types, `job_execution()` guard) | Implemented & tested |
| `probe`: version, cluster, TLS (pin/CA), per-verb effective permissions with exact `pveum` fix commands, unnecessary privileges, capabilities, ICS-self-VM warning | Implemented & tested (simulator); **read-only parts verified once against real pve06 by the lead**, the permission mapping itself is awaiting a real run after the owner's ACL fixes |
| `discover` (cluster, nodes incl. "not managed" detection, storage content/usage/thin+provisioned, bridges/VLAN-aware, SDN zones/vnets, VM+LXC guests, tags, templates) | Implemented & tested (simulator); real pve06: inventory path exercised by the lead's probe (gzip bug found+fixed), normalized upsert not yet run on the real cluster |
| `metrics` via `rrddata` -> normalized samples; collector, 1m/5m/1h rollups, retention, bucketed API | Implemented & tested (simulator). PVE `rrddata` field names/units follow the PVE 8 docs: awaiting real cluster |
| Mutations: clone (full/linked) + `finalize_clone` tagging, configure (cores, memory, NICs, disks, cloud-init fields, optional cicustom), resize, power, snapshot, rollback, migrate, destroy | **Implemented, awaiting integration test against a real cluster** (simulator-tested incl. every scope refusal) |
| Endpoint settings: `endpoint.register` (extended), `endpoint.update`, `endpoint.remove`, `endpoint.disable/enable`, `GET /endpoints[/{id}]` | Implemented & tested |
| `POST /setup/probe` (tls stage + full probe + wizard-shaped `permissions`/`discovery`), `GET /setup/state` | Implemented & tested |
| `/infra/summary|clusters|nodes|storage|networks|guests|templates|metrics` | Implemented & tested |
| Deployment executor, plan generation, `guest.*` actions, agent enrollment | Not mine (agent B/C); the provider gives them `open_mutations(rt, ep)` only inside `job_execution` |

## Safety rules enforced in code (each has tests)
1. **Mutations only from job execution.** `ProxmoxMutations.__init__` calls `require_job_execution()`; `actions.run_job` is the only place that enters
   `base.job_execution()`. The read-only `ProxmoxProvider` has no mutating method at all; `open_read_provider` hands out only that.
   `open_mutations` also refuses endpoints with no `provision` credential, disabled or detached endpoints.
2. **Scope on every mutation, re-resolved live from `/cluster/resources`** (never the DB cache): pool in `allowed_pools`, storage in `allowed_storage` (clone target, new disks, cloud-init drive,
   the guest's existing disks on resize/migrate), NIC bridge[/vlan] in `allowed_networks` (`vmbr1` = any VLAN, `vmbr1/20` = that VLAN only), template in an allowed pool
   (or explicitly listed in `allowed_templates`), target node part of the cluster, guest carries **`ou-managed` + `ou-deployment-<id>`** matching the caller's deployment id. Pool membership alone is never ownership.
   `finalize_clone` adds the tags and only accepts the UPID of a successful `qmclone` task started by this very token for that vmid.
3. **The ICS's own VM is never touched**: every guest mutation first compares the guest's NIC MAC(s) / `smbios1` uuid with this host's MACs and `/sys/class/dmi/id/product_uuid`,
   plus `protected_vmids` (also blocks clone-into / clone-from). Fail closed when the config cannot be read. The probe warns loudly (`DANGER`) when a token can mutate that VM and
   when it is inside a managed pool.
4. No free-form fields: every parameter is rebuilt from validated structured fields (ssh keys, ciuser, ipconfig, domains, snapshot names, disk keys). cicustom needs endpoint opt-in AND an allowed snippets storage.
5. TLS: pin/CA on every connection (unchanged `ProxmoxReadClient` machinery, `ProxmoxWriteClient` extends it). The setup *tls stage* reads the certificate the server presents (CERT_NONE handshake, no HTTP request, no credential) so an admin can compare it out of band; its `ok` is true only if the pin/CA matches.
6. Secrets: never selected for display; AAD binds trust anchors (+ provision token id); errors/probe/audit contain no secret (tested by string search across plans, jobs, audit, API).

## Required PVE privileges per verb (`providers/proxmox/privileges.py`)
| verb | privileges (on) |
|---|---|
| discover | Sys.Audit (per node or /), VM.Audit, Datastore.Audit (any visible scope is enough; unaudited nodes are reported "not managed") |
| metrics | Sys.Audit, VM.Audit |
| clone_vm | pool: VM.Allocate, VM.Clone, VM.Audit, VM.Config.Disk; storage: Datastore.AllocateSpace |
| configure_vm | pool: VM.Config.CPU/Memory/Network/Disk/Cloudinit/Options/HWType, VM.Audit; storage: Datastore.AllocateSpace; **each bridge: SDN.Use on `/sdn/zones/localnetwork/<bridge>`** (or `/sdn/zones/<zone>/<vnet>`); cicustom: Sys.Modify (PVE restricts it) |
| resize_disk | pool: VM.Config.Disk; storage: Datastore.AllocateSpace |
| power | pool: VM.PowerMgmt |
| snapshot / rollback | pool: VM.Snapshot / VM.Snapshot.Rollback |
| migrate | pool: VM.Migrate; storage: Datastore.AllocateSpace |
| destroy_vm | pool: VM.Allocate |
Not needed (reported as "unnecessary"): VM.Console, VM.Backup, Sys.Console, Sys.Modify, Sys.PowerMgmt, Permissions.Modify. `Pool.Audit` is optional (membership is derived from `/cluster/resources`); the probe reports it missing.
Differences from `proxmox-setup.md` as first written: the role also needs **VM.Snapshot, VM.Snapshot.Rollback, VM.Migrate** (+ Pool.Audit recommended); PVE 9 has VM.GuestAgent.Audit and no VM.Monitor (not used).
**Real pve06 finding:** the owner's role has no `VM.Migrate`, so `migrate` reports unavailable until it is added (not needed for single-node pve06).

## Capabilities reported by the probe
`vm_disks` (storage offers `images`; blocking), `cloudinit_snippets` (no `snippets` on pve06's lvmthin storage: cloud-init must use ciuser/sshkeys/ipconfig/nameserver/searchdomain, agent enrollment cannot depend on snippets: bake a first-boot unit into the template or use a directory storage with snippets),
`template_import` (needs `import` content to build templates; otherwise supply a cloud-init template inside the pool, e.g. VM 131 `ou-debian12-template`), `vlan_tagging` (no VLAN-aware bridge in scope on pve06: tagging unavailable, blocking only if a `bridge/vlan` entry was requested).

## Inventory model, collectors, metrics
Tables `infra_clusters|nodes|storage|networks|guests|templates` (+ `infra_collect_state`, `metric_samples`), every row with `endpoint_id`, `observed_at`, `source`. Discovery runs per enabled, non-detached endpoint every 300 s from the worker loop (and after `inventory.refresh`); rows of a kind are pruned only when that kind was fetched completely.
Nodes the token has no `Sys.Audit` on (pve06 token: 5 of 6) are stored `managed=false` with **NULL** capacity (PVE reports zeros: "no visibility", not "idle"), excluded from health and from `capacity` in `/infra/summary`; storage is only probed on managed nodes.
Storage rows carry PVE's physical `total/used` plus `thin` and `provisioned_bytes` (sum of visible volumes = a lower bound); a thin pool whose provisioned size exceeds physical capacity is a **warning** ("overcommitted") so planners never plan against virtual size alone (pve06 PVE06-Storage: 15.17 TiB vs 10.91 TiB; autoextend off).
Metrics: every 60 s `rrddata` of managed online nodes + running guests -> `metric_samples` (1m). Rollups 1m->5m->1h (complete buckets only, idempotent) every 5 min. Retention 1m 48 h, 5m 7 d, 1h 30 d. `GET /infra/metrics?scope=node|guest|storage&id=<infra uuid>&metric=&range=1h|24h|7d|30d`: 1h = 1m rows/60 s buckets, 24h = 1m rows/300 s, 7d = 5m rows/1 h, 30d = 1h rows/1 h; points are `{ts, avg, max}`.
Metric names: cpu_pct, mem_used_bytes, mem_total_bytes, net_in_bps, net_out_bps, disk_read_bps, disk_write_bps, disk_used_bytes, disk_total_bytes, load1, iowait_pct (+ storage used_bytes/total_bytes from discovery).

## Health rollup (`inventory/health.py`)
node: online ok, else critical; unmanaged: excluded. cluster: no quorum critical, offline nodes warning. storage: disabled/inactive warning, >= 95 % critical, >= 85 % warning, thin overcommit warning. guest: running/stopped/paused ok, else warning.
Anything not observed for `inventory_stale_seconds` (900) is `unknown`, never ok. Endpoint: discovery failing critical, never discovered / stale unknown, partial data warning, disabled/detached shown as such and excluded. Overall = worst of critical > warning > unknown > ok; nothing at all = unknown.

## Endpoint settings as typed plans
`endpoint.register` (high; adds `display_name`, `provision_token_id/secret` (role provision), `allowed_pools|storage|networks|templates`, `allow_cicustom`, `protected_vmids`, `defaults`), `endpoint.update` (partial; **normal** for display_name/enabled only, **high** for base_url, TLS trust, any credential or secret rotation, scope lists, defaults, protected_vmids; any connection change re-probes with the NEW config and persists nothing if that fails; secrets are re-encrypted under the new binding),
`endpoint.remove` (high; needs `confirm_name`; refused while deployments reference it unless `force_detach` - visible in the approved params; credentials are destroyed, inventory rows/metrics/snapshots kept and hidden from live views, name freed), `endpoint.disable|enable` (normal; a disabled endpoint is not contacted and refuses mutations). Plans for these are bound to the endpoint's current trust anchors (plan-hash binding): changing them between approval and execution fails the job.
Deployment reference check introspects `deployments.endpoint_id` / `status` (agent B's table) - align when that migration lands.

## API shapes vs the wizard (agent F `wizards/api.ts`)
Implemented as specified: `POST /setup/probe {stage:'tls', base_url, fingerprint_sha256|ca_pem}` -> `{tls:{ok, verified_by:'fingerprint'|'ca', presented_fingerprint_sha256, subject, not_after, error}}` with no credential; full probe -> `{ok, version, cluster_name, tls, permissions:{inventory,provision}:{ok, missing:[{path, privilege}], unnecessary:[{path, privilege}], fix_commands[]}, discovery:{nodes,storage,networks,guests,pools,warnings}, error}` plus richer `verbs`, `capabilities`, `warnings`, `self_vm`; `GET /setup/state` includes `has_endpoint`.
Differences to report: `credential_roles` is **not** a parameter - credentials are `token_id/token_secret` (inventory) and `provision_token_id/provision_token_secret` (provision); `defaults` fields are `storage, bridge, vlan, ip_mode (dhcp|static), dns_servers, search_domain, backup_storage, approved_os_images, resource_policy (conservative|balanced|dense)`; discovery guests mark templates with `template:true`; DiscNode adds `managed` (cpu/mem null when not managed); `mfa`/`alert_channels` in setup state are not provided.
