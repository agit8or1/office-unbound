# Provider scope modes (one node only / whole cluster) and scope change - agent AK

Branch `scope-ak` on `integration-3`. Evidence: Proxmox **simulator** (`tests/test_scope_modes.py`, 15 tests) plus one **read-only** contact with the real cluster (below). Nothing was applied to the real cluster.

Owner requirement: "ONLY connect one pve in a cluster and it sets up its permissions to not allow beyond that for security, or the whole cluster. this can also be changed later."

## What exists
Every Proxmox connection has a **scope mode** (`Policy.scope_mode`):

| Mode | What Proxmox is configured to allow |
|---|---|
| `single_node` (default, "recommended for security") | One or more explicitly selected nodes (normally exactly one): `Sys.Audit` only on `/nodes/<node>`, storage only if node-local, no `VM.Migrate`, no cloud-init snippets, no grant on `/`, `/nodes`, `/vms`, `/storage`, `/pool`, `/sdn` roots |
| `whole_cluster` | `Sys.Audit` on `/nodes` with propagation (also nodes that join later); shared storage when selected; `VM.Migrate` only if the migrate option is on |

Policies stored before this change have no mode (`mode()` reports `nodes`): behaviour unchanged, the editor treats them as `single_node` with their node list.

### Single-node permission plan (what makes Proxmox itself refuse)
* **Node visibility.** `Sys.Audit` lives in its own role (`<prefix>NodeAudit`) granted only on `/nodes/<n>`; the monitor role no longer carries it, so it is not repeated on pool/storage/vm paths. (Scope modes only; legacy policies keep the old role layout.)
* **Disk placement.** Every storage in `scope.storages` (and any backup storage that can hold `images`/`rootdir`) must be non-shared AND exist only on the selected node(s). Otherwise the plan is **blocked**, naming the storage and why. Explicit high-risk override: `scope_risk_overrides: ["shared_storage:<name>"]` (ACL step marked high, warning + consequence in the plan, plan risk high).
* **No `VM.Migrate`.** `allow_migrate` in single_node is a validation error unless `scope_risk_overrides` contains `migrate`.
* **No `/` grants.** `allow_cicustom` (needs `Sys.Modify` on `/`) is refused; custom grants on `/`, `/nodes`, another node, `/vms`, `/storage` are blocked; `full_admin` cannot be single_node.
* **Templates** must live on a selected node (clone sources on other nodes are blocked).
* **Verification** (`verify_token`, run after every apply) and **drift** (`drift_check`, every 6 h and on "Run validation"): `/access/permissions` of the token is scanned for any grant on `/`, `/nodes`, another node, or an unlisted storage -> `scope_reach` (label `proxmox`); also probes `/`, `/nodes`, `/vms`, `/storage`. Any finding makes the check fail. Separate **ICS-side drift** (`ics_scope`): `endpoints.allowed_nodes/allowed_storage` must equal the approved policy.

### What Proxmox cannot do (stated in the plan, API and UI, labelled `ics`/`both`)
* **Pools are cluster-wide.** `/pool/<p>` cannot mean "only on node X". A guest placed on another node is stopped (a) incidentally by Proxmox because the node-local storage does not exist there, and (b) deliberately by the ICS broker (`EndpointScope.nodes`, deny by default; verified by `test_broker_refuses_clone_to_pve05_even_when_proxmox_would_allow`: with a widened allowlist the simulator clones to pve05, with the real one the broker refuses before any API call). If a shared-storage override is approved, only (b) remains.
* **Classic bridges live in the cluster-wide zone `localnetwork`.** `/sdn/zones/localnetwork/vmbr0` covers `vmbr0` on every node. Plan warning + `ics` enforcement note.
* Pool members already living on other nodes are listed as a warning (visible to the integration; the ICS allowlist refuses acting on them).
* Whole-cluster: the broker allowlist is the node list **found at plan time** (deny by default for nodes that join later) until the scope is changed.

### Labels
`EnforcementNote.enforced_by` = `proxmox | ics | both | not_enforced`, produced by `scope_enforcement(policy)` and merged into the plan, `GET /providers/{id}/permissions` (`scope_mode`, `scope_enforcement`, `enforcement`, `grants[].enforced_by`), the connect wizard Review step (PlanView), the Permissions page ("Scope" card) and the scope-change wizard.

## Scope change (`provider.scope.change`)
`provider.provision.plan_preview` with `purpose: "scope_change"` + `scope_target {mode, nodes, storages?, template_vmids?, risk_overrides, detach_orphans}` (read-only; admin login recommended: a restricted token cannot see nodes/storage it does not yet have) returns: new policy, `direction` (widen/narrow/same; any addition of node/storage/migrate/override/whole-cluster = widen), ACL entries to add/remove, role privilege changes, ICS allowlist before/after, capacity per node (added/removed/kept), **managed guests that would fall outside** (live tags `ou-managed` + `infra_guests`, node and disk storage), blocked reasons, risk, before/after enforcement labels, and `scope_hash` (binds the approval to exactly this change: new policy, direction, detach list, ACL diff, role changes).

* **Narrowing refuses** while managed guests would be orphaned (node left or disks on a removed storage) unless `detach_orphans` is chosen; detach raises risk to high, is part of the hash (cannot be dropped to get a cheaper approval: precheck returns 409), records `managed.detached_guests` and `infra_guests.ou_managed=false`; guests keep running untouched.
* **Risk/approvals.** `provider.scope.change`/`.package`: high when direction is `widen` or detach, else normal. Customer policy (`tenancy/policy.classify`): always mutating (refused for `monitoring_only`, customer link for `customer_approval`), category `expand_permissions` (extra approvals) only when widening.
* **Mode A** (`execution: mode_a`, temporary admin credentials, <= 15 min): recompute against live facts, refuse if hash differs, `apply_plan` (creates before removes), verify with the integration's vault tokens (`scope_reach`, exposure, verbs), then **one transaction**: `endpoint.update` (new node/storage/template allowlists; re-probes with the new scope; re-binds the credential trust anchor) + `endpoint_policy` (policy, design, last_verification). If verification or commit fails the previous ACLs are re-applied (`provider.scope.reverted` audit).
* **Mode B** (`provider.scope.package` then `provider.scope.change` with `execution: confirm_package`): idempotent script (`ensure_acl` new entries, `remove_acl` old ones, `update_role` only if the role still has exactly the old privileges), rollback script that restores the previous scope (never deletes users/tokens/roles), commands.txt, report with the scope section. After the customer runs it, confirm verifies the real PVE state with the existing tokens and only then updates the ICS allowlists; a premature confirm fails ("has the package been run on the cluster?") and changes nothing.
* UI: Permissions page -> **Change scope** (`ScopeChangeFlow.vue`): target (one node / more nodes / whole cluster, node picker from live inventory, storage list with node-local filter), read-only preview with credentials, before/after, permission diff with Proxmox/ICS labels, capacity, affected guests, then Mode A (credentials + risk acknowledgement) or Mode B (script, download, confirm). The connect wizard's Access step has the first choice "Connect one node only (recommended for security)" vs "Connect the whole cluster" (`ScopeEditor.vue`), single node by default, shared storage shown disabled with the reason, override under Advanced; "Change access" shows the scope read-only and points to Change scope.

## Tests (simulator mirroring the owner's cluster: pve01 pve2 pve3 pve04 pve05 pve06, PVE06-Storage local to pve06, ha-zfs shared, PBS1)
`tests/test_scope_modes.py`: single_node(pve06) plan has no `/`/`/nodes` grants, no ha-zfs, no `VM.Migrate`, `Sys.Audit` only on `/nodes/pve06`; labels; shared-storage refusal and override; migrate/cicustom/root-grant/template refusals; whole-cluster plan; injected grant on `/nodes` and on `/` caught by verification and drift (`scope_reach`); broker refuses clone to pve05; scope diff single->whole; narrowing refused with a managed guest on pve05 (detach allowed, high); Mode A widen then narrow (allowlists, ACLs, stored policy, verification, 409 when `detach` flag is dropped); normal-risk narrowing (1 approval); failed verification restores ACLs; ICS allowlist mismatch = drift; Mode B package run twice through the fake `pveum` shim (second run: 0 changes, 0 writes), premature confirm refused, confirm updates allowlists, rollback restores. Frontend: `model.test.ts` (+9). Existing suites unchanged and green.

## Real cluster, read-only (2026-11-15)
GET requests only (`ProxmoxReadClient`, TLS pin `AD:51:9B:...:B1:CA`, token `officeunbound@pam!ics`, secret read into memory from the root-only file, never printed). No apply, no `pveum`, nothing written. Generated: single_node(pve06) plan and Mode B package (files in the agent scratchpad, hashes below; contain no secrets).

Discovery: PVE 9.2.21, 6 nodes (names visible), `PVE06-Storage` lvmthin, not shared, `nodes=[pve06]` (so it qualifies as node-local), pool `officeunbound-pve06`, guests visible 126 (ICS VM), 131 (template), **136 `lab-test-e2e5-all`** (tagged `ou-managed`, in the pool - a leftover of the lead's e2e run; it is exactly the kind of guest the orphan check watches), bridge `vmbr0` found on all 6 nodes.

Plan for `single_node(pve06)`, deploy preset, pool officeunbound-pve06, storage PVE06-Storage, vmbr0, template 131, protected 126: **no blockers, risk normal**, one warning (vmbr0 / `localnetwork` is cluster-wide by name). It would create a NEW service account `ics-svc@pve` with 2 privsep tokens, 6 roles and 27 ACL entries; ACL paths: `/nodes/pve06`, `/pool/officeunbound-pve06`, `/storage/PVE06-Storage`, `/vms/131`, `/sdn/zones/localnetwork/vmbr0`. Nothing on `/`, `/nodes`, other nodes, `ha-zfs`, `PBS1`; no `VM.Migrate`, `VM.Backup`, `VM.Console`, `Sys.Modify`. The role `OfficeUnboundDeploy` already exists on the cluster with different privileges, so the plan correctly uses `OfficeUnboundDeploy-2` and never touches the owner's role.

Compared with the owner's current effective permissions of `officeunbound@pam!ics` (from `/access/permissions`): same paths, plus the owner's token additionally holds `/vms/126` (audit-only incl. `Sys.Audit`, `Pool.Audit`, `VM.GuestAgent.Audit`) and an empty `/vms/136`; on common paths the existing token has extra `VM.Backup` and `VM.GuestAgent.Audit` on the pool and `SDN.Audit` on the bridge; the plan adds `Datastore.Audit` on the pool, `Pool.Audit`/`VM.Audit` on the storage, and `VM.Audit`/`Datastore.Audit`/`Pool.Audit`/`VM.Clone` on `/vms/131` (the owner's token has only the pool-inherited rights there). **The owner's existing token does not reach beyond pve06** (`scope_reach` of its current permissions: none); applying the plan would therefore add a second, cleaner account, not change the existing one. The existing account is not touched by anything generated.

Package files (sha256 prefix): provision.sh 3df5d0883026, rollback.sh 82aa3570e69c, commands.txt 4a5812ec3f39, validate.txt dc1c21a037d2, report.md f98bd3cfe52c, package.json aa2b4593a0ba; no token secret in any file.

## Not verified / limits
* Everything about how PVE 9.2 answers `/access/permissions` for propagated paths is still the simulator's model; on the real cluster only the token's own, already-observed output was used.
* Storage locality uses `/storage` config `nodes` and `shared`. A storage without a `nodes` restriction counts as available on all nodes (refused); the real cluster's single storage is restricted to pve06.
* A node that joins a whole-cluster scope later is not usable until a scope change (by design).
* Restricted tokens cannot discover resources outside their scope: widening previews should use the administrator login (the wizard asks for it). The wizard does not yet offer an admin-login discovery inside the scope-change drawer (storage outside the current scope is added by name).
* Pool/bridge cluster-wide limitation is inherent to Proxmox, documented, not solved.
* Detach does not edit Proxmox tags; guests on out-of-scope nodes are simply no longer managed.
* Migration: no schema change (policy JSON gained optional fields).
