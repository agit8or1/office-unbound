# ADR-0009 ICS infrastructure orchestration, deployment engine and console IA
Status: Accepted (design) — Implementing (2026-11-15). Owner directive: ICS is the central infrastructure control plane. Builds on ADR-0002 (security), 0006 (per-customer isolation), 0007 (zero cost), 0008 (own builds).

## Non-negotiables (unchanged)
Every mutation = typed action → plan (params hash) → approvals by risk → single-use durable job → hash-chained audit. Wizards are **front ends to plans**, never a side channel. No arbitrary commands, images, mounts or scripts from user input. TLS always verified. Least-privilege provider credentials. No Docker/Podman socket exposed to the ICS. Nothing in the UI is simulated: a control appears only when its action exists; otherwise it is shown as "Planned".

## 1. Layering (packages under `ics/ics/`)
- `providers/` — **Provider adapter** interface (`base.py`) + `proxmox/` (first full provider). Pure infrastructure verbs, no Office Unbound knowledge.
- `inventory/` — normalized resource model + collectors (providers and node agents) + metrics time series.
- `deploy/` — **deployment engine**: catalog (profiles, components), sizing, dependency graph, plan generation, desired/actual state, drift, executor steps.
- `guest/` — guest bootstrap: cloud-init rendering (agent enrollment, rootless Podman), Quadlet unit rendering for pinned images.
- Existing: `actions.py` (catalog + plans/approvals), `worker.py` (jobs), `monitor.py` (checks/incidents/remediation), `identity.py` (customer users), `agentclient.py`.

## 2. Provider interface (`providers/base.py`)
```python
class Provider(Protocol):
    kind: str                                   # "proxmox"
    def probe(self) -> ProbeResult              # version, cluster name, TLS ok, effective permissions per path
    def discover(self) -> Discovery             # clusters, nodes, storage, networks(bridges/VLAN/SDN), guests(VM/LXC), templates
    def metrics(self, scope, since, step) -> list[Sample]
    # mutations — each returns a provider task handle; the executor polls `task_status` until done/timeout
    def clone_vm(self, spec: VmCloneSpec) -> TaskRef        # from an approved template in an allowed pool
    def configure_vm(self, ref, spec: VmConfigSpec) -> TaskRef   # cores, memory, disks, NICs (bridge/VLAN), cloud-init drive
    def resize_disk(self, ref, disk, new_size_gb) -> TaskRef
    def power(self, ref, op: Literal["start","shutdown","stop","reboot"]) -> TaskRef
    def snapshot(self, ref, name) -> TaskRef ; def rollback(self, ref, name) -> TaskRef
    def migrate(self, ref, target_node, online: bool) -> TaskRef
    def destroy_vm(self, ref) -> TaskRef        # high risk; only guests whose ICS ownership tag matches
    def task_status(self, task: TaskRef) -> TaskStatus
```
Rules: provider calls are made only from job execution (never from request handlers, except read-only probe/discover previews). Every mutation re-checks scope: target pool ∈ endpoint.allowed_pools, storage ∈ allowed_storage, bridge/VLAN ∈ allowed_networks, guest carries tag `ou-managed` + `ou-deployment-<id>` before modification. Permission probe uses `GET /access/permissions` and reports missing privileges per required action.
Proxmox credentials: two endpoint credentials per cluster — `inventory` (PVEAuditor) and optional `provision` (pool-scoped role, docs/status/proxmox-setup.md). Mutations refuse if only `inventory` exists.

## 3. Resource model (DB, migrations 0006+)
`infra_clusters`, `infra_nodes`, `infra_storage`, `infra_networks`, `infra_guests` (vmid, kind vm|lxc, node, status, tags, ou_deployment_id), `infra_templates`, `metric_samples` (scope_type, scope_id, metric, ts, value; rollups 1m/5m/1h; retention 30 d) — each row has `endpoint_id`, `observed_at`, `source`. Inventory snapshots remain as raw evidence.
Deployments: `deployments` (id, customer_id, profile, profile_version, status, desired_spec JSON, created_by), `deployment_resources` (deployment_id, kind vm|container|service|volume|dns|check, logical_name, provider_ref, desired JSON, actual JSON, state), `deployment_revisions` (each approved change = new revision; spec hash), `deployment_events`.

## 4. Deployment engine
- **Catalog** (`blueprints/catalog/*.yaml`, versioned, validated by pydantic): *components* (e.g. `identity` = OpenLDAP+Keycloak+Postgres, `groupware` = gromox stack, `files` = OpenCloud, `office` = Collabora, `edge` = reverse proxy/TLS, `monitoring`), each with: artifact (OCI image **by digest** or OB-built package version), resource formula (base + per-user), ports, volumes, dependencies, health checks, backup method. *Profiles* (`lab`, `small`, `medium`, `large`, `ha`, `msp-multi`, `dedicated`, `custom`): component set, VM layout (which components share a VM), HA replicas, backup policy defaults.
- **Plan generation** (pure function, unit-tested): inputs (profile, users, tenants, availability, storage/network choices, optional components, target endpoint) + discovered capacity → `DeploymentPlan` {vms[] (name, os image, cores, mem, disks, nics), containers[], services[], dependency DAG + ordered steps, ports/firewall, DNS records, backups, checks, estimated consumption, capacity remaining per node/storage, warnings/blocking errors}. Deterministic: same inputs → same plan hash.
- **Execution**: approved plan → job with ordered **steps**, each idempotent with its own status/progress/attempts/log excerpt, persisted (`job_steps`). Step types: provider tasks, wait-for-agent-enrollment, agent runbooks (`podman.deploy_unit`, `podman.pull_verified`, `pkg.install_pinned`, …), DNS/TLS, register checks, verify health. Resume from last completed step after crash; cancellation between steps.
- **Desired vs actual**: reconciler compares `deployment_resources.desired` vs discovered/agent-reported actual → drift report; no silent destructive fixes (same rule as identity reconcile).
- **Change wizard** = edit of desired spec → diff (resources added/changed/removed, capacity impact, downtime estimate per step, required snapshot/backup, dependencies, risk) → plan → approvals → execution → verification. Disruptive steps require a maintenance window or explicit override approval.

## 5. Guests
Default isolation = full VM (Proxmox QEMU) from approved cloud images (Debian 12 / Ubuntu 24.04, checksum-pinned). cloud-init: hostname, SSH disabled or key-only for break-glass, node agent install + one-time enrollment token, **rootless Podman** (Quadlet/systemd) for containerized components; package-built components (gromox) via our signed apt repo. Images pinned by digest and signature-verified (cosign/sigstore or our signing key, ADR-0008). LXC only by explicit profile choice.

## 6. Console information architecture
Overview (dashboard) · **Infrastructure** (Clusters, Nodes, Virtual machines, Containers, Storage, Networks) · **Deployments** (Catalog, New deployment wizard, Environments + drill-down, History) · **Operations** (Jobs, Approvals, Changes, Maintenance, Updates) · **Monitoring** (Health checks, Utilization, Alerts/Incidents) · **Administration** (Users & roles, Access policies, Integrations/endpoints, Configuration, Audit, System). First-run **Setup wizard** when no endpoint exists. Audit is never on the dashboard. User-facing copy never mentions internal API gaps — unimplemented features are hidden or labelled "Planned".
Dashboard: status cards (infra health, clusters, nodes, VMs, containers, deployments, pending operations, incidents) · utilization charts (CPU, memory, storage, network; 1h/24h/7d/30d from `metric_samples`) · health matrix (cluster→node→storage/network→guest→service, click-through) · deployment activity · actionable incidents (severity, resource, duration, next action).

## 7. API additions (`/api/v1`, all role-checked, read endpoints viewer+)
`GET /infra/summary`, `/infra/clusters|nodes|storage|networks|guests[?node=&deployment=]`, `/infra/metrics?scope=&id=&metric=&range=1h|24h|7d|30d`, `POST /setup/probe` (dry probe of connection details; no secrets persisted), `GET /setup/state`, `GET /catalog/profiles|components`, `POST /deployments/plan` (preview, no side effects), `GET /deployments[/{id}[/resources|/events|/drift]]`, `POST /deployments/{id}/changes/preview`, `GET /jobs/{id}/steps`, `GET /users` (+ last_login, status, pending invites), `GET /approvals`. Mutations remain `POST /plans {action, params}` with new actions: `endpoint.register` (extended: credential roles, allowed pools/storage/networks), `deployment.create`, `deployment.change`, `deployment.destroy` (high), `guest.power`, `guest.snapshot`, `guest.migrate`, `guest.resize`.

## 8. Status labels used everywhere
Implemented & tested · Implemented, awaiting integration test (e.g. Proxmox mutations before real cluster runs) · Planned · Blocked (with reason).
