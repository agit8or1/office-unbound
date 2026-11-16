# Deploying a customer environment

**Label: Implementing.** The engine, the wizard and every step are tested (simulator and fakes). A real end-to-end run happened **once, in the lab, on one real Proxmox node, with a single test container**, not with a real customer stack ([first-real-deployment.md](../status/first-real-deployment.md)). The no-SSH production bootstrap path (golden image plus callback) is implemented and tested without a real VM ([bootstrap-v2.md](../status/bootstrap-v2.md)). Do not promise a customer a deployment date on the strength of this page.
Evidence: [deployment-engine.md](../status/deployment-engine.md), [first-real-deployment.md](../status/first-real-deployment.md), [bootstrap-v2.md](../status/bootstrap-v2.md), [tenant-isolation-results.md](../status/tenant-isolation-results.md), [ADR-0006](../adr/0006-deployment-model.md), [ADR-0009](../adr/0009-infrastructure-orchestration.md).
Before you start you need: a connected Proxmox endpoint with a **provision** token and at least one allowed node ([Connecting Proxmox](connecting-proxmox.md)), a customer ([Customers and approvals](customers-and-approvals.md)), and two approvers.

## 1. Start the wizard
Console: Overview, **Start deployment wizard** (it is offered once a cluster is connected and no deployment exists; it never opens by itself). It is a convenience over the same API: `POST deployments/plan` builds a plan with no side effects, and a `deployment.create` plan sends it for approval.
The wizard warns "No cluster connected yet" or "Read-only connection" when the endpoint has no provision token; then the ICS cannot create machines.
You choose a **profile** and describe the environment (names, users, domain, OS image). Profiles live in `blueprints/catalog/profiles/` (`lab`, `small`, `medium`, `large`, `ha`, `dedicated`, `msp-multi`, `custom`); components in `blueprints/catalog/components/` (identity, groupware, files, office, edge, monitoring agent). Sizing formulas cite the lab measurement or say "assumption" ([catalog README](../../blueprints/catalog/README.md)). Choose the `ha` profile for replicas on separate nodes; the plan warns when the cluster cannot place them.

## 2. Review the plan
The plan is generated from the latest inventory snapshot and shows: the machines, their size, the node chosen, the ordered steps, an estimated duration, and warnings. Read the warnings; they are the useful part.
| Warning or refusal | What it means |
|---|---|
| capacity shortfall (blocking) | memory, CPU or **physical** disk would be over the reserve. Thin pools are judged on physical space |
| `no_vlan_isolation` | no VLAN was chosen, so there is no tenant network isolation on the bridge |
| `anti_affinity_unsatisfiable` (blocking) | the profile needs more distinct nodes than are authorised |
| `artifact_unpinned` (blocking) | a component image has no pinned digest. Real-catalog plans are non-executable until components are pinned and signed (ADR-0008 pipeline) |
| disruptive change without a maintenance window | refused at plan time for `deployment.change`; use a maintenance window or an explicit override (two approvers) |
If you change an input after the plan was generated the wizard says "Inputs changed": re-plan before submitting. The plan is bound to a hash; if the inventory changed so that the regenerated plan differs, the submit is refused (HTTP 409) and you re-plan.

## 3. Approvals
`deployment.create` and `deployment.destroy` are **high risk**: two approvers who are not the requester. `deployment.change` is normal risk, high if anything is removed, a disk shrinks, or you override the maintenance window. The customer's mode adds more ([Customers and approvals](customers-and-approvals.md)). Approvers open **Approvals** and read the same plan before deciding. Approving starts one job.

## 4. What each step does
Step names are those in `ics/ics/deploy/plan.py`. Progress, timing, and an operator explanation of any error are visible under **Deployments** and **Jobs**.
| Step | What it does |
|---|---|
| `vm.clone` | Full clone of an allowed template inside the allowed pool and storage. Refuses any other pool, storage, node or bridge |
| `vm.tag` | Marks the guest `ou-managed` plus `ou-deployment-<id>`. The ICS only ever changes guests that carry its tags |
| `vm.configure` | CPU, memory, network, cloud-init user and network, and the first-contact material for the guest (see below) |
| `vm.resize` | Grows the root disk when the plan asks for more than the template has |
| `vm.start` | Powers the VM on |
| `guest.await_callback` | Production path: waits for the guest's one-time, signed first-boot report (no inbound SSH to the guest) |
| `agent.enroll` | Enrolls the guest's node agent over a TLS connection pinned to the fingerprint the guest reported, then clears the first-contact material from the VM configuration |
| `comp.install` | Pulls each component image by digest after the agent checked its signature, and starts it as a systemd service |
| `checks.register` | Registers monitoring checks for the new services |
| `health.verify` | Runs the checks from the ICS and fails the job if the service is not healthy |
Steps are idempotent. Re-submitting the same plan carries over finished steps. A job that crashes is marked failed and is never re-run by itself.
Real timing from the one real run: clone 9 s, enrollment 98 s (the longest step), whole job 121 s for a single small VM.

**How the guest gets its first code.** Production: a golden image built by the release pipeline carries our node agent; at first boot it reads a random per-VM secret from the VM's SMBIOS data and makes one authenticated callback to the ICS (single use, time limited). The ICS needs `ICS_GUEST_CALLBACK_URL` and `ICS_GUEST_CALLBACK_PIN_SHA256` set in `/etc/office-unbound/ics.env`. Lab only: a fixed-script SSH bootstrap of a stock cloud image, refused unless `ICS_ENVIRONMENT=lab` ([ADR-0002](../adr/0002-ics-security-model.md) addendum). The golden image has not been imported into Proxmox on a real cluster yet; the build recipe is in `blueprints/build/guest-image/`.

## 5. Change and destroy
`deployment.change` and `deployment.destroy` use plans derived from the **applied** revision, re-derived at execution. A change is refused if another change was applied after you planned. Ownership is by recorded VM id plus tags, never by name. Drift (the cluster differs from the plan) is reported, never repaired automatically. Destroy needs two approvers; the real run destroyed its test VM in 10 s.

## 6. Troubleshooting a deployment
| Symptom | Cause and action |
|---|---|
| Plan refused: `artifact_unpinned` | Component digests are not pinned. Expected today for the real catalog; use a pinned test catalog in the lab (`OU_CATALOG_DIR`, see first-real-deployment.md "Reproduce") |
| Plan refused for thin-pool capacity | The pool is over-provisioned against physical space. Free space or adjust the policy; see [Troubleshooting](troubleshooting.md) |
| `vm.clone` refused | Template not in the allowed pool, or the node is not in the endpoint's allowed nodes (deny by default) |
| `vm.configure` or `vm.tag` fails right after a clone | Proxmox cluster cache lag. The provider waits for pool membership; retry by re-submitting |
| Guest never reports (`guest.await_callback` times out) | The VM network cannot reach the callback URL, or the pin is wrong. The step fails closed: the VM is stopped and its first-contact material is wiped. Fix and re-create the VM |
| "bootstrap material is gone: destroy and re-create" | Deliberate after a failed bootstrap. Destroy the deployment and create it again |
| Deployment stuck `provisioning` after an ICS restart | The job was lost with the restart (known limit). Re-submit the same create; steps already done carry over |
| Agent stops answering after a few days | The agent is bound to the guest's DHCP address at bootstrap. Use a DHCP reservation (static addressing is not built yet) |
| Real-cluster permission errors | The console prints the exact `pveum` fix; see [Connecting Proxmox](connecting-proxmox.md) |
Remove a failed deployment with `deployment.destroy`; it only touches guests whose tags and recorded VM ids match.

## 7. After a deployment
Run the checks in [Day-2 operations](day-2-operations.md), set up backups ([Backup and restore](backup-and-restore.md)), and create the customer's users ([Users and access](users-and-access.md)). Customer-side services (mail, files, documents) are lab-proven components; see [Lab-proven components](lab-proven-components.md).
Known limits: single-VM deployments only so far, no inter-VM firewall rules for internal or edge exposure, `tls_trust` for HTTP/TLS checks not implemented, backup scheduling and DNS records are plan output only. See [Known limitations](known-limitations.md).
