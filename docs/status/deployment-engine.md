# Deployment engine (agent B) - status
Branch work for ADR-0009 sections 3, 4, 7. Status labels per ADR-0009 section 8.

## Design
- `blueprints/catalog/` - 6 components (identity, groupware, files, office, edge, monitoring-agent), 8 profiles; every resource formula cites its lab source or says "assumption"
  (sources: groupware-lab-results, identity-files-lab-results, restore-drill-results). Schema: `blueprints/catalog/README.md`.
- `ics/ics/deploy/`: `catalog.py` (pydantic loader), `plan.py` (pure `generate_plan(PlanInput, Capacity, catalog, existing)`; canonical-JSON `plan_hash`; integers only),
  `state.py` (resources, change diff, drift, destroy steps), `executor.py` (durable step engine), `ports.py` (ExecEnv: provider / agent / checks injection),
  `ops.py` (actions deployment.create|change|destroy: models, plan-time precheck + risk, job executors), `api.py` (read endpoints + previews).
- Flow: `POST /deployments/plan` (no side effects) -> `POST /plans {deployment.create, {spec, plan_hash}}` -> precheck regenerates the plan against the latest inventory and requires the same
  hash (409 otherwise), stores the proposed revision (plan JSON) -> 2 approvals (high) -> job loads the stored revision, re-verifies its hash, runs steps.
- Risk: create/destroy high. change = normal, high if anything is removed, a disk shrinks, or `maintenance: override` (explicit override = 2 approvers). Disruptive changes without
  `maintenance: window` (+active window id, re-checked at execution) or `override` are refused at plan time.
- Executor: `job_steps` (status, attempts, progress, log excerpt, error message + operator explanation, result). Idempotent handlers (clone adopts an existing `ou-managed`+`ou-deployment-<id>`
  guest; destroy only touches tag-verified guests). Resume: a re-submitted action carries over steps already succeeded for the same revision; a step left `running` by a crash is re-run.
  Cancellation: `jobs.cancel_requested`, honoured between steps (`executor.request_cancel`; no operator path yet). Unexpected exception text is never stored/returned.
- Capacity: only nodes present and healthy in the latest inventory snapshot are candidates (a node with an error entry is treated as offline); memory/CPU reserve, vCPU overcommit,
  physical free space minus a safety margin, thin pools use PHYSICAL space and a policy ratio (`thin_max_ratio_pct`, default 100: a plan may not grow a pool beyond 100% provisioned);
  `no_vlan_isolation` warning when no VLAN is set; HA/anti-affinity needs distinct nodes (else blocking `anti_affinity_unsatisfiable`).
- Migration `0006b`: deployments, deployment_revisions, deployment_resources, deployment_events, job_steps, `jobs.cancel_requested`.
- `providers/base.py` is a minimal stand-in with the ADR signatures (provider branch version wins at merge); only `deploy/executor.py` and `deploy/ports.py` touch it.
- `actions.py` edits: ActionType + CATALOG entries, one precheck block in `create_plan`, `DeployError` in `_SAFE_ERRORS`, executors in `_EXEC`. `main.py`: one `register_deploy_routes` call.

## Tested (executed; `tests/test_deploy_plan.py`, `test_deploy_policy.py`, `test_deploy_exec.py`)
Implemented & tested: catalog validation (12 rejection cases), exact formula rounding, plan determinism + hash sensitivity, all stock profiles, capacity refusal with shortfall text,
anti-affinity across nodes (and refusal on one node), dedicated-node exclusion, node-local storage pools, multi-tenant isolation, thin overcommit + audited-node-only capacity, DAG order,
change diff (grow, add, remove, shrink refusal, capacity credit of existing allocation), drift (report-only), full create/change/destroy via plan -> 2 approvals -> job with a fake provider +
fake agent (real DB, real check registration), crash resume (no VM cloned twice, orphan adoption), retries and hard failure with explanation, cancellation between steps, health failure,
tampered stored plan refused, unconfigured provider fails cleanly, no secret leakage from unexpected exceptions.

## Awaiting real integration (not claimed working)
- Real provider (`ics.providers.proxmox`): clone/configure/power/snapshot/resize/destroy are exercised only against a fake. Provider ref/`TaskRef.vmid` semantics must match A's module.
- Real agent side: `podman.pull_verified`, `podman.deploy_unit`, `pkg.install_pinned` runbooks, guest enrollment flow, `AgentPort` adapter over `agentclient` (wait_enrollment, tls_trust, address) do not exist yet.
- No real component artifact is pinned: OCI digests are placeholders (`sha256:`), so real-catalog plans are non-executable until the ADR-0008 pipeline publishes them (by design, blocking error `artifact_unpinned`).
  Package versions in the catalog (`ou-gromox 2.40-ou1` etc.) are placeholders for the future OB apt repo.
- Backups: plans declare policy per component; no backup scheduler/executor exists. DNS records are plan output only (operator creates them). Maintenance-window and cancel have no operator action yet.
- OS image: catalog default is Ubuntu 24.04 (`ou-tpl-ubuntu-2404`); the real cluster only has `ou-debian12-template` (VM 131). Selecting `debian-12` works but emits `os_image_unvalidated`
  (packages validated on noble only). Template checksums unpinned. The Proxmox storage list gives no `provisioned` figure for thin pools; provide it from the provider (otherwise a warning).
- Job wall-clock: `run_job` uses the global job timeout; long deployments should raise `ICS_JOB_TIMEOUT_SECONDS` or rely on resume (re-submit continues).
- Sizing numbers marked "assumption" in the catalog (per-user mailbox/file quota, office concurrency) are not measured.

## Integration with the provider and the wizards (resolved at merge)
- `providers/base.py` is agent A's module. The executor uses its types: template looked up by name in the endpoint's pools (`VmCloneSpec.template_vmid`), the clone `TaskRef` (with `template_vmid` and `name`) is persisted in the `vm.clone` step result, and a separate `vm.tag:<vm>` step (plan step list: after the clone, before configure) runs `finalize_clone` so a crash between the two resumes from the stored reference. Guests are never adopted unless they carry `ou-managed` + `ou-deployment-<slug>`; an untagged guest with the planned name stops the step with an operator explanation.
- `ExecEnv` is wired to `ProxmoxMutations` by `deploy/envs.py` inside job execution (needs a provision credential and authorized nodes). The agent port is still unconfigured: steps after `agent.enroll` fail with a clear message until the guest enrollment flow exists.
- Plans only count capacity on the endpoint's authorized nodes (`allowed_nodes`).
- Known limits: the root disk keeps the template's size (no create-time resize step yet; later disk growth uses `resize_disk` on `scsiN` by plan position); a `configure_vm` re-run after a crash in the middle of the call may re-attach an extra disk key.
- Wizards use the backend shapes directly (`frontend/src/wizards/api.ts` maps them): `PlanInput`, `ChangeSet` (users, tenants, profile, optional, backup retention, allowed nodes; other change types are listed as Planned), `maintenance: window|override`, `job_steps` rows, catalog `name/title`.
