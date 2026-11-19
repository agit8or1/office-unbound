# Changelog

All notable changes to Office Unbound are recorded here. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/) as defined in [ADR-0011](docs/adr/0011-versioning-and-releases.md).
While the major version is 0 the project is pre-alpha: MINOR releases may contain breaking changes.

Every entry links to the document that holds its evidence (executed tests, lab results, review reports). An entry without
evidence is a plan, not a change (ADR-0000). Release 0.1.0 is a **lab pre-alpha**: everything below was demonstrated in an
isolated lab; nothing is production supported ([ROADMAP.md](ROADMAP.md)).

## [Unreleased]

## [0.4.3] - 2026-11-19

- **Fix: no container unit could start on a real VM** (Keycloak on e2e-id5: `mkdir /sys/fs/cgroup/user.slice/.../ou-identity-keycloak.service/runtime: read-only file system`, visible thanks to the 0.4.2 unit log). The first podman command of the service user creates its long-lived rootless `pause` process, and every later podman command, the Quadlet units under the user manager included, joins that process's mount namespace. It was created inside a runbook unit with `ProtectControlGroups=true` (and, for the configuration helper, `PrivateTmp`/`ProtectKernel*`), which froze a read-only `/sys/fs/cgroup` into every container start. The two units that run podman (`ou-rb-podman@`, `ou-rb-cfg@`) now carry no mount-namespace option. Node agent **0.5.0-ou7**, catalog pin raised. Evidence: `test_first_real_deployment.py::test_units_that_run_podman_create_no_mount_namespace`; real-VM evidence in docs/status/host-changes.md.
- **Fix: the Files VM was refused `cfg.volume_files` (`bad_params`)** on e2e-fo1: the marker file `.ou-volume` the engine writes into the Files and Office data volumes starts with a dot, which the agent's path rule refuses. Renamed `ou-volume`. The engine test now passes every configuration runbook it produces through the node agent's own validator. Evidence: `test_deploy_exec.py::test_files_and_office_are_configured_and_the_edge_reaches_them_over_verified_https`.
- **An agent refusal now carries its reason**: a request the agent refuses before running it (status `rejected`) returns the reason in `result.message`, which the step error dropped ("cfg.volume_files refused: bad_params: "). Evidence: `test_first_real_deployment.py::test_run_runbook_turns_agent_refusals_and_failed_verification_into_step_failures`.

## [0.4.2] - 2026-11-19

- **Files and Office are configured by the engine** like Identity and Edge: OpenCloud (plus its collaboration unit, same image, `command: [collaboration, server]`) and Collabora get their TLS, environment and CSP files; on their own VM a same-VM TLS proxy serves them, and the edge reaches it over HTTPS verified against the deployment CA (`upstream_name`), with a matching per-peer firewall rule. A catalog unit may now set a `command`; a port may be `shared_with` another component on the same VM (the edge and a hosted service both on 443). Evidence: `test_deploy_exec.py` (files/office), `test_deploy_plan.py` (unit order, shared 443, firewall).
- **Fix: writing files into a component volume failed on a real VM** (`cfg.volume_files`, e2e-id2 on pve06: crun "create directory …/libpod-….scope/container: No such file or directory"). The configuration helper is a system unit; podman's default systemd cgroup manager asked the service user's systemd for a scope it cannot move a system-unit process into. The one-shot copy container now runs with `--cgroup-manager=cgroupfs --cgroups=disabled` (it stays in the helper's cgroup); the services' own units are unchanged. Node agent package **0.5.0-ou5**. Evidence: `test_guest_configure.py::test_volume_files_need_a_verified_image_and_carry_exact_modes`; real-VM evidence in docs/status/host-changes.md.
- **A unit that fails to start now says why.** `podman.deploy_unit` returns the unit's last journal lines (printable ASCII, long token-like strings replaced by `***`) and the step error carries them; before, a failed Keycloak start on the first real VM (e2e-id3) read only "control process exited with error code". Step and event messages keep up to 2000 characters. Node agent package **0.5.0-ou6**, catalog pin raised. Evidence: `test_guest_bootstrap.py::test_a_failed_start_reports_the_units_redacted_log`.

## [0.4.1] - 2026-11-19

- **Fix: a fresh deployment refused its own VM** ("VM … is not a guest of this deployment (tags/name do not match)", real pve06, deployment e2e-id1). Right after the ownership tags were set, Proxmox's `/cluster/resources` cache still listed the template's tags; the ownership checks read that cache. They now read name and tags from the guest's live configuration (`guest_owned`, provider `_guest`), which is authoritative in both directions. The simulator models the cache lag. Evidence: `test_first_real_deployment.py::test_ownership_is_read_from_the_live_config_not_the_lagging_resources_cache` (fails without the fix with the real error).
- **A deployed VM no longer carries the golden-image markers** (`ou-image`, `ou-rel-…`) it inherited from its template. Evidence: `test_a_clone_does_not_keep_the_golden_image_markers_of_its_template`.

## [0.4.0] - 2026-11-19

Release line **Daybreak**: the deployment engine now creates the node-local state a component needs before its service starts (open item 5 of docs/status/artifacts-core-results.md), for **identity** (OpenLDAP + Keycloak + PostgreSQL) and the **edge** (nginx). Files, documents and groupware still carry their catalog notices.

- **Guest configuration runbooks `cfg.*`** in the node agent 0.5.0 (`ics/agent/ou_agent/cfgspec.py`, `cfghelper.py`): name resolution for the deployment's names, deployment TLS material, OpenLDAP first configuration (overlays, ACLs, base tree, bind user, role groups), an initial administrator, a PostgreSQL role/database, podman secrets, files inside a component's named volume, nginx sites, and exact VM-to-VM firewall allowances. Fixed code in a root helper started only as `ou-rb-cfg@`; closed schemas; secrets reach programs on stdin only; errors scrubbed; the request is spooled 0600. Remote upstreams are HTTPS verified against the deployment CA (plain HTTP only to loopback).
- **Per-deployment secrets and CA** (`ics/ics/deploy/configure.py`, migration `0019c`): random passwords vault-encrypted in `deployment_secrets`, a deployment CA whose NameConstraints permit only the deployment's own domain, leaf certificates for exactly the names on each VM. Built at execution time: the hashed plan never holds a secret; the audit log records cfg runbooks without values; everything is wiped when the deployment is destroyed.
- **Health of deployed services** through the node agent (`guest.probe`, check kind `agent_probe`): service ports are loopback-only or open to the deployment's own VMs, so the agent probes them on loopback and verifies TLS against the deployment CA. Replaces the unimplemented TLS trust discovery every http/tcp_tls check of a deployed component would have hit.
- **Golden image ubuntu-24.04 version 2** (`ou-golden-ubuntu-24.04-20261118.qcow2`, sha256 18fe77f5…): agent 0.5.0-ou4; first-boot firewall with an empty peer-allowance set; independent boot test 97/97.
- Engine: every component install waits for all VMs of the deployment to enroll; when several templates carry the catalog name, the newest imported golden image wins.
- Catalog: `ldap-utils` for identity, exact nginx pin `1.24.0-2ubuntu7.19` (the upstream-only `1.24.0` could not install), node-agent pin `0.5.0-ou4`, production realm template without the lab test client.
- Evidence: `test_guest_configure.py` (agent schemas, root helper against recording stand-ins, probes against real loopback servers), `test_deploy_exec.py` (order, no secret in steps/audit, wipe on destroy, agent_probe registration, template choice); real-program verification in the lab machine `ou-cfg1` (docs/status/host-changes.md 2026-11-18 23:00).

## [0.3.7] - 2026-11-18

- **Fix: every production deployment stopped at agent enrollment** with "the reporting address could not be tied to the VM's network card (no neighbour entry)". The guest had booted and called back correctly; the ICS service's systemd sandbox (`ProcSubset=pid`) hid the host neighbour table `/proc/net/arp`, so the MAC binding check (review 5 M2) never saw any entry. `ics.service` no longer sets `ProcSubset=pid` (the rest of the /proc hardening stays), and an unreadable table is now reported as such instead of blaming the network. The binding check itself is unchanged and still fails closed. Evidence: `test_review5_bootstrap.py` (unit-file check, unreadable-table case; fail without the fix).
- **Fix: storage growth trend lost precision.** The days-to-full regression used raw Unix timestamps (~1.8e9 s with microseconds) as x, so the growth rate came out a byte off in about 6% of cases (seen as an intermittent gate failure). Time is now measured relative to now; 0 of 2000 sub-second offsets wrong (124 of 2000 before). Evidence: `test_infra_ha_backups.py::test_projection_needs_history_and_never_invents_a_date`.

## [0.3.6] - 2026-11-18

- **Fix: image import failed at template creation** with "403 Permission check failed (/vms/136, VM.Config.Options)". Proxmox checks tag rights on the new VM without its pool while creating it, and Office Unbound's rights come through the pool. Tags are now set right after creation, once the VM is in the pool (as clones already did). The simulator now models this check. Evidence: `test_image_import.py`, `test_import_storage.py` (fail without the fix with the same error as the real cluster).
- **Failed-backup alert: only the latest result per guest counts.** A later successful backup of the same guest clears an earlier failure (VM 113 on pve06 failed three times on PBS1, then backed up OK). Evidence: `test_infra_ha_backups.py::test_a_later_successful_backup_clears_an_earlier_failure_of_the_same_guest`.

## [0.3.5] - 2026-11-18

- **Fix: image import failed with "malformed task reference"** on the real cluster although the upload succeeded. The cluster's public address forwards to another node; Proxmox runs the upload task on the node that received the request, verifies the checksum there and copies the file to the target node. That task's ID names a node outside Office Unbound's scope, so the job gave up. The import now waits for the file on the target node's import storage (exact size, two consecutive reads) and never queries the out-of-scope node. Evidence: `test_image_import.py::test_upload_received_by_another_node_is_followed_on_the_target_storage`.
- **Standard alerts: no false warnings for what Office Unbound is not allowed to see, and no missed backup failures.** Node CPU/memory rules evaluate only the nodes Office Unbound monitors (others were reported STALE); the HA rule reports "not monitored" when HA status is outside the read access (it warned "no data" with a wrong hint about backup storage). The failed-backup rule also reads each monitored node's own task list: a node-scoped token gets an empty cluster task list, so real failed backups on pve06 were reported as "no backup task". Evidence: `test_infra_ha_backups.py::test_selected_nodes_only_reports_no_data_not_no_backup`.
- A file left on the import storage by an earlier attempt is never reused (the token cannot delete it and Proxmox did not checksum it for this job): the image is uploaded again under a fresh name. Evidence: `test_image_import.py::test_a_file_left_by_an_earlier_attempt_is_never_reused`.

## [0.3.4] - 2026-11-18

- **Fix: Manage access Apply was refused with "the cluster or the managed guests changed since the scope change was previewed"** although nothing had changed (real cluster, apply 6 s after Calculate). Proxmox lists a storage's content types in a random order on each read; that order went into the plan, so the same change hashed differently at preview and at apply. Content types and storage node lists are now sorted when read. Evidence: `test_import_storage.py::test_scope_hash_ignores_the_order_proxmox_lists_content_types_in` (fails without the fix).
- If Proxmox really did change between Calculate and Apply, the access wizard now recalculates automatically and asks you to check and apply again (never re-applied silently).

## [0.3.3] - 2026-11-18

- **Fix: `local` was not offered as the image import storage** on the real cluster: it is a directory storage that also holds VM disks on every node, and the node rule for disk storages was applied to it. An import storage only receives `Datastore.AllocateTemplate` + `Datastore.Audit` (never `Datastore.AllocateSpace`), so Proxmox refuses a VM disk on it on every node. It is now offered and preselected (also in Manage access); as a deployment disk storage it stays blocked. Evidence: `test_import_storage.py::test_import_storage_that_can_hold_disks_on_other_nodes_is_allowed_upload_only`.

## [0.3.2] - 2026-11-18

- **New deployment wizard and sizing engine** (owner spec "Redesign Deployment Wizard and Sizing Engine"). Five steps: deployment type → workload and services → infrastructure and placement → backup and options → generated plan, with a live resource summary. Sizing comes from each component's catalog data (minimum/recommended, fixed overhead, per-user / per-concurrent-user / per-GB factors, consolidation and isolation rules, HA capability). Every number is marked measured (with its lab evidence) or estimate (with a safety margin). The recommended VM count comes from the engine and the generated plan, not from a profile. The plan is checked against the real approved Proxmox capacity: headroom, overcommit, failure domains, growth. HA is offered only when both the components and the infrastructure qualify (with the stock catalog no component has application replication yet, so HA is not offered). `POST /api/v1/deployments/size` is a dry run; provisioning still goes through `/deployments/plan`, the plan fingerprint and approval. "Re-run sizing" on a deployment (`/deployments/{id}/resize-plan`) proposes an approval-gated change and flags downtime and data migration. The contradictory profile VM counts were fixed at the source. Legacy profiles keep working. Evidence: `ics/tests/test_deploy_sizing.py` (21), `wizards/deploy/sizing.test.ts` (21), API in `docs/status/sizing-api.md`.

## [0.3.1] - 2026-11-18

- **Image import from the UI.** Manage access → Deployment targets has an "Image import storage" choice (`local` preselected). If the storage lacks the `import` content type, the dry run includes a disclosed step that adds it with the administrator's sign-in (existing content kept exactly; restored if a later step fails). The write token gets only `Datastore.AllocateTemplate` + `Datastore.Audit` there, never disk placement. Evidence: `ics/tests/test_import_storage.py` (simulator).
- **Ubuntu 24.04 golden image** (owner decision: all service VMs run Ubuntu 24.04): release `ubuntu-24.04-20261116` v1, two byte-identical builds, first-boot enrollment proof + hardening suite 97/97, signed with the production golden-image key.
- **Artifact service on the ICS** (`https://192.168.22.167:8446`, LAN only): all 13 service images and the Office Unbound packages, dev-signed (owner decision for the beta); guests verify every image and package. Catalog pins now match the built artifacts (`ou-node-agent` 0.4.0-ou1, `ou-gromox` 3.13-ou3+noble1, grommunio web/dav/sync). Groupware rebuilt for Ubuntu 24.04.
- Catalog: Debian 12 points at the golden template `ou-tpl-debian-12`.
- Conflict choices (0.2.0-dev.7) also work through the SSH onboarding path (read-only pool member query allowed).

## [0.3.0] - 2026-11-18

**Office Unbound 0.3.0 "Compass"** (owner decision 2026-11-18: the 0.2 "Beacon" development line, builds 0.2.0-dev.1 to dev.8, is released as 0.3.0). Pre-alpha; deployed to the owner's ICS. Highlights: Proxmox connection wizard with sign-in, dry-run Calculate and separate Apply, conflict choices and cleanup, Validate step, read-only whole-cluster monitoring, permissions screen with enforcement labels, infrastructure health page with HA/backup alerts and capacity outlook, single-admin approvals (ADR-0017), first production golden-image release path, neutral console palette.

### 0.2.0-dev.8 (2026-11-18)
- **Fix: oversized info icon on the dashboard** (the guest-visibility note). Icons now default to 1em, so an icon without explicit sizing can no longer fill the page.
- **CI: roadmap workflow** accepted only `X.Y.Z-dev`; numbered builds (`-dev.N`) made it fail on every push. Fixed in `scripts/release_notes.py`.

### 0.2.0-dev.7 (2026-11-17)
- **Conflict choices in the dry run.** When Calculate finds an existing role, service account or token, it offers four choices: use it as is (only if it grants nothing beyond what is needed), overwrite it, remove and recreate it, or create a new one alongside (the default). Built-in roles, roles used by other users' permissions and anything a connected integration owns are never overwritten or removed. Overwriting a role other users rely on lists them and needs an explicit acknowledgement (high risk). The choices are part of the plan fingerprint; Apply is offered only for the plan on screen.
- **Cleanup of failed earlier attempts.** Office Unbound leftovers that no connected integration owns can be removed as part of the same plan: marked users, tokens, empty pools, unused `OfficeUnbound…` roles and stale permissions. Anything it cannot remove is listed with the reason. Evidence: `ics/tests/test_conflict_choices.py` (simulator).
- **Next steps after connecting**: a checklist (import the golden image → standard alerts → first deployment) on the wizard's last step and on the cluster page, from real state, with one button to the next step. The dashboard explains that only Office Unbound's guests are visible without whole-cluster read-only monitoring.
- **Quieter discovery**: nodes outside the selection and the cluster summary (needs Sys.Audit on `/`) are no longer warnings when the administrator chose "selected nodes". The cluster is recorded with quorum "unknown" instead of missing.
- **Storage picker**: aligned rows, usable storage first.
- **Dependencies / CI**: paramiko 5.0.0 (PYSEC-2026-2858), PyNaCl 1.6.2 (PYSEC-2026-3002), invoke 3.0.3. Backend workflow YAML fixed.

### 0.2.0-dev.6 (2026-11-17)
- **Fix: the wizard pre-selected shared storage** (owner report: `ha-zfs`, also present on pve04, pve05, pve2, pve3). The read-only calculation correctly refused it. Storage that also exists on nodes outside the selection is now never suggested and cannot be ticked. The picker says which other nodes it is on, and says so when no storage is confined to the selected node(s). The server-side refusal and its explicit high-risk override are unchanged.
- **Neutral console palette**: cool greys, one steel-blue accent, system fonts, no gradients (replaces the copper / cream scheme). Wizard components use the shared colour tokens, so dark mode is consistent.

### 0.2.0-dev.5 (2026-11-17)
- **Infrastructure health page** (*Monitoring › Infrastructure health*, `GET /api/v1/infra/overview`): every connected cluster on one page with quorum, nodes, guests, HA, backup coverage, storage with a capacity outlook, data age and the alert rules configured. The outlook is a least-squares trend of recorded storage usage, only with at least 24 h of samples; otherwise it says "insufficient history". Nothing is estimated.
- **HA and backup monitoring** (migration 0018h): read-only collection of HA service / LRM state, newest backup per guest on readable backup storage and recent vzdump results. New alert rules `cluster_quorum`, `ha_state`, `backup_age`, `backup_failed`; without visibility they report "no data", never "no backup". Evidence: `ics/tests/test_infra_ha_backups.py`.
- **Add standard alerts**: one click per cluster creates a disclosed set of seven read-only alert rules, each as a normal approved `check.create` plan.
- **Connection wizard Validate step**: after Apply, shows what Proxmox reports each new token can do (verbs, missing and unexpected rights). ADR-0016 amended.

### 0.2.0-dev.4 (2026-11-17)
- **Infrastructure alert rules** (check kind `infra`, migration 0017i): node offline, guest stopped, node CPU / memory and storage-used thresholds (an inactive storage is critical), per node / VMID / storage or `*`. Evaluated from what the inventory and metrics collectors already recorded: no extra Proxmox polling, no agent, nothing installed or executed in guests. Data older than `stale_after_seconds` is reported as STALE, never as a reading; nothing is estimated. Feeds the existing check state machine (flap damping, incidents, escalation, maintenance windows, email / webhook). Evidence: `ics/tests/test_infra_checks.py`.

### 0.2.0-dev.3 (2026-11-16)
- **Read-only cluster monitoring** (`monitor_cluster`): a separate choice ("only the selected nodes" / "the whole cluster, read-only"). It grants an audit-only role (Sys.Audit, VM.Audit, Datastore.Audit, Pool.Audit) at `/` to the READ token only; the write token stays confined to its pool, storage and network; monitoring alone never creates a write token; post-setup verification accepts exactly those read-only rights and still refuses anything more; node metrics then cover every online node. Can be switched on later through Manage access without touching deployment rights.
- **Permissions screen**: "Can observe / Can modify / Never allowed", each line labelled with who enforces it (Proxmox RBAC, Office Unbound, or both) and the real node, pool, storage and network names; levels renamed "Monitoring (read-only)" and "Deployment + Monitoring"; the Review step shows the cluster, address, signed-in user and a compact summary, and states that Calculate is a dry run.
- **Fix: "Calculate the exact Proxmox changes" appeared to do nothing.** The server rejected the dry-run plan (422) and the wizard only rendered progress once a plan existed, so the reason was never shown. Submission errors of the calculation, of Apply and of the maintenance actions are now shown; every rejected plan is logged by the ICS (action, user, field names and messages only, never values). Regression test: public-CA sign-in -> dry run through the HTTP API.

### 0.2.0-dev.2 (2026-11-16)
- Connection wizard: the four protections (never delete VMs/disks it did not create, never change storage/network/cluster configuration, never change Proxmox users or permissions beyond its own service account, never open consoles or run commands in guests) are shown ticked and locked ("always on") instead of as greyed-out empty boxes.
- **First production golden image** (owner-authorized): `ou-golden-debian-12-20261116` release version 1 with node agent 0.4.0 (published to the signed `dev` repo after an independent install test), reproducible (two builds byte-identical), independent boot test = enrollment proof + hardening suite 97/97, signed by the new `ou-image-sign sign-manifest` with a dedicated release key; the ICS trusts only that key's pin and the independent test runner. [host-changes](docs/status/host-changes.md)

### 0.2.0-dev.1 (2026-11-16)
First numbered development build (ADR-0011 amendment: every production deploy gets its own `-dev.N`; earlier deploys of the 0.2 line all reported `0.2.0-dev`).
- **Proxmox connection wizard (ADR-0016)**: sign in once with user name, password and TOTP (never stored; 30-minute Proxmox session), pick the hypervisor nodes only (existing VMs and containers are never selectable or shared), Office Unbound picks its own new pool, the roomiest disk storage and the shared bridge, then creates its own restricted service account, tokens, roles and ACLs as one approved plan; Manage access (add/remove nodes, repair, rotate, disconnect); every "add a cluster" entry point and `/setup` open it. Migration `0016p`. [ADR-0016](docs/adr/0016-proxmox-connection-wizard.md)
- **Single-admin approvals (ADR-0017)**: `ICS_APPROVAL_MODE=single_admin`: an admin approves their own plans, one approval per plan; plan, digest check and audit unchanged. [ADR-0017](docs/adr/0017-single-admin-approval-mode.md)
- Test isolation: agent-epoch tests no longer fence the shared test database.

Merged on integration branches `integration-6`, `integration-7` and `integration-8` (not yet released). Production schema head is `0009b`; this batch adds `0009a` (controller epoch), `0010` (customer scoping), `0011` (one policy per repository URL) and `0012a`-`0012d` (Organization Admin, MSP API, collaboration check kinds, mailbox administration). Node agent 0.2.0 (controller epoch in signed requests; an agent without epoch support keeps working with an ICS at epoch 1, see [ICS recovery and standby](docs/admin/ics-recovery-and-standby.md)).

### Added
- **Warm-standby ICS (ADR-0012, agent AW)**: physical streaming replication, key bundle, `ICS_ROLE=standby`, fenced promotion CLI (`python -m ics.cli promote`), controller epoch in signed agent requests (optional field; agents refuse a lower epoch than they have seen), migration `0009a`. ICS falls back to the pre-epoch request format for agents deployed before this release (tested with an old-agent fake), so lab agents keep working until upgraded. [ics-standby-results](docs/status/ics-standby-results.md)
- **Golden guest image recipe (agent AT)**: Debian image from the signed archive via mmdebstrap + systemd-repart, pinned Ubuntu key, `ou-image-sign` signer, TCG boot proof. [golden-image-results](docs/status/golden-image-results.md)
- **Clean-room installer re-runs (agent AO)**: 12 installer fixes in the lab blueprints, parametrised lab domain/realm. [clean-room-results](docs/status/clean-room-results.md)
- **Document engine ou2 (agent AZ)**: `ou-docs` 26.04.6-ou2 (product name Office Unbound Docs) with a new signed OCI image digest in the `office` catalog component. [docengine-ou2-results](docs/status/docengine-ou2-results.md)
- **Organization Admin** (tenant admin API `/api/v1/tenant/*`, portal area, welcome page, per-customer branding): a customer's own administrators manage people, groups/apps, domains and branding through ordinary `idm.*` plans under the customer's approval policy. Portal 0.2.0. [org-admin-results](docs/status/org-admin-results.md)
- **Mailbox administration**: aliases, shared mailboxes with grants, mail and file-storage quotas (typed `idm.user.set_aliases`, `idm.shared_mailbox.*`, `idm.user.set_*_quota`, fixed gromox runbooks, tenant API and portal pages). [mailbox-admin-results](docs/status/mailbox-admin-results.md)
- **MSP provisioning API v1** (`/api/msp/v1`, interface `msp_api: v1`, ADR-0013): HMAC-signed, idempotent, customer-scoped; signed webhooks, metering, OpenAPI spec and a reference Python client. [msp-api-results](docs/status/msp-api-results.md)
- **Collaboration catalog components**: chat, meetings and telephony (source-built images, unsigned/unpinned artifact refusal, new check kinds). [catalog-collab-components](docs/status/catalog-collab-components.md)
- Database migrations `0012a` (tenant admin, `idm_stacks.customer_id`), `0012b` (MSP API), `0012c` (check kinds), `0012d` (mailbox admin), chained after `0011`, then `0013h` (rate limits), `0012r7` (fence guard) and `0013r7` (image floor): one linear chain, head `0013r7`.
- **Console v3** ([console-v3-results](docs/status/console-v3-results.md)): Releases page, controller banner, scope approvers and a guest start-up panel with read-only APIs.
- **Hardening** ([hardening-results](docs/status/hardening-results.md)): dedicated `ics-bootstrap` callback listener, PostgreSQL shared rate limiter, two workers with advisory-lock worker election, PVE cluster-log exposure detection; migration `0013h` (`rate_limits`).
- **Per-customer VNet network model** (`ics/ics/deploy/netmodel.py` with plan errors), bill of materials, [SDN isolation owner doc](docs/admin/proxmox-sdn-isolation.md) and [network isolation test plan](docs/status/network-isolation-test-plan.md) ([fullstack-readiness](docs/status/fullstack-readiness.md)).
- **Node agent 0.4.0**: gromox alias/shared-mailbox/quota runbooks (additive; older ICS builds simply never request them); epoch mark kept in two copies, an unreadable mark refuses everything until re-seeded; `pkg.install_pinned` checks the fetched `InRelease` Suite/Codename of the Office Unbound repository line only (distro keyrings and sources untouched).
- **Privilege separation (owner-applied)**: `ics/deploy/privsep/` replaces the operator NOPASSWD ALL by exact signer rules and argument-validated lab shims, adds polkit/ssh/unit hardening, apply/revert scripts and a key-separation test; audit in [docs/status/privilege-audit.md](docs/status/privilege-audit.md). Not yet applied to the host.
- **Python 3.11 gate**: `ics/ics/actions.py` used a Python-3.12-only nested same-quote f-string, so the ICS did not start on Debian 12 (3.11); fixed, and `scripts/check_py311.sh` (3.11 byte-compile, or a static 3.12-syntax check where 3.11 is not installed) plus a 3.11/3.12 matrix in `backend.yml` keep it that way.
- **ICS as a signed package (`ou-ics`)**: recipe through the ADR-0008 pipeline (annotated tag -> deterministic archive, hash-locked cp311/cp312 wheels vendored, installed offline with `--require-hashes`, SBOM/licence/OSV), `ics.cli upgrade-preflight`, backup-gated upgrade (`preinst`/`postinst` refuse to migrate without a verified backup), rollback = previous version + `ou-ics-rollback <backup>`, `bootstrap.sh --from-repo <channel>` with a pinned repository key. Proven on Ubuntu 24.04 and Debian 12 (install, upgrade with migration, rollback). [ics-package-results](docs/status/ics-package-results.md), [runbook](docs/runbooks/ics-upgrade-rollback.md)

### Security
- **Security review 5 fixes** ([report and remediation table](docs/status/security-review-5-2026-11-15.md)): H1 `ou-release-sign` validates every index named in `Release`; H2 typed `release.promote` action (ICS-approved manifest, hardened signer, `ou-test-attest` for test evidence); H3 PBX helper secret directory handling; M1/M2 guest bootstrap rate limits per IP and VM and binding of the callback to the VM's MAC; M3 scope-change risk counts templates and ACL widening; M4 `decide_plan` scoped to the plan's customer; M5 `customer_id` on nodes, checks, alert channels, maintenance windows and backup policies (migration `0010`, all list/detail endpoints scoped); M6 identity stacks and SIP credentials refuse foreign-customer nodes; M7 `image.import` verifies the signed manifest itself and refuses older releases; L1-L7 (secret sweeps, callback body cap, constant-work unknown ids, dedicated callback listener, major-only version for anonymous callers, Mode B live inputs, dated upstream pins with anti-rollback).
- **Per-customer backup isolation (agent AU)**: customer policies get their own runner profile, repository namespace, vault binding and plan binding; one policy per repository URL (migration `0011`).
- **Security review 6 (tenant/MSP findings)**: administrator/privileged-account credential resets, re-enables and disables are high risk and never shown to the requester (H2); API-key holders cannot approve plans submitted through their client (M1); webhook SSRF guard with pinned connections and no redirects (M2); no implicit deployment-to-customer slug binding (M3); throttled, unaudited unauthenticated tenant failures (M4); one `idm_stacks.customer_id` definition (M5); SVG allow-list, `realm_access`-only roles, mTLS proxy secret and other Lows. [report and remediation](docs/status/security-review-6-2026-11-15.md)
- **Release signer**: strict deb822 parsing, every index stanza bound to the ledger (control fields, size, hashes), one signing key per channel, Suite/Codename checks on first contact; `ou-test-attest` runs the install smoke test itself in a throw-away container. [security-review-7](docs/status/security-review-7-2026-11-16.md)
- **Fencing**: a fenced, standby or superseded controller stops all side effects (job claim, worker loops, provider/agent/notification egress, enrollment, API mutations); migration `0012r7`; with a witness configured a lease (`ics.witness`) fences an isolated old primary and promotion waits for it to expire.
- **Tenancy**: plan customer derived server-side from every referenced resource; scoped admins cannot invite wider accounts; image import trust and downgrade floor are server state (migration `0013r7`).
- Agent epoch mark fails closed and is stored twice; standby key-bundle passphrase never stored beside the bundle.

## [0.1.0] - 2026-11-16

Release name: **Anchor**. This is the build deployed to the lab ICS (commit 416aafe).

### Added
- **Golden images, production pieces** (branch `golden-prod`): Ubuntu 24.04 image from the signed archive (pinned 2018 archive key, 3 sources), byte-reproducible Debian 12 and Ubuntu 24.04 builds (package lock, pinned filesystem/time inputs; two builds identical per OS), independent boot-and-hardening test suite (97 checks, 6 stages, both images pass), signed manifest v2 with attestation, package-list/SBOM/provenance hashes, and a rollback floor in the ICS database (migration `0012`). Lab evidence only; not run on Proxmox. [golden-image-prod-results](docs/status/golden-image-prod-results.md)
- **Artifact distribution (ADR-0015, agent CC)**: read-only signed apt repository + OCI registry for guests (nginx TLS front end, Distribution registry reader, unix-socket push instance, verifying publisher `ou-artifact-publish`, nftables allow-list), `OU_ARTIFACT_*` configuration replacing the `registry.ou.invalid` placeholder in plans, per-channel apt keys and a scoped CA in the guest bootstrap metadata, health in `/api/v1/system`, backup coverage. [artifact-dist-results](docs/status/artifact-dist-results.md)
- **Provider scope modes**: `single_node` / `whole_cluster` permission plans and the `provider.scope.change` flow (Mode A/B), console UI. [provider-scope-modes](docs/status/provider-scope-modes.md)
- **Telephony productization**: Asterisk 22 built from signed source (`ou-asterisk` recipe) and ICS telephony downstream: `idm.user.set_extension`, `idm.user.issue_sip_credential` (one-time SIP credentials, encrypted at rest until revealed), `pbx.*` agent runbooks, migration `0009`. [telephony-productization](docs/status/telephony-productization.md)
- **Guest bootstrap v2**: no-SSH golden-image path with HMAC callback `POST /api/v1/guest-bootstrap/report`, `guest.await_callback` step, `image.import` verb, migration `0009b`; the SSH path is lab-only behind `ICS_LAB_SSH_BOOTSTRAP` (default off). [bootstrap-v2](docs/status/bootstrap-v2.md), [SSH bootstrap review](docs/status/review-ssh-bootstrap-2026-11-15.md)
- **Quick-start fixes**: `bootstrap.sh` supports Debian 12, `--check-os`, waits for the apt lock; documentation corrections from a dry run.
- **Version information in System**: `/api/v1/system` (admin) now also reports build commit, schema heads, component versions and a read-only pending-updates comparison.

### Security
- **Tenant isolation (agent AS, T20 suite 153/155)**: two scoping holes fixed. Customer-scoped operators could list and read all deployments (deployment list/detail, plan, change/destroy preview and job steps are now filtered by the owning customer's endpoint); identity stacks had no customer binding (stacks carry a `customer_id`, the identity stack/user/reconcile lists and identity actions are scoped to it). [tenant-isolation-results](docs/status/tenant-isolation-results.md)
- Security review 4 fixes (AL) and lifecycle gaps (AC) from main remain; telephony runbook user names are validated with a full-match regex.
- The SSH guest bootstrap path no longer runs by default (fail-open finding in the SSH bootstrap review).
- Security review 4 findings still open on the release-engineering branch (M4-M6, M10, M11 partly, L-series): see [security review 4](docs/status/security-review-4-2026-11-15.md).

### Fixed
- ICS failed to start on Debian 12 / Python 3.11 (`ics/actions.py` used a Python 3.12-only nested-quote f-string). [ics-package-results](docs/status/ics-package-results.md) finding 1.
- Production monitor loop (`_next_vault`): failure-based worker health and thread joins on stop.

### Known issues
- Lab pre-alpha, not production supported. The packages and images built for this release are signed with lab keys only.
- Security reviews 5–7 have open High findings in release signing, test attestation, cross-tenant plan scoping, controller fencing and org-admin account recovery. They are being fixed for 0.2.0. Details: [security review 7](docs/status/security-review-7-2026-11-16.md), [execution queue](docs/status/ALPHA-EXECUTION-QUEUE.md).


First tagged state of the project: a lab-integrated pre-alpha. Installable ICS, console, groupware, identity, files, document
editing, chat/meetings, telephony prototype, migration tooling and package pipeline, all verified only in an isolated lab.

### Added
- **Versioning and releases** (this release): `VERSION`, `VERSIONS.json`, build info written at install time, `GET /api/v1/version`, `GET /api/v1/system`, console footer and Administration → System page, portal `/about`, changelog and release tooling. [ADR-0011](docs/adr/0011-versioning-and-releases.md)
- **Architecture and decisions**: ADR set 0000-0009 including the zero-cost / no-artificial-limits requirement (ADR-0007), own source builds where vendor packages are restricted (ADR-0008) and the infrastructure orchestration contract (ADR-0009). [ARCHITECTURE](docs/ARCHITECTURE.md), [docs/adr/](docs/adr/)
- **Infrastructure Control Server (ICS) foundation**: operator authentication with TOTP, encrypted vault, hash-chained audit log, typed actions with approvals and durable jobs, read-only Proxmox client, plan preview. [security review 1](docs/status/security-review-ics-2026-11-15.md)
- **ICS operator console** (Vue 3) served under a strict CSP, later redesigned with an app shell, design system, dashboard, infrastructure views and integrations. [ui-verification-main](docs/status/ui-verification-main.md)
- **Groupware** built from public source in an isolated lab: MAPI/HTTP, EWS, ActiveSync, Autodiscover, IMAP/SMTP, CalDAV/CardDAV, shared mailboxes, restart persistence, backup/restore (57 checks). Single user store through OpenLDAP. [groupware-lab-results](docs/status/groupware-lab-results.md), [groupware-ldap-results](docs/status/groupware-ldap-results.md)
- **Identity, files and documents lab**: OpenLDAP, Keycloak, OpenCloud, OIDC, WebDAV, browser document edit/save with versions, and the desktop sync engine (upload, download, offline, conflict, delete). [identity-files-lab-results](docs/status/identity-files-lab-results.md)
- **Restore drills**: identity tier, files tier, groupware tier (23 mailboxes restored to a clean-room rebuild) and the ICS controller itself (passive restore to a fresh machine). [restore-drill-results](docs/status/restore-drill-results.md), [ICS recovery runbook](docs/runbooks/ics-recovery.md)
- **Monitoring, alerting and remediation**: health checks, incidents, maintenance windows, signed node agent, approved auto-restart with verified recovery (failure detected in 21 s in the lab). [ics-monitoring-results](docs/status/ics-monitoring-results.md)
- **Identity lifecycle across OpenLDAP, Keycloak, Gromox and OpenCloud**: create, update groups, disable with verification, enable, delete, reconcile; later Matrix. [user-lifecycle-results](docs/status/user-lifecycle-results.md)
- **Operator user management**: directory, invitations, access policy view and a guided privileged-access workflow; audited break-glass `disable-user` CLI. [users-and-access](docs/admin/users-and-access.md)
- **Proxmox provider and real-cluster integration**: provider interface, simulator, inventory and metrics, endpoint settings, node allowlist, VM lifecycle verified on a live cluster. [provider-proxmox-real](docs/status/provider-proxmox-real.md), [provider-proxmox](docs/status/provider-proxmox.md)
- **Deployment engine**: component and profile catalog, plan generation, drift/diff, step executor, `deployment.*` actions. [deployment-engine](docs/status/deployment-engine.md), [catalog schema](blueprints/catalog/README.md)
- **Guest bootstrap**: cloud-init renderer, typed rootless Podman/Quadlet and package runbooks, pinned image-signature policy, proven on a lab guest. [guest-bootstrap-results](docs/status/guest-bootstrap-results.md)
- **Wizards**: first-run setup, connection edit, new deployment and change wizards as the default path. [provider-stack-integration](docs/status/provider-stack-integration.md)
- **Provisioning modes A/B, credential vault, customers and approval links**: permission model, drift detection, customer policy and scoping, external customer approval, master-key re-wrap. [provider-provisioning](docs/status/provider-provisioning.md), [credential-vault](docs/status/credential-vault.md)
- **Providers UI**: Proxmox connection wizard, cluster dashboard, permissions, credentials, customers, read-only discovery. [providers-ui](docs/status/providers-ui.md)
- **Office Unbound Docs**: own source build of Collabora Online (`cp-26.04.6-1`, revision `ou1`), rebranded, unlimited connections and documents, with recipe, patches, tests and SBOM; convert 9/9 and WOPI edit/save verified. [docengine-build-results](docs/status/docengine-build-results.md), [recipe](blueprints/build/collabora)
- **User portal**: Keycloak OIDC backend-for-frontend, launcher, recent files, account, device onboarding (Apple profile, Thunderbird autoconfig); lab end-to-end 39/0. [portal-results](docs/status/portal-results.md)
- **Single sign-on**: webmail SSO into the groupware web client through Keycloak, calendar/contacts deep links, Gromox bearer-claim validation patch, key follower with rotation. [webmail-sso-results](docs/status/webmail-sso-results.md), [sso-rollout-results](docs/status/sso-rollout-results.md)
- **Chat and meetings lab**: Synapse with MAS and Keycloak, Element Web, Jitsi with an Office Unbound JWT. [collaboration-lab-results](docs/status/collaboration-lab-results.md)
- **Telephony lab prototype**: Asterisk PJSIP over WSS and TLS/SRTP, LDAP-provisioned extensions, browser softphone behind Keycloak, voicemail to email (65/0). No outside line and no emergency calling. [telephony-lab-results](docs/status/telephony-lab-results.md)
- **Migration tooling**: read-only Microsoft 365 / Google Workspace readiness assessment (52 fixture-based tests) and an IMAP-to-Gromox mail mover (read-only source, incremental, resumable, verified). [migration-assessment](docs/status/migration-assessment.md), [migration-engine-results](docs/status/migration-engine-results.md)
- **ICS installer**: single-command idempotent `bootstrap.sh` for a fresh Ubuntu 24.04 host (install, upgrade, uninstall), proven on two fresh machines. [ics-installer-results](docs/status/ics-installer-results.md), [installing-the-ics](docs/admin/installing-the-ics.md)
- **Administrator guide** built from executed procedures. [docs/admin](docs/admin/index.md)
- **Public roadmap feed** `docs/progress.json` with generated `ROADMAP.md` and a CI freshness check. [progress-schema](docs/progress-schema.md)
- **CI**: backend, frontend, security and lint workflows with actions pinned by commit SHA, checksum-verified tools and a license allowlist. [.github/workflows](.github/workflows)
- **Playwright UI verification harness** and baseline of UI defects. [ui-verification-baseline](docs/status/ui-verification-baseline.md)
- **Third-party inventory and license review** for every shipped component. [third-party-inventory](docs/status/third-party-inventory.md)

### Changed
- Console login lands on the dashboard; the setup wizard is offered there instead of opening automatically (owner decision). [ui-verification-main](docs/status/ui-verification-main.md)
- Production ICS demo data purged at the owner's request. [host-changes](docs/status/host-changes.md)
- Groupware authenticates from OpenLDAP (single user store) with measured deprovisioning. [groupware-ldap-results](docs/status/groupware-ldap-results.md)
- ICS console is reachable over TLS (nginx, private name-constrained CA, LAN and VPN only) with a loopback-only trusted proxy for real client IPs. [host-changes](docs/status/host-changes.md)
- Migrations linearized (monitoring hardening before the deployment engine, then node scope, security-review-3 fixes, provisioning, vault and provider stack). [ics/migrations](ics/migrations/versions)
- Test databases are per agent (`ics_test_<slot>`) so development can run in parallel. [ics/README](ics/README.md)

### Fixed
- Proxmox: gzip-encoded responses from the real API; clone UPID handling and missing node allowlist found in a real-cluster mutation test; destroy precondition uses live status (cluster resources lag after stop on PVE 9.2). [provider-proxmox-real](docs/status/provider-proxmox-real.md)
- Restore drills found and fixed gaps: plaintext-LDAP regression, UID shift, missing inotify tools, CA trust, split-brain-safe cut-over. [restore-drill-results](docs/status/restore-drill-results.md)
- Document open failure in the ~5 s window after an OpenCloud restart diagnosed; tests wait for editor re-registration (KI-1). [identity-files-lab-results](docs/status/identity-files-lab-results.md)
- Installer: accepts a passive (restored) controller as ready, tolerates `--skip-tls` hosts during backup. [ics-installer-results](docs/status/ics-installer-results.md)
- Production `/catalog` returned 500 because the catalog was not installed to `/opt`; `install.sh` now ships it and ICS backup includes it. Retention no longer fails to run for ten minutes after host boot (monotonic-clock sentinel; found by CI).
- Demo approver credentials moved out of `/tmp`. [security review 1](docs/status/security-review-ics-2026-11-15.md)
- gitleaks allowlist narrowed to test fixtures; E2E harness adapted to the redesigned console.

### Security
- **Review 1** (3 High, 8 Medium) remediated: dedicated `ics` service user, split migration credentials, invite-based accounts, plan-hash-bound approvals, audit HMAC; agent TLS handshake with deadline and connection cap (H1). [report](docs/status/security-review-ics-2026-11-15.md)
- **Review 2** (monitoring and agent) remediated: restart budget, check deadlines, stale plans, silencing approval, approval mode never auto-executes, agent hardening. [report](docs/status/security-review-ics-monitoring-2026-11-15.md)
- **Review 3** (1 High, 5 Medium, 8 Low) remediated, including node-scope fencing and removal actions. [report](docs/status/security-review-3-2026-11-15.md)
- **Review 4** (2 High, 11 Medium, 9 Low; gromox patches, lifecycle, SSO, telephony, migration engine, package pipeline, Collabora) reported. Findings are **open** on `main`; see Unreleased. [report](docs/status/security-review-4-2026-11-15.md)
- `SECURITY.md` (private reporting) and `CONTRIBUTING.md` (DCO sign-off) added; AGPL-3.0 license. [SECURITY](SECURITY.md)

[Unreleased]: https://github.com/agit8or1/office-unbound/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/agit8or1/office-unbound/releases/tag/v0.4.3
[0.4.2]: https://github.com/agit8or1/office-unbound/releases/tag/v0.4.2
[0.4.1]: https://github.com/agit8or1/office-unbound/releases/tag/v0.4.1
[0.4.0]: https://github.com/agit8or1/office-unbound/releases/tag/v0.4.0
[0.3.7]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.7
[0.3.6]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.6
[0.3.5]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.5
[0.3.4]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.4
[0.3.3]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.3
[0.3.2]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.2
[0.3.1]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.1
[0.3.0]: https://github.com/agit8or1/office-unbound/releases/tag/v0.3.0
[0.1.0]: https://github.com/agit8or1/office-unbound/releases/tag/v0.1.0
