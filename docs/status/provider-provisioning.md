# Provider provisioning (Mode A / Mode B) - status

Branch `provisioning-l` (based on the Proxmox provider branch). Everything below was exercised against the **Proxmox simulator**
(`ics/tests/pve_sim.py`, a test double). Nothing here has run against the owner's real cluster. "Tested" means "passes against the simulator".

## Design

One computed plan, two ways to execute it, one resulting integration.

```
Policy (preset + AccessScope)  --design()-->  roles + ACL entries + 2 privsep tokens
        |                                          |
   plan_for(policy, facts) -> ProvisioningPlan (steps, conflicts, elevated, enforcement, blocked, plan_hash)
        |                                          |
 MODE A  apply_plan() with TEMP credentials   MODE B  ProxmoxPackageGenerator -> provision.sh, rollback.sh, commands.txt,
        |  token secrets -> vault                        validate.txt, report.md/html, package.json (schema v1)
        '------------- verify_token() / drift_check() (same design) -------------'
```

* Framework (provider-agnostic): `ics/ics/provisioning/` - `model.py` (policy), `plan.py` (Step/Plan/hash, `PackageGenerator` protocol, diff helper),
  `drift.py` (comparison), `enforce.py` (application-level scope guard), `actions.py` (typed actions), `service.py` (drift runner + API).
* Proxmox implementation: `ics/ics/providers/proxmox/admin.py` (ticket/token admin client, discardable) and `provisioning.py`
  (matrix, design, plan, apply/rollback, verification, package).
* Account: `<service_user>@pve` (realm is validated to be `pve`; PAM is refused; no OS account, no password). Two privilege-separated tokens
  (`privsep=1`): `-inv` (monitor role only) and `-prov` (everything else). ACLs are written for the user AND each token (effective = intersection).
  A monitoring-only preset gets only the inventory token.
* Roles (names configurable, collision-safe: an existing role with different privileges is never modified; `-2`, `-3` ... is used and the conflict shown):
  `OfficeUnboundMonitor / Deploy / Storage / TemplateClone / Network / Backup / Custom / FullAdmin`.
* Temporary credentials: plan secrets (vault-encrypted under the plan id), TTL 15 min (`TEMP_CRED_TTL`), decrypted only inside the job, client
  discarded in `finally`, `plans.secret_enc` NULLed on job end (success or failure), on reject, and by the reaper after 15 min.
  The job result, audit and params never contain them (tested by scanning plans/jobs/audit/artifacts/API).
* Apply is hash-bound: apply/reconcile approve a *previewed* plan hash; if the cluster changed meanwhile the job refuses. A failure rolls back
  exactly what the run created. Nothing is ever widened to make a step pass.
* Actions: `provider.provision.plan_preview` (low, read-only), `.apply` (high), `.package` (normal; high for full_admin/elevated),
  `provider.credential.import` (normal), `provider.permissions.reconcile` (high; restores the STORED policy only), `provider.token.rotate` (high),
  `provider.token.revoke` (high, confirm name).
* API: `GET /providers/{id}/permissions` (expected vs actual, PVE-enforced vs ICS-enforced, last verification/drift), `POST .../permissions/check`
  (operator, read-only live drift check), `GET /providers/{id}/provisioning/packages/{pkg}` (admin; `?format=json|zip|<file>`; `id` = endpoint id or `unbound`).
* DB: migration `0007l` (`endpoint_policy`, `provision_artifacts`; `down_revision = 0006a` - re-chain if another branch also adds 0007).

## Never granted
`Permissions.Modify`, `User.Modify`, `Group.Allocate`, `Realm.*` (hard refusal, also in custom grants), `Sys.Modify` (only as an *elevated* privilege, e.g. `cicustom`,
shown with why/where/what and requiring `approve_elevated` + high-risk approval), the built-in `Administrator` and `PVEAdmin` roles. Full cluster administration
needs `acknowledge_full_admin`, is high risk, lists its consequences, and still withholds the items above.

## Privilege matrix (PVE 8 / 9)
Source of truth: `PRIV_MATRIX` in `providers/proxmox/provisioning.py` (exposed by `matrix_for_docs()`). Citations: pveum(1) "Privileges"
(https://pve.proxmox.com/pve-docs/pveum.1.html), chapter "User Management" (https://pve.proxmox.com/pve-docs/chapter-pveum.html), the API viewer permission
line of each call (https://pve.proxmox.com/pve-docs/api-viewer/index.html), PVE 9.0 release notes (https://pve.proxmox.com/wiki/Roadmap).

| Privilege | PVE 8 | PVE 9 | ICS uses it for | Where |
|---|---|---|---|---|
| Sys.Audit | yes | yes | node status/metrics/network | /nodes/<n> |
| VM.Audit, Pool.Audit, Datastore.Audit | yes | yes | read guests, pools, storages | pool, /vms/<tpl>, /storage/<s> |
| VM.Allocate | yes | yes | create/destroy guests (clone target) | /pool/<p> |
| VM.Clone | yes | yes | clone (source) | /vms/<tpl>, and /pool/<p> for in-pool clones |
| VM.PowerMgmt, VM.Config.{CPU,Memory,Disk,Network,Cloudinit,Options,HWType,CDROM}, VM.Snapshot(.Rollback) | yes | yes | configure/operate | /pool/<p> |
| VM.Migrate | yes | yes | opt-in (`allow_migrate`) | /pool/<p> |
| Datastore.AllocateSpace | yes | yes | disks/clones | /storage/<s> |
| SDN.Use | yes (bridges since 8) | yes | NIC on bridge/vnet | /sdn/zones/<zone>/<vnet> (`localnetwork` for classic bridges) |
| VM.Backup | yes | yes | Backup capability only | pool |
| VM.Monitor | yes | **removed** | guest agent (opt-in `guest_agent`) | - |
| VM.GuestAgent.Audit | - | yes | replaces VM.Monitor for read-only agent info (opt-in) | - |
| VM.GuestAgent.File*/Unrestricted, VM.Console, Sys.Console | n/a / yes | yes | never granted by a preset (custom + approval only) | - |
| Sys.Modify | yes | yes | ELEVATED: `cicustom` only | / |

## Who enforces what
| Control | Enforced by |
|---|---|
| Pool membership, storage allowlist, bridge/vnet allowlist, clone sources by VMID, token privilege separation, no ACL/user/realm admin | **Proxmox** (ACL paths + privsep) |
| Ownership tags, protected guests (incl. the ICS VM, which Proxmox cannot "deny"), pool/storage/network re-checks per mutation | **ICS** broker (existing `ProxmoxMutations`) |
| **Authorised nodes** | **ICS (application-enforced).** Proxmox pool ACLs do not restrict which node a pooled guest is created/cloned/migrated to; Proxmox only scopes node *visibility* (Sys.Audit). Policy field `scope.nodes` is persisted; drift reports `node_reach` (online nodes outside the allowlist where an authorised storage exists). Broker wiring (`EndpointScope.nodes`) is being added by the integration agent. |
| VMID ranges, guest types, CPU/RAM/disk caps | **ICS only** - cannot be expressed in Proxmox ACLs. `provisioning/enforce.py` implements and tests the checks; **not yet wired into the broker.** |

## Tested (simulator)
connection (ticket + token), failed auth, TLS pin mismatch (no request sent), discovery of the owner-shaped cluster (6 nodes, PVE06-Storage/ha-zfs/PBS1,
officeunbound@pam, templates 9612/131, ICS VM 126), exact plan contents, node/storage restriction (token has nothing on pve01/ha-zfs/PBS1//), authorised
template clone, unauthorised clone (other pool / ha-zfs / PBS1 / unlisted template) refused by Proxmox even with a widened ICS scope, destroy outside the pool,
token creation/revocation, privsep intersection, permission drift (missing / unexpected / forbidden / node reach), reconcile restoring only the stored policy,
token-failure detection + audit, cross-cluster isolation, high-risk approval (two approvers, no self-approval), temporary-credential discard (success, failure,
reject, 15-minute expiry), rollback on failure, hash-bound apply, role/user collisions, forbidden/elevated/full-admin rules, PVE 8 vs 9 matrix, Mode B script
run twice through a fake `pveum`/`pvesh` shim (second run: zero changes and zero write calls), conflict abort, wrong-major abort, rollback script, package
import validation (foreign token, over-privileged token), Mode A and Mode B ending in identical roles/ACLs, rotate, revoke, no secrets in packages/audit/API/DB.

## Awaiting the real cluster (NOT verified)
* Exact privilege names/paths and the clone permission model on PVE 9.2 (the matrix is from documentation; the simulator encodes the same assumptions).
* `pvesh get /access/acl|/access/users?full=1` output shapes, key order of `--output-format json`, and the script's grep-based parsing of them.
* Whether a privsep token can read `/access/permissions` (own) with only the granted privileges, and what paths that call lists with inheritance (drift's "covered" heuristic).
* `pveum user token add --output-format json` field names (`value`).
* TOTP/2FA on the admin user (ticket login cannot satisfy it - use a privileged token), and ticket lifetime: a PVE ticket is valid ~2 h and cannot be revoked
  by the client; `discard()` removes it from ICS memory only. Prefer a short-lived privileged API token for Mode A.
* Alerting: token failure/drift currently produce audit events and the endpoint-policy status; routing to alert channels is not wired.
* Broker enforcement of nodes/VMID ranges/caps (above). Migration chain position (0007l after 0006a).
