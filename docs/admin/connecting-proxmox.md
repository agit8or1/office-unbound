# Connecting Proxmox

Evidence: [provider-proxmox-real.md](../status/provider-proxmox-real.md) (real PVE 9.2 cluster: probe, owner ACL remediation, scope-refusal tests, full VM lifecycle),
[provider-proxmox.md](../status/provider-proxmox.md) (provider, endpoint settings, safety rules), [proxmox-setup.md](../status/proxmox-setup.md) (original commands),
[authorized-endpoints.md](../status/authorized-endpoints.md), ADR-0002/0009.

## What is proven
| Capability | State |
|---|---|
| Read-only probe and inventory against a real node (TLS pinned, permissions checked) | **Verified** (one node of a 6-node cluster, PVE 9.2) |
| VM lifecycle through the provider on the real node: refuse wrong pool/storage/node/bridge and the ICS VM; clone a template, tag, configure, resize, start, snapshot, stop, destroy | **Verified** by the lead on one test VM (14 of 15 checks passed; the 15th, destroy right after stop, was fixed and the VM destroyed through the provider) |
| Endpoint settings (add, edit, disable, enable, remove), node allowlist, protected VMs | Implemented and tested (simulator and unit tests); the node allowlist refusal was also confirmed on the real node |
| Console guided setup (the wizard that registers an endpoint) | **In development**: deployed and tested against the API and simulator; a real registration through the wizard is not recorded in any evidence document |
| Deploying a customer stack to Proxmox end to end | **In development**: [deployment-engine.md](../status/deployment-engine.md); will stay so until `docs/status/first-real-deployment.md` exists (it does not yet) |
| Migrate, rollback verbs | Implemented against the simulator only; `migrate` needs `VM.Migrate`, not granted on the real cluster |
| Automatic (Mode A) or customer-approved package (Mode B) permission setup, permissions/drift view, credential vault pages | Implemented; **simulator-proven only**, never run on a real cluster (sections 8-11) |
| Token rotation actions (`credential.rotate`, `provider.token.rotate`) | Implemented; simulator/mock-proven only. The manual rotation in section 7 is the only path used on the real node |

## Principles
- Two separate Proxmox identities, neither `root@pam`, both **privilege-separated** API tokens: an **inventory** token (read-only) and an optional **provision** token (scoped to a pool). Without the provision token the endpoint is monitor-only and cannot create machines.
- With privsep, effective permissions are the **intersection** of the user's and the token's ACLs: grant every ACL to both the user and the token.
- Run all `pveum` commands on a Proxmox node as root, by the infrastructure owner. Never paste a token secret into chat or tickets (this happened once and forced a rotation).
- Check privilege names on your version first: `pveversion`, `pveum role list` (PVE 9 renamed some `VM.*` privileges).
- The console's setup check prints the exact `pveum` command for anything missing and also lists privileges that are more than ICS needs.

## 1. Read-only inventory token
```sh
pveum user add ics-inventory@pve --comment "Office Unbound ICS read-only inventory"
pveum user token add ics-inventory@pve inventory --privsep 1     # shows the secret ONCE
pveum acl modify / --users  ics-inventory@pve             --roles PVEAuditor
pveum acl modify / --tokens 'ics-inventory@pve!inventory' --roles PVEAuditor
```
Evidence: proxmox-setup.md section 1. The real endpoint used one token with pool/storage/node-scoped ACLs instead of `/`; a node on which the token lacks `Sys.Audit` is shown as "not managed" with unknown capacity (5 of 6 nodes on the real cluster).

## 2. Provisioning pool, role and ACLs (least privilege)
Applied by the owner on the real node as role `OfficeUnboundDeploy` on a pool dedicated to Office Unbound; the exact owner commands are not in the repo, so this block is the generalised template (privileges from `ics/ics/providers/proxmox/privileges.py`, command shape from proxmox-setup.md). The ICS probe reported "missing for provisioning: none; unnecessary: none" with this privilege set.
```sh
pveum pool add ou-pool --comment "Office Unbound managed machines"
pveum user add ics-deploy@pve --comment "Office Unbound ICS provisioner"
pveum user token add ics-deploy@pve deploy --privsep 1
pveum role add OfficeUnboundDeploy --privs "VM.Allocate VM.Clone VM.Audit VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback VM.Config.CPU VM.Config.Memory VM.Config.Network VM.Config.Disk VM.Config.Cloudinit VM.Config.Options VM.Config.HWType Pool.Audit"
for p in "--users ics-deploy@pve" "--tokens ics-deploy@pve!deploy"; do
  pveum acl modify /pool/ou-pool                      $p --roles OfficeUnboundDeploy
  pveum acl modify /storage/<STORAGE>                 $p --roles PVEDatastoreUser
  pveum acl modify /sdn/zones/localnetwork/<BRIDGE>   $p --roles PVESDNUser        # gives SDN.Use
done
```
- **`SDN.Use` on each bridge** the ICS may attach NICs to (first real probe: NIC attach would have failed without it). **`Pool.Audit` on the pool** (without it the pool read returned 403).
- Do **not** grant `VM.Console`, `VM.Backup`, `Sys.Console`, `Sys.Modify`, `Sys.PowerMgmt` or `Permissions.Modify` (reported as unnecessary). Add `VM.Migrate` only if you need migrate. `cicustom` snippets need `Sys.Modify` and are off unless the endpoint opts in.
- Create a cloud-init **template inside the pool** (the real cluster used a checksum-verified Debian 12 genericcloud image, VM `ou-debian12-template`); the ICS clones only from templates in an allowed pool. Without `snippets` content on the storage, cloud-init is limited to user, SSH keys and network fields.
- Verify the result, not your intentions: `pveum user token permissions ics-deploy@pve deploy` and the ICS probe.

## 3. Protect the ICS's own VM (lesson from the real cluster)
The first probe showed the token held mutating rights on the VM the ICS itself runs in, because that VM sat in the provisioning pool and pool rights propagate. Required state (verified after remediation):
- Remove the ICS VM from the pool. On the VM path (`/vms/<vmid>`) leave at most audit-only rights (`PVEAuditor`).
- List the ICS VM in the endpoint's **protected VMs**. Independently of ACLs the provider compares each guest's NIC MACs and SMBIOS UUID with the host's own and refuses to mutate a match; the probe warns `DANGER` when a token can mutate it. This refusal was exercised on the real cluster (power-off and snapshot of the ICS VM refused by the ICS).
- Pool membership is never ownership: the ICS only changes guests tagged `ou-managed` plus `ou-deployment-<id>` and refuses untagged guests (tested on the real node: it would not configure or destroy an untagged clone).

## 4. Trust: verify the TLS fingerprint out of band
The ICS never trusts on first use. On the **node console** (not over the path the ICS will use):
```sh
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256
```
Register the endpoint with that SHA-256 (or the cluster CA PEM). The setup check first reads the certificate the server presents, with no credential sent, so you can compare it with the console value before any token is entered.

## 5. Register the endpoint (needs two approvers)
Use **Integrations** or the dashboard's **Start guided setup** (optional; see [Operating](operating-the-ics.md)). The wizard probes, shows what it found, and files an `endpoint.register` plan (**high risk**: a requester plus two other approvers). Nothing is stored or contacted until it is approved.
Fields: name, `https://<host>:8006`, token id (`user@realm!tokenname`) and secret, the optional provision token, trust anchor, and the scope:
- **Pool, storage, networks, templates** the ICS may use (`vmbr1` = any VLAN, `vmbr1/20` = that VLAN only).
- **Nodes** (`allowed_nodes`): **deny by default**. A provision credential cannot be registered without at least one node; the ICS refuses to clone to, migrate to, or change guests on any other node, before contacting Proxmox (confirmed on the real cluster for a second node).
- Defaults (storage, bridge, VLAN, DNS, search domain, backup storage, approved OS images, packing policy `conservative|balanced|dense`).
Hand over secrets through the form, never in chat. Secrets are stored AES-GCM-encrypted and bound to the URL, token id and trust anchor, so editing the trust anchor in the database makes them undecryptable.
Record the endpoint (no secrets) in `docs/status/authorized-endpoints.md`.

## 6. Change an endpoint later
Typed plans, bound to the endpoint's current trust anchors (changing them between approval and execution fails the job):
| Action | Risk | Notes |
|---|---|---|
| `endpoint.update` | normal for display name / enabled only; **high** for URL, trust, credentials, scope lists, defaults, protected VMs | A connection change is re-probed with the NEW settings first; nothing is saved if that fails |
| `endpoint.disable` / `endpoint.enable` | normal | A disabled endpoint is not contacted and refuses all mutations |
| `endpoint.remove` | high | Needs the endpoint name typed as confirmation; refused while deployments reference it unless `force_detach` is approved. Credentials are destroyed; inventory history is kept but hidden |
| `inventory.refresh` | low | Inventory also refreshes every 300 s |

## 7. Token rotation
Rotate after any exposure (the real token was pasted in chat and rotation is still an open owner item) and periodically. The ICS rotation actions of section 11 exist but have only run against the simulator; this manual path has not been rehearsed on the real cluster either.
1. On the node: `pveum user token remove <user> <tokenname>`, `pveum user token add <user> <tokenname> --privsep 1`, then re-apply the token ACLs from sections 1-2 (a recreated token has none).
2. Submit an `endpoint.update` with the new secret (high risk, two approvers) and check the probe result.
3. Confirm with `pveum user token list <user>` that only the intended token exists.

## 8. Providing the permissions: automatic (Mode A) or customer-approved package (Mode B)
**Simulator-proven only.** Evidence: [provider-provisioning.md](../status/provider-provisioning.md) and [provider-stack-integration.md](../status/provider-stack-integration.md) say plainly that none of this ran on a real cluster; sections 1-3 above remain the only hand procedure that was applied to a real node. The simulator is a test double, so exact privilege names, `pvesh` output shapes and clone permission behaviour on PVE 9.2 are **not verified**.
Both modes compute the same design: service user `<name>@pve` (never PAM, no password), two privilege-separated tokens (inventory with the monitor role only; provision with the rest), roles `OfficeUnboundMonitor/Deploy/Storage/TemplateClone/Network/Backup/Custom/FullAdmin` (an existing role with different privileges is never modified), and ACLs for the user and each token.
| | Mode A: automatic | Mode B: package |
|---|---|---|
| Action | `provider.provision.apply` (**high**, two approvers) | `provider.provision.package` (normal; high for full-admin or elevated) |
| Who runs it | The ICS, using a **temporary admin credential** you supply for this one job | The Proxmox owner runs the generated `provision.sh` on a node (with `rollback.sh`, `commands.txt`, `validate.txt`, report) |
| Credential handling | Held in the vault for at most 15 minutes, used only inside the job, destroyed when the job ends, is rejected, or expires; never in plans, audit or results | No admin credential ever reaches the ICS; the owner then imports the resulting token with `provider.credential.import` (normal) |
| After | Token secrets go to the credential vault | Import is refused for a foreign or over-privileged token |
Start with the read-only `provider.provision.plan_preview` (low risk): it lists every role, path and privilege, any conflicts, and any elevated privilege with its reason. Apply is bound to the previewed plan hash and refuses if the cluster changed since. A failed apply rolls back what that run created.
Never granted by any preset: `Permissions.Modify`, `User.Modify`, `Group.Allocate`, `Realm.*`, and the built-in `Administrator`/`PVEAdmin` roles. `Sys.Modify` (for `cicustom`) only as an explicit elevated privilege with high-risk approval; full cluster administration needs `acknowledge_full_admin` and still withholds those items.
Console: **Infrastructure > Providers > Proxmox** (list, connect wizard, dashboard, permissions, credentials; [providers-ui.md](../status/providers-ui.md): typechecked, unit-tested and screenshotted against a dev-only mock; **not exercised against a real backend** by its author). The connect wizard's read-only discovery with temporary admin credentials (setup probe stage `discover`) is in main (commit `291bb1e`) and has no results document yet.
**Customer-owned clusters** can require the customer's approval of the permission design before anything is applied: see [Users and access](users-and-access.md#customers-scoping-and-external-approval-links). Limit: a Mode A plan waiting on a customer link outlives its 15-minute credential and must be re-planned; Mode B is the intended path.

## 9. What is enforced where
| Rule | Enforced by |
|---|---|
| Pool, storage and bridge allowlists, clone sources, token privilege separation | Proxmox ACLs |
| Ownership tags, protected VMs (including the ICS VM), per-mutation scope re-checks, **authorised nodes** | The ICS (Proxmox cannot restrict which node a pooled guest lands on) |
| VMID ranges, guest types, CPU/RAM/disk caps | Policy fields exist and the check code is tested, but it is **not yet wired into the provider** ("Not enforced yet"); do not rely on them |

## 10. Permissions view and drift
`GET /providers/{id}/permissions` (console: provider > Permissions) shows expected versus actual access, which side enforces each control, and the last verification. `POST /providers/{id}/permissions/check` (operator, read-only) re-checks live and reports missing, unexpected and forbidden grants, and online nodes outside the allowlist that still have an authorised storage. Drift and token failures are written to the audit log and the alert channels once per transition. `provider.permissions.reconcile` (high) restores only the **stored** policy, never a wider one. Evidence: provider-provisioning.md (simulator).

## 11. Credentials page
Console: provider > Credentials, `GET /credentials` (metadata only; secrets are never returned). Types and purposes: inventory, provision, temporary provisioning; status `active|expiring|expired|revoked|invalid|retired`; an alert is raised 14 days before expiry and at expiry. Actions: `credential.create|replace|revoke` (high), `credential.rotate` (normal; the new secret is authenticated against Proxmox before it is stored), `credential.test` (low). A replaced credential stays unusable for 7 days then its ciphertext is purged; a revoked one is destroyed immediately. `provider.token.rotate` and `provider.token.revoke` (high) act on the Proxmox side token. `GET /credentials/access-review` (approver) lists who used which credential, from the audit chain.
This **replaces** the manual rotation steps in section 7 once verified; until a rotation has been run against a real cluster treat section 7 as the tested path. Evidence: [credential-vault.md](../status/credential-vault.md) (executed against the test database and a mock Proxmox). Recovery cases (expired token, disabled service account, customer revoked access, lost vault key): [provider-access-recovery.md](../runbooks/provider-access-recovery.md). Encryption design: [Security](security.md).

## 12. Connect with SSH
Console: **Infrastructure > Providers > Proxmox > Connect with SSH** (also reachable from the connect wizard's first step; for later changes: the cluster's Permissions page > **Change with SSH**). Design and limits: [ADR-0014](../adr/0014-ssh-onboarding.md). Status: tested against a real OpenSSH server with faithful `pvesh`/`pveum` fakes; **not yet run against a real Proxmox node** ([ssh-onboard-results.md](../status/ssh-onboard-results.md) has the owner test checklist).

**What it does.** You log in to one node once (root, or a user that can run `sudo -n` without a password; password or pasted private key + optional passphrase). Office Unbound reads the cluster, you choose which node(s) it may reach and what it may do, it shows the exact commands, an approver other than you signs off (one approver; two if the plan widens an existing scope), and then it creates **its own** identities and discards your login:
- the Proxmox account `officeunbound@pve` (no Linux account), `OfficeUnbound*` roles, an optional pool (default `officeunbound`), ACLs and privilege-separated API tokens;
- on the node, a locked system account `ou-ics` whose only SSH key is generated by Office Unbound (the private key never leaves the vault) and is restricted to a forced command: `restrict,command="sudo -n /usr/local/sbin/ou-pve-helper"`. The helper only reads, rotates its own token and **narrows** its own permissions. Nothing it does can grant more.

**Steps.**
1. *Connect*: host, port, user, password or key. The credential goes straight into the vault (valid 30 minutes, one purpose, never shown again). Optional: the API address if it differs from the node, and this server's address (written as `from=` into the node's `authorized_keys`).
2. *Host key*: Office Unbound shows the node's SSH host-key fingerprint and the command to compare it. On the node's own console run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` and type the `SHA256:...` value into the page. Nothing else runs before you do; there is no trust-on-first-use.
3. *Discover*: read-only. It shows cluster name, nodes, storage, bridges, pools, templates and guest counts (guests are only counted). It also reads the node's API certificate over SSH and checks it against the certificate this server sees on port 8006. A mismatch stops the flow.
4. *Choose*: one node or the whole cluster, pool, storage, networks, templates, and the rights as plain choices: **See inventory only**, **Deploy into this pool**, **Import images**, or an advanced privilege checklist. Single-node scope must be the node you logged in to.
5. *Review*: the permission plan (roles, ACL paths, propagate flags, who enforces what), the node-side identity (account, key fingerprint, helper hash, sudoers text), every command that will run, and the risk. Approvers see the same list. **Approval level (owner decision 2026-11-16): onboarding is normal risk, so one approver who is not you (the requester) must approve; you therefore need a second console account with the approver role.** A plan that widens an existing integration's scope, or contains an elevated privilege, is high risk and needs two approvers; removing the access (offboarding) is high risk too.
6. *Apply*: the job reconnects with the pinned host key and runs only those commands. It verifies that the new token's permissions equal the plan exactly, that the new SSH key works and is refused for everything except the helper, registers the endpoint, and destroys your SSH credential. Any failure removes what this run created.

**API address and certificates.** The SSH address and the API address may differ (SSH to an internal address, API by your public host name, or the reverse); both must be the same node, which is verified. Over SSH the node's certificate is read (`/etc/pve/local/pveproxy-ssl.pem` when present, the custom/ACME certificate, else `pve-ssl.pem`) and compared with what Office Unbound itself sees on the API address. Trust is then recorded as: **public CA** (the API presents the node's certificate and its chain is publicly trusted for the host name: the issuing root and the host name are pinned, not the leaf, so Let's Encrypt renewals every 60-90 days do not break the integration), **cluster CA** (the cluster's own CA is pinned), or **fingerprint** (the leaf is pinned). If the API address presents a *different* certificate (a reverse proxy in front), the flow stops and shows both fingerprints; it continues only if the proxy's certificate chain is publicly valid for the host name and you confirm its fingerprint. A different certificate without a valid chain is a hard stop. TLS verification is never switched off.

**Re-running** with an existing integration re-uses the accounts and rotates the tokens (the plan lists them). **Widening** later (more nodes, storage or privileges) always asks for an administrator's login again, or use the Mode B package: the identities Office Unbound created cannot widen themselves.
**Single node vs whole cluster:** for a whole-cluster scope the SSH identity is installed only on the node you logged in to; `/etc/pve` and the API token are cluster-wide, so one node is enough. If that node is down the SSH helper is unavailable (the API token keeps working); a second node needs your login again.
**Remove everything it created:** Permissions page > **Remove SSH-created access** (needs your SSH login again; high risk, two approvers). It deletes the ACLs, tokens, user and roles Office Unbound created, optionally the pool if empty, and on the node the account, key, helper, config and sudoers file. Guests are never touched.

## Known real-cluster caveats
- Thin pool overcommit (15.17 TiB provisioned on 10.91 TiB physical, autoextend off) is a warning; plans use physical space ([troubleshooting](troubleshooting.md)).
- No VLAN-aware bridge or SDN zone yet, so tenant network isolation is not available (the plan carries a `no_vlan_isolation` warning).
- PVE `rrddata` metric field names follow the PVE 8 docs and were not confirmed on the real cluster.
