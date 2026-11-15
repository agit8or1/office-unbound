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
| Token rotation action | **Planned** (rotate on the Proxmox side, then update the endpoint; not rehearsed) |

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
Rotate after any exposure (the real token was pasted in chat and rotation is still an open owner item) and periodically. There is no dedicated ICS rotation action (**Planned**) and rotation has not been rehearsed.
1. On the node: `pveum user token remove <user> <tokenname>`, `pveum user token add <user> <tokenname> --privsep 1`, then re-apply the token ACLs from sections 1-2 (a recreated token has none).
2. Submit an `endpoint.update` with the new secret (high risk, two approvers) and check the probe result.
3. Confirm with `pveum user token list <user>` that only the intended token exists.

## Known real-cluster caveats
- Thin pool overcommit (15.17 TiB provisioned on 10.91 TiB physical, autoextend off) is a warning; plans use physical space ([troubleshooting](troubleshooting.md)).
- No VLAN-aware bridge or SDN zone yet, so tenant network isolation is not available (the plan carries a `no_vlan_isolation` warning).
- PVE `rrddata` metric field names follow the PVE 8 docs and were not confirmed on the real cluster.
