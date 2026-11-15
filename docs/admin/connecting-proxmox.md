# Connecting Proxmox

Evidence: [proxmox-setup.md](../status/proxmox-setup.md) (commands), [provider-proxmox-real.md](../status/provider-proxmox-real.md) (first real contact with
one PVE 9.2 node, including the owner's ACL remediation), [authorized-endpoints.md](../status/authorized-endpoints.md), ADR-0002/0009.

**What works today:** read-only inventory against a real cluster (probe + discovery, GET only, TLS pinned). **What does not exist yet:** any Proxmox
mutation (clone/configure/power/destroy). The deployment engine is tested only against a fake provider ([deployment-engine.md](../status/deployment-engine.md)).
The in-UI endpoint provisioning modes and deployment wizards are **In development**: do not rely on them.

## Principles
- Two separate identities, neither `root@pam`, both **privilege-separated** tokens: `inventory` (read-only) and optional `provision` (pool-scoped). Mutations refuse if only `inventory` exists.
- With privsep, token permissions are the **intersection** of user and token ACLs: grant every ACL to both the user and the token.
- Check privilege names on your version first: `pveversion` and `pveum role list` (PVE 9 renamed some `VM.*` privileges).
- Run all `pveum` commands on the Proxmox node as root, by the infrastructure owner. Never paste a token secret into chat or tickets (this happened once in the lab and forced a rotation).

## 1. Read-only inventory token
```sh
pveum user add ics-inventory@pve --comment "Office Unbound ICS read-only inventory"
pveum user token add ics-inventory@pve inventory --privsep 1     # shows secret ONCE
pveum acl modify / --users  ics-inventory@pve           --roles PVEAuditor
pveum acl modify / --tokens 'ics-inventory@pve!inventory' --roles PVEAuditor
```
(From proxmox-setup.md. The lab's real endpoint used a differently named user/token with pool/storage/node-scoped ACLs, per authorized-endpoints.md.)

## 2. Provisioning pool and role (scoped)
```sh
pveum pool add ou-lab --comment "Office Unbound lab - isolated"
pveum user add ics-lab@pve --comment "Office Unbound ICS lab provisioner"
pveum user token add ics-lab@pve lab --privsep 1
pveum role add OULabProvisioner --privs "VM.Allocate VM.Clone VM.Audit VM.PowerMgmt VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options"
for p in --users\ ics-lab@pve "--tokens ics-lab@pve!lab"; do
  pveum acl modify /pool/ou-lab $p --roles OULabProvisioner
  pveum acl modify /storage/<STORAGE> $p --roles PVEDatastoreUser
  pveum acl modify /sdn/zones/localnetwork/<BRIDGE> $p --roles PVESDNUser
done
```
Create a cloud-init **template inside the pool**; the ICS clones only from templates in the allowed pool. Do not grant `VM.Console` (unnecessary; it was
removed from the real role). The first real probe also needed `SDN.Use` on the bridge and `Pool.Audit` on the pool.
The real pve06 ACLs were applied by the owner and verified through the ICS probe ("missing for provisioning: none; unnecessary: none"); the exact commands
used there are not in the repo, so the block above is the documented template (proxmox-setup.md), not a transcript.

## 3. Self-VM protection (lesson from the real cluster)
The first probe showed the token held mutating rights on the **ICS's own VM** (VM 126), because the VM sat in the provisioning pool and pool rights propagate.
Required state, verified after owner remediation (provider-proxmox-real.md):
- The ICS VM is **not** in the provisioning pool and has at most audit-only ACLs (`PVEAuditor`) on `/vms/<vmid>`.
- Verify with `pveum user token permissions <user> <tokenname>` and the ICS probe, not by assumption.
- Independently of ACLs, the provider rule (ADR-0009) is that the ICS refuses to mutate its own VM. That rule is design; it becomes enforceable code only once mutations exist.

## 4. TLS fingerprint, verified out of band
The ICS never trusts on first use. Obtain the fingerprint **on the node console**, not over the network path the ICS will use:
```sh
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256
```
Register the endpoint with that SHA-256 (or the cluster CA PEM). Compare the value shown in the plan with the console value before approving
(`endpoint.register` is high risk: two approvers). In the lab the owner confirmed the pve06 leaf fingerprint this way before the first authenticated call.

## 5. Hand-off of the secret
On the ICS host (no secret in chat):
```sh
sudo install -d -m 0700 /etc/office-unbound/bootstrap
sudo install -m 0600 /dev/stdin /etc/office-unbound/bootstrap/pve-inventory.token   # paste secret, Ctrl-D
```
Register through an `endpoint.register` plan: `name`, `type: proxmox`, `base_url`, `token_id` (`user@realm!tokenname`), `token_secret`, and `ca_pem` or
`fingerprint_sha256`. The secret is stored AES-GCM-encrypted with AAD bound to the URL, token id, fingerprint and CA, so editing the trust anchor in the
database makes it undecryptable. Record the endpoint (no secrets) in `docs/status/authorized-endpoints.md`.

## 6. Token rotation
Rotate after any exposure and periodically. **Status: the Proxmox side uses standard `pveum`; the ICS has no dedicated rotate action, and rotation has not
been rehearsed in the lab** (it was a recorded open owner item after a secret was pasted in chat).
1. On the node: `pveum user token remove <user> <tokenname>`, then `pveum user token add <user> <tokenname> --privsep 1` (secret shown once), then re-apply the token ACLs from sections 1-2 (a recreated token has no ACLs).
2. Register the new secret with a new `endpoint.register` plan (two approvers) and re-run the probe.
3. Delete the old bootstrap file and confirm with `pveum user token list <user>` that only the intended token exists.
