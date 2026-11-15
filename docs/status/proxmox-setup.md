# Proxmox access for the ICS (run on a Proxmox node as root — by the owner, not by Claude)

Two separate identities (ADR-0002). Neither is root@pam; both tokens are privilege-separated.
Check privilege names against your version first: `pveversion` and `pveum role list` (PVE 9 renamed some VM.* privileges).

## 1. Read-only inventory (deferred by owner 2026-11-15)
```sh
pveum user add ics-inventory@pve --comment "Office Unbound ICS read-only inventory"
pveum user token add ics-inventory@pve inventory --privsep 1     # shows secret ONCE
pveum acl modify / --users  ics-inventory@pve           --roles PVEAuditor
pveum acl modify / --tokens 'ics-inventory@pve!inventory' --roles PVEAuditor
```
PVEAuditor = Sys.Audit, VM.Audit, Datastore.Audit, Pool.Audit, SDN.Audit, Mapping.Audit (read-only).

## 2. Lab pool for integration spikes (approved in principle)
Pick: node `<NODE>`, storage `<STORAGE>`, an isolated bridge/VLAN `<BRIDGE>` that the ICS (192.168.22.167) can reach but that has no inbound path from the internet.
```sh
pveum pool add ou-lab --comment "Office Unbound lab - isolated"
pveum user add ics-lab@pve --comment "Office Unbound ICS lab provisioner"
pveum user token add ics-lab@pve lab --privsep 1
pveum role add OULabProvisioner --privs "VM.Allocate VM.Clone VM.Audit VM.PowerMgmt VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Snapshot VM.Snapshot.Rollback VM.Migrate Pool.Audit"
for p in --users\ ics-lab@pve "--tokens ics-lab@pve!lab"; do
  pveum acl modify /pool/ou-lab $p --roles OULabProvisioner
  pveum acl modify /storage/<STORAGE> $p --roles PVEDatastoreUser
  pveum acl modify /sdn/zones/localnetwork/<BRIDGE> $p --roles PVESDNUser
done
```
Then create one Ubuntu 24.04 cloud-init template **inside the pool** (`qm create … --pool ou-lab`, `qm set … --template 1`). The ICS clones only from templates in `ou-lab` and only creates VMs in `ou-lab`.

## 3. Hand-off (no secrets in chat)
On the ICS host:
```sh
sudo install -d -m 0700 /etc/office-unbound/bootstrap
sudo install -m 0600 /dev/stdin /etc/office-unbound/bootstrap/pve-inventory.token   # paste secret, Ctrl-D
```
Also record, in `docs/status/authorized-endpoints.md`: API URL (`https://<host>:8006`), token id, node/storage/bridge names, and the TLS fingerprint obtained **out of band** on the node:
`openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256`

## 4. Privilege analysis update (agent A, 2026-11-15; see provider-proxmox.md)
The role above gained VM.Snapshot, VM.Snapshot.Rollback, VM.Migrate (snapshot/rollback/migrate verbs) and Pool.Audit (pool membership; optional). Do NOT grant VM.Console/VM.Backup (unused).
Never grant the provisioning token any mutating privilege on the ICS's own VM; the ICS also refuses to mutate it by NIC MAC / SMBIOS UUID. Each bridge a NIC may attach to needs SDN.Use (`pveum acl modify /sdn/zones/localnetwork/<bridge> --tokens '<token>' --roles PVESDNUser`).
