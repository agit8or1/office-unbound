# Troubleshooting

Each entry is a real issue found in the lab, with the evidence document.

| Symptom | Cause / fix | Evidence |
|---|---|---|
| Editor (Collabora) unavailable for ~5 s after an OpenCloud restart (KI-1) | The editor app re-registers after restart. No data loss. Wait on OpenCloud `/app/list` listing CollaboraOnline; an ICS check for editing must use it | [STATUS.md](../status/STATUS.md) |
| Every Proxmox call except `/version` fails with "unexpected response body" | pveproxy gzips larger responses; old client read the raw stream. Fixed (decoded with a size cap on the decompressed stream). Make sure the ICS build includes it | [provider-proxmox-real.md](../status/provider-proxmox-real.md) |
| Proxmox probe: 403 on the pool, NIC attach would fail | Token lacked `Pool.Audit` on the pool and `SDN.Use` on the bridge. Grant to the user **and** the token (privsep intersection) | provider-proxmox-real.md |
| Token can mutate the ICS's own VM | VM in the provisioning pool. Remove it from the pool, audit-only ACL, list it as protected | [connecting-proxmox.md](connecting-proxmox.md) |
| Deployment plan refused for thin-pool capacity | Thin pools are judged on physical space and `thin_max_ratio_pct` (default 100). The real cluster was 15.17 TiB provisioned on 10.91 TiB physical with autoextend off: an owner item | provider-proxmox-real.md, [deployment-engine.md](../status/deployment-engine.md) |
| Restore: `Permission denied` on the uploaded archive in an nspawn machine | `PrivateUsers=pick` shifts uids; restore scripts chown to the container's shifted root (`stat -c %u <rootfs>/root`) | [restore-drill-results.md](../status/restore-drill-results.md) |
| Restored ICS: `status=203/EXEC Permission denied` | `umask 077` made release/venv unreadable; fixed (secrets 077, code 022). Ownership is re-applied by name because gids differ per host | restore-drill-results.md |
| OpenCloud panics "inotifywait is not installed" after restore | Package list drift; single list in `blueprints/lab/common/packages.env` used by install and restore | restore-drill-results.md |
| Restored slapd listening plaintext on all interfaces, Keycloak federation fails | `/etc/default/slapd` not in backup; now backed up and restore asserts an ldaps listener | restore-drill-results.md |
| Groupware import fails `allocate_message_id RPC failed` | `localhost` must resolve to `::1` (exmdb binds `[::1]:5000`); nspawn base has no `/etc/hosts` | restore-drill-results.md |
| Gromox export of one mailbox writes a 564-byte empty file | Quarantined mailbox (mode 000) unreadable by `gromox`; backup detects and handles it | restore-drill-results.md |
| Rootless Podman fails in nspawn (`create keyring`, `mount proc`, single-id mapping) | Lab-only accommodations: `keyring = false`, early `mount -t proc`, explicit subuid range inside the machine's 65536 ids. Not needed on a real VM | [guest-bootstrap-results.md](../status/guest-bootstrap-results.md) |
| Collabora jails unavailable in the lab | Unprivileged nspawn cannot `unshare` (KI-3). Production VMs must run with jails | STATUS.md |
| Disabled user still logs in via Keycloak (>420 s) | LDAP lock alone is insufficient (KI-2). Use `idm.user.disable` | STATUS.md, [users-and-access.md](users-and-access.md) |
| Agent unresponsive while an idle TCP connection is open | Fixed (handshake in worker thread, 10 s deadline, 32 connection cap). Update the agent | security review, monitoring |
| All remediation requests `expired` | Node clock more than 60 s ahead of the ICS; run NTP on nodes | monitoring security review |
| `/readyz` returns `ready:false` on a restored controller | Expected while passive (worker off) | [ics-recovery.md](../runbooks/ics-recovery.md) |
| Lab machine unreachable by name | Lab IPs are DHCP from zone `oulab`; `/etc/hosts` entries on the ICS must be updated | [host-changes.md](../status/host-changes.md) |
| Installer refuses: missing key while the database has data / key too short or a symlink / `0.0.0.0/0` / hostname outside the CA's constraints | By design; restore the key from backup, fix the argument, or (for a new name) use a new CA. Nothing is changed | [ics-installer-results.md](../status/ics-installer-results.md) |
| Login right after enrollment rejected, then 429 | TOTP codes are single use; wait for the next 30 s code. Clear throttling with `ics.cli unlock` | ics-installer-results.md |
| Provision credential cannot be registered / clone refused on a node | The endpoint's allowed nodes are empty or do not include it (deny by default) | [provider-proxmox.md](../status/provider-proxmox.md) |
| Destroy refused right after a stop on Proxmox | Fixed: the provider confirms with live status because the cluster cache lags a few seconds | provider-proxmox-real.md |
| Console login throttled | `sudo -u ics .venv/bin/python -m ics.cli unlock --username X` | ics/README.md |
