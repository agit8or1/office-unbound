# Proxmox — first real-cluster contact (pve06), 2026-11-15

Endpoint `https://192.168.22.17:8006`, token `officeunbound@pam!ics` (privsep). TLS: leaf SHA-256 `AD:51:9B:27:21:C0:0B:4F:83:3D:4C:AD:11:99:2B:BB:DF:66:F2:39:F7:65:07:23:A6:54:EB:D5:1A:0E:B1:CA` presented by the node and **confirmed by the owner out of band** on pve06 (`openssl x509 -in /etc/pve/local/pve-ssl.pem …`). Probe = ICS `ProxmoxReadClient` (GET-only, pinned), run from the ICS host.

## Observed (read-only)
| Item | Result |
|---|---|
| Version | PVE **9.2.21** (release 9.2) |
| Cluster | 6 nodes online: pve01, pve2, pve3, pve04, pve05, pve06 — token sees details only for **pve06** (56 cores, 251.5 GiB RAM, 26.5 % CPU, 117.6 GiB used, uptime 45 d) |
| Storage | `PVE06-Storage` lvmthin, content `images,rootdir`, 1538 / 11140 GiB used. No `snippets`/`iso`/`import` content → no cicustom snippets, no image import via this storage |
| Guests visible | 1: qemu **126 `office-unbound`**, running, not a template, 24 cores / 16 GiB, net0 `bridge=vmbr0` MAC BC:24:11:E7:F0:24, cloud-init drive, DHCP — **this is the ICS host itself** (matches ICS eth0 MAC) |
| Pool `officeunbound-pve06` | `GET /pools/…` → **403** (no `Pool.Audit`) |
| Effective privileges | provisioning set present except **`SDN.Use`** (NIC attach to vmbr0 will fail); `VM.Console` granted but unnecessary |

## Defect found and fixed
`ProxmoxReadClient` read `iter_raw()` (still gzip-encoded) → every compressed response (e.g. `/nodes`) failed with "unexpected response body"; only small uncompressed ones (`/version`) worked. Fixed to `iter_bytes()` with the size cap on the **decompressed** stream (decompression-bomb guard). Regression tests `test_gzip_encoded_responses_are_decoded` (fails on the old client) and `test_gzip_bomb_is_capped_on_decompressed_size`; mock now gzips like pveproxy.

## Required before provisioning (owner)
1. **Self-protection:** remove the mutating ACL on `/vms/126` (the ICS VM). At most `PVEAuditor` there for self-visibility. The ICS also refuses any mutation of its own VM regardless of ACLs (provider rule, ADR-0009).
2. `SDN.Use` on `/sdn/zones/localnetwork/vmbr0` (role `PVESDNUser`).
3. `Pool.Audit` on `/pool/officeunbound-pve06` (role `PVEPoolUser`).
4. Drop `VM.Console` from the role.
5. A cloud-init **template** inside the pool (Debian 12 / Ubuntu 24.04 cloud image, checksum-verified), or a directory storage with `import,snippets` content for the ICS to build its own.
Privsep reminder: token permissions are the intersection of the user's and the token's ACLs — grant to both.

## Owner remediation applied (2026-11-15) — verified
Owner ran the ACL changes on pve06; effective token permissions (`pveum user token permissions officeunbound@pam ics`) and the ICS probe now show:
- `/vms/126` (the ICS VM): **audit-only** (Datastore/Mapping/Pool/SDN/Sys/VM/GuestAgent .Audit). VM 126 removed from pool `officeunbound-pve06`, so pool rights no longer propagate to it.
- `/sdn/zones/localnetwork/vmbr0`: SDN.Use + SDN.Audit. `/pool/officeunbound-pve06`: Pool.Audit + VM lifecycle set. `VM.Console` removed from role `OfficeUnboundDeploy`.
- Template **VM 131 `ou-debian12-template`** (Debian 12 genericcloud, image SHA-512 verified on the node) in the pool — clone source.
- Probe: **missing for provisioning: none; unnecessary: none.**
Remaining owner items: rotate the token (secret was pasted in chat); later a VLAN-aware bridge or SDN zone for tenant isolation; thin-pool overcommit (15.17 TiB provisioned / 10.91 TiB physical, autoextend off).
