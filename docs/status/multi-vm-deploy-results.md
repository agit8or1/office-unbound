# Multi-VM deployment through the ICS on real Proxmox (2026-11-19)

Status vocabulary: ADR-0000. **Milestone: first repeatable multi-VM deployment of the core stack (identity, edge, files, Office) through the
production ICS onto the real cluster, with every health check green and a clean destroy.** Mail/groupware, chat, meetings and telephony are
NOT part of this result (see "Not claimed").

## What was deployed
Spec (sample deployment, `custom` profile, 5 users), created by the operator `claude-e2e` through the production ICS (127.0.0.1:8088) with the
normal path: `POST /deployments/plan` -> `deployment.create` plan -> approval -> durable job -> hash-chained audit.

| VM | Components | What runs |
|---|---|---|
| `c-000000000000-<slug>-id` | identity, edge | OpenLDAP (LDAPS), PostgreSQL 16, Keycloak 26.8.2 (signed OCI, rootless Podman), nginx edge with deployment TLS |
| `c-000000000000-<slug>-files` | files, office | OpenCloud 9.1.0 (signed OCI), Office Unbound Docs / Collabora (signed OCI, `SYS_CHROOT` only) |

Cluster `agit8or1`, node pve06, pool `officeunbound-pve06`, storage `PVE06-Storage`, bridge `vmbr0`; clone source = golden image v7
(Ubuntu 24.04, template VM 148, signed manifest v7, node agent 0.5.0-ou9). VM 126 (the ICS) is protected and was never touched.

## Results (executed, from the ICS jobs table and `GET /checks`)
| Deployment | ICS | Create job | Health checks (6) | Destroy job | Checks after destroy |
|---|---|---|---|---|---|
| e2e-fo7 | 0.4.7 (41d26d0) | succeeded, 269 s (15:55:26-15:59:55Z) | 6/6 ok | succeeded, 14 s | 0 left, 0 open incidents |
| e2e-fo8 | 0.4.8 (54fdea0) | succeeded, 267 s (17:11:16-17:15:42Z) | 6/6 ok | succeeded, 14 s | 0 left, 0 open incidents |
| e2e-fo9 | 0.4.9 (61df4d3) | succeeded, 314 s (20:13:56-20:19:10Z) | 6/6 ok | succeeded, 17 s | 0 left, 0 open incidents |

Health checks of each run: `keycloak-ready` (HTTP 200, `"UP"`), `keycloak-oidc` (HTTP 200), `ldaps-tls` (TLS 1.3, certificate valid for
`ldap.<domain>`), `edge-tls` (TLS 1.3, certificate valid for `auth.<domain>`), `opencloud-status` (HTTP 200), `wopi-discovery` (HTTP 200).

**3 of 3 since the Office fix (0.4.7).** Before it, 15 `deployment.create` jobs ran since 2026-11-18 19:44Z: 1 succeeded, 14 failed. Each
failure stopped at a defect that was root-caused and fixed: VMID ownership check, volume file writer (rc 127, then bad params), Keycloak unit
start, a Proxmox API timeout, apt install timeout and held packages (exact pins), OpenCloud health body match, the Collabora unit on a rootless
private network (KI-4: units moved to host networking), Collabora `wopi-discovery` timeout (document processes could not chroot with an empty
capability bounding set: `SYS_CHROOT` added). Details and evidence per run: `docs/status/host-changes.md` (2026-11-19 rows) and
CHANGELOG 0.4.3-0.4.7.

## Not claimed
- Mail and groupware (gromox, webmail, CalDAV/CardDAV, ActiveSync/EWS/MAPI) are not deployed by the ICS yet: the `groupware` component has
  packages and health checks but no configuration runbook. Next work item.
- Chat, meetings and telephony: not deployed (unsigned/placeholder artifacts, see `fullstack-readiness.md`).
- No public DNS/ACME: the deployment domain is `<slug>.example` with the deployment CA; external access and external mail need the owner's
  public IP and domain.
- No per-customer network isolation (SDN) on the cluster yet (P2.10), and no second customer in parallel.
- Upgrade and rollback of a running multi-VM deployment are not yet demonstrated on real VMs.
