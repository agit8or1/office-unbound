# Office Unbound — status

**Milestone:** Phase 0 complete → Phase 1 (ICS foundation + spike preparation) in progress. Updated 2026-11-15.

## Component status (ADR-0000)
| Component | Status | Evidence / notes |
|---|---|---|
| ICS backend (auth, vault, audit, jobs, PVE read-only client) | Implementing | `ics/` — see test results in this file when recorded |
| ICS UI | Planned | after backend API contract stabilises |
| Proxmox inventory against a real cluster | Blocked | owner deferred token (proxmox-setup.md §1) |
| grommunio groupware | Researching | groupware-eval.md; licensing gate open (ADR-0003) |
| Keycloak + lldap identity | Researching | files-identity-eval.md, ADR-0004 |
| OpenCloud + Collabora | Researching | files-identity-eval.md, ADR-0005 |
| Lab spike blueprints | Implementing (not executable: no lab pool) | `blueprints/lab/` |
| Chat/meetings, migration, MSP center | Planned | per roadmap phases 4–7 |

## Open owner decisions / approvals
1. Proxmox: create `ou-lab` pool + scoped token (approved in principle) and later read-only inventory token — procedure in `proxmox-setup.md`. Need node/storage/bridge names.
2. grommunio licensing: Community is "up to 5 users, no support"; >5 users and rebranding unclear → written answer from grommunio GmbH or subscription/partner decision.
3. Collabora production licensing (CODE is lab-only).
4. Gateway resolver 192.168.22.1 SERVFAILs officeunbound.com — fix on gateway, then drop the local workaround (host-changes.md).

## Next tasks
- Integrate & review ICS backend slice (independent security review, Opus).
- ICS minimal UI on the backend API.
- When lab pool exists: run `blueprints/lab` spikes and record results in the capability matrix.
