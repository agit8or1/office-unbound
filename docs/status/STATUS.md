# Office Unbound — status

**Milestone:** Phase 1 core proof largely done; Phase 2 (orchestration) + Phase 3 (UX) in progress. Updated 2026-11-15. Public roadmap: ROADMAP.md / docs/progress.json.
**Constraints:** ADR-0007 zero mandatory licensing cost / no artificial limits. Proxmox out of scope until owner re-enables (lab = isolated systemd-nspawn on ICS host, zone `oulab`).

## Component status (ADR-0000)
| Component | Status | Evidence |
|---|---|---|
| ICS backend (auth/TOTP, vault, HMAC hash-chained audit, typed actions, 2-approver plans, jobs, PVE read-only client) | Tested (unit/integration; 329 tests on main as of 2026-11-15 19:05 UTC) | security-review-ics-2026-11-15.md incl. remediation; service `ics` on 127.0.0.1:8088 |
| ICS console (Vue, redesigned shell/dashboard/users) | Integrated in lab — deployed 2026-11-15 | vitest 32/32, typecheck, build; screenshots docs/screenshots/ |
| ICS monitoring, alerts, node agent, remediation | Integrated in lab | ics-monitoring-results.md; review fixes H1, H2, M1–M4, Lows merged |
| ICS identity lifecycle (create / update_groups / disable+VERIFY / enable / delete / reconcile) | Integrated in lab | user-lifecycle-results.md: acceptance script PASS (all paths refused <= 7 s), pytest suite; open gaps: OpenCloud app tokens resurrect on enable, ActiveSync wipe, Gromox open-session kill is a quarantine workaround |
| Proxmox pve06 (real) | Read-only probe verified; provider broker + mutations implemented vs simulator, integration in progress | provider-proxmox-real.md, provider-proxmox.md |
| Groupware: own source build of gromox 3.13 + sync/dav/web | Integrated in lab | groupware-lab-results.md — 57 automated checks pass (lead re-run): MAPI/HTTP Connect, EWS, ActiveSync, Autodiscover, IMAP/SMTP, CalDAV/CardDAV, shared mailbox, restart, export/import restore; 7 users (no cap) |
| Groupware ↔ OpenLDAP single user store | Implementing | groupware-ldap-results.md (pending) |
| Identity: OpenLDAP + Keycloak 26.8.2 | Integrated in lab | identity-files-lab-results.md (T01 36/0) |
| Files: OpenCloud 9.1.0 | Integrated in lab | T02 11/0 incl. restart, T05 versions 9/0 |
| Documents: Collabora via WOPI | Integrated in lab with vendor CODE (lab-only) | T03 28/0 standalone, T04 13/0 (real edit → PutFile → content verified). KI-1 below |
| Collabora own source build (unlimited, rebranded) | Implementing | docengine-build-results.md (pending) |
| Desktop sync engine (opencloudcmd 4.0): upload/download/offline/conflict/delete | Integrated in lab | T07 11/0 |
| Backup → restore to separate machine: files tier | Tested in lab | restore-drill-results.md: 18 s restore, content + version history byte-identical |
| Backup → restore to separate machine: identity tier | Tested in lab | online backup; 79 s restore; logins via restored KC+LDAP, DB-only canary, identical realm keys + entryUUIDs |
| GUI desktop client, mobile, real Outlook clients | Planned (manual) | blueprints/lab/tests/MANUAL-CHECKLIST.md |
| Build/release pipeline | Implementing (design ADR-0008; first recipe = Collabora) | |
| MSP center, migration, chat/meetings | Planned | |

## Known issues
- KI-1 (diagnosed): ~5 s window after OpenCloud restart before the editor app re-registers; tests now wait on `/app/list`; ICS check must use it. No data loss.
- KI-2: LDAP lock alone does not end Keycloak SSO/offline refresh tokens (>420 s). Deprovisioning must revoke in Keycloak (<1 s measured).
- KI-3: Collabora CODE in nspawn runs without chroot jails (unshare fails in unprivileged container) — lab-only acceptable; production VM must have jails.
- Lab install scripts: clean-room one-pass re-runs of identity, files, office (vendor + own editor) and groupware DONE on fresh machines in a separate domain (A22), 12 script fixes, all tiers idempotent; see docs/status/clean-room-results.md. Not covered: t07 desktop sync, manual checklist, collab/pbx spikes.

## Open owner items
1. Gateway resolver 192.168.22.1 SERVFAILs officeunbound.com (local workaround in host-changes.md).
2. Counsel questions consolidated in third-party-inventory.md (GPL-2.0-only gromox files, trademarks, AGPL §13, ONLYOFFICE §7, fonts).
3. Proxmox access when ready (proxmox-setup.md).

## Next tasks
- Integrate monitoring/remediation demo (acceptance 15–16), Collabora own build, Gromox↔LDAP.
- ~~ICS provisioning action: one user lifecycle~~ done (user-lifecycle-results.md); next: OpenCloud app-token revoke path, ActiveSync wipe, mailbox purge/export action, clean-room re-run.
- Restore drill for groupware tier to separate machine; clean-room reinstall (22).
- Fix monitoring security review findings (security-review-ics-monitoring-2026-11-15.md: H1 agent idle-connection DoS, H2 approval mode ineffective, M1–M5) once user-lifecycle work lands.
- Rebranding patch queues + package recipes for gromox stack (ADR-0008).
