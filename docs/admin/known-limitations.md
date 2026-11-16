# Known limitations

Sources: [STATUS.md](../status/STATUS.md), [ARCHITECTURE.md](../ARCHITECTURE.md) section 4, and the evidence documents cited per page.

## Platform
- Pre-alpha, lab only. One host; customer stacks run in systemd-nspawn on the ICS host, not on Proxmox VMs. Clean-room reinstall of the whole stack is not yet re-run.
- Proxmox: automatic and customer-approved permission setup, the credential vault and customer approval links are simulator-proven only ([connecting-proxmox.md](connecting-proxmox.md)). The provider ran a full VM lifecycle once on one real node, but **no customer deployment has run end to end** (Implementing; see [deploying-a-customer.md](deploying-a-customer.md)). Component artifacts are unpinned, so real-catalog plans are non-executable by design. The console wizard has no recorded real-cluster registration.
- Collabora own build ("Office Unbound Docs") is Implementing and only lab-tested; other labs used the vendor CODE image. Chat, meetings and telephony are lab prototypes without ICS integration; anti-spam (rspamd/ClamAV) and archiving are **Planned** ([lab-proven-components.md](lab-proven-components.md)).
- Backup product (scheduling, encryption, off-host copies, retention, RPO): **Integrated in lab** for customer tiers ([backup-product-results.md](../status/backup-product-results.md)); the ICS controller tier of it was not run, second-copy replication and S3 backends are **Planned**, and ICS controller backups are not yet encrypted, scheduled or copied off-host ([backup-and-restore.md](backup-and-restore.md)).
- No HA ICS and no automated cut-over on main. A warm standby with fenced, operator-triggered promotion is in the code base (lab-proven; enabled by deploying a standby): [ICS recovery and warm standby](ics-recovery-and-standby.md).

## Clients and user experience
- New Outlook for Windows and Outlook mobile cannot use MAPI/EWS against a non-Microsoft server (IMAP/SMTP only). Classic Outlook and Outlook for Mac are the targets, but **no real Outlook, phone or Thunderbird client has been tested**.
- Webmail SSO is proven in the lab on two nodes; the Keycloak key follower is a script with no ICS action or health check, and the Gromox token-claims patch is not deployed ([lab-proven-components.md](lab-proven-components.md)). Other protocols still use the LDAP password.
- Device onboarding profiles are unsigned and untested on real devices.
- Migration assessment has never run against a real Microsoft 365 or Google tenant, and the IMAP mail migration engine is lab-proven for one mailbox only, with no calendar, contact, file or ICS-orchestrated migration ([migration.md](migration.md)).

## Operations and security
- Pushover and SMS alert channels cannot be enabled (ADR-0007). Webhook channel tested only locally.
- Revocation gaps and the lack of mailbox purge/export: see [users-and-access.md](users-and-access.md).
- Removal actions exist for checks, channels, agents, maintenance windows and plans but have not been used on a running lab controller; no mailbox purge and no general demo-data purge tool.
- No separate node revoke, password-change endpoint, off-host audit head export, privileged executor process, or key-generation tooling.
- Real restart of `mariadb`/`nginx` through the agent and the monitoring UI in a browser were not exercised.
- Legal review items (GPL-2.0-only gromox files, trademarks, AGPL section 13, fonts) are open: [third-party-inventory.md](../status/third-party-inventory.md).
