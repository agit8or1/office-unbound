# Known limitations

Sources: [STATUS.md](../status/STATUS.md), [ARCHITECTURE.md](../ARCHITECTURE.md) section 4, and the evidence documents cited per page.

## Platform
- Pre-alpha, lab only. One host; customer stacks run in systemd-nspawn on the ICS host, not on Proxmox VMs. Clean-room reinstall of the whole stack is not yet re-run.
- Proxmox: read-only inventory only. No clone/configure/power/destroy, no real deployment execution. Deployment wizards and endpoint provisioning modes are **In development**. Component artifacts are unpinned, so real-catalog plans are non-executable by design.
- Collabora own source build (unlimited, rebranded) is Implementing; labs used the vendor CODE image. Anti-spam (rspamd/ClamAV), archiving, chat/meetings/telephony: **Planned**.
- Product-grade backup (scheduling, encryption, off-host copies, retention, RPO) is **Planned**; see [backup-and-restore.md](backup-and-restore.md).
- No HA/standby ICS; no automated cut-over.

## Clients and user experience
- New Outlook for Windows and Outlook mobile cannot use MAPI/EWS against a non-Microsoft server (IMAP/SMTP only). Classic Outlook and Outlook for Mac are the targets, but **no real Outlook, phone or Thunderbird client has been tested**.
- Webmail has no SSO (grommunio-web lacks OIDC): users sign in with the same LDAP password. SMTP submission (587/465) is not configured on the lab host.
- Device onboarding profiles are unsigned and untested on real devices.
- Migration assessment has never run against a real Microsoft 365 or Google tenant, and no data-migration step exists.

## Operations and security
- Pushover and SMS alert channels cannot be enabled (ADR-0007). Webhook channel tested only locally.
- Revocation gaps and the lack of mailbox purge/export: see [users-and-access.md](users-and-access.md).
- No node revoke/disable, password-change endpoint, off-host audit head export, privileged executor process, or key-generation tooling.
- Real restart of `mariadb`/`nginx` through the agent and the monitoring UI in a browser were not exercised.
- Legal review items (GPL-2.0-only gromox files, trademarks, AGPL section 13, fonts) are open: [third-party-inventory.md](../status/third-party-inventory.md).
