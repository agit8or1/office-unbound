# ICS host changes log

| Date | Change | Why | Revert |
|---|---|---|---|
| 2026-11-15 | `/etc/systemd/resolved.conf.d/10-officeunbound.conf`: route `~officeunbound.com` to 1.1.1.1/9.9.9.9 | Gateway resolver 192.168.22.1 returns SERVFAIL for officeunbound.com (public resolvers OK). Fix belongs on gateway (likely DNSSEC/blocklist in its resolver). | delete file, `systemctl restart systemd-resolved` |
| 2026-11-15 | apt: python3-venv, python3-pip, postgresql-16 (listens 127.0.0.1/::1 only) | ICS dev toolchain (user approved) | apt purge |
| 2026-11-15 | apt repos + packages: NodeSource node_22.x (nodejs 22.23.5), GitHub CLI (gh 2.104.0); keys in /etc/apt/keyrings | Frontend build, future git remote (user approved) | remove list + key files, apt purge |
| — | Docker deliberately NOT installed on ICS | avoid root-equivalent socket on control plane | |
| 2026-11-15 | Postgres roles `ics_owner` (migrations), `ics_app` (runtime, no UPDATE/DELETE on audit_events); databases `ics`, `ics_test`; `/etc/office-unbound/{ics.env,vault.key}` (root:administrator 0640, dir 0750; dev vault key, random 32 bytes) | ICS backend dev | `DROP DATABASE ics, ics_test; DROP ROLE ics_app, ics_owner;` rm /etc/office-unbound |
