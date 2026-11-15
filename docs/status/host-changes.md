# ICS host changes log

| Date | Change | Why | Revert |
|---|---|---|---|
| 2026-11-15 | `/etc/systemd/resolved.conf.d/10-officeunbound.conf`: route `~officeunbound.com` to 1.1.1.1/9.9.9.9 | Gateway resolver 192.168.22.1 returns SERVFAIL for officeunbound.com (public resolvers OK). Fix belongs on gateway (likely DNSSEC/blocklist in its resolver). | delete file, `systemctl restart systemd-resolved` |
| 2026-11-15 | apt: python3-venv, python3-pip, postgresql-16 (listens 127.0.0.1/::1 only) | ICS dev toolchain (user approved) | apt purge |
| 2026-11-15 | apt repos + packages: NodeSource node_22.x (nodejs 22.23.5), GitHub CLI (gh 2.104.0); keys in /etc/apt/keyrings | Frontend build, future git remote (user approved) | remove list + key files, apt purge |
| — | Docker deliberately NOT installed on ICS | avoid root-equivalent socket on control plane | |
