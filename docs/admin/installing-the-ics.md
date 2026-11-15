# Installing the ICS

Evidence: [ics/README.md](../../ics/README.md) (deployment layout), [host-changes.md](../status/host-changes.md) (what was installed on the lab host),
[security-review-ics-2026-11-15.md](../status/security-review-ics-2026-11-15.md). The service install is scripted; the TLS front end was set up
by hand in the lab and **has no install script** (see below).

## Prerequisites (as built in the lab: Ubuntu 24.04)
- Root on the host; PostgreSQL 16 on 127.0.0.1; Python 3 with `venv`; `rsync`; systemd.
- Roles and database, created once as the postgres superuser (passwords only go in the env files):
```
CREATE ROLE ics_owner LOGIN PASSWORD '...'; CREATE ROLE ics_app LOGIN PASSWORD '...';
CREATE DATABASE ics OWNER ics_owner; REVOKE ALL ON DATABASE ics FROM PUBLIC; GRANT CONNECT ON DATABASE ics TO ics_app;
```
- Config directory `/etc/office-unbound/` (`root:root 0711`) with these files (formats from ics/README.md):

| file | mode | content |
|---|---|---|
| `ics.env` | `root:ics 0640` | `ICS_DATABASE_URL` (the **ics_app** role), `ICS_VAULT_KEY_FILE`, `ICS_AUDIT_KEY_FILE`, `ICS_SIGNING_KEY_FILE`, optional `ICS_TRUSTED_PROXY=127.0.0.1` |
| `ics-migrate.env` | `root:root 0600` | `ICS_MIGRATE_DATABASE_URL` (**ics_owner**); the app process cannot read it |
| `vault.key` | `root:ics 0640` | 32 raw bytes (AES-256 for stored secrets) |
| `ics-signing.key` | `root:ics 0640` | 32 raw bytes, Ed25519 private key that signs requests to node agents |
| `audit.key` | `root:ics 0640` | at least 32 bytes, HMAC key for audit entries |

Key files must be regular, non-symlink, not world-accessible; the ICS refuses to start otherwise. The repo has **no key-generation script**; generate
random bytes of the stated length yourself. Losing `vault.key` loses every stored secret; losing `audit.key` ends audit verification.

## Install / upgrade the service
```
sudo sh ics/deploy/install.sh
```
(`ics/deploy/install.sh`) creates the `ics` system user, copies code to root-owned `/opt/office-unbound/ics`, builds the venv from
`requirements.lock --require-hashes`, installs `ics.service` and `ics-migrate.service`, and restarts both. Re-run after every code change.
The service binds `127.0.0.1:8088` only. To rebuild the console first: `cd ics/frontend && npm run build && cd .. && sudo sh deploy/install.sh`
([ics/frontend/README.md](../../ics/frontend/README.md)). Migrations alone: `sudo systemctl restart ics-migrate`.

## TLS front end and CA import
The console needs HTTPS (the session cookie is `__Host-` + Secure). Lab build, recorded in [host-changes.md](../status/host-changes.md) (manual, not scripted):
- nginx site `/etc/nginx/sites-available/ics.conf`: `192.168.22.167:443` -> `127.0.0.1:8088`; allows only the admin LAN/VPN ranges, denies the rest; overwrites `X-Forwarded-For`; no port 80.
- `ics-admin-fw.service` loading `/etc/office-unbound/ics-admin-fw.nft` (tcp/443 only from loopback and admin ranges; tcp/80 dropped) as defence in depth.
- Private CA `/etc/office-unbound/tls/ca.{key,crt}` (P-256, name-constrained to the console IP/localhost) and a server certificate; keys root 0600.
- `ICS_TRUSTED_PROXY=127.0.0.1` in `ics.env` so the app honours forwarded addresses from the local proxy only (non-loopback values are refused at startup).

**Import the CA** (public cert only) into each admin workstation's trust store and verify its SHA-256 out of band against the value recorded at creation
(`openssl x509 -in ca.crt -noout -fingerprint -sha256`). Do not click through browser warnings. Multi-host/ACME certificate handling is **Planned**.

## First admin (CLI enrollment)
No password is ever chosen or displayed. On the host:
```
sudo -u ics /opt/office-unbound/ics/.venv/bin/python -m ics.cli create-admin --username admin
```
It prints a one-time token (24 h, single use, stored hashed). The person calls `POST auth/enroll` (sets their own password, receives a TOTP URI) then
`POST auth/enroll/confirm` with a TOTP code; the console's enrollment page does this. Other CLI commands: `issue-enrollment --username X` (re-issue; resets
password, TOTP and sessions), `unlock --username X`, `verify-chain`. CLI use is the break-glass path and is audited as actor `cli`.

## Operator roles and approvals
Roles: `viewer < operator < approver < admin`. Operators and admins create plans; approvers decide them; admins manage users. Every mutation is
`typed action -> plan (bound to a params hash) -> approvals -> single-use job -> audit`. Risk tiers: **low** (auto-approved, still planned and audited),
**normal** (one approver who is not the requester), **high** (two distinct approvers). The requester never approves their own plan; an approver created or
elevated by the requester cannot decide that requester's plans. Effective rules are visible read-only in the console at `GET access-policy`.
Check `GET /readyz` after install (database, worker heartbeat, audit tail). Evidence: ics/README.md; two-person rules tested in the suite and live in
[user-lifecycle-results.md](../status/user-lifecycle-results.md).
