# Installing the ICS

Evidence: [ics/README.md](../../ics/README.md) (deployment layout), [host-changes.md](../status/host-changes.md) (what was installed on the lab host),
[security-review-ics-2026-11-15.md](../status/security-review-ics-2026-11-15.md). `ics/deploy/bootstrap.sh` installs everything on a fresh host in one idempotent command (section **Bootstrap** below); the sections after it
describe what the lab host looks like (it was built by hand before the script existed) and remain the reference for each piece.

## Prerequisites (as built by hand in the lab: Ubuntu 24.04; `bootstrap.sh` does all of this for you)
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

Key files must be regular, non-symlink, not world-accessible; the ICS refuses to start otherwise. `bootstrap.sh` generates them (never overwriting an existing key); for a manual build generate
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
The console needs HTTPS (the session cookie is `__Host-` + Secure). Lab build, recorded in [host-changes.md](../status/host-changes.md) (by hand; `bootstrap.sh` now renders the same configuration):
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

## Bootstrap (single command, fresh Ubuntu 24.04)
Evidence: [ics-installer-results.md](../status/ics-installer-results.md) (executed on two fresh lab machines; commands below are the ones that were run).
```
sudo ics/deploy/bootstrap.sh --listen-ip 192.168.186.137 --allow-cidr 192.168.186.0/24 \
     --hostname ics1.ou-lab.internal --admin alice
```
| flag | meaning |
|---|---|
| `--listen-ip IP` | address nginx binds on :443; must already be configured on the host |
| `--allow-cidr C` (repeatable, at least one) | networks allowed to reach 443 (nginx `allow` + nftables). No default; `0.0.0.0/0` is refused. Loopback and the listen address itself are always added so the installer can health-check |
| `--hostname FQDN` | extra DNS name for the certificate, `server_name` and the CA's name constraints |
| `--admin USER` | after install, create that admin (`ics.cli create-admin`) and print its one-time enrollment token as the **last** output. Not issued again if the account exists |
| `--tls-cert F --tls-key F` | use an operator-provided certificate/key instead of the private CA (key must match, cover the IP/hostname, be valid) |
| `--skip-tls` | loopback only: backend on 127.0.0.1:8088, no nginx, no nftables, no certificates (reach it via an SSH tunnel; the session cookie is `Secure`, so use a browser that treats `localhost` as secure) |
| `--skip-firewall` | do not install the nftables unit (nginx allow-list still applies) |
| `--uninstall` / `--purge` | see below |

What it does, in order (each step compares before writing, so a re-run changes nothing that is already right):
1. Requires root and Ubuntu 24.04; validates arguments (fail closed on missing allow-list).
2. `apt-get install` of the missing packages `python3 python3-venv postgresql-16 rsync openssl curl sudo ca-certificates nginx nftables` from the noble archive
   (**pinning is by release and major version** - `postgresql-16`, noble's python 3.12/nginx 1.24; exact installed versions are printed in the summary; Python packages are hash-pinned
   by `requirements.lock`). A temporary `policy-rc.d` stops dpkg starting nginx on port 80 with the default site.
3. Service user `ics`; `/etc/office-unbound` (`root:root 0711`); PostgreSQL started.
4. Keys `vault.key`, `audit.key`, `ics-signing.key`: 32 bytes from `os.urandom`, created with `O_EXCL` as `root:ics 0640`. An existing key is **never overwritten**; the install stops if one is
   a symlink, not a regular file, unreadable (by root or by `ics`), too short, or if a key is missing while database `ics` already holds data (restore it instead: recovery runbook).
5. Roles `ics_owner` / `ics_app` and database `ics` (as in ics/README.md) with random passwords that exist only in `ics-migrate.env` (`root:root 0600`) and `ics.env` (`root:ics 0640`).
   Existing env files are never rewritten: absent keys are appended, operator edits survive, a password is replaced only if the role exists but the recorded password is missing or no longer works.
6. TLS: private CA (P-256, 5 years, `pathlen:0`, name-constrained to the listen IP, 127.0.0.1, `localhost` and the hostname) and server certificate (P-256, 397 days, re-issued when within 30 days
   of expiry or when the requested names change; a CA that cannot cover a new name is not touched - the installer stops and explains). Files in `/etc/office-unbound/tls` (`ca.key`, `ics.key` 0600).
7. `deploy/install.sh` (code to `/opt/office-unbound/ics`, hash-pinned venv, units, `ics-migrate` + `ics` restart) only when the source tree hash, venv or unit files differ from what is installed.
8. `ics-admin-fw.service` + `/etc/office-unbound/ics-admin-fw.nft`, nginx site `ics.conf` (+ `sites-enabled` link, default site removed, `nginx -t` before start/reload), `ICS_TRUSTED_PROXY=127.0.0.1`.
9. Waits for `/readyz` on the backend and over https with the generated CA (and the hostname via `--resolve`). A restored **passive** controller (`ICS_WORKER_ENABLED=false`) is accepted with 503 when only the worker check is red.
10. Prints a summary: URL, package versions, CA path and SHA-256 (verify out of band, then import `tls/ca.crt` on admin workstations), the list of changes made (or `none`), and the enrollment token last.

Re-run it after pulling new code: it is the upgrade path (migrations run by `ics-migrate`; data, keys and certificates are kept).
**Uninstall:** `sudo ics/deploy/bootstrap.sh --uninstall` stops/disables `ics`, `ics-migrate`, `ics-admin-fw`, removes the units, nginx site, nft table and `/opt/office-unbound/ics`; it **keeps** `/etc/office-unbound`
(env files, keys, tls), the database, roles, the `ics` user and packages, so a later `bootstrap.sh` run resumes on the same data. `--uninstall --purge` additionally drops the database and roles and deletes
`/etc/office-unbound` and the user; it first prints what will be lost and requires typing `purge <hostname>`. Take a backup first (`ics/deploy/backup/ics-backup.sh`, which now also works on `--skip-tls` hosts).
**What was executed** (Ubuntu 24.04 nspawn machines `ou-icsinst1/2`): fresh install, re-run with file/mode/hash snapshots before and after (identical), install of commit `8cade08` (migrations to 0003) then upgrade to HEAD
(0003 -> 0006b, user, password, TOTP, audit chain intact), `ics-backup.sh` inside the machine and the passive restore (`ics-restore-inner.sh`) onto the second machine with `verify-chain` ok, key-safety refusals,
uninstall/reinstall keeping data, and `--purge` confirmation. Not exercised: operator-provided certificate (`--tls-cert`), IPv6, renewal of an expiring server certificate, a source outside `--allow-cidr`.
