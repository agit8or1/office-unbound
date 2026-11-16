# Installing the ICS

Evidence: [ics-installer-results.md](../status/ics-installer-results.md) (the installer run on two fresh Ubuntu 24.04 lab machines: install, re-run, upgrade, restore, key safety, uninstall),
[ics/README.md](../../ics/README.md) (layout, roles, approvals), [security-review-ics-2026-11-15.md](../status/security-review-ics-2026-11-15.md).
New to this? Follow the [Quick start](quick-start.md); this page is the reference.

## Requirements
- A fresh Ubuntu 24.04 host (PostgreSQL 16, Python 3.12) or Debian 12 host (PostgreSQL 15, Python 3.11; dry-run evidence in [quickstart-dryrun-results.md](../status/quickstart-dryrun-results.md)), root access, outbound access to the distribution archive and PyPI, and an IP address already configured on the host for the console.
- The Office Unbound source tree on the host. The lab copied the tree to `/root/src` and ran the script from there; run the commands below from the repository root.
- Not tested: other distributions or releases (`bootstrap.sh` refuses anything but Ubuntu 24.04 and Debian 12; `bootstrap.sh --check-os` prints the detected profile), IPv6, a host without internet access.

## One-command install
```
sudo ics/deploy/bootstrap.sh --listen-ip 192.168.186.137 --allow-cidr 192.168.186.0/24 \
     --hostname ics1.ou-lab.internal --admin alice
```
(These are the arguments that were run in the lab; replace the addresses with yours.) Takes about 2 minutes on a fresh Ubuntu host (about 4 on a fresh Debian 12 cloud VM).
The `ics.cli` commands below must be run from `/opt/office-unbound/ics` (the code is not installed into the virtualenv); from any other folder they fail with `No module named 'ics'`.

| flag | meaning |
|---|---|
| `--listen-ip IP` | address nginx binds on :443; must already be configured on the host |
| `--allow-cidr C` (repeatable, at least one) | networks allowed to reach 443 (nginx `allow` + nftables). No default; `0.0.0.0/0` is refused. Loopback and the listen address are always added so the installer can health-check |
| `--hostname FQDN` | extra DNS name for the certificate, `server_name` and the CA's name constraints |
| `--admin USER` | create that admin after install and print its one-time enrollment token as the **last** output. Not issued again if the account exists |
| `--tls-cert F --tls-key F` | use your own certificate/key instead of the private CA. **Not exercised in the lab** |
| `--skip-tls` | loopback only: backend on 127.0.0.1:8088, no nginx/nftables/certificates; reach it through an SSH tunnel |
| `--skip-firewall` | do not install the nftables unit (the nginx allow-list still applies) |
| `--uninstall` / `--purge` | see [Uninstall](#uninstall) |
| `--artifacts-listen-ip IP` (+ `--artifacts-port`, `--artifacts-hostname`, `--artifacts-allow-cidr` (default `10.64.0.0/16`), `--artifacts-channel-key dev\|staging\|stable=KEY.asc`, `--artifacts-image-key CH=PUB.pem`) | also install the **artifact distribution service** ([ADR-0015](../adr/0015-artifact-distribution.md)): the signed apt repository and OCI registry guests install from, read-only, on its own TLS port (default 8444) with its own private CA and an nftables allow-list for the customer VNets. The installer writes the `OU_ARTIFACT_*` settings (CA pin, channel key pins) to `ics.env`. Published with `ou-artifact-publish apt --src <repo tree>` and `ou-artifact-publish oci --from <registry URL> --repo ou/x --ref <tag or digest> --channel dev` (verifies signatures first; nothing unsigned is served). Standalone: `ics/deploy/artifacts/ou-artifacts-setup.sh`. Lab-proven on a separate machine, **not** yet run through `bootstrap.sh` end to end |

What it does (every step compares before writing, so a re-run changes nothing that is already right; a second run prints `changes this run: none`):
1. Requires root and Ubuntu 24.04 or Debian 12; refuses a missing allow-list.
2. Installs missing packages from the distribution archive, waiting for a running first-boot `apt` job (`python3 python3-venv postgresql-16 [postgresql-15 on Debian 12] rsync openssl curl sudo ca-certificates nginx nftables`). Pinning is by release and major version; exact versions are printed in the summary. Python packages are hash-pinned.
3. Creates the `ics` service user and `/etc/office-unbound` (`root:root 0711`).
4. Generates the keys `vault.key`, `audit.key`, `ics-signing.key` (32 random bytes each). **An existing key is never overwritten**; it refuses to continue if a key is a symlink, unreadable, too short, or missing while the database already holds data (restore it from backup instead).
5. Creates the database roles `ics_owner` / `ics_app` and database `ics` with random passwords held only in `ics-migrate.env` (`root:root 0600`) and `ics.env` (`root:ics 0640`). Your edits to these files survive re-runs.
6. Private CA (P-256, 5 years, name-constrained to the listen IP, 127.0.0.1, `localhost` and the hostname) and server certificate (397 days, renewed when within 30 days of expiry or the names change).
7. Installs the code to `/opt/office-unbound/ics` with a hash-pinned virtualenv, runs migrations, and starts `ics` (binds 127.0.0.1:8088 only).
8. Installs `ics-admin-fw.service` (nftables, 443 only from the allowed networks), the nginx site and `ICS_TRUSTED_PROXY=127.0.0.1`.
9. Waits for `/readyz` on the backend and over HTTPS with the generated CA.
10. Prints a summary: console URL, package versions, the CA path and its **SHA-256**, what changed, and the enrollment token last.

**After install**
1. Verify the CA SHA-256 printed in the summary out of band (`sudo openssl x509 -in /etc/office-unbound/tls/ca.crt -noout -fingerprint -sha256`; `/etc/office-unbound/tls` is root-only), then import `/etc/office-unbound/tls/ca.crt` (public certificate only) into each admin workstation's trust store. Do not click through browser warnings.
2. Enroll the first admin: open `https://<listen-ip>/`, use the enrollment page with the token, choose your own password and confirm your TOTP code. No password is ever chosen or shown for you.
3. Check `GET /readyz` (database, worker heartbeat, audit tail).

Not exercised: `--tls-cert/--tls-key`, certificate renewal near expiry, a connection from outside `--allow-cidr`, IPv6. Multi-host/ACME certificates are **Planned**.

### Guest-bootstrap listener (golden-image deployments)

Add `--callback-listen <ip>[:8444] --callback-allow-cidr <guest network>` (repeatable) to enable the dedicated listener `ics-bootstrap.service` (own port, own
certificate that guests pin, firewall restricted to the guest networks). `install.sh` always deploys and enables the unit, which stays inactive until
`/etc/office-unbound/callback.env` exists. The backup includes `callback.env`, `callback-tls/`, the unit and its firewall file. Details: [security.md](security.md).

## Create the accounts you need
Roles: `viewer < operator < approver < admin`. Operators and admins create plans; approvers decide them. **High-risk plans need two different approvers and the requester can never be one of them**,
so a working installation needs at least three people: one requester and two approvers. Registering a Proxmox endpoint is high risk, so you need these before [Connecting Proxmox](connecting-proxmox.md).

**Only one administrator?** Set `ICS_APPROVAL_MODE=single_admin` in `/etc/office-unbound/ics.env` and restart `ics`. An *admin* then reviews and approves their own plans, and every plan needs one approval. Nothing else changes: every change is still a plan bound to a hash, needs an explicit approval, runs as a job and is recorded in the audit log. Approver and operator accounts still need someone else. Remove the setting (default `two_person`) when a second approver joins. See [ADR-0017](../adr/0017-single-admin-approval-mode.md).

On the ICS host, for each person (prints a one-time token, valid 24 h, single use, stored hashed; hand it over out of band):
```
cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli create-admin --username bob --role approver
```
`--role` is one of `viewer|operator|approver|admin` (default `admin`). The lab created its requester and two approvers this way. Re-issue a token with `issue-enrollment --username X` (this resets the password, TOTP and sessions).
Once an admin can log in, further accounts are invited from the console ([Users and access](users-and-access.md)); inviting an approver or admin is itself a two-approver plan.
CLI use is the break-glass path and is audited as actor `cli`. Evidence: ics/README.md; [host-changes.md](../status/host-changes.md) (lab accounts); two-person rules live in [user-lifecycle-results.md](../status/user-lifecycle-results.md).

## Upgrade
Update the source tree and re-run the same `bootstrap.sh` command. Migrations run via `ics-migrate`; data, keys, certificates and your env edits are kept. Proven: upgrade from an older commit (Alembic 0003 to 0006b) with users, passwords, TOTP and the audit chain intact.
Rebuilding the console from source is only for developers: `cd ics/frontend && npm run build` ([ics/frontend/README.md](../../ics/frontend/README.md)); the repository already contains a built console.

## Production contains no sample data
A fresh `bootstrap.sh` install contains exactly the accounts you create and nothing else (the lab proof ended with one user). Do not run the lab demo scripts (`ics/scripts/lab_*.py`) or create throwaway accounts on a real controller.
If a controller was used for demonstration, the lab precedent ([host-changes.md](../status/host-changes.md), "Production ICS cleanup" and "demo-data purge") was:
1. Take a backup first (`ics/deploy/backup/ics-backup.sh`).
2. Disable demo checks through normal approved plans, and demo operator accounts with the audited break-glass command:
   `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli disable-user --username <name> --reason "<why the approval workflow could not be used, at least 10 characters>"`
   (refuses the last active admin; ends the account's sessions; recorded as `user.disabled.break_glass`).
3. Purge the remaining rows in one database transaction using the DB-owner credential (`ics-migrate.env`), because approval records are insert-only for the application role by design. That purge was done **by hand once**; **there is no purge tool for it in the repository** (users, IdM stacks and approval records are outside the removal actions; a generic purge procedure is **Planned**). It recorded the audit event `maintenance.demo_data_purged`, and the chain was verified afterwards.

Easier and safer: reinstall on a clean host (`--uninstall --purge`, below). Typed removal actions for checks, alert channels, node agents, maintenance windows and plans now exist on main ([Operating the ICS](operating-the-ics.md#removing-things); tested, not yet used on a running lab controller), so step 3 should only be needed for rows they do not cover (for example demo users and customer stacks).

## Uninstall
`sudo ics/deploy/bootstrap.sh --uninstall` removes the services, nginx site, firewall table and code, and **keeps** `/etc/office-unbound` (env files, keys, certificates), the database, roles, the `ics` user and packages, so a later `bootstrap.sh` resumes on the same data (proven).
`--uninstall --purge` additionally drops the database and roles and deletes `/etc/office-unbound` and the user. It lists what will be lost and requires typing `purge <hostname>`. Back up first.
Losing `vault.key` loses every stored secret; losing `audit.key` ends audit verification.

## What is on disk (reference)
| file in `/etc/office-unbound/` | mode | content |
|---|---|---|
| `ics.env` | `root:ics 0640` | `ICS_DATABASE_URL` (role `ics_app`), key file paths, `ICS_TRUSTED_PROXY`; `ICS_WORKER_ENABLED` / `ICS_MONITOR_ENABLED` (both default true) |
| `ics-migrate.env` | `root:root 0600` | `ICS_MIGRATE_DATABASE_URL` (role `ics_owner`); the app cannot read it |
| `vault.key` / `ics-signing.key` / `audit.key` | `root:ics 0640` | AES-256 key for stored secrets / Ed25519 key that signs requests to node agents / HMAC key for audit entries |
| `tls/ca.crt`, `tls/ics.crt`, `tls/*.key` | keys 0600 | private CA and server certificate |
| `ics-admin-fw.nft` | root | nftables rules (443 from allowed networks only) |

Key files must be regular, non-symlink files and not world-accessible, or the ICS refuses to start.

## Operator roles and approvals
Every change is `typed action -> plan (bound to a params hash) -> approvals -> single-use job -> audit`. Risk tiers: **low** (auto-approved, still planned and audited), **normal** (one approver who is not the requester),
**high** (two distinct approvers). An approver created or elevated by the requester cannot decide that requester's plans. Effective rules are visible read-only at `GET access-policy`.
