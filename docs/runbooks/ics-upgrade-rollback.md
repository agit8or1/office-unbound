# ICS package: install, upgrade, rollback

Applies to an ICS installed from the signed package `ou-ics` (ADR-0008 pipeline, versions per ADR-0011). A git-tree install
(`install.sh`, `bootstrap.sh` without `--from-repo`) stays supported for development; installing the package over one is supported
too (the existing database is backed up first, the old unit copies in `/etc/systemd/system` are set aside).

## What the package does and does not own
| Owns (replaced on upgrade) | Never touched after the first install |
|---|---|
| `/opt/office-unbound/ics` (code, built console, migrations, `BUILD_INFO.json`), `/opt/office-unbound/blueprints/catalog`, the generated `.venv`, units in `/usr/lib/systemd/system`, `/usr/lib/ou-ics/*`, `/usr/sbin/ou-ics-rollback`, vendored wheels in `/usr/share/ou-ics/wheels` | database `ics`, `/etc/office-unbound/{vault,audit,ics-signing}.key`, `ics.env`, `ics-migrate.env`, TLS, nginx/nftables config (`bootstrap.sh` owns the front end), `/var/backups/office-unbound` |
| `/etc/office-unbound/ics-tuning.env` is a **conffile**: your edits survive; dpkg asks when the packaged default changes | |

Python dependencies are installed into `/opt/office-unbound/ics/.venv` by the postinst from wheels shipped in the package
(`pip --no-index --require-hashes`, hashes from `ics/requirements.lock`): no network at install time. The package carries wheels for
CPython 3.11 (Debian 12) and 3.12 (Ubuntu 24.04).

## First install
```
sudo ics/deploy/bootstrap.sh --from-repo stable --repo-url http://<repo>:8077 --listen-ip ... --allow-cidr ... --admin alice
```
`bootstrap.sh` pins the repository key (`blueprints/build/keys/ou-release-lab.pub.asc`, fingerprint file next to it, or
`--repo-key-fingerprint`), adds the apt source with `signed-by`, installs `ou-ics`, then sets up TLS/nginx/firewall as usual.
Without bootstrap (loopback only): add the apt source yourself and `apt-get install ou-ics`; the postinst provisions keys, PostgreSQL
roles, the database and env files **only if absent**.

## Upgrade
1. `cd /opt/office-unbound/ics && sudo -u root .venv/bin/python -m ics.cli upgrade-preflight` (read-only; run as root so the schema
   revision can be read). It reports disk space (3x database size on the backup volume, space for new code), backup freshness, running
   and queued jobs/deployments, passive/standby state (`ICS_WORKER_ENABLED`/`ICS_MONITOR_ENABLED=false`) and whether the database
   schema is known to the installed code. A `FAIL` blocks; exit code 1. The package runs the same check itself before it changes anything.
2. `sudo apt-get update && sudo apt-get install ou-ics` (or `ou-ics=<version>`).
   * **preinst** (runs before the new files are unpacked, from the old version): preflight, then `ou-ics-preupgrade-backup`: a full
     `ics-backup.sh` (database dump, keys, env, units, code), verified (archive hash, member hashes, dump readable by `pg_restore -l`),
     recorded in `/var/lib/office-unbound/ics-preupgrade.json`. If anything fails the upgrade is **refused with the old version intact**.
   * **postinst**: stops the ICS, rebuilds the venv from the vendored wheels, refuses to continue if the database schema is *newer* than
     the code (see rollback), requires a backup younger than 6 h (takes one itself if the preinst did not; refuses to migrate if that
     fails), runs `ics.migrate`, starts `ics-migrate` + `ics`. A failed migration leaves the ICS **stopped** and the backup in place.
3. Check: `curl -s http://127.0.0.1:8088/readyz`, `sudo -u ics /opt/office-unbound/ics/.venv/bin/python -m ics.cli verify-chain`,
   Administration > System (version, commit, `dirty:false`, schema).

## Rollback
`alembic downgrade` is **not** used (several revisions are irreversible by design, see `0010`). Rollback = previous code + the database as
it was before the upgrade:
```
sudo apt-get install --allow-downgrades ou-ics=<previous version>
```
* If the schema did **not** move (no new migration) that is all: the postinst starts the old code.
* If the schema moved, the old postinst finds a database revision it does not know, writes `/var/lib/office-unbound/ics-needs-restore`,
  leaves the ICS **stopped** and prints the next step:
```
sudo ou-ics-rollback /var/backups/office-unbound/ics/<timestamp>        # the directory named in ics-preupgrade.json / ics-last-upgrade.json
```
  It verifies the backup (archive and member hashes), checks that the installed code knows the backup's schema revision, compares the keys
  (refuses if they differ unless `--restore-keys`), keeps a **safety dump of the current database** next to the backup, drops and
  recreates database `ics`, `pg_restore`s the backup, starts the services and verifies `/readyz` and the audit chain. Data written between
  the backup and the rollback is lost by design; it stays recoverable from the safety dump.
* Failed migration during an upgrade: same two commands (the ICS is stopped; the database may be half-migrated, so restore).

## Removal
`apt-get remove ou-ics` stops the services and removes code and venv. `purge` additionally drops the conffile. **Neither deletes the
database, keys, env files, TLS or backups** (they are the customer's data; `bootstrap.sh --uninstall --purge` is the explicit wipe).

## Operator notes
* Backups include every ICS secret (keys, DB credentials): `/var/backups/office-unbound` is root 0700. Copy them off-host encrypted
  (backup product work, `docs/status/backup-product-results.md`); this package does not.
* Release engineers: building and publishing the package is in [RELEASING.md](../RELEASING.md) ("Packaging the ICS").
* `OU_ICS_SKIP_PREFLIGHT=1` skips the preflight inside the package scripts (not the backup). Use only on a host whose preflight itself is broken.
