# Upgrades and rollback

Label: ICS upgrade by re-running the installer: **Integrated in lab**. Signed-package upgrade and rollback of a groupware node: **Integrated in lab** (acceptance A21, one node). Patch rings, staged rollout and an ICS typed action for upgrades: **Planned** (progress.json phase P5 "Patch rings, controlled upgrades and rollback" is **Implementing**).
Evidence: [ics-installer-results.md](../status/ics-installer-results.md), [upgrade-drill-results.md](../status/upgrade-drill-results.md), [package-pipeline-results.md](../status/package-pipeline-results.md), [RELEASING.md](../RELEASING.md), [ADR-0008](../adr/0008-build-release-pipeline.md), [ADR-0011](../adr/0011-versioning-and-releases.md).

## 1. Rules that always apply
1. **Back up first and check the backup** ([Day-2 operations](day-2-operations.md), [Backup and restore](backup-and-restore.md)).
2. Deploy only a **tagged, gated release from a clean checkout**, never from a working tree.
3. Releases are tagged and published by the owner. There is no production release yet (`docs/progress.json` has no released version); until the owner's signing key exists, tags are unsigned and release notes say so ([RELEASING.md](../RELEASING.md)).
4. Record the change in `docs/status/host-changes.md`.

## 2. Upgrade the ICS
1. Get the release: `git clone --branch vX.Y.Z <repository> /tmp/ou-release && cd /tmp/ou-release`, then check `git status` is clean.
2. Back up: `sudo ics/deploy/backup/ics-backup.sh`.
3. Re-run the installer with the **same arguments you used the first time**:
```
sudo ics/deploy/bootstrap.sh --listen-ip <ip> --allow-cidr <cidr> --hostname <fqdn>
```
(`sudo sh ics/deploy/install.sh` refreshes the code only.) Migrations run through `ics-migrate`. Data, keys, certificates and your edits to the env files are kept; a re-run with nothing to change prints `changes this run: none`. Proven: an upgrade across several migrations with users, passwords, TOTP and the audit chain intact.
4. Confirm: `GET /readyz`, and signed in, `GET /api/v1/version` shows the tag's commit and `dirty: false`. **Administration > System** lists component versions and compares them with the releases bundled at install time. It makes no network request, so it cannot know about newer releases ([RELEASING.md](../RELEASING.md)).
5. Run `verify-chain`: `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli verify-chain`.
**Rollback of the ICS:** restore the backup ([ICS recovery and warm standby](ics-recovery-and-standby.md)). Migrations are not reversed in place. Restore to a new machine and cut over; do not downgrade the code over a migrated database.
**Node agents:** upgrade agents before the ICS if the release says so. Once agents have seen a newer controller epoch (standby feature, pending merge) the ICS cannot be rolled back without keeping the epoch; roll forward instead.

## 3. Upgrade and roll back signed packages on a node (lab procedure)
The groupware packages (`ou-gromox`, `ou-grommunio-web`, ...) are built, scanned and published to a **signed apt repository** with three channels, `dev`, `staging` and `stable`. A package reaches a channel only after test records and a named approver; the signing key is held by a separate system user, not by the build user.
| Role | Command (from `blueprints/build/repo/repo.sh`) |
|---|---|
| Builder | `blueprints/build/build.sh <component>` then `blueprints/build/repo/repo.sh publish <component>` |
| Tester | `blueprints/build/tests/pkgtest.sh` installs on a fresh machine and records the result |
| Release owner | `blueprints/build/repo/repo.sh promote dev staging <component>` then `promote staging stable <component> --approved-by <name>` |
On a node (the drill ran from the ICS host into the lab machine; there is no ICS action for this yet):
```
blueprints/lab/upgrade/gw-pkg-upgrade.sh pre                       # records the current state and a recovery copy on the node
sudo blueprints/lab/backup/gw-backup.sh <machine>                  # official logical backup
blueprints/lab/upgrade/gw-pkg-upgrade.sh migrate                   # one-time move from a source build to pinned packages
blueprints/lab/upgrade/gw-pkg-upgrade.sh change <gromox-version>   # upgrade, rollback or roll forward to an exact version
blueprints/lab/upgrade/gw-pkg-upgrade.sh status
```
Set `REPO_URL` to the repository and (optionally) `CHANNEL` (default `stable`) first. Versions are **pinned** (apt preferences) and **held**, so a routine `apt upgrade` cannot move them. The script downloads first, then stops services, swaps packages, restarts in order and checks every unit.
Measured in the drill: in-place web package upgrade 14.9 s (11.6 s of service stop); **rollback by pinned downgrade** 19.5 s (16.2 s stop); roll forward 20.4 s. Rollback works because promotion keeps the previous version in the channel. It is only valid when the two versions share data formats; for a package pair that migrates data, restore from the backup instead.
Lessons: the pipeline's install test passed while 3 of 9 end-to-end checks failed for one package, so run the lab suite (`gw_run_all.sh`) after each upgrade. The first migration from a source build stopped service for 181 s (mostly the data snapshot).
Not done: the whole-node restore was not run on that node (one mailbox was restored from the backup), a second node was not migrated, and the migration is a script, not an approved ICS action.

## 4. Release signing key (owner items)
The lab key is passphrase protected but lives on the build host, is used by the same host, and expires. Offline or hardware signing, per-channel keys and a rotation and revocation process are open ([Security model](security-model.md), owner actions).
