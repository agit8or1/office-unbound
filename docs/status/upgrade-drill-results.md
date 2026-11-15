# Upgrade and rollback drill on ou-gw1 (roadmap acceptance A21: "pinned upgrades and recovery demonstrated")

Date: 2026-11-15, agent AG (release engineering), branch `release-ag`. Status words per ADR-0000: PASS/FAIL below mean the command was executed in this session and the quoted output was produced; the logs are in `docs/status/upgrade-drill-evidence/` (numbered in execution order) and the package evidence in `docs/status/package-pipeline-evidence/`. The node was the main lab groupware machine `ou-gw1` (192.168.186.218, Debian 12); its monitoring checks had been removed from the production ICS by the owner, so short restarts were acceptable. The production `ics` service and database, Proxmox and every other lab machine were not touched. Scripts: `blueprints/lab/upgrade/{gw-pkg-upgrade.sh,gw-pkg-inner.sh,gw_behaviour_tests.py}`; backup with the existing `blueprints/lab/backup/gw-backup.sh`.

## 1. Verdict

| Claim | Result |
|---|---|
| ou-gw1 migrated from the source-built install in `/usr` to signed `ou-*` packages of the **stable** channel, exact versions pinned (apt preferences, Pin-Priority 1001) and held (`apt-mark hold`), configuration and data preserved | PASS (section 3) |
| Same test set before and after: `gw_run_all.sh` (GW01..GW08), webmail SSO e2e, bearer-claims behaviour, USER-KICK behaviour | PASS after the migration and after the in-place upgrade; **one real regression found by the drill** (the first web package lacked the deep-link patch: 3 of 9 SSO e2e checks FAILED) and fixed with a new package version (section 5) |
| In-place upgrade of one package set (web 5.2-ou1 to 5.2-ou2) | PASS, 14.9 s total, 11.6 s of service stop |
| **Rollback by pinned downgrade** (gromox and php-mapi 3.13-ou2 to 3.13-ou1, previous version kept in the channel pool) | PASS, 19.5 s total, 16.2 s of service stop; all tests green, patched behaviours correctly gone (section 6) |
| Roll forward again to ou2 | PASS, 20.4 s total, 16.5 s of service stop |
| Restore from the pre-migration backup as the second recovery path | PARTIAL: not run for the whole node (to avoid destroying the node under test), but **one mailbox was restored from the backup archive on ou-gw1 by accident of the drill and verified**: `grace@gw1` (see section 5, item 5), exact message counts 2088 / 40 as in the MANIFEST. The full-node restore script and drill exist from earlier work (`gw-restore.sh`, `gw_09_restore_drill.py`). |

## 2. What was installed (stable channel, `http://192.168.186.149:8077`, machine `ou-repo1`, key `5D2750D022E0218361518491CE58A8B691F84C1B` fingerprint-checked on the node before it was trusted)

Final state of ou-gw1 (`gw-pkg-upgrade.sh status`, all `hold`): ou-libhx 4.28-ou1, ou-wmime 1.2.0-ou1, **ou-gromox 3.13-ou2**, **ou-gromox-php-mapi 3.13-ou2**, ou-mapi-header-php 2.4-ou1, ou-grommunio-sync 2.7-ou1, ou-grommunio-dav 1.9-ou1, **ou-grommunio-web 5.2-ou2**. Not installed on ou-gw1: ou-admin-api, ou-admin-web, ou-libexmdbpp (the node does not run them), ou-docs (Ubuntu package, other machine).

## 3. Migration: commands and timings

Every step is a function of `gw-pkg-inner.sh`, driven from the ICS host by `gw-pkg-upgrade.sh` through `sudo systemd-run -M ou-gw1` (no ssh, no new listener). `REPO_URL=http://192.168.186.149:8077` in all calls.

| # | Command (ICS host) | What it does | Time |
|---|---|---|---|
| 1 | `gw_run_all.sh` | baseline: GW01 13, GW02 12, GW03 7, GW04 10, GW05 4, GW08 4, GW07 7 PASS, 0 FAIL | 48 s |
| 2 | `gw-pkg-upgrade.sh pre` | records the installed state in `/var/backups/ou-prepkg/<ts>/` on the node: source pins (libhx v4.28, wmime 1.2.0, gromox-3.13 8b620206, mapi-header-php 2.4, sync 2.7, dav 1.9, web 5.2 dd9029d9), 0 dpkg-owned gromox packages, service states, listening sockets, a list and sha256 of the 5014 files of the source install and a 299 MB tar of them (`source-built.tar`: recovery path 2), config tar. gromox binaries before: http 56e324d6, imap 8e3b4647 (hand-patched), event 7a6824f5 | 10.4 s |
| 3 | `sudo gw-backup.sh ou-gw1` | the official online logical backup to `/var/backups/office-unbound/lab/ou-gw1/20261115T213520Z` (192 MB archive, MANIFEST, 54 mailboxes exported, SQL counts before and after, per-mailbox checksums, stream verified) | 68.8 s |
| 4 | baseline behaviour test `gw_behaviour_tests.py --expect-bearer unpatched --expect-kick patched` | before: audience/issuer directives ignored (a token for another client is accepted under every setting), the hand-patched imap closes the kicked sessions | 20 s, 6 PASS |
| 5 | `gw-pkg-upgrade.sh migrate` | (a) apt source + key (fingerprint check) + pins file, `apt-get update`; (b) `apt-get install --download-only` of the exact versions while the node is still serving; (c) stop gromox-* and php-fpm; (d) **data snapshot** with services stopped: `mysqldump --single-transaction email` (42 KB) and a tar of `/var/lib/gromox` (410 MB, tree hash `69db7466bf3eec98`, 53346 files); (e) copy the three application `config.php` files; (f) `make uninstall` in `/usr/src/ou/{libhx,gromox}`, remove the remaining files of the list, move the old web/sync/dav trees to the backup directory; (g) `apt-get install` of the 8 pinned packages with `--force-confold`; (h) put the lab `config.php` files into the package conffiles `/etc/grommunio-{sync,dav,web}/config.php`; (i) bearer directives in `/etc/gromox/gromox.cfg`; (j) enable and start the units in order, check that every unit is active; (k) `apt-mark hold` | download 4.1 s, **service stop 181.4 s** (of which the snapshot was about 155 s, the package swap itself 23 s), install step 9.0 s, total 185.7 s |
| 6 | install the updated runbook helper `ou-gw-user` (old copy kept as `ou-gw-user.pre-ag`) | needed for the new acknowledgement of the kick (review M3) | seconds |
| 7 | `gw_run_all.sh` | after: GW01 13, GW02 12, GW03 7, GW04 10, GW05 4, GW08 4, GW07 7 PASS, 0 FAIL (identical) | 56 s |
| 8 | `gw_behaviour_tests.py` | after: 9 PASS (section 4) | 20 s |
| 9 | `webmail_sso_e2e.js` (WEB_HOST=gw1.ou-lab.internal) | **6 PASS, 3 FAIL**: the three deep-link checks fail (context stays `mail`), see section 5 | 5 min |

Result of the removal and install: `dpkg -S` finds an owning package for every file of `/usr/libexec/gromox/*` and `/usr/sbin/gromox-*` (no unowned leftover); `dpkg -V` is clean for the gromox packages except the conffiles we deliberately changed (`config.php` of sync, dav and web). The lab config is preserved by design (`/etc/gromox`, `/etc/ou-*`, nginx, postfix, php pools were not touched; `/var/lib/gromox` and MariaDB were not written to).

One mistake of the drill, fixed in the script (`gw-pkg-inner.sh migrate`): a loop that deleted the package's own `/etc/php/8.2/cli/conf.d/mapi.ini` because it was identical to the lab's file; `php -m` showed no `mapi` for the CLI until the file was put back. The loop is gone.

## 4. Behaviour tests (`gw_behaviour_tests.py`, real tokens and real IMAP sessions against ou-gw1)

Bearer claims (`bearer_issuer=https://auth.ou-lab.internal/realms/ou-lab`, `bearer_audience=ou-webmail` are now set in `/etc/gromox/gromox.cfg`; the test sets four policies temporarily and restores these two lines): the real token of bob (client `ou-lab-test`, `aud=account`) and three forged variants (JOSE `alg` none, HS256, RS512 on the same payload and signature) go to zcore `mapi_logon_token`.

```
                        ou2 (patched)                                   ou1 after rollback (unpatched)
legacy (no directives)  real ACCEPTED, 3 forged alg rejected            real ACCEPTED, 3 forged alg rejected
aud=ou-webmail          real rejected                                   real ACCEPTED   <- directive ignored
aud=account + issuer    real ACCEPTED                                   real ACCEPTED
aud=account + wrong iss real rejected                                   real ACCEPTED   <- directive ignored
```
(The two-line difference is exactly the "audience confusion" the patch closes.) The e2e flow of the real webmail uses client `ou-webmail`, so it satisfies `bearer_audience=ou-webmail`: the SSO e2e passed with enforcement switched on (section 5).

USER-KICK: bob has two IMAP sessions (SELECTed INBOX), alice one. `ou-gw-user.event_kick('bob@gw1.ou-lab.internal')` runs on the node:
```
ou2:  KICK (True, True)   bob's sessions: NOOP => [UNAVAILABLE] Session terminated by administrator (0.0 s), alice's session unaffected, bob logs in again
ou1:  KICK (True, False)  event delivered (gromox-event answers TRUE) but NO listener acknowledged; bob's sessions stay open
```
The second line is review finding M3: before the change the runbook reported `kick_sent: true` in the unpatched case, now it reports false (journal line `imap: USER-KICK received for <user>` is the acknowledgement).

## 5. Findings of the drill

1. **The pipeline's web package lacked the SSO deep-link patch** (`0001-context-deep-link.patch` from the SSO work sat in the patch directory but the ou1 build predates it). ou-grommunio-web 5.2-ou1 passed the install smoke test of the pipeline but 3 of 9 e2e checks failed on ou-gw1 (`deep link ?action=context&view=calendar opens calendar view - current context=mail`, same for contacts and for the redirect case). Fix: 5.2-ou2 (patch renumbered to `0002-context-deep-link`), built, tested (pkgtest: 13 verify + 9 smoke PASS), promoted, and installed on ou-gw1 as an in-place upgrade (section 6). After that: **9 PASS, 0 FAIL**, deep links `context=calendar`, `context=contact`, deep link survives the OIDC redirect, logout ends the webmail session after 279 s (the known refresh-interval bound).
2. The snapshot dominates the migration's service stop (155 of 181 s). A pre-snapshot with services running plus a short consistent delta, or a filesystem snapshot, would cut the stop to the 23 s of the package swap; not done.
3. The pipeline must also be re-run for every web patch: the lesson for the pipeline is that "install smoke passes" does not say that the lab's integration tests pass. The ou-gw1 drill is the first run of the lab suite against packages.
4. MariaDB and nginx were untouched, but php-fpm was restarted with every step (all steps stop and start it).
5. **Incident during the drill and a real restore from the backup.** Two runs of `gw_run_all.sh` overlapped (a background command was started twice) and I killed one of them while GW07 had wiped grace's INBOX and not yet imported it back. GW07 re-imports the complete `IPM_SUBTREE` dump on every run, so the aborted and concurrent runs left grace with 51876 messages (the MANIFEST of the backup says 2088 / 40 inbox / 0 calendar) and `gromox-http` at 100 % CPU. The mailbox was restored from the pre-migration backup (`groupware.tar` member `mbx/grace@gw1.ou-lab.internal.mt` and its `perm.sql`): stop the gromox units, move aside the store, `gromox-mkprivate` + `gromox-mkmidb`, start the units, `gromox-import -u grace@gw1.ou-lab.internal -x -c`, ACL rows with `sqlite3`. Result counts 2088 / 40, exactly the MANIFEST values; the final solo `gw_run_all.sh` then passed (GW07 7 PASS) and, as with every GW07 run before, adds about 2050 duplicate messages to grace (4140 after the final run): a property of the GW07 test, not of the packages. The pre-restore store is kept in `/root/grace-pre-restore` on ou-gw1.

## 6. In-place upgrade, rollback and roll forward

All three use the same call, `gw-pkg-upgrade.sh change <gromox-version>`: refresh the index, `apt-get install --download-only` of the exact versions first (a failed download must not leave the node down: the first attempt of the drill failed because the repo machine was being restarted, and with the original order it had left ou-gw1 stopped, which is why the order was changed), stop services, `apt-get install --allow-downgrades --allow-change-held-packages` with the pinned versions, `daemon-reload`, start in order, verify every unit is active, `apt-mark hold`.

| Step | Pins | Timing (index / swap / restart / total / service stop) | Verification |
|---|---|---|---|
| web ou1 to ou2 (upgrade) | `ou-grommunio-web=5.2-ou2`, rest as before | 3.0 / 7.3 / 4.4 / **14.9 s** / 11.6 s | gw tests 13/12/7/10/4/4/7 PASS, behaviours 9 PASS, SSO e2e 9 PASS (config.php conffile kept, `dpkg -V` shows only the conffile hash) |
| **rollback** gromox + php-mapi ou2 to ou1 (downgrade) | `ou-gromox=3.13-ou1`, `ou-gromox-php-mapi=3.13-ou1` | 3.1 / 11.7 / 4.5 / **19.5 s** / **16.2 s** | gw tests all PASS (13/12/7/10/4/4/7), SSO e2e 9 PASS, behaviours as table in section 4 (patched behaviours are gone, as expected for ou1) |
| roll forward to ou2 | `ou-gromox=3.13-ou2`, `ou-gromox-php-mapi=3.13-ou2` | 3.7 / 12.3 / 4.2 / **20.4 s** / 16.5 s | final solo run: gw tests 13/12/7/10/4/4/7 PASS (an earlier overlapping run had 2 GW01 FAILs and a GW07 timeout, see section 5 item 5), behaviours 9 PASS; the SSO e2e was not repeated after the roll forward (last run: ou2 gromox + ou2 web, 9 PASS) |

**Which rollback:** the pinned downgrade, not the restore from backup. It works because the promotion no longer deletes the previous version from the channel (`repo.sh promote` change of this task): ou1 and ou2 of ou-gromox are both in `pool/stable/gromox` and in the signed `Packages`. It costs about 20 s with the data untouched (ou1 and ou2 are the same upstream 3.13 code, the two patches touch token validation and the IMAP/event processes only; no data or schema migration is involved). For a package pair that migrates data, the backup of step 3 (`gw-restore.sh`, GW09 restore drill from earlier work) is the way back; the pre-migration source-built binaries are available as `source-built.tar` on the node as a third path.

## 7. Not done, limits

* The whole-node restore from the logical backup was not run on ou-gw1 (see verdict table); one mailbox was restored.
* The migration is a script, not an ICS typed action with approval and audit (ADR-0008 steps 9-10 remain open); it ran from the ICS host as `administrator` with `sudo systemd-run`.
* Rollback timing excludes human decision time; the node's services were down for the stated "service stop" values, clients retry.
* A second node (ou-gw-sso1, ou-gw-r1) was not migrated.
* Behaviours were tested at zcore, IMAP and browser level only; EWS, ActiveSync and DAV are covered by GW02..GW05 (they use the LDAP password and do not exercise bearer tokens).
* After the rollback the bearer directives stay in `gromox.cfg` unused by ou1 (ou1 ignores unknown directives), which is why the "unpatched" column shows the old acceptance.
* Concurrent runs of two test processes against the node disturbed GW07 once (a read timeout); it passed alone and in the full run.
* Host memory was shared and tight during the whole task (4 to 6 GB available); builds stayed within the 3 GB builder cap.

## 8. Files

`blueprints/lab/upgrade/gw-pkg-upgrade.sh` (driver), `gw-pkg-inner.sh` (on the node: `pre`, `migrate`, `change`, `status`), `gw_behaviour_tests.py`; `blueprints/build/**` for the pipeline (see `package-pipeline-results.md` section 8); node-side state of the migration under `/var/backups/ou-prepkg/<timestamp>/` on ou-gw1 (state, file list and checksums, `source-built.tar`, `config.tar`, `db.sql`, `var-lib-gromox.tar`, old web/sync/dav trees, `uninstall-*.dryrun`); host-side backup `/var/backups/office-unbound/lab/ou-gw1/20261115T213520Z` (root only). Host changes: `host-changes.md`.
