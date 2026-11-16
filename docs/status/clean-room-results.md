# Clean-room re-run of every lab installer (acceptance A22)

Date: 2026-11-15. Agent AO. Lab only. Status words per ADR-0000: PASS/FAIL below are executed counts from the logs of this run.

Setup: four FRESH nspawn machines in zone `oulab` (PrivateUsers=pick) cloned from `ou-base-noble` / `ou-base-bookworm` with
`blueprints/lab/common/create-machine.sh`, lab domain **`cr.ou-lab.internal`** with its own lab CA (created by `install-kc.sh` on `ou-cr-id`),
static IPs 192.168.186.251-254 (`ou-cr-id`, `ou-cr-files`, `ou-cr-office`, `ou-cr-gw`; caps 2G/2G/3G/3G). Nothing of the existing lab
(ou-id1, ou-files1, ou-office1, ou-gw1, ...) was changed (read-only: the 1.3 GB own-editor artifact was copied out of `ou-build1`'s rootfs).
Tests ran from the ICS host with the documented env pointing at `*.cr.ou-lab.internal` (test venv in the agent scratchpad).
Tiers were run sequentially; host MemAvailable stayed >= 4.3 GiB throughout (min observed 4.3 GiB; the guard in `create-machine.sh` refuses < 2 GiB).

## Summary

| Tier | One-pass result | Tests (clean-room stack) | Second run (idempotent?) | Wall time, first pass | Peak machine memory (cgroup, incl. page cache) |
|---|---|---|---|---|---|
| identity `install-kc.sh` (+ `install-openldap.sh`, `lab-ca.sh`) then `install-openldap.sh test-users` | OK in one pass (after fix 1) | t01 36/0, t06 14 PASS / 2 FAIL (the 2 FAIL are the documented, expected finding: Keycloak refresh tokens survive an LDAP-only lock) | yes, after fixes 5-6: 295 config files hash-identical, test users and passwords kept | 2 m 08 s | 1.83 GB (cap 2G) |
| files `install-files.sh` | OK in one pass | t01 36/0, t02 11/0, t05 9/0 | yes, 168 files identical | 42 s | 0.35 GB (cap 2G) |
| office (vendor CODE) `install-office.sh` | OK in one pass (twice: second pass after fixes 7-8 on a re-created machine) | t03 28/0, t04 13/0, t05 9/0 | yes after fixes 7-8: 171 files identical | 1 m 28 s | see next row |
| office (own editor) `ou-docs-install.sh` (new, replaces the hand steps of docengine-rollout-results.md 1) | OK; the first attempt failed only because the artifact had been deleted with my re-created machine (my error), the repeat ran clean | t03 28/0, t04 13/0, t05 9/0, **t08 5/0 (30 concurrent sessions)** | yes: 209 files identical | 20 s (+ artifact copy 1.3 GB) | 3.02 GB (cap 3G, page cache of the 1.3 GB artifact + t08) |
| groupware `build-from-source.sh` (8 stages) | OK in one pass (EXIT=0), 18 m 01 s at `JOBS=3`, 7 pinned sources recorded | - | build re-run EXIT=0 in 9 m 46 s (the `sync/dav/web` stages recreate the app trees, so the config stages must follow, see below) | 18 m 01 s | 3.22 GB (cap 3G; compiler + page cache) |
| groupware `lab-configure.sh` -> `lab-nginx.sh` -> `lab-apps.sh` -> `lab-ldap.sh` -> `lab-sso-existing.sh` | OK, but gromox/postfix were never started by any script (fix 9), so `lab-ldap.sh` silently skipped its provisioning until `lab-configure.sh` was fixed and re-run | `gw_run_all.sh` **57 PASS / 0 FAIL** (GW01 13, GW02 12, GW03 7, GW04 10, GW05 4, GW08 4, GW07 7); `gw_ldap_01` 25/0 (after fix 10), `gw_ldap_03` 12/0, `gw_ldap_02` 9/0 | yes: full chain build -> configure -> nginx -> apps -> ldap -> sso re-run, 307 files hash-identical; tests re-run after it: same 57/0 | configure..sso: ~1.5 min | (same machine) |

Total clean-room test counts: identity/files/office-vendor t01 36, t02 11, t03 28, t04 13, t05 9 (all 0 FAIL); own editor t03 28, t04 13, t05 9, t08 5 (0 FAIL); t06 14/2 (expected);
groupware 57 + 46 = 103 PASS, 0 FAIL after the fixes. Not run: t07 (needs the `ou-desk1` AppImage client machine; it has no Collabora/installer part), the webmail SSO shell/JS tests,
`blueprints/build/collabora/tests/setup_runtime.sh` (the test-flavour setup for `ou-office2` with `/opt/cool` paths; superseded by `deploy/ou-docs-setup.sh`, which `ou-docs-install.sh` runs), the MANUAL checklist.

How idempotency was measured: sha256 of every file under `/etc` (minus trust-store/passwd noise), `/root/ou-lab-ca`, `/root/ou-lab-secrets`, `/opt/keycloak/conf`, the realm import
(id/office), plus `/root/lab-creds.env`, `/usr/local/sbin`, sync/dav `config.php`, web `grommunio.js` for the gateway, taken before and after the second run (`diff` empty = identical).
Not hashed: LDAP `cn=config` (slapd.d LDIF carries modify timestamps), databases, mailbox data.

## Fixes forced by the clean-room run (all committed)

| # | Error / symptom | Fix |
|---|---|---|
| 1 | A second lab cannot exist: `lab.env` hard-coded `ou-lab.internal`, the lab IPs and the base DN; `realm-ou-lab.json` hard-coded names (the first attempt at `cr.ou-lab.internal` would have produced a realm whose issuer/redirects point at the old lab) | `lab.env` now sources `/etc/ou-lab/lab-local.env` (or `$LAB_LOCAL_ENV`) and all of `LAB_DOMAIN`/`IP_*` are overridable, `LDAP_BASE_DN` is derived; `install-kc.sh` rewrites domain and base DN in the realm import. Defaults unchanged, so the old lab behaves as before |
| 2 | Machine creation existed only as prose in host-changes.md; clones kept hostname `ou-base` (sudo/hosts warnings) | `common/create-machine.sh` (clone, `.nspawn`, MemoryMax, static IP, hostname, 2 GiB memory guard) |
| 3 | `fetch-bundle.sh` needs ssh, which the nspawn machines do not have; `install ... /dev/stdin` fails ("Permission denied") through `systemd-run --pipe` | `machine:<name>` targets via `sudo systemd-run -M`, bundle written with `sh -c 'umask 077; cat > ...'` |
| 4 | `install-files.sh` dies with "put the LDAP bind password ... first" - an undocumented manual copy | `common/fetch-bind-password.sh <kc> <target>` |
| 5 | Idempotency: `lab-ca.sh` repacked the per-role bundles with new mtimes/gzip timestamps on every run (hash churn in `/root/ou-lab-ca/out`) | deterministic `tar --sort=name --mtime=@0 ... | gzip -n` |
| 6 | `install-openldap.sh test-users` truncated `test-users.env` and failed re-adding the five users on a second run (passwords would have been lost) | skip existing users, never truncate the env file |
| 7 | `install-office.sh` second run inserted the WOPI `<group>` host a second time into `coolwsd.xml` (the idempotency check compared our whitespace, but `coolconfig` rewrites the file with tabs) | check for the `<host allow="true">https://HOST:443</host>` element instead |
| 8 | `install-office.sh`: `coolconfig set-admin-password` writes a new random PBKDF2 salt on every run (config churn) | run once, marker `/root/ou-lab-secrets/.collabora-admin-set` |
| 9 | Groupware: nothing starts gromox, postfix or enables the units (gw1 had them started by hand); `lab-ldap.sh` then printed "gromox-imap inactive: restart later" and exited 0 without provisioning | `lab-configure.sh` ends with `systemctl enable --now gromox-* postfix` |
| 10 | `gw_ldap_01` FAIL "LDAPS certificate verification enforced - rc=0 unchanged": the wrong-CA probe used the system bundle, which contains the directory CA once the SSO step installed it (stale since agent AA's SSO rollout) | probe uses the gateway's own CA file (`/etc/ou-lab-tls/ca.crt`) |
| 11 | Hard-coded names in the groupware tooling made a second lab impossible/unsafe: `lab-ldap.sh`, `lab-sso-existing.sh`, `lab-sso-keysync.sh`/`ou-sync-bearer-key.py` (ou-id1, 192.168.186.241, `ou-lab.internal`, base DN), `gw_ldap_lib.py`/`gw_ldap_01_provision.py` (base DN, LDAP host, mail domain, `gw1-users.env` path; first run silently talked to `auth.ou-lab.internal` of the old lab and was stopped by TLS verification), `gw_run_all.sh` (`python3` instead of the venv) | env overrides `ID_MACHINE`, `LAB_DOMAIN`, `ID_IP`, `OU_GW1_ENV`, `OU_PYTHON`; defaults unchanged |
| 12 | Own-editor rollout was a hand sequence (apt runtime packages only in `oci/Containerfile`, extract, setup, configure, unit, restart) | `blueprints/build/collabora/deploy/ou-docs-install.sh <artifact.tar> <wopi-host-url>`: one pass, idempotent |

## Observations that are not fixed

- `build-from-source.sh` is repeatable (EXIT=0) but its `sync`/`dav`/`web` stages `rm -rf` the installed app trees: after a re-run the configure/apps/sso scripts must be run again (they were, and the result is hash-identical). Document as "re-run the whole chain".
- The install scripts still print "(untested script...)" footers (`install-kc.sh`, `install-files.sh`) although they are now executed twice; cosmetic.
- `install-grommunio.sh`/`post-setup-grommunio.sh` (vendor packages) were not run: per ADR-0007 the source build is the authoritative path and vendor packages are reference only.
- Memory figures are cgroup `MemoryPeak` including page cache, not RSS. The gateway reached its 3G cap during the compile (no OOM kill at JOBS=3).
- The first office pass and the first gateway configure pass were not repeated from a pristine image after fixes 8 and 9 (verified by re-running the fixed scripts on the same machines); every other installer ran from pristine on its first pass.

## State at the end

All four `ou-cr-*` machines are powered off, images kept in `/var/lib/machines`. Host: `/etc/hosts` block `192.168.186.251-254` (cr names), `/etc/systemd/nspawn/ou-cr-*.nspawn`,
`MemoryMax` drop-ins (see host-changes.md). Secrets stay inside the machines (`/root/ou-lab-secrets`).
Rerun: `sudo blueprints/lab/common/create-machine.sh ou-cr-id ou-base-noble 192.168.186.251 2G start`, write `lab-local.env` (LAB_DOMAIN=cr.ou-lab.internal, IP_KC/IP_FILES/IP_OFFICE) to `/etc/ou-lab/`, copy `blueprints/lab` to `/root/lab`, then follow `blueprints/lab/README.md`.
