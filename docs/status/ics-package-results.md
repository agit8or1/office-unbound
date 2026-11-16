# ICS as a signed package (`ou-ics`): results

Branch `ics-pkg` (from `fixes-r5`), agent BQ, 2026-11-16. Design: ADR-0008 (pipeline), ADR-0011 (versions). Operator procedure:
[runbooks/ics-upgrade-rollback.md](../runbooks/ics-upgrade-rollback.md), [RELEASING.md](../RELEASING.md) "Packaging the ICS".
Evidence (logs, SBOM, licence/OSV reports, checksums) in [`ics-package-evidence/`](ics-package-evidence/).
Status words follow ADR-0000: everything below marked PASS was executed; items under "Not done / not proven" were not.

## What was built
| Piece | Where |
|---|---|
| Recipe (`OU_ICS_TAG=vX.Y.Z build.sh ics`; Debian version `X.Y.Z-ou1`, pre-release `0.1.1~dev.1-ou1`) | `blueprints/build/ics/recipe.yaml`, `ics/debian/*`, `lib/{recipe,artifact-check,licensecheck,sbom}.py`, `build.sh` |
| Source = annotated tag of this repo: commit + tag object + signature state recorded, `VERSION` must equal the tag, deterministic `git archive`, `SOURCE_DATE_EPOCH` = commit time, `.ou-source-commit` -> `BUILD_INFO.json` (`commit`, `dirty:false`, `package`, schema head) | `build.sh fetch`, `ics/deploy/write_build_info.py` |
| Python deps: `pip download --require-hashes --only-binary=:all:` in the builder (unprivileged, network only there) for cp311 + cp312 from `ics/requirements.lock`; wheels shipped in the .deb; postinst installs with `--no-index --require-hashes` | `debian/fetch-wheels.sh`, `ou-ics.postinst` |
| Console: the committed `ics/ics/static` is shipped as tagged (not rebuilt by the pipeline); alembic migrations; deployment catalog; units `ics`, `ics-migrate`, `ics-callback` (no `ics-bootstrap` unit exists); sysusers + tmpfiles; conffile `/etc/office-unbound/ics-tuning.env` (loaded by `ics.service`) | `debian/rules` |
| First-run provisioning only for what is absent (keys never overwritten, DB roles, env files) | `ics/deploy/pkg/ou-ics-setup` |
| Backup gate: preinst preflight + verified backup before unpack (refuses = old version untouched); postinst re-checks, backs up itself if none is fresh, refuses to migrate if that fails; migration failure leaves the ICS stopped | `ou-ics.preinst`, `ou-ics.postinst`, `ou-ics-preupgrade-backup` |
| Rollback tool | `/usr/sbin/ou-ics-rollback` (`ics/deploy/pkg/ou-ics-rollback`) |
| `python -m ics.cli upgrade-preflight` (disk, backup freshness, running/queued jobs and deployments, passive/standby state, schema known/ahead) | `ics/ics/upgrade.py`, `ics/ics/cli.py`, `ics/tests/test_upgrade_preflight.py` |
| `bootstrap.sh --from-repo <channel> --repo-url URL [--repo-key F] [--repo-key-fingerprint FPR] [--version V]`; key fingerprint verified before anything is provisioned; `install.sh` unchanged for development | `ics/deploy/bootstrap.sh` |
| Pipeline additions: builder lock (`flock`, the builder machine is a singleton), `keep_versions` (older `ou-ics` stay in the pool so a rollback can install them), PSF-2.0 added to the licence policy (greenlet, typing_extensions) | `build.sh`, `repo/repo.sh`, `license-policy.yaml` |

Signed into the dev channel only through `sudo -u ou-release ou-release-sign admit/sign` (via `repo.sh publish`); never by the operator user, never promoted.

## Build results (builder `ou-pkg1`, a fresh clone of `ou-pkg-golden` per build, destroyed afterwards)
| Package | sha256 (deb) | size | licence | SBOM | OSV |
|---|---|---|---|---|---|
| `ou-ics 0.1.0-ou1` (lab tag `v0.1.0` = branch commit `aea4ce6`) | see `build-0.1.0-ou1/SHA256SUMS` | 40.3 MB | PASS: 38 vendored wheels + 203 bundled (npm/PyPI) packages, 0 problems | SPDX 2.3 (105 packages) + syft | 103 packages scanned |
| `ou-ics 0.1.1~dev.1-ou1` (lab tag `v0.1.1-dev.1`, adds dummy migration `0011`) | see `build-0.1.1~dev.1-ou1/SHA256SUMS` | 40.3 MB | PASS | same | same |

OSV: **no advisory in any Python or npm package**. The 45 advisories are against Debian `curl 7.88.1-10+deb12u15` (38) and `systemd 252.39-1~deb12u2` (7): they come from the SBOM's runtime `Depends` entries resolved to the *builder's* versions (the package does not ship them; the target hosts use their own, newer, Ubuntu/Debian packages). Recorded, not triaged further. Lintian: only `dir-or-file-in-opt` (deliberate layout, ADR-0001) and style warnings.

## Proof in fresh machines (MemoryMax 1500M each; `free -g` available >= 2 GiB checked before each start)
`ou-pkgt1` Ubuntu 24.04 (python 3.12, wheels cp312) and `ou-pkgt2` Debian 12 (python 3.11, wheels cp311), both fresh clones of the base images, only the signed `dev` repo from `ou-repo1` added (key pinned by fingerprint `3082B558...22A4`, the dev channel key). Driver: `blueprints/build/tests/icspkgtest.sh` + `icspkg-guest.sh`. Logs: `ics-package-evidence/lab/`.

| Step | pkgt1 (Ubuntu 24.04) | pkgt2 (Debian 12) |
|---|---|---|
| `apt-get install ou-ics=0.1.0-ou1`: first run (keys, roles, DB, env, venv, migrations, start), `/readyz` 200, `BUILD_INFO` commit + `dirty:false` + package, audit chain verifies, key/env modes, units from `/usr/lib/systemd/system` | 12/12 PASS (54 s) | 12/12 PASS (69 s) |
| Offline wheel install in an empty network namespace; a tampered wheel is refused by `--require-hashes` | 2/2 PASS | 2/2 PASS |
| Owner bootstrap (`ics.cli create-admin`, token printed once, not logged here) + audit writes, chain verifies | 2/2 PASS | 2/2 PASS |
| Publish `0.1.1~dev.1-ou1` (signed dev), then **upgrade with a broken backup tool: refused**, apt exit 100, version/schema/service unchanged, package still `ii` | 6/6 PASS | 6/6 PASS |
| **Upgrade** `apt-get install ou-ics` after `upgrade-preflight` (exit 0): backup taken automatically (schema 0010, archive hash = MANIFEST), migration 0010 -> 0011 applied, `/readyz` 200, audit chain verifies, owner and audit events preserved, keys untouched | 13/13 PASS (40 s) | 13/13 PASS (37 s) |
| **Rollback**: `apt-get install --allow-downgrades ou-ics=0.1.0-ou1` leaves the ICS stopped + marker and names the pre-upgrade backup; `ou-ics-rollback <dir>`: schema back at 0010, dummy table gone, `/readyz` 200, audit chain verifies, owner present, safety dump kept | 13/13 PASS | 13/13 PASS |
| `bootstrap.sh --skip-tls --from-repo dev ...` on a fresh Ubuntu 24.04 (`ou-pkgt3`): wrong fingerprint refused before anything is provisioned; missing `--repo-url` and stray repo options refused; correct pin installs `0.1.0-ou1`, admin created, `/readyz` 200, verify-chain ok, re-run is a no-op | PASS (`lab/t3-bootstrap2.log`) | |

Static tests (`ics/tests/test_ics_package.py`, 27) hold the contract of the recipe/scripts (postinst order, empty `strip_nondeterminism` override so wheel hashes survive, tag -> Debian version mapping, `BUILD_INFO` with pinned commit, prerm/postrm never touch data). Preflight tests: `ics/tests/test_upgrade_preflight.py` (11). Full suite (`ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-a.env .../pytest -q -p no:cacheprovider`, log `ics-package-evidence/full-suite.log`): **888 passed, 0 failed** (20 min), run on branch state `aea4ce6` plus the new test files; the later commit only touched bootstrap.sh (early key check) and docs, and the package/preflight/version/bootstrap test files were re-run after it (all pass).

## Findings made on the way (all fixed in this branch unless stated)
1. **The ICS did not start on Debian 12.** `ics/actions.py:1013` used an f-string with nested same-type quotes (Python 3.12 only): `SyntaxError` on 3.11. Every Debian 12 claim in the installer docs rested on a host that never imported that module. Fixed (`limit_s`); `compileall` of the whole tree on Debian 12 is clean now. Found by the first Debian 12 run (`python3.11`, `ics.service` crash loop), not by the test suite, which only runs on 3.12.
2. **The host signer has moved to per-channel keys** (`/var/lib/ou-release/FINGERPRINT-{dev,staging,stable}`, key `3082B558...`), so the lab key committed in `blueprints/build/keys/` (`5D2750D0...`) no longer verifies the dev channel (`NO_PUBKEY`). That change is not in `fixes-r5`. The tests pinned the dev key from the served tree; `bootstrap.sh --from-repo` prefers `keys/ou-release-<channel>.pub.asc` and falls back to the lab key, and the fingerprint must always match exactly. The committed key file and `FINGERPRINT` need updating when that branch merges.
3. `ics_app` cannot read `alembic_version` (the console's `/version` swallows the error): the preflight reads the schema revision with the owner URL when run as root and reports "unknown" otherwise.
4. The builder `ou-pkg1` is a shared singleton: a concurrent `compile gromox` from another agent collided with my first run (clone "busy", leftover half-cloned image). `build.sh compile` now takes `flock` on `$STATE/builder.lock`; builds that do not use it can still collide.
5. Lab-run bugs fixed before the final run: revision grep without `[[:space:]]*` (postinst would have treated every database as "newer" and stopped the ICS on any upgrade), CR characters in apt output in the test script, a negative test that did not exercise the refusal because apt had not yet seen the new version (the final run asserts a newer candidate is visible). The first lab run is superseded by the clean run documented here.

## Not done / not proven
* **Reproducibility is not verified** (inputs are pinned and mtimes clamped; no second build was compared). Wheels are verified by hash, not rebuilt.
* The console static is not rebuilt by the pipeline; tags are **unsigned** annotated lab tags in a scratch clone (the real repository was not touched). `v0.1.0` here is not a release; the package shipped commit `aea4ce6` of `ics-pkg`.
* Not promoted: no test attestation (`record-test`) and no `release.promote` plan were made. Only `dev` holds `ou-ics` (both versions); the pool/ledger are shared host state.
* The postinst's own fallback backup (when the preinst marker is missing/stale) and a **failing migration** path are covered by code and static tests, not by an executed lab case. Likewise: upgrade with a running job (preflight FAIL), standby/passive controller, `dpkg` conffile prompt, `apt-get purge`, TLS/nginx/firewall via `--from-repo` (only `--skip-tls` was run), install over an existing git-tree installation.
* `ou-ics-rollback` loses data written after the backup (by design; kept in the safety dump). Backups stay on the same host (no off-host/encrypted copy: backup-product work).
* Debian `postgresql (>= 15)` is a plain dependency; the package neither tunes nor backs up PostgreSQL itself.

## Host changes
Recorded in [host-changes.md](host-changes.md).
