# Releasing Office Unbound

Scheme and rationale: [ADR-0011](adr/0011-versioning-and-releases.md). Format of the record: [`CHANGELOG.md`](../CHANGELOG.md).
Releases are prepared on a branch and **published by the owner/lead** (tag, GitHub Release, deployment). Nothing in this
checklist is automated to push or tag.

## Checklist

1. **Gate is green on CI** for the commit to be released: backend, frontend, security, lint and roadmap workflows
   (`.github/workflows/`). Run the full local suite as well (`cd ics && .venv/bin/pytest -q`, `cd ics/frontend && npm test && npm run build`).
   Open Blocker/High issues for the milestone must be closed or explicitly waived in the changelog.
2. **Draft the entries**: `python3 scripts/changelog_draft.py` lists commits since the last tag. Edit them into
   `CHANGELOG.md` under `## [Unreleased]`, each with an evidence link (ADR-0000: no evidence, no entry).
3. **Bump the version**: edit `VERSION` (product + ICS) and, if a component changed, `VERSIONS.json` and the component's own
   literal (`ics/agent/ou_agent/__init__.py`, `portal/app/version.py`); `ics/tests/test_version.py` fails on a mismatch.
4. **Cut the changelog section**: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh empty `## [Unreleased]`,
   update the link references at the bottom.
5. **Update the progress feed**: in `docs/progress.json` set `current_version`, add the release to `releases[]` (newest first;
   `status: "prepared"` until the tag exists, then `"released"`), refresh `updated`, then
   `python3 scripts/render_roadmap.py` and `python3 scripts/release_notes.py --check`.
6. **Commit** (`git commit -s`) and merge through the normal review. Rebuild the console assets (`cd ics/frontend && npm run build`)
   if the frontend changed, in the same change.
7. **Tag** from the merge commit on `main`: `git tag -s vX.Y.Z -m "Office Unbound X.Y.Z"` when a signing key is configured
   (`git config user.signingkey`); otherwise `git tag -a vX.Y.Z -m ...` and say "unsigned" in the release notes. The production
   signing key is an offline owner item (tracked on GitHub); until it exists releases are unsigned. `git push origin vX.Y.Z`.
8. **GitHub Release**: `python3 scripts/release_notes.py > /tmp/notes.md` then
   `gh release create vX.Y.Z --title "Office Unbound X.Y.Z" --notes-file /tmp/notes.md` (add `--prerelease` while the major version is 0).
9. **Deploy.** Preferred for anything that is not a developer machine: **ship the ICS as the signed `ou-ics` package** (next section) and
   upgrade it with apt. The git-tree route below stays supported for development hosts and for the first bring-up.
   **Deploy from a clean checkout of the tag** (never from a working tree): `git clone --branch vX.Y.Z <repo> /tmp/ou-release && cd /tmp/ou-release`,
   verify `git status` is clean, **take and verify a backup first** ([backup and restore](admin/backup-and-restore.md)), then
   `sudo ics/deploy/bootstrap.sh ...` (or `sudo sh ics/deploy/install.sh` for a plain code refresh). The installer writes
   `BUILD_INFO.json`; confirm `GET /api/v1/version` (signed in) shows the tag's commit and `dirty: false`, and Administration → System
   lists the expected component versions. Roll back with the restore runbook ([ICS recovery](runbooks/ics-recovery.md)) if checks fail.
   Record the host change in `docs/status/host-changes.md`.
10. **After publishing**: set the release's `status` to `"released"` in `docs/progress.json`, re-render `ROADMAP.md`, close the GitHub
    milestone, and open the next milestone.

## Hotfix releases
Branch from the tag, fix, add a `### Fixed` or `### Security` entry, bump PATCH, and follow steps 3-10. Security fixes are described
without exploit detail until the fix is deployed ([SECURITY.md](../SECURITY.md)).

## What "pending updates" means
Administration → System compares the installed version with the `releases[]` list that was bundled into `BUILD_INFO.json` at
install time. It makes no network request; it cannot know about a release published after the last install. Updating is
step 9, an operator action.

## Packaging the ICS (`ou-ics`, signed pipeline)
The ICS ships through the same pipeline as every other component (ADR-0008): recipe `blueprints/build/ics/`, builder `ou-pkg1`, SBOM, licence
check, OSV scan, signed apt repository with dev -> staging -> stable promotion (`release.promote` plan, approvers, test evidence). Version =
the git tag (ADR-0011): `vX.Y.Z` -> package `X.Y.Z-ou1`, pre-release `vX.Y.Z-rc.1` -> `X.Y.Z~rc.1-ou1` (sorts before the release). Bump `-ouN`
(`ou_revision` in the recipe) when only the packaging changed.
1. Steps 1-7 above give you the annotated tag `vX.Y.Z` on the merge commit (`VERSION` must equal the tag; the build refuses otherwise).
   The built console (`ics/ics/static`) is shipped as committed: rebuild it in the release commit if the frontend changed (step 6).
2. On the ICS host as the operator user (never as root, never with the signing key): `OU_ICS_TAG=vX.Y.Z [OU_ICS_COMMIT=<sha>] [OU_ICS_REQUIRE_SIGNED=1] blueprints/build/build.sh ics`
   - `fetch`: resolves the tag, refuses a lightweight tag or a VERSION mismatch, records commit + tag object + signature state, exports a
     deterministic `git archive` (SOURCE_DATE_EPOCH = commit time) plus `.ou-source-commit`;
   - `license`: SPDX scan of the tree + npm lock licences; after the build the METADATA licences of every vendored wheel are checked against
     `license-policy.yaml` (unknown = fail);
   - `compile` in a fresh clone of the golden builder: the only network step is the unprivileged prefetch (`pip download --require-hashes
     --only-binary=:all:` for cp311 and cp312, hashes from `ics/requirements.lock`); the binary build runs in an empty network namespace;
   - `sbom` (SPDX 2.3 + syft cross-check) and `scan` (osv-scanner) are recorded under `out/ics/`.
   `BUILD_INFO.json` inside the package carries version, commit, `dirty:false`, schema head, package version, build time.
3. `blueprints/build/repo/repo.sh publish ics` (admission and signing go through `sudo -u ou-release ou-release-sign`; older `ou-ics` versions stay in the
   pool so a rollback can install them). Run the package proof (`blueprints/build/tests/icspkgtest.sh`, see
   `docs/status/ics-package-results.md`), record the result, then promote through the ICS `release.promote` plan.
4. Customer/host upgrade and rollback: [runbooks/ics-upgrade-rollback.md](runbooks/ics-upgrade-rollback.md): `ics.cli upgrade-preflight`, then
   `apt-get install ou-ics`; the package takes and verifies a backup first and refuses to migrate without one. Rollback = reinstall the previous
   version + `ou-ics-rollback <backup>` when the schema moved (alembic downgrade is not trusted).
5. New host straight from a channel: `bootstrap.sh --from-repo <channel> --repo-url <url> ...` (the repository key fingerprint is pinned).
Record the host change in `docs/status/host-changes.md` as in step 9.
