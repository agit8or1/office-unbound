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
9. **Deploy from a clean checkout of the tag** (never from a working tree): `git clone --branch vX.Y.Z <repo> /tmp/ou-release && cd /tmp/ou-release`,
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
