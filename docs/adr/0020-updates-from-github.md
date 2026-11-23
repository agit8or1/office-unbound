# ADR-0020: Updates from GitHub: the controller fetches signed releases and rolls them out to deployments

Status: **Proposed — PLANNED** (owner, 2026-11-23: "this system will also need an update mechanism to pull updates from github to the
controller. the controller can then deploy the updates to servers deployed"). Builds on ADR-0008 (release pipeline), ADR-0011 (versions),
ADR-0015 (artifact distribution) and the 0.12.0 in-place upgrades. Roadmap: P2.13. Status words: ADR-0000.

## What exists today (verified; unchanged by this ADR)
| Capability | Evidence |
|---|---|
| The ICS as a signed `ou-ics` package with preflight, automatic pre-upgrade backup and rollback (lab; production ICS still a git-tree install) | P2.9, `docs/runbooks/ics-upgrade-rollback.md` |
| Signed apt repository and OCI registry on the ICS host for guests, per-channel key pins, tamper/unsigned/wrong-key refusals | P2.8, ADR-0015 |
| In-place change of a running deployment: agent self-update, component upgrades, reconfigure; no new VMs or images | 0.12.0, `ics/tests/test_deploy_inplace.py` |
| Releases on GitHub (public repo, prerelease per version) | notes only today: **no assets** attached |

What is missing is the link: a release reaches the controller only by someone running `install.sh` from a checkout, and its artifacts
(agent, portal, office image) only by a build on this host.

## Decision
1. **Release bundle on GitHub.** Each release attaches the signed artifacts (`ou-ics` deb, `ou-agent`/`ou-portal` debs, OCI images as
   OCI archives with their cosign signatures) and a **release manifest** (`ou-release-<version>.json`: version, release name, channel,
   every artifact with sha256 and size, the catalog pins, the minimum ICS and agent versions, migration notes) with a detached signature
   by the release key. GitHub is transport only: nothing is trusted because of where it came from or TLS.
2. **Check** (read-only, scheduled daily and on demand): the ICS asks the GitHub Releases API (anonymous, public repo, an endpoint already
   in `authorized-endpoints.md`) for versions newer than its own on its channel (dev / stable; prereleases only on dev). It shows them in
   the console with the release notes. No credentials, no user or deployment data sent.
3. **Download** (typed action `ics.update.fetch`, approval, durable job, audit): fetch the manifest and signature, verify against the
   pinned release key **before** downloading anything else, then each artifact with size limits and sha256 check, then import into the
   local signed apt repository and registry (ADR-0015). A failure leaves nothing half-imported.
4. **Update the controller** (typed action `ics.update.apply`): the `ou-ics` package path (preflight, backup, migrate, health check,
   automatic rollback on failure). Requires the ICS to be a package install first (P2.9 on production).
5. **Roll out to deployments** (one `deployment.change` per deployment, each previewed and approved): agent, components and configuration
   to the versions the new catalog pins, in place. The console lists each deployment's current and available versions; rollout order
   (rings) is the admin's choice; a deployment is never updated without its own approval.

## Not decided / out of scope
* Automatic (unattended) apply: not planned; check and download may be automatic, apply and rollout stay approved actions.
* A private mirror for air-gapped sites (manual bundle import with the same verification) — later, same manifest.
* Release key custody and rotation for production (today the lab release key) — owner decision before the first stable channel.

## Consequences
* The release process (`scripts/release_notes.py`, `gh release create`) gains artifact upload and manifest signing.
* The production ICS moves from a git-tree install to the `ou-ics` package (one-time, with backup; P2.9 runbook).
