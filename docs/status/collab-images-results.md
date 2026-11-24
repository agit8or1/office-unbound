# Collaboration images: build, pin, (not) sign - 2026-11-15

Status: **Partially done.** Five OCI images were built from source in the builder (`ou-build1`, since powered off), SBOM'd, scanned and pinned by digest in the catalog, but they are **NOT signed**: they carry `signed: false` and plans containing them are refused with the new blocking error `artifact_unsigned`. MAS and the four Jitsi parts were not touched (endpoints not authorized) and stay `artifact_unpinned`. Nothing in this document is deployed anywhere.

## Result table
| Artifact | Version | Digest (registry manifest, docker v2) | State |
|---|---|---|---|
| chat/synapse | 1.165.0 | `sha256:542de3d410dc142cf45c69e42c13cbd970a497803dc7edb78c3e2b2ee5160a9d` | pinned, **unsigned** |
| chat/element-web | 1.12.35-ou2 (2026-11-24: config under /ou-element) | `sha256:13210cdafd616799bc3673a7ac7c6cb11ea58ae201c5f369c5d08c2eaecb01a3` | pinned, dev-signed (runner scan pass: 229 vuln ids, max CVSS 9.8); 1.12.35 was `sha256:3466abb4…` |
| meetings/meet-token-service | 0.1.0-ou1 | `sha256:69b20d09d661d29ad5482e9603dfe628d5ca176925513c5d312ba04513e1e283` | pinned, **unsigned** |
| telephony/softphone-web | 0.1.0-ou1 | `sha256:efc5d8b4ad04b70e25d66b3ef9219c5009f4ee33d328005d6ed3accaa8b33941` | pinned, **unsigned** |
| telephony/pbx-helper | 0.1.0-ou1 | `sha256:481adefa96c173b81a7871b738498edea255269441ae2dde8c1d25d9f2c97f8d` | pinned, **unsigned**, not usable standalone (see below) |
| chat/mas 1.29.0 | | | **unpinned**: Rust build needs crates.io (not an authorized endpoint) |
| meetings/jitsi-web, prosody, jicofo, jvb | | | **unpinned**: need download.jitsi.org / Maven or docker.io (not authorized) |

The digests exist only in the builder's loopback registry (127.0.0.1:5000 inside `ou-build1`, `ou/<name>:<tag>`); they are not published anywhere. The builds are **not bit-reproducible** (apt layer = archive state of the build day; image config carries build time). A rebuild yields different digests; the pinned digest identifies these exact bytes.

## Why unsigned
The only hardened signer on the host, `/usr/local/sbin/ou-image-sign`, signs golden **qcow2** images only (filename regex `ou-golden-<os>-<date>.qcow2`, requires a first-boot test record and a CycloneDX SBOM); it has no OCI mode. The lab OCI key (`ou-build1:/home/imgbuild/ou-lab-image-key`, used for the office image) is a builder-resident key, not the hardened path, and the review-5 note says the signer's own `*` argument handling needs validation work. Per instruction, no signature was made. Evidence of the gate: with a `sigstoreSigned` policy (lab public key, `matchRepository`, default reject) `skopeo copy` of the Synapse digest from the lab registry fails with `Source image rejected: A signature was required, but no signature exists` (executed in the builder). **The positive pull under the policy and the `ou-img2` nspawn check were not done** (nothing signed to pull).
Next step: BA's signer path (OCI mode, key-signed via the hardened user) -> sign these five digests -> flip `signed: false` away in the catalog (delete the field) -> plans for chat (still blocked by MAS) / telephony become executable.

## How they were built (`blueprints/build/collab/`, `build.sh`)
- Base: `debootstrap --variant=minbase noble` from archive.ubuntu.com (no docker.io pull). Base tarball sha256 `c1b7b9dd59c6847cc22a71479558c8ad19a27fd64194bf8b757c3c350350f420`; noble InRelease sha256 `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` (state of 2026-11-15).
- Builds: `buildah bud --isolation chroot` as rootless `imgbuild` (nspawn cannot mount proc for crun), pushed to the loopback registry; SBOM = syft 1.18.1 CycloneDX of the pushed digest (`blueprints/build/collab/sbom/`).
- **Synapse**: PyPI `matrix-synapse[postgres,oidc]==1.165.0`, full dependency set hash-locked (`requirements.lock`, `pip install --require-hashes --no-deps`, `pip check` passes). uid 10020. Telemetry: the entrypoint refuses to start unless the mounted config has `report_stats: false`. Healthcheck GET /health. Licence AGPL-3.0-only (or Element commercial).
- **Element Web**: release tarball `element-v1.12.35.tar.gz` sha256 `5aaff32e348eba976aea8da11cd50f9ca7f824f235aa66e24d1176f829e6bba5`; its detached PGP signature verified as VALIDSIG by subkey `E95B7699E80B68A9EAD9A19A2BAA9B8552BD9047` of primary key `712B FBEE 92DC A452 52DB 17D7 C7BE 97EF A179 B100` ("Element Releases <releases@riot.im>"), fetched from keyserver.ubuntu.com. **The key's authenticity was not cross-checked against a second source** (trust on first use; add it to a pinned keyring before relying on it). Served by distro nginx-light, uid 10030, :8080, /healthz. Default config has posthog/sentry/piwik/rageshake/integration manager/map tiles disabled (served config verified, 0 posthog entries). Licence AGPL-3.0 / GPL-3.0 (or Element commercial).
- **Token service, softphone, PBX helper**: from the lab spike sources (`blueprints/lab/spike-collab/meet-token/app.py`, `spike-pbx/phone/`, `spike-pbx/pbx/`), noble distro Python packages (versions in the SBOM), uid 10040/10050/10060, healthchecks. Softphone ships the lockfile-pinned JsSIP 3.13.9 bundle already in the repo (not rebuilt here). Source licences of our own code: not yet declared (`LicenseRef-Office-Unbound-TBD` label).
- **PBX helper caveat**: `ou_pbx` runs `/usr/sbin/asterisk -rx` and writes `/etc/asterisk/ou`; the image has no Asterisk. It is only useful with the host's asterisk binary/socket/config bind-mounted and the asterisk gid added. Imports verified only; not exercised against a PBX. Architecturally this helper probably belongs in the Asterisk package, not an OCI image.

## Scans (what is and is not known)
- Python (Synapse lock): `pip-audit` 2.7.3 (PyPI advisory data): 62 resolved dependencies, **0 known vulnerabilities** at 2026-11-15.
- OS packages (all images): grype was NOT available in the builder and its database host is not an authorized endpoint. `osv-scanner` 1.9.2 (OSV, authorized) on the syft SBOMs returned advisories for 16 to 23 deb packages per image (219 / 212 / 264 / 264 / 219 unique OSV ids for synapse / element-web / meet-token / softphone / pbx-helper). **Not triaged**: OSV matches by source package and includes issues Ubuntu has not fixed or does not consider applicable. Treat as "needs triage", not as clean and not as exploitable.
- Element Web: prebuilt JS bundle; no npm-level scan was done.

## Runtime smoke tests (executed in the builder, buildah chroot, non-root uids)
Synapse: entrypoint refuses with no `report_stats` line and with `report_stats: true`; `import synapse, psycopg2, authlib` OK as uid 10020 (version 1.165.0). **A real Synapse start with a database was not tested.** Element: nginx as uid 10030, /healthz 200, / 200. Token service and softphone: uvicorn starts with throwaway test secrets, healthcheck exit 0 as uid 10040/10050. PBX helper: imports as 10060. Not tested: healthchecks via podman `HEALTHCHECK` (nspawn forbids crun), a Matrix login, a Jitsi token round trip, a softphone call.

## Catalog / planner changes
- `OciArtifact.signed: bool = True` (new); `signed: false` + pinned digest makes the plan refuse with blocking `artifact_unsigned` (plan.py). `office` (lab-signed) is unaffected.
- Catalog: synapse, element-web, meet-token-service (0.1.0-ou1), softphone-web, pbx-helper pinned with `signed: false`; versions of own services renamed from `0.1.0-spike/-lab` to `0.1.0-ou1`.
- Tests updated (`pinned()` helper also sets `signed = True`; collab tests assert the new states).
- **Plan proof**: the requested "no blocking artifact errors for medium chat+meetings" is NOT achieved, by design: `generate_plan(medium, 100 users, real catalog)` now returns `artifact_unsigned` for synapse, element-web, meet-token-service and `artifact_unpinned` for mas, jitsi-web, prosody, jicofo, jvb (plus pre-existing keycloak, opencloud). The live `POST /deployments/plan` call on 127.0.0.1:8127 was not made (the same code path is covered by the unit test).

## Open items
1. OCI mode in the hardened signer (BA), then sign + pull test under `sigstoreSigned` in `ou-img2` (incl. tampered ref refused).
2. Owner decision on endpoints for MAS (crates.io) and Jitsi (download.jitsi.org / Maven / docker.io).
3. Triage the OSV deb advisories; add a grype DB mirror or an Ubuntu-USN source if wanted.
4. Pin and cross-check the Element release key; apt snapshot mirror for reproducibility.
5. Decide whether the PBX helper should be an OCI image at all.
6. Publish the images to a real registry (digests are registry independent; the catalog host `registry.ou.invalid` is still a placeholder).

## Test gates (2026-11-15/16)
`tests/test_deploy*.py` (DB ics_test_j): 62 passed. Full suite (log kept in the agent scratchpad): 659 passed, 1 failed: `tests/test_migration_chain.py::test_single_linear_chain` (`['0009c'] == ['0008']`): the head-revision expectation predates agent BB's migration `0009c` on the base branch; not caused by this change, not fixed here.
