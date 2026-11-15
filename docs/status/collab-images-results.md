# Collaboration images: pinning and signing - 2026-11-15

Status: **BLOCKED before any build. Nothing was pinned; catalog unchanged; all 9 OCI placeholders (chat, meetings, telephony) keep `artifact_unpinned`.**

## Why it stopped
1. **Endpoint authorization.** `docs/status/authorized-endpoints.md` lists no container registry (ghcr.io for Synapse/MAS/Element Web, docker.io for Jitsi, quay.io, sigstore/rekor/TUF, Anchore grype DB, crates.io, download.jitsi.org). "Anything not listed here must not be contacted." The task was handed over by another agent, which cannot grant that approval; only the owner can. Nothing was contacted.
2. **Tooling absent on the ICS host**: no podman, skopeo, buildah, cosign, syft, grype. They exist only inside `ou-build1` (stopped; not started because nothing could be pulled).
3. **Pipeline docs** (`package-pipeline-results.md`, `docengine-ou2-results.md`) are not on this branch's base; `docengine-rollout-results.md` on main documents the lab pattern (skopeo `--sign-by-sigstore-private-key`, loopback registry in builder, key held in ou-build1). The hardened signing path (`/usr/local/sbin/ou-image-sign`, sudo as `ou-imgsign`) takes `*` arguments and security-review-5 flags that its argument validation must be reviewed first; I did not use it.

## Proposed owner decision (smallest set that unblocks)
Authorize, read-only/anonymous: `ghcr.io` (element-hq/synapse, element-hq/element-web, element-hq/matrix-authentication-service), `registry-1.docker.io`/`auth.docker.io` (jitsi/*, library/ubuntu base by digest), `github.com` release assets for syft/grype/cosign, `grype-db` listing (or use OSV only, already authorized).
Alternative needing no registries: build from source on a debootstrap Ubuntu base (archive.ubuntu.com, authorized): Synapse (PyPI), Element Web (GitHub release tarball), our token service/PBX helper/softphone. MAS (Rust, crates.io) and Jitsi (download.jitsi.org / Maven) still need new endpoints.

## Planned per-artifact work once approved
- Upstream: pin by digest, `cosign verify` if upstream signs (else record "no upstream signature"), licence (Synapse/MAS AGPL-3.0 or commercial; Element Web AGPL-3.0/GPL; Jitsi Apache-2.0), syft SBOM, OSV/grype scan, check telemetry (Synapse `report_stats: false`, Element `piwik`/analytics config off, Jitsi analytics off) by config baked into the image, mirror to lab registry, sign with the lab image key through the signer path, pull test under `sigstoreSigned` in `ou-img2` (ou-base-noble, MemoryMax 1.5G) incl. tampered ref refused.
- Own services: minimal non-root images, base by digest, HEALTHCHECK, SBOM, scan, sign.
- Then: replace the digests in `blueprints/catalog/components/{chat,meetings,telephony}.yaml`, prove `POST /deployments/plan` (medium, chat+meetings) has no `artifact_unpinned` error, run the deploy tests and the full suite.
