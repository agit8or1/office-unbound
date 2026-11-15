# ADR-0008 Office Unbound build & release pipeline
Status: Accepted (design) — Implementing (2026-11-15). Follows from ADR-0007.

We build and ship our own distributions of: gromox (+libHX, wmime), groupware web/sync/dav/admin-api (patched: no user cap, rebranded), Collabora Online engine (rebranded, unlimited), and any other component without a usable unrestricted upstream artifact. Components with clean upstream artifacts (Keycloak, OpenCloud, PostgreSQL, rspamd…) are consumed pinned + checksum-verified, not rebuilt, unless a patch is needed.

## Pipeline (per component, declared in `build/<component>/recipe.yaml`)
1. Fetch pinned upstream tag + commit SHA; verify signature/checksum where upstream provides one.
2. Apply our patch queue (`build/<component>/patches/*.patch`, small and documented; rebased per upstream release).
3. License check (SPDX scan of source tree) and diff against `docs/status/third-party-inventory.md`; unknown license = fail.
4. Build in a clean, network-restricted build machine (nspawn, later dedicated builder) from pinned toolchain; reproducible where feasible (SOURCE_DATE_EPOCH, recorded build env).
5. Produce .deb packages (apt repo) and/or OCI images; generate SBOM (SPDX/CycloneDX).
6. Vulnerability scan of SBOM; record known issues.
7. Functional tests (component) + integration tests (`blueprints/lab/tests`).
8. Sign artifacts and repo metadata (offline-held release key; signing step isolated from build step).
9. Publish to channel `dev` → `staging` → `stable`; promotion requires passing tests + recorded approval in ICS.
10. Customer deployments pin a channel + version; upgrades are customer-scheduled ICS jobs with pre-upgrade backup and documented rollback/restore.

## Upstream tracking
Weekly upstream release check per component; security-relevant commits flagged (Collabora: DoS fixes have no CVE → read commit logs). Owner per component recorded in the inventory.

## Not yet built
Recipes, builder machine, signing key ceremony, apt repo hosting. First recipe target: gromox (from the lab build script).
