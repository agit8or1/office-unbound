# ADR-0011: Versioning, build metadata and releases

Status: accepted (2026-11-15) · Owner request: "add version numbers and name, changelog, tracking"

## Context

Office Unbound has components that ship together (ICS, console) and components that are installed on other machines and may
be updated independently (node agent, portal, migration toolkit, packaged groupware/files/docs components). Until now the only
version strings were hard-coded literals (`0.1.0` in several files). We need one product identity, a rule for each component,
a way to show it in running software, and a release process the owner can follow.

## Decision

### 1. Product name and version
* Name: **Office Unbound**. No codename is used; one may be added later as a `codename` field in `VERSION` consumers without
  changing this scheme.
* [Semantic Versioning 2.0.0](https://semver.org/). While the project is pre-alpha the major version is `0`: **`0.MINOR.PATCH`**,
  where MINOR may include breaking changes (documented under "Changed" in `CHANGELOG.md`) and PATCH is fixes only. `1.0.0` is
  reserved for the first production-supported release (ADR-0000 status `production`, roadmap phase P8 exit).
* First version: **0.1.0** (2026-11-15), the lab-integrated pre-alpha described in `CHANGELOG.md`.
* Pre-release identifiers (`0.2.0-rc.1`) are used for release candidates; they sort before the release.
* Git tags are `vMAJOR.MINOR.PATCH`, annotated and signed when a signing key is configured (docs/RELEASING.md).

### 2. Single source of truth
* **`VERSION`** at the repository root contains exactly the product version. The ICS core (backend + console) always has the
  product version; it has no separate number.
* **`VERSIONS.json`** at the repository root lists the independently shipped components and interface versions. Components
  whose code is deployed without the repository (node agent, portal) also carry a literal in their own package
  (`ou_agent.__version__`, `portal/app/version.py`); a test (`ics/tests/test_version.py`) fails when a literal and
  `VERSIONS.json` disagree. Nobody edits a third copy.

| Thing | Scheme | Where it lives |
|---|---|---|
| Product / ICS core / console | SemVer `0.x.y` | `VERSION` |
| Node agent | SemVer; bumped only when its code or wire protocol changes; a protocol-breaking change requires a documented minimum agent version (policy; not yet enforced in code) | `VERSIONS.json`, `ics/agent/ou_agent/__init__.py` |
| User portal | SemVer | `VERSIONS.json`, `portal/app/version.py` |
| Migration toolkit | SemVer | `VERSIONS.json` |
| Packages `ou-*` (own builds of groupware, files, identity pieces) | `<upstream version>-ou<N>` (Debian-style revision, e.g. `gromox 2.xx-ou2`); N counts our patch/rebuild revisions of that upstream version and resets when upstream changes | package recipes (`blueprints/build/`, ADR-0008) |
| Office Unbound Docs (own Collabora Online build) | `<upstream>+ou<N>`, currently upstream `cp-26.04.6-1` with revision `ou1` | `VERSIONS.json` |
| Deployment catalog schema | integer, bumped on incompatible catalog changes | `VERSIONS.json` `interfaces.catalog_schema`, `blueprints/catalog/README.md` |
| HTTP API | path version `/api/v1`; a breaking change creates `/api/v2` and `v1` is kept for at least one MINOR release | `ics/ics/version.py` `API_VERSION` |
| Progress feed schema | `office-unbound-progress/N` (docs/progress-schema.md) | `docs/progress.json` |
| Database schema | Alembic revision; the head at build time is recorded in the build info | `ics/migrations/` |

A product release lists, in its changelog entry, any component whose version changed.

### 3. Build metadata
Build metadata (git commit, build date, dirty flag, Alembic head, component versions, release list) is **injected at
build/install time and never computed at runtime**:

* `ics/deploy/write_build_info.py` writes `/opt/office-unbound/ics/BUILD_INFO.json`; `deploy/install.sh` (and therefore
  `deploy/bootstrap.sh`) runs it after copying the code. It is the only place that calls `git`. Outside a git checkout
  `commit`/`dirty` are `null`, not guessed. `SOURCE_DATE_EPOCH` is honoured for reproducible builds.
* `bootstrap.sh` includes `VERSION`/`VERSIONS.json` in its release hash so a version bump triggers a reinstall.
* At runtime `ics.version` reads `BUILD_INFO.json` once; in a source checkout (tests, development) it falls back to `VERSION` and
  `VERSIONS.json` and reports `commit: null`. A corrupt or missing file never prevents startup; the fallback value is
  `0.0.0+unknown`.
* A tree with uncommitted changes at install time is recorded as `dirty: true` and shown as such; release deployments must be
  from a clean checkout of the tag (docs/RELEASING.md).

### 4. Exposure
* `GET /api/v1/version`: unauthenticated callers get only `{product, version}`; a signed-in session also gets commit, build date,
  dirty flag, API version, schema (build head and, when readable by the service role, the database revision) and component versions.
* `GET /api/v1/system` (viewer+): the same plus the read-only "pending updates" comparison.
* `/readyz` includes `version`. The node agent reports `agent_version` in its identity/status responses (already present).
* Console: sidebar footer "Office Unbound ICS v0.1.0 (abc1234)" and Administration → System. The frontend reads everything
  from the API; no version is hard-coded in the frontend. Portal: footer and `/about`.

### 5. Pending updates (read-only, offline)
ICS compares its own version with the highest version in the `releases[]` list of `docs/progress.json` **as bundled into
`BUILD_INFO.json` at install time**. It makes no network request, so it can only report releases that were known when it was
installed or last upgraded; the UI says so. Applying an update is an operator procedure (docs/RELEASING.md), not a button.

### 6. Release records
`CHANGELOG.md` (Keep a Changelog 1.1) is the human record; `docs/progress.json` `current_version` and `releases[]` is the
machine record used by the website and by ICS; GitHub Releases carry notes generated from the changelog section
(`scripts/release_notes.py`). Entries link to their evidence documents (ADR-0000: nothing is "working" without executed evidence).

## Consequences
* One edit (`VERSION`) bumps the product; two literals (agent, portal) are guarded by tests.
* Production never shells out to git; build info is auditable as a file.
* A release is a tag plus a record, not a build artifact yet: the signed package pipeline (ADR-0008) is separate and the
  production signing key is an open owner item, so 0.1.0 is source-only and unsigned.

## Amendment 2026-11-16 (owner: "make sure you are bumping version numbers/names")
* **Release names.** Each MINOR release line has a name, assigned alphabetically: 0.1 "Anchor", 0.2 "Beacon", 0.3 "Compass", 0.4 "Daybreak", 0.5 "Ember". The names live in `VERSIONS.json` `release_names` and are copied into `BUILD_INFO.json` at install. `GET /api/v1/version`, `/system` and the console footer show the name. GitHub Releases are titled `Office Unbound X.Y.Z "Name"`.
* **Development versions.** Right after a release, `main` moves to the next MINOR with the suffix `-dev`, for example `0.2.0-dev`. Every build deployed from main therefore reports a version that is distinct from the release, and the build metadata adds the exact commit. `[Unreleased]` collects changes; cutting the release drops `-dev` and dates the section.
* **Component bumps are part of every merge.** An integration that changes a component bumps that component in `VERSIONS.json` and in its own version constant in the same merge, following the table in §2. For example, the node agent wire protocol changes from the controller epoch bump `node_agent` MINOR and record the minimum compatible agent version, and a new `ou-docs` revision updates `docs_engine`.
* 0.1.0 "Anchor" is tag `v0.1.0`. Its code is identical to the build deployed to the lab ICS on 2026-11-16 (416aafe).
