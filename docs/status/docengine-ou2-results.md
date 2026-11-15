# Document engine ou2 results (agent AZ)

Date: 2026-11-15. Branch `docs-ou2` (from `release-ag`, merged with agent AF's `worktree-agent-abfc24b9c9541fc30`; the only conflict was the append-only `host-changes.md`, both sides kept).

## 1. Engine rebuild

Unit `ou-engine-pn` (AF) had already finished when this work started: log `/root/build/engine-pn.log` 20:58 to 21:03 UTC (5.5 min, the engine build tree and ccache were warm; the configure run shows `checking for product name... Office Unbound Docs`, the log ends with `[build ALL] top level modules: build-non-l10n-only build-l10n-only`, no error line; the transient unit is gone so its exit status is not available, the evidence of success is the instdir below). Executed checks on the new instdir: `libmergedlo.so` 21:03:53, `program/bootstraprc` `ProductKey=Office Unbound Docs 26.04`, `UserInstallation=$SYSUSERCONFIG/officeunbounddocs/4`, registry `ooName` = `Office Unbound Docs`. No recipe fix was needed.
Online was rebuilt (`recipe.sh online` + `install`, unit `ou-online-pn`, MemoryMax 8G, JOBS=6, NINJA_JOBS=4, rc=0, ~3 min) and a new stage tar written (`ou-docs-cp-26.04.6-1.tar`, same size 1296558080 bytes as before, new content).

## 2. Product name verification (runtime `ou-office2`, MemoryMax 3G)

| Check | Result |
|---|---|
| `/hosting/capabilities` | `productName":"Office Unbound Docs"`, `productVersion":"26.04.6.1"` |
| PDF `Producer` (convert-to docx to pdf, `pdfinfo` + raw object) | `Office Unbound Docs 26.04.6.1 (X86_64)` (was "Collabora Office 26.04.6.1") |
| `bootstraprc` ProductKey, registry `ooName` | `Office Unbound Docs 26.04`, `Office Unbound Docs` |
| Browser bundle (About dialog, `brandProductName` fallback) | 10 occurrences of "Office Unbound Docs"; the one remaining literal "Collabora Office" is the title `.replace("Collabora Office", brandProductName)` (a substitution pattern, never shown) |

## 3. Remaining "Collabora" strings and decisions

| Location | Content | Decision |
|---|---|---|
| `libmergedlo.so` (2), `libsclo.so` (1) | copyright/file headers "Collabora Office contributors / project", internal API names `org.collaboraoffice.sheet.addin.*`, `COM.COLLABORAOFFICE.MSVD` (an OOXML function name `_xlfn.COM.COLLABORAOFFICE.MSVD` and the extension namespace `urn:com:collaboraoffice:names:experimental:office:xmlns:coext:1.0`) | keep: copyright notices are licence-required (MPL-2.0); the UNO/OOXML identifiers are file-format and API compatibility names, renaming would break interchange with documents written by upstream |
| `LICENSE`, `LICENSE.html`, `EULA_en-US.rtf`, `THIRDPARTYLICENSES` | "Copyright the Collabora Online contributors", "All rights are reserved to Collabora branding elements and Marks" | keep (licence-required attribution and trademark reservation; this sentence is the reason not to ship their marks) |
| `share/registry/main.xcd` `InfoURL` = `https://collaboraoffice.com` | vendor info link in the engine | rebrand: set `--with-info-url` equivalent (engine option) or patch to `https://officeunbound.com`; not done here (needs another engine configure; the link is not shown in the browser UI) |
| `share/config/**` (wizard styles, soffice.cfg menus/styles/effects XML, ui files) | comments and unused desktop menu entries (desktop UI is not shipped to users) | keep (not user visible in online) |
| `bundle.js`/`admin-bundle.js`: links `help.collaboraoffice.com/latest/`, `sdk.collaboraonline.com/docs/...`, `gerrit.collaboraoffice.com/.../online/` (About dialog commit link), `collaboraonline.com`, `www.collaboraoffice.org/post/faq/` | help and admin diagnostics links | help link: rebrand when Office Unbound hosts its own help; for now keep (works, and points at the upstream documentation of the upstream code); gerrit/commit link: keep (source attribution and AGPL/MPL source pointer); SDK links in the admin console only: keep |
| `cool-help.html` (4), `l10n/help-*.json` (85 files), all translated catalogs | help text names the upstream product and "Collabora" in translations | rebrand later through a string patch on the English source plus regenerating the catalogs (translations lag); not shipped as marketing but is user visible in the Help dialog: open item |
| `branding.js`, CSS/JS comment headers, `TaskWorker.js`, `CanvasTileUtils.js` | copyright headers, comments | keep (licence-required) |
| `coolwsd`, `coolforkit`, `/usr/share/coolwsd`, user `cool` | binary/dir/user names | keep (coolforkit hard-requires the user name `cool`; renames are a later packaging decision) |

Trademark policy of Collabora was not fetched here: whether the retained links and statements are acceptable is a legal item for the lawyer list.

## 4. Tests (runtime `ou-office2`, coolwsd as user `cool`, plain HTTP, `mount_jail_tree=false` as before)

- coolwsd starts, capabilities as above.
- `convert_roundtrip.py`: RESULT PASS (9/9).
- `wopi_edit_test.py edit`: loaded, typed marker, save, PutFile body contains the marker (PASS).
- `wopi_edit_test.py many 30`: loaded_ok=30 failures=0, 37.6 s (PASS). `conns 60`: loaded_ok=60 failures=0 (PASS).
- cgroup `memory.peak` of the machine after the whole run: 2.27 GB (cap 3G).
- Not done: a >30-document run, an interactive browser session against the new bundle (the bundle is the same files; only the engine strings changed).

## 5. Package `ou-docs` 26.04.6-ou2 (pipeline, `blueprints/build/build.sh`)

- `recipe.yaml` `ou_revision: ou2`; `build.sh package-prebuilt collabora` (190 ELF files, shlibdeps) -> `ou-docs_26.04.6-ou2_amd64.deb` sha256 `58d217e28fb0eb0ca9709f27387865e0ba7f5ae340e423408b01d19ece9b74f5`. First attempt failed in the artifact check because the old ou1 deb was still in the builder's `pkg-out`; it was moved to `/root/build/pkg-out-old` and the run repeated.
- `build.sh sbom` (18 packages ou-sbom, 16 syft) and `scan` (osv-scanner: 16 packages, 0 advisories; as before this says little because the bundled `engine/external` tarballs are listed, not scanned). `build.sh license collabora`: PASS but vacuous (`files=0`): the prebuilt-stage kind has no machine licence scan of the engine tree (still open).
- `repo.sh publish collabora` -> admitted to `dev` and signed by `ou-release-sign` (user `ou-release`; nothing signed as administrator), Valid-Until 2026-11-29. `tests/pkgtest-docs.sh dev` on a fresh noble clone: 9 PASS, install-smoke recorded. Not promoted to staging/stable (task asked for dev).
- Evidence: `docs/status/package-pipeline-evidence/collabora/*ou2*`, `pkgtest-docs-dev-ou2.log`.

## 6. OCI image

`build-image.sh` and the Containerfile now take the version (`OU_DOCS_VERSION`, default 26.04.6-ou2) instead of the hard-coded ou1. Built rootless in `ou-build1` from the new stage tar, base digest unchanged: `127.0.0.1:5000/ou/office:26.04.6-ou2`, digest **`sha256:38e885c494e5e129d29c4998a9f163895170a67ab0ba1cbb2a1f61f7ad998ddb`** (ou1 `sha256:da2488...ae097` remains in the registry). Signed with the same lab sigstore key as ou1 (not the `ou-release` GPG key: image signing and apt signing are separate lab arrangements; production key still open). Verified: `skopeo copy` with a `sigstoreSigned`/`matchRepository` policy and the lab public key: accepted. Package list of the image: 132 packages (`/root/ou-docs-image-dpkg.txt` on the builder). apt in the image is the non-reproducible part (as for ou1).

Catalog: `blueprints/catalog/components/office.yaml` pinned to the new digest and version 26.04.6-ou2.

## 7. Not done / caveats

- Promotion of ou-docs ou2 beyond dev; deployment of the ou2 image or package into ou-office1 or the ICS-managed guests (AF's rollout in `docengine-rollout-results.md` still runs ou1).
- Engine `InfoURL` and Help-dialog rebranding (section 3).
- The engine rebuild was incremental (warm tree): reproducibility of the engine is still NOT PROVEN.
- ou-build1 was already running at the start and is left running; ou-office2 was powered off.
