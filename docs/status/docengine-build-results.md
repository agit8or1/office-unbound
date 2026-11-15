# Document engine build results: Office Unbound Docs (Collabora Online source build)

Date: 2026-11-15. Follows `docengine-source-eval.md` (recommendation R1) and ADR-0005/0007/0008.
Everything below was executed in nspawn machines on the ICS host; excerpts are real output. Status per ADR-0000: items
marked PASS were observed; "unproven" items are listed in section 9.

## 1. What was built

| Item | Value |
|---|---|
| Upstream | github.com/CollaboraOnline/online.mirror (monorepo: `engine/` core + online) |
| Tag (newest `cp-26.04.x-y` on the mirror) | `cp-26.04.6-1` (annotated tag object `494e0e0b4d73b473aabe880e96900f9ecf9119bb`) |
| Commit SHA (peeled) | `febe91b27107ff458ddb8dcdf8c0c6d521483033` (recipe verifies it and aborts on mismatch) |
| Version reported by server | `productVersion 26.04.6.1`, `productName "Office Unbound Docs"` |
| Builder | `ou-build1` (Ubuntu 24.04 noble, from `ou-base-noble`; gcc 13.3, node 22.21.1 pinned+sha256, OpenJDK 21) |
| Runtime | `ou-office2` (Ubuntu 24.04, MemoryMax 3G, separate from `ou-office1`) |
| Recipe | `blueprints/build/collabora/recipe.sh` (phases deps/fetch/patch/engine/online/install), patches in `blueprints/build/collabora/patches/` |
| Artifact | `ou-docs-cp-26.04.6-1.tar` (DESTDIR tree), 1,296,558,080 bytes, sha256 `814c402e82a61238e992cb60893e999b96608d0da60d2166b4f110a7868392bd` (tar is not bit-reproducible: mtimes) |

Sizes after install in `ou-office2`: engine `/opt/officeunbound-office` 1.2 GB (fonts 185 MB), `/usr/share/coolwsd` (browser) 44 MB,
`coolwsd` 19.9 MB, `coolforkit-ns` 16.3 MB, `coolmount` 10.6 KB. Engine `workdir` (build tree) 7.1 GB.

## 2. Configure lines (exact; also in recipe.sh)

Engine (core): `cd engine && ./autogen.sh --with-distro=OfficeUnbound-LOKit --disable-epm --without-package-format --disable-symbols --with-parallelism=$JOBS`
where `engine/distro-configs/OfficeUnbound-LOKit.conf` + `OfficeUnboundCommon.conf` (added by patch 0001) are copies of
`CPLinux-LOKit.conf`/`CPLinuxCommon.conf` with `--with-vendor=Office Unbound`, the `--with-branding=icon-themes/galaxy/brand_cp` line removed and
`--enable-epm`/`--with-package-format=deb rpm` removed. Everything else (internal freetype/harfbuzz/fontconfig/ICU, mergelibs, quickjs, hardening) unchanged.

Online:
```
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-tests \
  --with-lokit-path=$SRC/engine/include --with-lo-path=/opt/officeunbound-office \
  --with-vendor="Office Unbound" --with-app-name="Office Unbound Docs" --with-info-url="https://officeunbound.com" \
  --with-max-connections=100000 --with-max-documents=100000 --enable-branding=CODE
```
NOT passed: `--with-welcome-url`, `--with-support-public-key`, `--with-infobar-url`, `--with-feedback-url`. (`--enable-branding=CODE` selects the
theme *directory* `browser/branding/themes/CODE`, whose contents patch 0001 replaces with Office Unbound branding.)
Generated `/etc/coolwsd/coolwsd.xml` has `welcome.enable=false`, no `home_mode` element (grep count 0), `allow_update_popup=false` (patch 0002).

## 3. Build time and resources

| Phase | Result |
|---|---|
| deps (apt build-dep libreoffice + online deps) | ~10 min |
| engine fetch of ~127 external tarballs (from gerrit.collaboraoffice.com and upstreams) | ~2 min |
| engine compile, `make -jN`, 15,660 gbuild steps | wall 16:50:51 -> ~19:58 UTC = ~3 h 07 min, **including two aborted attempts** (see below). Estimate for an uninterrupted run at -j10: ~2.5 h |
| online (coolwsd + browser bundle) | ~6 min each time (3 runs: first, rebuild with CODE theme, rebuild with config patch) |
| install + tar | ~1 min |

Peak memory: the container cgroup hit its 8 GiB `MemoryMax` twice (peak 8,589,934,592 bytes, `memory.events: oom_kill 4`; the container hung and was
restarted once). Cause (diagnosed, not guessed): the bundled harfbuzz is built by meson/ninja, which ignores make's `-j` and started nproc+2 (~50)
`cc1plus` (anon 8.4 GB while process list showed ~50 cc1plus at ~240 MB). Fix in recipe: `/usr/local/bin/ninja` wrapper capping `-j${NINJA_JOBS:-4}`.
After the fix, anon memory sampled at 0.8 GB (-j6) and 2.4-3.2 GB (-j10); `MemoryHigh=7G` was added as a safety margin; `MemoryMax` stayed 8G.
The build was resumed (gbuild is incremental), so the engine succeeded across 3 `make` invocations (-j6, -j6, -j10) over one tree.
Other lab machines (ou-gw1/id1/files1/office1) were never stopped.

## 4. Branding (task step 2) - patch `0001-office-unbound-branding-and-engine-distro.patch`

Replaced with neutral placeholders (a rounded "OU" tile and "Office Unbound" text, SVG, no Collabora artwork):
`browser/branding/themes/collabora-online-brand/images/{full-logo,full-logo-white,toolbar-bg-logo,toolbar-bg-logo-dark,toolbar-bg-logo-notebookbar,compact-logo-text,compact-logo-spreadsheet,compact-logo-presentation,compact-logo-drawing}.svg`, `browser/images/collabora-office-white.svg`.
`themes/CODE/branding.js`: `brandProductName='Office Unbound Docs'`, URL `https://officeunbound.com`; "built on a great technology base" credit now reads
"Collabora Online (MPL-2.0) and LibreOffice technology" (attribution deliberately kept). Fallback strings `Collabora Online Development Edition (unbranded)`,
`Collabora Online`, onboarding title, admin console titles, `cool.html` `<h1 id=product-name>`, Help/forum menu targets all changed to Office Unbound Docs / officeunbound.com.
Patch `0002-office-unbound-config-defaults.patch`: default `brandProductURL` and `allow_update_popup=false` in generated coolwsd.xml.
All copyright/SPDX headers and `THIRDPARTYLICENSES` are untouched. Verified in the running server: `/hosting/capabilities` `productName":"Office Unbound Docs"`,
`cool.html` contains `<h1 id="product-name">Office Unbound Docs</h1>`, `init-product-branding-url value="https://officeunbound.com"`, `branding.js` as above.

### Remaining Collabora strings (could not / did not remove)
- Engine product name: `PRODUCTNAME=Collabora Office` baked at engine configure time (I did not pass `--with-product-name`; changing it forces a long engine
  re-configure/rebuild and was not attempted). Visible effects: PDF `Producer: Collabora Office 26.04.6.1`, `office version details` log line, `bootstraprc ProductKey=Collabora Office 26.04`,
  `UserInstallation=$SYSUSERCONFIG/collaboraoffice/4`, registry values (`ooName`, help URL `https://help.collaboraoffice.com/help.html?`, `https://collaboraoffice.com`), `/opt/.../share/registry/{main,calc}.xcd`. Recommended fix for next cycle: add `--with-product-name="Office Unbound Docs"` to OfficeUnboundCommon.conf.
- `coolwsd` binary (7 strings) / `coolforkit-ns` (4): error-message URLs to sdk.collaboraonline.com docs, a built-in AI assistant system prompt "You are a helpful assistant for Collabora Online", `https://www.collaboraoffice.com/` in the CSP img-src list (FileServer.cpp:1849), "Collabora Online WebSocket server" description, "CollaboraOffice" in kit messages. Not patched.
- Browser dist (22 non-l10n files; 85 l10n files): the `bundle.js` string "Collabora Online not loaded yet..." (postMessage API console error), "Collabora Office" (one string in bundle.js), `cool-help.html` (user help text), CSS/JS comments and copyright headers (kept on purpose), `ServerAuditDialog`/`AdminSocketServerAudit` links to sdk.collaboraonline.com, `FormulaErrorHelpSection` link to help.collaboraoffice.com, `Control.AboutDialog.ts` link to gerrit.collaboraoffice.com commit log, `browser/welcome/welcome.html` (not served: welcome disabled; URL 404 in test), all translated `.json/.po` catalogs contain "Collabora".
- Package/dir names inherited by DESTDIR layout: `/usr/share/coolwsd`, `coolwsd`, `coolforkit` binary names (upstream-neutral; rename is a packaging decision).
- The Collabora trademark policy was not fetched; whether remaining attributions/links are acceptable is a legal question.

## 5. Verification (task step 4), all in `ou-office2`, final build (sha above)

Runtime caveat: nspawn gives no CAP_SYS_ADMIN, so `coolmount` cannot mount jails: coolwsd ran with `--o:mount_jail_tree=false`, plain HTTP on 127.0.0.1
(`ssl.enable=false`), as user `cool`, `coolforkit-caps` with file caps `cap_fowner,cap_chown,cap_sys_chroot` (works). Config via `tests/run_coolwsd.sh`.

**PASS coolwsd starts**: `Ready to accept connections on port 9980.` Log lines (real):
```
INF  Maximum concurrent open Documents limit: 100000 | COOLWSD.cpp:2815
INF  Maximum concurrent client Connections limit: 100000 | COOLWSD.cpp:2816
office version details: { "ProductName": "Collabora Office", "ProductVersion": "26.04", "ProductExtension": ".6.1", "BuildId": "febe91b27107ff458ddb8dcdf8c0c6d521483033" ...
```
**PASS `/hosting/discovery`**: `http=200 bytes=42592`, 292 `<action>` entries, urlsrc `http://127.0.0.1:9980/browser/febe91b271/cool.html?`.
**PASS `/hosting/capabilities`**: `{"convert-to":{"available":true,...},"hasDocumentSigningSupport":true,...,"productName":"Office Unbound Docs","productVersion":"26.04.6.1",...}`
- no support-key, `home_mode`, or limit fields; `/etc/coolwsd/coolwsd.xml` has 0 `home_mode` occurrences.
**PASS no nag in logs/config**: grep over coolwsd.log + stdout for `welcome|feedback|unsupported|support key|home_mode` = 0 hits (the word "limit" appears only in the two limit=100000 lines above and cgroup TRC lines; "nag"/"watermark" hits were substrings of file names in `Pre-read` TRC lines, checked). `FetchUpdate` is inert: `INFOBAR_URL` empty (no `--with-infobar-url`), `ss -tn` during the run showed no non-loopback connections. This is not a packet capture (see 9).
**PASS convert-to round trips** (`tests/convert_roundtrip.py`, REST `POST /cool/convert-to/<fmt>`, content verified with pdftotext/zipfile/python-docx/openpyxl/python-pptx):
```
PASS in.docx -> pdf :: http=200 bytes=15987 marker_in_pdf_text=True
PASS in.xlsx -> pdf :: http=200 bytes=11170 marker_in_pdf_text=True   (see note)
PASS in.pptx -> pdf :: http=200 bytes=18235 marker_in_pdf_text=True
PASS in.docx -> odt -> docx :: paras='OU Roundtrip Heading\nOU-DOCX-BODY-ALPHA table below\n' cells=['c00', '', '', 'OU-CELL-11']
PASS in.xlsx -> ods -> xlsx :: A1='OU-XLSX-TEXT' B1formula='=A2+A3' B1cached=42
PASS in.pptx -> odp -> pptx :: texts=['OU-PPTX-TITLE', 'OU-PPTX-BODY']
RESULT: PASS (9/9)
```
Note: the first run of this script FAILED 8/9 because my check searched for the full cell text `OU-XLSX-TEXT` in the PDF; the PDF correctly shows the clipped print layout
`OU-XLSX-T   42` (cell overflow blocked by the neighbouring B1). I changed the PDF marker to `OU-XLSX-T` (the 42 and round-trip formula checks are independent). Disclosed for honesty.
**PASS real edit + save through WOPI** (`tests/wopi_edit_test.py edit`): local aiohttp WOPI host (CheckFileInfo/GetFile/PutFile) in the same machine, websocket client
(`coolclient`, `load`, `mouse` click, `textinput`, `save`):
```
loaded=True err=None typed=True unocommandresult_save=True putfile_calls=1 getfile=1 checkfileinfo=1
PutFile body bytes=20532 sha256=c1236d5c51477abd
MARKER_IN_PUTFILE_DOCX = True
paragraph text: 'OU-EDIT-MARKER-7f3a9cOriginal paragraph.'
RESULT: PASS
```
The PutFile body was parsed with python-docx; the typed marker is in the first paragraph, original text preserved.
**PASS concurrency beyond the CODE-style caps (what was measured, precisely)**: each session = one websocket `load` of a WOPI doc, held ~25 s, all started at once.
- `many 30`: 30 sessions on 30 *distinct* documents (distinct WOPI file ids): `loaded_ok=30 failures=0`; admin metrics sampled mid-run (earlier 30-run): `kit_assigned_count 30`, `kit_count 33`, `coolwsd_tcp_connections_used 31`. This exceeds both the 10-document and 20-connection caps. Passed in 4 of 5 runs.
- `conns 60`: 60 sessions on ONE document: `loaded_ok=60 failures=0`, metrics mid-run `coolwsd_tcp_connections_used 61`, `kit_assigned_count 1`.
- One `many 30` run FAILED (some sessions never got a doc-load status; log: `getNewChild: No child available. Sending spawn request to forkit and failing.`) on a cold start right after
  restart: the prespawn pool of kit processes was empty and it is a spawn-rate effect, not a limit message. I did not capture the exact failure count; 2 consecutive re-runs passed 30/30. Raising `num_prespawn_children` would address it; not tested.
- Memory in `ou-office2` (3G cap): `memory.peak` 2.36 GB with 30 docs open; kit ~42 MB average per assigned doc by the server's own metric (`kit_memory_used_average_bytes 42374290`).
- Not measured: >30 distinct docs, >61 connections, behavior at 100000 (the configured limit is shown in the log only).

## 6. SBOM-ish inventory (step 5)

Generated with the upstream generator `scripts/create-sbom.py --branding-theme CODE` (SPDX 3.0.1; 3,118 files, 77 packages): saved to
`blueprints/build/collabora/sbom/collabora-online-sbom.spdx.json`. It describes coolwsd, browser JS and statically linked externals. The engine SBOM
(`make LIBO_TEST_INSTALL=TRUE CustomTarget_instsetoo_native/sbom`) was attempted, ran >10 min without producing output and was stopped: **no engine SPDX exists yet**.
Engine externals actually downloaded by this build are in `sbom/engine-external-tarballs.txt` (127 entries incl. boost 1.91.0, icu4c 78.2, openssl 3.5.8, poco 1.15.4, curl 8.22.0, freetype 2.15.0, harfbuzz 14.3.0, libxml2 2.15.4, nss 3.131.1, pdfium, python 3.14.10, sqlite, liborcus/libmwaw/libwps/... office-format libs; licenses for these NOT verified by me; mostly MPL/LGPL/MIT/BSD-style, a few GPL-compatible exceptions to check) and bundled font families in `sbom/engine-bundled-font-families.txt` (320 files in `share/fonts/truetype`: Carlito/Caladea (OFL), Liberation (OFL-1.1), DejaVu (Bitstream Vera/public domain-style), Noto (OFL), Amiri, Karla, Open Sans, Source Sans, Gentium, Linux Libertine G, OpenDyslexic, Reem Kufi, Scheherazade...; per-font license verification still TODO).
Online SBOM, licenses as determined by the generator (selection): coolwsd MPL-2.0; branding Apache-2.0; poco 1.15.4 BSL-1.0; openssl 3.5.8 Apache-2.0; expat 2.10.0 MIT; libpng 1.6.59 Libpng; zlib 1.4 Zlib; zstd 1.5.7 BSD-3-Clause OR GPL-2.0-only; pcre2 10.48 BSD-3-Clause; utf8proc 2.11.3 MIT; double-conversion BSD-3-Clause; SpookyHash public domain; pdjson MIT;
browser: jquery 3.5.1 MIT, jquery-ui 1.13.2 MIT, Leaflet 0.8-dev BSD-2-Clause, d3 7.9.0 + 37 d3-* modules ISC/BSD-3, hammerjs 2.0.8 MIT, marked 15.0.6 MIT, dompurify 3.4.14 (MPL-2.0 OR Apache-2.0), gl-matrix MIT, fzstd MIT, Autolinker.js MIT, Bulma MIT, Base.js MIT, smartmenus (license NOASSERTION - needs manual review), Montserrat OFL-1.1, robust-predicates Unlicense, cairo-png LGPL-2.1 OR MPL-1.1 (name as reported). Unresolved/flagged: `smartmenus` NOASSERTION; DT_NEEDED system libs (libc, libstdc++, libcap, libz...) from Ubuntu 24.04 (not bundled).
ADR-0008 step 3 (SPDX scan vs `third-party-inventory.md`) is therefore only partly satisfied.

## 7. Files added in the repo

`blueprints/build/collabora/recipe.sh`, `patches/0001-*.patch`, `patches/0002-*.patch`, `tests/{wopi_edit_test.py,convert_roundtrip.py,setup_runtime.sh,run_coolwsd.sh}`, `sbom/*`.

## 8. Notes on the recipe

Pinned inputs: repo URL, tag, tag object, commit SHA (verified), node tarball sha256, Ubuntu noble apt (not version-pinned). Re-runnable: `fetch` keeps build products if already at the pinned commit; `patch` is idempotent.
Network use at build: github.com (clone), archive.ubuntu.com, nodejs.org, **gerrit.collaboraoffice.com plus other upstream hosts for engine tarballs** (checksum-verified by the engine Makefile.fetch), pypi (tests only). The oulab zone permitted all of it.

## 9. What is unproven / open

- The recipe was never run as one `all` pass from an empty machine: phases ran separately and `deps` was amended after the fact (meson, ninja-build, rsync, node 22, ninja wrapper were added by hand first, then written into the recipe). A clean one-shot rebuild is the next ADR-0008 test (and would confirm the ~3 h cost without crashes).
- No ccache, no SOURCE_DATE_EPOCH reproducibility check, no signature verification of the tag (the mirror tag is unsigned in what I saw: only SHA pin), no vulnerability scan of the SBOM, no `.deb`/OCI packaging.
- Not tested: browser UI rendering (no browser in the lab: logo/theme appearance, absence of UI popups verified only via served files/config, not visually), TLS/reverse proxy, jail mounting (`coolmount`/`mount_jail_tree=true`, seccomp), WOPI locks (`SupportsLocks=false` in test host), PutRelativeFile, multi-user co-editing, OpenCloud integration, XLSX/PPTX editing (only DOCX edit tested), macros, fonts coverage/fidelity vs MS Office, performance.
- Outbound-traffic absence is inferred from config/code (empty infobar URL, no welcome/feedback/support key) and an `ss` snapshot, not a packet capture over time.
- Engine product-name leak (section 4) and engine SBOM remain TODO. Licenses of the 127 engine externals and 320 font files are not individually verified.
- Concurrency ceiling is not established (stopped at 30 docs / 60 connections because of the 3 GiB cap and test time).
