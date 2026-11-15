# Document Engine Source Evaluation (Collabora Online vs ONLYOFFICE Docs)

Date: 2026-11-15. Method: shallow clones + read-only source inspection (nothing built or executed).
Gate: ADR-0007 (zero mandatory licensing cost, no artificial session/connection/document limits, own builds).
Confidence tags: [CONFIRMED] = read in source/cloned file; [PARTIAL] = source + inference; [UNVERIFIED] = not checked in source.
Supersedes the Collabora/ONLYOFFICE sections of files-identity-eval.md where they conflict (see section 7).

## 0. Bottom line

- Both engines pass the ADR-0007 limits gate in source. Neither needs a subscription for a self-built, unlimited server. [CONFIRMED]
- Recommended engine: **Collabora Online, own build from the `distro/collabora/co-26.04` branch of CollaboraOnline/online.mirror**, configured WITHOUT `--with-welcome-url`, `--with-support-public-key`, and with our own branding. ONLYOFFICE Docs Community (server 10.0.0) is the fallback and has the better OOXML fidelity story but a heavier branding/legal constraint set.
- Biggest practical risk is not licensing but build/maintenance cost of a LibreOffice-derived C++ engine (hours of build, large patch/rebase surface if we diverge) and keeping up with security fixes.
- The earlier "CODE caps at 10 docs / 20 connections" lore is real but is an opt-in "home mode" in CODE builds, not a hard cap, and does not exist in a plain source build.

## 1. Clone inventory (reference/upstream/, gitignored)

| Dir | Repo | Commit / date | Notes |
|---|---|---|---|
| collabora-online | github.com/CollaboraOnline/online | 821f341 (2026-11-13) | NOT the source any more: only docker/from-source-gh-action, helm chart, issues. README says dev moved to Gerrit (README.md:3-12). |
| collabora-online-mirror | github.com/CollaboraOnline/online.mirror | 049f448 (main, 2026-11-15) | The real source, read-only mirror of Gerrit `online`. 79,741 files. **Contains `engine/` (the LibreOffice-derived core) in-tree** (monorepo). main = 26.04.7.0 dev (configure.ac:6). |
| onlyoffice-documentserver | github.com/ONLYOFFICE/DocumentServer | 2026-11-13 | Meta repo; submodules (core, sdkjs, server, web-apps, core-fonts...) are EMPTY (shallow, not recursive). .gitmodules lists them. |
| onlyoffice-server | github.com/ONLYOFFICE/server | f037d2c (2026-10-15, "Merge release/v10.0.0 into master") | Node.js DocService/FileConverter; contains the connection-limit code. |
| onlyoffice-web-apps | github.com/ONLYOFFICE/web-apps | 2026-10-15 | Client UI; checked for branding gating only. |

Relation online vs online.mirror [CONFIRMED]: `online` on GitHub = issues, nightly container image, Helm chart, docker build assets
(collabora-online/README.md:3-12). `online.mirror` = read-only source mirror of Gerrit (gerrit.collaboraoffice.com), PRs disabled
(collabora-online-mirror/README.md:3-12). Upstream of truth is Gerrit. We should pin to mirror tags/branches and be able to fall back to Gerrit.

Core relation [CONFIRMED for 26.04, PARTIAL for older]: In 26.04 the core is merged into the monorepo as `engine/` (README.md "Building for development":
"The engine (core) is built first, then online on top of it"; GitHub API: `distro/collabora/co-26.04` has `engine/`; `merge-engine` tag exists).
Branches: `distro/collabora/co-24.04` (24.04.20.4), `co-25.04` (25.04.14.3), `co-26.04` (26.04.6.1 at time of check), `main` (26.04.7.0).
co-25.04 and co-24.04 have NO `engine/` dir (404) so they build against a separate core repo (Collabora's LibreOffice core fork, branch of the same
name); exact repo URL for those: [UNVERIFIED], not needed if we pin 26.04+. This is a decisive simplification: one repo, one pin.
Release tags: `cp-26.04.6-1` (2026-11-07) etc. exist on the mirror (cp-26.04.2-4 ... cp-26.04.6-1 seen), so exact release sources are tagged publicly and promptly. [CONFIRMED, tag dates seen]

## 2. Collabora Online: licensing

2.1 Licenses [CONFIRMED]
- online (wsd/, kit/, common/, browser/): MPL-2.0 (COPYING:1-3 header; README.md "primarily under the MPLv2").
- browser/LICENSE: Leaflet-derived BSD-2-clause (Agafonkin/CloudMade) for the Leaflet portions; other bundled JS has its own notices (THIRDPARTYLICENSES, CODA-THIRDPARTYLICENSES.html).
- browser/branding/ (themes, CSS, logos): Apache-2.0 (branding/LICENSE, README.md:3-4) BUT the Collabora name/logos are under the trademark policy and "must be removed from custom builds" (browser/branding/README.md:9-11).
- engine/ (core): MPL-2.0 primarily, LGPLv3 alternative (engine/COPYING.MPL, engine/COPYING.LGPL; engine/COPYING contains GPLv3 text, so some files may be GPLv3+/dual; per-file headers decide). Typical LibreOffice licensing: MPL-2.0 + many bundled externals (hundreds, in engine/external). [PARTIAL: did not enumerate per-file headers]
- POCO is statically linked (Boost Software License) per THIRDPARTYLICENSES.
- No file we saw is AGPL/GPL-only in the online server proper. A complete third-party inventory is auto-generated: SBOM.md describes SPDX 3.0.1 SBOMs for engine, online and container image (`make sbom-check`, `sbom-audit`, `sbom-freshness`). This directly feeds ADR-0007 third-party-inventory and ADR-0008 SBOM requirements. [CONFIRMED]

2.2 Fonts [PARTIAL]
- Engine bundles fonts via engine/external/more_fonts (80 files): Carlito, Caladea (OFL; metric-compatible with Calibri/Cambria), Liberation + Liberation Narrow (OFL), DejaVu, Noto Sans/Serif families (OFL), Open Sans, Source Sans, Gentium, Linux Libertine G, OpenDyslexic, Amiri, Scheherazade, Culmus, Reem, Karla, etc. (ExternalPackage_*.mk). Mostly SIL OFL / permissive; Culmus/some are GPL+font-exception. Per-font license verification still needed for the inventory. Not shipped: any Microsoft fonts. Metric-compatible substitutes are what drives layout fidelity of MS documents.
- Docker from-source images additionally pull distro CJK fonts: fonts-wqy-zenhei, fonts-wqy-microhei, fonts-droid-fallback, fonts-noto-cjk (docker/from-source/Debian:15-16, Ubuntu:18-19). wqy = GPLv2+font exception/Apache dual; droid = Apache-2.0; noto-cjk = OFL. Fine, but must be in the inventory.
- What the *CODE image* contains beyond that: [UNVERIFIED]. The CODE docker image is built from packages (docker/from-packages) in a repo not fully in this clone. Not needed if we build our own image.

## 3. Collabora Online: limits, nags, support key (the ADR-0007 core question)

All [CONFIRMED] from collabora-online-mirror (main 049f448).

3.1 Build-time limits (configure.ac)
- `MAX_CONNECTIONS=9999` default (configure.ac:1453); override `--with-max-connections=N` (1454-1455), minimum 3.
- `MAX_DOCUMENTS=9999` default (1461), override `--with-max-documents=N`, clamped to <= MAX_CONNECTIONS and >= 2 (1462-1467).
- NOTE the `--help` text at configure.ac:543-549 says "Def: 20 / Def: 10" which is stale/misleading; the code defaults are 9999.
- Both become C defines (AC_DEFINE_UNQUOTED MAX_CONNECTIONS / MAX_DOCUMENTS, lines 1458, 1468). Runtime assignment in wsd/COOLWSD.cpp:2759-2776.
- COOLWSD.cpp:402: `if (MaxDocuments >= 10000)` is treated as unlimited in the document-limit check.

3.2 "Home mode" = the 10 docs / 20 connections cap (this is what CODE users see)
- configure.ac:1507-1512: ONLY when `--with-welcome-url=<url>` is passed (ENABLE_WELCOME_MESSAGE=1) does the generated coolwsd.xml contain `<home_mode><enable default=false>`. Description text: enabling it "disables welcome screen and user feedback popups, but also limits concurrent open connections to 20 and concurrent open documents to 10. The default means ... unlimited, but welcome screen and user feedback cannot be switched off."
- COOLWSD.cpp:2759-2776: with ENABLE_WELCOME_MESSAGE and `home_mode.enable=true`: MaxConnections=20, MaxDocuments=10 (hard-coded literals). With home_mode false: MaxConnections=MAX_CONNECTIONS, `welcome.enable` forced true. Without ENABLE_WELCOME_MESSAGE (no --with-welcome-url): MAX_CONNECTIONS/MAX_DOCUMENTS (9999) and no home-mode code path is reachable in config.
- FileServer.cpp:1696-1700, 1781-1788: welcome auto-show and auto-feedback popup are forced ON for CODE-style builds unless home_mode, and never shown by default in plain builds (`welcome.enable` default false in generated config, configure.ac:1520-1522).
- So: CODE packages (built with --with-welcome-url, flags not in this clone's snap/packaging; inferred from the code paths) are UNLIMITED by default but nag with welcome/feedback popups; the 20/10 cap only applies if the admin opts into home_mode to hide the nags. A plain source build has neither nags nor caps. [PARTIAL: exact CODE configure flags are in Collabora's packaging repo, not seen]
- Even where the connection limit is hit, ClientRequestDispatcher.cpp:3378-3390 only rejects (shutdownLimitReached) inside `if constexpr (isSupportKeyEnabled())`; with support key disabled the code logs "Limit ... reached" and carries on. Effective enforcement of connection limit in non-support-key builds is therefore a log line only.

3.3 Support key
- Compiled only with `--with-support-public-key=<file.pub>` (configure.ac:539-541, 2331-2345; "Targeted at Collabora Online Service Providers"). Otherwise `ENABLE_SUPPORT_KEY=0`, `support-public-key.hpp` is deleted, and every use is `if constexpr (ConfigUtil::isSupportKeyEnabled())` (ConfigUtil.hpp:200-207), i.e. compiled out.
- If compiled in and key absent/invalid/expired: watermark override "Unsupported, the support key is missing/invalid/has expired" (COOLWSD.cpp:2907-2937; applied in DocumentBroker.cpp:1927-1930), unsupported branding theme (FileServer.cpp:3273-3290, 3365-3380), and valid key sets MaxConnections=1000 / MaxDocuments=200 (COOLWSD.cpp:2940-2941). Hence the commercial enterprise builds are the ones with the key mechanism (and a 1000/200 effective cap even WITH a key unless more_exact config).
- A source build WITHOUT the public key has no key code, no watermark, no cap. Conclusion [CONFIRMED]: **source build can be unlimited; CODE-style limits are build/config choices, not inherent.**

3.4 Other nag/branding surfaces to neutralise in our build
- Configurable (when no welcome-url): `brandProductName`, `brandProductURL` (default https://www.collaboraonline.com), `logoURL` (configure.ac:1523-1527) in coolwsd.xml.
- Default compiled theme: `--enable-branding=CO-theme|CODE|CODA` or `--disable-branding` (browser/branding/README.md). Use `--disable-branding` or our own theme. Release server builds are unbranded unless asked (README "Release server builds ... coolwsd package stays unbranded").
- `allow_update_popup` (FileServer.cpp ~1790) default true; set false in our config. Infobar via `--with-infobar-url` (configure.ac:559): leave unset.
- Telemetry/"feedback" URL `--with-feedback-url`: leave unset. Verify during first build with a network trace (no outbound calls): TODO.

## 4. Collabora Online: branding and trademark

- Policy URL: https://www.collaboraonline.com/trademark-policy/ (browser/branding/README.md:9-11) — not fetched; contents [UNVERIFIED].
- Source states: "The Collabora name and logos are not to be used except in accordance with the Trademark Policy and must be removed from custom builds."
- Rename required: "Collabora", "Collabora Online", "CODE", "Collabora Office/CODA" product names, logos, package names (`code-brand`, `collabora-online-brand`, `coolwsd` is a binary name rather than the mark, but consider renaming), container image names, docs. Apache-2.0 on branding files lets us reuse the *mechanism* and SCSS, but not logos/names.
- Attribution: MPL-2.0 requires keeping file notices and making modified MPL files' source available (file-level copyleft, not whole-work); LGPL parts (if we ship engine under LGPL) require relinkability/notices; keep THIRDPARTYLICENSES/CODA-THIRDPARTYLICENSES. A "based on Collabora Online / LibreOffice" credit in About is good practice; whether Collabora policy REQUIRES a specific attribution/ "powered by" is [UNVERIFIED]. "LibreOffice" trademark is TDF's; do not use.
- Source tree itself contains `--with-vendor` (configure.ac:391; engine/configure.ac:2678): set to our own vendor; engine distro configs (engine/distro-configs/CPLinuxCommon.conf:22) hard-set "Collabora Productivity Limited": create our own distro config (copy of CPLinux-LOKit.conf) instead.

## 5. Collabora Online: build, release flow, security flow

5.1 Documented build [CONFIRMED in README.md "Building for development"]
```
cd engine && ./autogen.sh --with-distro=CPLinux-LOKit-Dev && make       # engine (core)
cd .. && ./autogen.sh --enable-developer && make                          # online
```
Release-style: engine distro `CPLinux-LOKit` (engine/distro-configs/CPLinux-LOKit.conf: `--with-package-format=deb rpm`, internal libs) and online configured with release options; packaged builds via docker/from-source/build.sh (host builds engine+coolwsd then `docker build` per distro Dockerfile: Debian/Ubuntu/Fedora/Arch/openSUSE; Alpine multi-stage self-contained build-alpine.sh). Env knobs: ENGINE_ASSETS (prebuilt engine tarball), ONLINE_EXTRA_BUILD_OPTIONS (docker/from-source/build.sh:5-14). Further docs: https://www.collaboraoffice.org/post/build-code/ [not fetched].
- Toolchain: GCC/Clang with C++20, autotools, GNU make, Python 3, Node/npm (browser build; node_modules vendored via browser/node_shrinkpack, dart-sass), Poco/libcap/PAM headers. Full engine builds download many external tarballs (Makefile.fetch) at build time unless prefetched. [PARTIAL]
- Resources (general LibreOffice experience, NOT measured here): clean engine build roughly 2-6 hours on 16 cores / 32 GB RAM, 40-60 GB disk; online build ~15-30 min. Plan CI runners accordingly and cache (ccache / prebuilt engine artefact as ENGINE_ASSETS-style).
- Reproducibility: engine uses vendored/fetched externals with hashes; online SBOM includes source tarball SHA256s (SBOM.md). Full bit-reproducibility [UNVERIFIED].
- Runtime security model: coolwsd uses chroot jails (coolforkit/coolmount), needs CAP_SYS_CHROOT/CAP_FOWNER/CAP_MKNOD or `--disable-cap`/mount namespaces; docker/cool-seccomp-profile.json shipped. Containers need specific caps or a custom seccomp (relevant to our image).

5.2 Release publication [CONFIRMED partially]
- Tags per release on the mirror (cp-26.04.6-1 tagged 2026-11-07; helm tags; for-code-assets). 24.04 / 25.04 / 26.04 maintained branches (SECURITY.md supported-versions table). Source for the exact enterprise/CODE versions therefore appears in public promptly as branch + tag; exact lag between binary release and tag/branch push [UNVERIFIED] (only one tag timestamp checked).
- Caveat: the "customer brands" (online-branding repo) and packaging repos are separate; Collabora-private branches may exist (`private_custom_pb` seen in mirror refs). Not an obstacle for upstream function.

5.3 Security flow [PARTIAL]
- SECURITY.md: reports to officesecurity@lists.freedesktop.org; public CVE advisory within 30 days of fix release at github.com/CollaboraOnline/online/security/advisories; DoS-only issues are not CVEs ("fixed as ordinary bugs, without CVE"): we must read commit logs, not only advisories. Fixes land in supported branches 24.04/25.04/26.04 (that is the stable maintenance cadence). Whether embargoed fixes appear in public source before the release binaries: [UNVERIFIED]; assume source appears at/after release.
- Engine (LibreOffice-derived) CVEs also arrive via LibreOffice upstream merges; third-party libs (libxml, freetype, openssl, ...) are our responsibility if we build with bundled externals. Our pipeline needs SBOM-driven scanning (SBOM.md supports this) and a policy to bump externals ourselves.

## 6. Collabora Online and OpenCloud (WOPI) [PARTIAL: from files-identity-eval.md + source skim]

- OpenCloud's collaboration service speaks WOPI to Collabora; `COLLABORATION_APP_PRODUCT=Collabora`, `COLLABORATION_APP_ADDR`, `COLLABORATION_WOPI_SRC`; opencloud-compose has weboffice/collabora module (files-identity-eval.md section 1). The compose module is stock-image based, so swapping in our own image requires the standard pieces: discovery.xml (the repo has `discovery.xml`), `storage.wopi` allowed-hosts (aliasgroup), TLS or `ssl.termination`, shared JWT.
- Source shows what coolwsd needs from the host: CheckFileInfo fields incl. SupportsLocks, SupportsUpdate etc. (wsd/wopi/WopiStorage.cpp:175,315), lock handling `X-WOPI-Override`/`X-WOPI-Lock` (WopiStorage.cpp:435-437). Whether OpenCloud implements locks/PutRelativeFile completely: UNVERIFIED (test).
- Concurrent editing: coolwsd is a multi-view collaborative server (per-document DocumentBroker + kit process; views are sessions). Fidelity/behaviour under many simultaneous editors: [UNVERIFIED]; test plan item.
- Unlimited server-side sessions are practically bounded by RAM (each open doc = a kit process, tens-hundreds MB, UNVERIFIED), so operator-adjustable resource limits via `--with-max-*` or config are legitimate under ADR-0007 ("quotas only as operator-adjustable resource protection").

## 7. ONLYOFFICE Docs Community: license and limit

7.1 License [CONFIRMED]
- server/LICENSE.txt: GNU AGPL v3 text followed by "Additional Terms" (lines ~663-727) under Section 7 (copyright Ascensio System SIA 2009-2026):
  1. Retain all copyright/license/attribution notices.
  2. Modified versions must carry prominent notice that they are modified, with date, and state they are based on original ONLYOFFICE software by Ascensio System SIA.
  3. Interactive UIs must display "Appropriate Legal Notices" via a clearly accessible and prominent UI feature enabling users to (i) identify ONLYOFFICE as original developer, (ii) understand version may be modified, (iii) access license info.
  4. No trademark license (7(e)); trademark policy https://www.onlyoffice.com/trademark-policy [not fetched].
  5. Non-code content (illustrations, icon sets, docs) is CC BY-SA 4.0.
- This replaced the older "logo must remain" wording (older terms not seen in this tree; do not assume). The current terms permit modification and redistribution; they do NOT require keeping the logo per se but DO require a prominent in-UI attribution/modified notice, which conflicts with a clean white-label strategy. Whether those terms are enforceable as 7(b) "reasonable author attributions" vs. "further restrictions" removable under AGPL section 7 final paragraph: LAWYER.
- AGPL network clause (section 13): any modified server we run for users must offer the modified source to users. Obligation exists for us but we publish source anyway.
- DocumentServer meta repo LICENSE = AGPLv3 (head of file); the C++ core, sdkjs, web-apps are separate repos (AGPLv3; web-apps/LICENSE exists with terms presumably identical, not read in full) [PARTIAL]. core-fonts repo: mixed font licenses (ASC.ttf, DejaVu, Liberation, Noto, Lohit, Nanum ...; ASC.ttf provenance [UNVERIFIED]).

7.2 Connection limit [CONFIRMED]
- server/Common/sources/constants.js:95-96: `LICENSE_CONNECTIONS = 20` (the commercial/free-trial figure) and `LICENSE_CONNECTIONS_OS = 0x7fffffff // max signed 32-bit`.
- server/Common/sources/license.js:48-70: `readLicense()` returns, for the open-source build with no license file, `connections: LICENSE_CONNECTIONS_OS`, `connectionsView: LICENSE_CONNECTIONS_OS`, `branding:false, customization:false, advancedApi:false, multitenancy:false, hasLicense:false, packageType: PACKAGE_TYPE_OS`.
- DocsCoServer.js:4118-4126 enforces `licenseInfo.connections`/`connectionsView`: effectively unlimited for the OS package type in v10.0.0 (this tree). So in this source the 20-connection limit applies only if a (trial/other) license sets it; the default community code has no cap. This matches linuxiac's claim of removal in 9.4 (files-identity-eval.md), now CONFIRMED from source. Whether the PUBLISHED community Docker image is built from this same code: assumed yes [UNVERIFIED]. A source build is unaffected.
- Branding/customization is gated by license in the client: web-apps documenteditor Main.js:1804-1811 sets `canBrandingExt = asc_getCanBranding()` and `canBranding = asc_getCustomization()`; server passes `branding: licenseInfo.branding` (DocsCoServer.js:4051). With OS license both false, so logo/UI customisation API options are ignored in stock builds; changing this means patching client code (permitted by AGPL, but see additional terms 2-4).
- Not available in Community (functional, per vendor; UNVERIFIED in source here): clustering/HA, admin panel, mobile web editors, multi-tenancy (license.js `multitenancy:false`), advanced API.
- Build: documented in `build_tools` repo (not cloned) [UNVERIFIED]; core (C++ with V8, big) + sdkjs (needs Closure compiler) + Node server. Build is heavy too; official Docker is typically used.

## 8. Other engines (one paragraph) [UNVERIFIED unless noted]

"LibreOffice Online" upstream (TDF) is archived/unmaintained (Collabora Online is its maintained descendant, per the repos above), so it is not a separate option. CryptPad (AGPL-3.0, collaborative, E2E-encrypted) has OnlyOffice integration but its native docs are not DOCX/XLSX/PPTX engines, so poor fidelity; it embeds ONLYOFFICE for office formats (inheriting the section 7 terms). Euro Office (an OnlyOffice-based fork, offered as an alternative OpenCloud compose module per files-identity-eval.md) is worth watching but is a young fork with unknown governance. Plain LibreOffice headless is converter-only, no browser editing. OnlyOffice generally has the stronger OOXML-native fidelity (OOXML is its internal model) while Collabora/LibreOffice is stronger on ODF and wide format import but sometimes shows layout differences on complex DOCX/PPTX (metric-compatible fonts Carlito/Caladea/Liberation mitigate). Neither claim was measured here; a corpus-based fidelity test is required before final commitment.

## 9. Comparison summary

| Criterion | Collabora Online (source) | ONLYOFFICE Docs Community (source) |
|---|---|---|
| License | MPL-2.0 (+LGPL options in engine); Apache-2.0 branding files | AGPL-3.0 + Section 7 additional terms |
| Copyleft strength | File-level (MPL) | Whole-work network copyleft (AGPL s13) |
| Connection/doc limit | None in plain build (9999 default, configurable); home_mode 20/10 only in welcome-url builds | None in OS code (0x7fffffff) |
| Nags | Only if built with welcome-url (CODE) | none seen |
| License key code | Compile-time optional; absent by default | License reader returns OS defaults |
| White-label | Allowed in source; trademark removal required; brand mechanism provided | Constrained: modified-notice + ONLYOFFICE attribution in UI; branding API disabled without license |
| Repos to pin | 1 (mirror, `engine/` in tree) for 26.04 | 6+ (server, web-apps, sdkjs, core, core-fonts, dictionaries, plugins) + build_tools |
| Release tags/security | Tags + SECURITY.md, 3 maintained branches | Release branches (v10.0.0); security process [UNVERIFIED] |
| WOPI w/ OpenCloud | Documented, compose module exists | Supported in OpenCloud collaboration service, no compose module |
| Build effort | Heavy (LibreOffice-size) | Heavy (C++ core + JS toolchain) |

## 10. Recommendation

R1. **Primary: build Collabora Online ourselves from `online.mirror` branch `distro/collabora/co-26.04`, pinned to a `cp-26.04.x-y` tag** (confident that it meets the limits gate; moderately confident on operations).
- Configure engine from a copy of `engine/distro-configs/CPLinux-LOKit.conf` with our own `--with-vendor`, no Collabora identifiers.
- Configure online WITHOUT `--with-welcome-url`, `--with-support-public-key`, `--with-infobar-url`, `--with-feedback-url`; set `--with-max-connections` and `--with-max-documents` to large operator-sane values (or leave 9999) and `--disable-branding` or our own theme (from browser/branding SCSS, Apache-2.0).
- Ship our own image(s) with our signed release channel; coolwsd.xml with `welcome.enable=false`, `allow_update_popup=false`, branding strings ours.
R2. **Fallback / second engine: ONLYOFFICE Docs Community** only if corpus fidelity tests show Collabora materially worse on OOXML, accepting the AGPL attribution UI. Don't ship both initially (maintenance doubling).
R3. Patch queue (target: a handful of small, rebased patches, not a fork): (a) our distro config; (b) default config tweaks (welcome/update popup/brand); (c) optional removal of residual Collabora strings/URLs (about dialog, help URLs `KIT_HELP_URL`, update checker); (d) image-level hardening. Fix-forward bugs upstream via Gerrit if desired.
R4. Divergence risk: LOW if we track a stable branch + tag and keep patches config-level; MEDIUM if we edit browser UI; HIGH if we backport fixes across branches or diverge engine. Only stable branches get security fixes (24.04/25.04/26.04 per SECURITY.md); we must move to the next stable branch (e.g. 27.xx) roughly yearly. [CONFIRMED supported-branch table; cadence inferred]
R5. Maintenance complexity: engine rebuild on each security release, third-party external bumps, font inventory upkeep, WOPI interop regression tests against OpenCloud each release. Expect a dedicated build job and ~hours-long CI.

### Build-pipeline requirements (feeds ADR-0008)
- Pinned inputs: mirror tag SHA + externals tarball hashes (engine fetches external sources; mirror them in our artifact store; fail on hash mismatch).
- Runners: 16+ cores, 32+ GB RAM, 80+ GB disk, ccache; separate engine artefact stage cached by (engine tree hash, distro config).
- Outputs: signed deb/rpm + OCI image, SPDX/CycloneDX SBOM (use upstream `scripts/create-sbom.py` and engine `create-sbom.py`), vuln + license scan, cosign signature (upstream already ships docker/cosign.pub as precedent), staged channels + rollback.
- Watch automation: poll mirror tags and SECURITY advisories; open update PR automatically.
- Smoke tests: start coolwsd, WOPI roundtrip with OpenCloud, DOCX/XLSX/PPTX corpus load/save/diff, 2-editor concurrency test, outbound-network audit (no calls to collaboraonline.com or others), 100+ concurrent connection test to disprove limits.

### Points needing a lawyer
1. Collabora Trademark Policy exact scope: what we may say ("built on Collabora Online"), whether a "Collabora" attribution is mandatory, hosting-provider status. (Fetch and review the URL; not done here.)
2. MPL-2.0 + LGPL-3.0 mixed distribution obligations for our binary images (source offer, notices, relinking), plus GPL-licensed bundled fonts/externals with exceptions.
3. ONLYOFFICE Additional Terms 2-3: enforceability vs AGPL s7 "further restrictions"; whether they block white-labeling; relationship to trademark policy.
4. AGPL s13 if ONLYOFFICE is used (modified-source offer to network users).
5. Font licensing audit for everything that ends up in the image (OFL, GPL+exception, ASC.ttf provenance) and any patent/codec items inside the engine.

## 11. Confident vs uncertain

Confident (read in source): MPL-2.0 core license of online; 9999 default for MAX_CONNECTIONS/MAX_DOCUMENTS; home-mode 20/10 only with welcome-url builds; support key compile-out and its 1000/200 + watermark behaviour when compiled in; 26.04 monorepo containing engine/; ONLYOFFICE OS connection cap 0x7fffffff and license.js defaults; ONLYOFFICE Additional Terms text; branding gated by license.
Uncertain / to verify: exact CODE and enterprise configure flags (separate packaging repos); per-file engine licences and bundled-font licences; actual build times/resources; time lag of tags vs binaries; CVE flow timing; Collabora and ONLYOFFICE trademark policy text; OpenCloud's complete WOPI feature support; real-world DOCX/XLSX/PPTX fidelity comparison; ONLYOFFICE build_tools details and whether the published community image matches master.
Next actions: (1) fetch trademark pages for counsel; (2) do a throwaway containerised build of co-26.04 with our flags in an isolated runner to measure time and confirm unlimited behaviour; (3) fidelity corpus test (Collabora vs OnlyOffice Docker) via OpenCloud; (4) populate third-party-inventory.md from upstream SBOM output.
