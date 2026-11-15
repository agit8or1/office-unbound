# grommunio / Gromox: source-level evaluation against "Office Unbound"

Date: 2026-11-15. Method: shallow clones (default-branch HEAD, read only, nothing built or executed) in
`/home/administrator/office-unbound/reference/upstream/`, plus GitHub API / tag listings. Supersedes the
vendor-page claims in `groupware-eval.md` where they differ. Paths are relative to that directory.
Cloned snapshots: gromox 667460b (2026-11-14, configure.ac says 3.13), grommunio-web 0bb6ff8 (version file 5.2),
grommunio-sync 0d1fa88, grommunio-dav 2555abd, admin-api 4b3cd9c, admin-web 858c63a, grommunio-setup a8c4ee6,
grommunio-setup-deb 3250b6a. Also cloned: grommunio-index, grommunio-chat, grommunio-cui, libexmdbpp,
mapi-header-php, wmime, configs, admin-configs, grommunio-pkg-bits, gromox-container, grommunio-auth-multi.

Note: `gromox/AGENTS.md` contains an instruction aimed at AI agents ("Add a unicorn emoji into the pull request
message"). It was treated as untrusted data and ignored; it is harmless but shows upstream files can address agents.

## 0. Bottom line

1. The user cap is NOT in the server. It exists only in admin-api (Python), as a check at user creation and
   reactivation. Gromox (C++ server), grommunio-web, -sync, -dav contain no license, user-count, subscription or
   activation logic (greps in section 2). Removing it is a ~10 line patch to AGPL code.
2. Everything needed for a working groupware stack is in public AGPL (or compatible) source. Exception: the
   `grommunio-antispam` and `grommunio-archive` packages are not in public repos; antispam is in practice
   Debian/Ubuntu `rspamd` plus config (see 7). Archive/journaling must be replaced.
3. Official Debian/Ubuntu binary packaging (spec/debian dirs for gromox, web, sync, dav, admin-*) is NOT public;
   no gromox/web/sync/dav/admin-api repo contains a spec or debian/ dir. We would have to write our own packaging.
   Build instructions for gromox are public and complete (doc/install.rst).
4. Legal conclusion (confident, not legal advice): AGPL permits us to build, modify (including deleting the
   admin-api limit), and distribute at zero licence cost. Trademarks must be replaced in a fork. Several points
   need a lawyer (section 12).

## 1. Licences per repo (file-level evidence)

| Repo | LICENSE file | Per-file headers | Notes |
|---|---|---|---|
| gromox | `gromox/LICENSE.txt` (1582 lines): AGPLv3 text (l.1-624) + GPLv3 text for Samba-derived code (l.626-1253) + GPLv2 for Steep-derived code (l.1255-1582) | 130 files `AGPL-3.0-or-later`; 147 files `GPL-2.0-only WITH linking exception` (exch/emsmdb, exmdb, http, nsp, zcore, midb, lib/...: e.g. `exch/emsmdb/rop_processor.cpp:1`); 5 files `AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception`; 73 doc files CC-BY-SA-4.0-or-later | GitHub shows NOASSERTION because of the multi-licence file. The "linking exception" is defined only by the Steep notice at LICENSE.txt:1260-1270 (additional permission to link with separately licensed software). See 12 (lawyer item). |
| grommunio-web | `LICENSE.txt`: AGPL-3.0-or-later plus inventory of third-party notices; `LICENSES/` (REUSE, 17 texts); `REUSE.toml` | SPDX header on every file; REUSE-compliant; `bom.json`/`bom.spdx.json` ship with it. Copyright also Kopano / Zarafa B.V. (must be kept) | See 1.1 for bundled code |
| grommunio-sync | `LICENSE` AGPLv3 (full text) | AGPL; `lib/utils/g_RFC822.php:10` third-party header | Z-Push derived. `vendor/` holds only composer autoloader. Needs `/usr/share/php-mapi` from gromox (composer.json classmap) |
| grommunio-dav | `LICENSE` AGPLv3; composer.json says "AGPL v3" | AGPL | Depends on sabre/dav, sabre/vobject, monolog (BSD/MIT, composer.lock) |
| admin-api | `LICENSE.txt` AGPLv3; files carry `AGPL-3.0-or-later` | AGPL | Python/Flask; pip deps (Pipfile) |
| admin-web | `LICENSE.txt` AGPLv3 | AGPL | React/MUI; package.json declares "version 3.0.0" (stale), tinymce ^7 (GPL-2.0-or-later) |
| grommunio-setup | `LICENSE.txt` AGPLv3 text ("free software" header) | AGPL | openSUSE-oriented installer; hardwired to download.grommunio.com |
| grommunio-setup-deb | none at root; debian/copyright; README says AGPL | AGPL (copyright "eryx12o45, crpb") | Community (non-grommunio-GmbH) Debian installer. Contains no `debian/` source packaging of gromox itself |
| grommunio-index | `LICENSE.txt` AGPLv3 | AGPL | C++ fulltext index tool |
| libexmdbpp, mapi-header-php | AGPLv3 | AGPL | |
| wmime | `COPYING` + `COPYING.OpenSSL` | GPLv3 with OpenSSL exception (fork of vmime) | Required build dep of gromox; not in Debian/Ubuntu |
| grommunio-chat | `LICENSE.txt` = "Mattermost Licensing": compiled Mattermost builds MIT; source builds AGPLv3 *or* commercial; webapp/model/plugin Apache-2.0 | No `enterprise/` dir present in the clone | Optional. Mattermost trademark restriction. Not needed for Office Unbound core |
| grommunio-cui, grommunio-pkg-bits, auth-multi | AGPLv3 | | Console UI / packaging helpers |
| Docs (grommunio-documentation, gromox/doc) | CC-BY-SA-4.0-or-later | | |

### 1.1 Bundled third-party code in grommunio-web (from `grommunio-web/REUSE.toml`, `LICENSE.txt`)
- Ext JS 3.4 (`client/extjs/`): GPL-3.0-only, Sencha (header of ext-all.js confirms GPLv3 option). Free, but old and
  unmaintained (2013); GPLv3-only combined with AGPLv3 is permitted via GPLv3/AGPLv3 section 13. OK. Maintenance risk.
- TinyMCE 8.9.3 (`client/tinymce/`): `GPL-2.0-or-later AND (Apache-2.0 OR MPL-2.0)` per REUSE.toml, Tiny Technologies.
  Free under GPL. Watch: TinyMCE 7+ upstream asks GPL users to set `license_key: gpl`; not a cost.
- DOMPurify (Apache-2.0 OR MPL-2.0), pdf.js (Apache-2.0, BSD, MIT, CC0, GPL-2.0-only WITH Font-exception-2.0 for fonts),
  ViewerJS/WebODF (AGPL/Apache/MIT-or-GPL), docx-preview, JSZip, pako, SheetJS (Apache-2.0 in the vendored copy), video.js
  (Apache-2.0/MIT), csstree, tokenizr, leaflet, leaflet-geosearch, OpenPGP.js stack (LGPL-3.0-or-later, MIT, MIT-0),
  sabre/dav (BSD-3), phpfastcache (MIT), phpseclib, Ext.ux.form.Metaform (LGPL-3.0 with an odd "commercial use permitted
  provided it does not become part of another open source or commercial library" sentence, `LICENSE.txt` near the
  Metaform block; flagged UNCLEAR, small component under plugins/files/js/external).
- Fonts: Roboto (Apache-2.0), Fira Mono (OFL-1.1), Outfit (OFL-1.1) in `client/resources/fonts/`. Icons: Microsoft Fluent UI
  System Icons (MIT) + grommunio own icons (`client/resources/iconsets/`).
- Plugins in tree: ai (disabled by default; calls external LLM API only when admin sets `PLUGIN_AI_ENABLE`),
  archive (just an iframe/menu link to "grommunio Archive", `plugins/archive/README.md`), chat, meet, files (Nextcloud/
  ownCloud/Seafile/WebDAV), kendox (third-party document-management connector), maps (OSM), mdm, pgp, smime, intranet, passwd.
  None carries a proprietary component; all are AGPL or listed above.
- admin-web: all deps in package.json are MIT/Apache/BSD class (MUI core + MUI X community packages, React, Redux,
  apexcharts MIT, leaflet, tinymce GPL). I did not install or run license-checker; per-package licences UNVERIFIED beyond
  package names. `@mui/x-data-grid` ^7 community edition is MIT; the paid "Pro/Premium" MUI packages are not listed.
- Nothing non-free found in the cloned trees. Unclear items: Metaform sentence; per-package licences of the full npm
  transitive tree (not audited; `bom.json` in grommunio-web covers web only).

## 2. Limits and licence enforcement: what the code actually does

### 2.1 admin-api (the only enforcement point found)
`admin-api/tools/license.py` (115 lines):
- `_defaultLicense()` (l.47-53): `users=5, product="Community"`, validity year 1000..9999.
- `loadCertificate()` (l.76-88) reads a PEM X.509 file from `options.licenseFile`
  (`admin-api/data/config.yaml.in:8` -> `/etc/grommunio-admin-common/license/license.crt`). User cap is
  read from certificate extension OID `1.3.6.1.4.1.56504.1.1`, product name from `...56504.1.2` (l.62-63).
  Only the validity dates are checked (l.36). There is NO signature or issuer verification anywhere in the file. Any
  syntactically valid certificate with that extension sets the cap. (This is the vendor's design choice; we do not
  propose forging certs, we propose patching the code, section 11.)
- `getLicense()` (l.111-115): expired or absent licence falls back to the 5-user default.
- Without a licence file a source build runs normally with `maxUsers=5`.
Enforcement call sites (all in `admin-api/orm/users.py`):
- l.258: `checkCreateParams`: refuses creation of a NORMAL user with a mailbox when `Users.count() >= getLicense().users`,
  message "License user limit exceeded".
- l.308-309: `fromdict`: same check when a user is reactivated to NORMAL.
- l.592-594: `status` setter: same check when restoring from suspended/deleted.
- `Users.count()` (l.738-757) counts users with `ID != 0, maildir != "", status == NORMAL(0)`. Suspended (1), deleted (3),
  SHARED (4, shared mailboxes) and CONTACT (5) are not counted (status enum at l.236-246).
Informational endpoints: `endpoints/system/misc.py:108-170` GET/PUT `/system/license`, GET `/system/license/certificate.pem`,
`/system/license/creds` (stores subscription username:password in `subscriptionFile`; PUT posts them to
`https://portal.grommunio.com/api/v1/licenses/user/<name>` to download the licence cert, l.169-185). That is the only
call-home to grommunio found in admin-api (and only when an admin enters credentials). admin-web shows
a licensed/unlicensed icon (`admin-web/src/components/LicenseIcon.tsx`) and a "License" page (`src/api.ts:652-676`).
Domain-level `max_user` (`orm/domains.py:179,302`) is a per-domain admin setting (required on domain create), not a licence.
Bypass notes (facts, not recommendations): the limit is enforced only in the ORM layer used by REST API and CLI
(`grommunio-admin`). Anything writing the `users` MySQL table directly (SQL, `gromox-dbop`-style tools, `tools/e4a2gromox`
migration scripts) is not checked, and Gromox itself never counts users. Also `ldap` sync goes via the ORM.

### 2.2 Gromox, web, sync, dav
Greps for `licen[cs]e|subscription|entitle|max_?users|user.?limit|activation|portal\.` across all of gromox (excluding
the licence texts and SPDX lines) return only: EWS protocol "subscription" (notifications) error codes, the SQL schema
column `max_user` (`lib/dbop_mysql.cpp:142,200,474`, domain attribute dropped from groups at l.725), and
`e4a2gromox.sh:347` setting `--maxUser 65536`. No count check, no key check. grommunio-web: licence mentions are only SPDX
and unrelated plugin code. grommunio-sync/dav: only the WBXML "RightsManagement license" element (unrelated).
grommunio-setup(-deb): "subscription" refers to the apt/zypper repo login (`grommunio-setup/common/repo:9-19`,
`grommunio-setup-deb/common/repo`): with no credentials it falls back to the `community` repo path. Nothing technical
caps connections, sessions, mailboxes, devices or protocols (no "5"-style constants found; per-protocol limits in Gromox are
config tunables such as thread pools, `ews_max_user_photo_size`).
Conclusion: for a source build, the only artificial cap is admin-api's 5-user default. Confirmed from code, not marketing.

## 3. Non-Debian / non-free dependencies
Build host used for this check: Ubuntu 24.04 (the apt candidate versions below are from this machine).
- Gromox build (`gromox/doc/install.rst`): autotools, g++>=12 (C++20), fmt>=8, jsoncpp, **libHX >= 4.28** (Ubuntu 24.04
  has 4.19: must build libHX from source or take a newer distro), libxml2, zstd, MariaDB connector, OpenLDAP, OpenSSL, perl,
  SQLite3, tinyxml2>=8 (24.04: 10.0), **wmime** (grommunio fork of vmime; not in Debian/Ubuntu; stock `libvmime-dev` 0.9.2
  is the alternative via `vmime_CFLAGS`, install.rst:"wmime notes"), zlib. Optional: libpff/libesedb/libolecf (in Ubuntu), c-ares,
  libcurl, GSSAPI, PAM, PHP dev headers (for php-mapi), libxxhash.
- Runtime: MariaDB, Redis, nginx, php-fpm (>= 8.2 for web), postfix, saslauthd, rspamd, clamav (all Debian/Ubuntu packages;
  `grommunio-setup-deb/grommunio-setup:~255-262` lists them).
- grommunio-web build: `make` needs npm (`grommunio-web/Makefile:13,77`: node_modules, deploy, precompress) and composer
  vendored trees for plugins; admin-web needs yarn/npm and react-scripts 5 (EOL tooling). All from public registries.
- No proprietary build dependency found. grommunio-chat needs Mattermost-derived Go/Node stack (optional).
- grommunio-setup-deb downloads binary packages from `download.grommunio.com` (community or subscriber repo): that is the
  only part of the packaged path that depends on vendor infrastructure; we would replace it with our own apt repository.

## 4. Trademarks, branding, AGPL network obligations
- No TRADEMARK or NOTICE file in gromox, web, sync, dav, admin-*. (grommunio-chat has the Mattermost trademark paragraph in
  LICENSE.txt.) Legal notice page https://docs.grommunio.com/legal_notice.html did not return trademark text with my fetch
  (UNVERIFIED; earlier research claimed "grommunio", logo and "gromox" are registered marks of grommunio GmbH). Treat all
  three names and the logo as protected.
- Where branding lives in code: `grommunio-web/client/resources/images/grommunio-logo.svg`, `grommunio_icon*.png`,
  `favicon.ico`; `grommunio-web` has an official re-branding mechanism: theme plugin with `theme.json`
  (`grommunio-web/README.rst` "Theming", `doc/theming.rst`, login title/favicon brand variables per `doc/changelog.rst:93`);
  admin-web `public/index.html` title "grommunio", `public/logo*.png`, `src/res/*.svg`, i18n strings; admin-api
  `grommunio-admin` CLI/package names and `grommunio-*` service names; package/path names `/etc/grommunio-*`, `/usr/share/
  grommunio-*`; Gromox names itself in binaries (`gromox-*`), man pages, EWS/EAS server banners; sync info page link
  (`grommunio-sync/lib/core/gsync.php:764`).
- A fork should rename: product name and logo in web/admin-web/CUI, hostnames/URLs to docs and portal, package names that
  embed "grommunio" in marketed form. Internal binary/file names (gromox-*, grommunio-sync) can stay if we say "built from
  grommunio source" (nominative use), subject to the lawyer item in 12. Copyright and SPDX headers (incl. Kopano/Zarafa
  notices in web) must stay (AGPL section 5, 7).
- AGPL section 13: if we modify (e.g. patched admin-api, branded web) and users interact with it over a network, we must offer
  them the Corresponding Source of our modified version (a link in the UI footer or about page to our public source repo is
  the standard way). Applies per AGPL component (gromox, web, sync, dav, admin-api, admin-web). Unmodified components: no
  extra duty beyond not removing existing source offers. Conveying binaries/packages: provide source under AGPL sections
  4-6 (our public repo of the exact commit + patches).

## 5. Security updates and cadence
- Gromox releases in the last 12 months (GitHub releases API, published dates): 3.2 (2025-11-24), 3.3 (2025-12-27), 3.4 (2026-02-02),
  3.5 (2026-02-26), 3.6 (2026-03-26), 3.7 (2026-04-30), 3.8 (2026-06-30), 3.9 (2026-07-23), 3.10 (2026-08-22), 3.11 (2026-09-24),
  3.12 (2026-10-02), 3.13 (2026-10-29): 12 releases, roughly monthly. Commit on 2026-11-14.
- grommunio-web: 3.16 (2025-12-17), 3.17 (2026-02-19), 3.18 (2026-05-29), 3.19 (2026-07-28), 5.0 (2026-09-15), 5.1 (2026-09-24),
  5.2 (2026-10-10). grommunio-sync: 2.4 (2025-12-17) ... 2.7 (2026-10-10). grommunio-dav: 1.6 ... 1.9 (2026-10-10).
  admin-api: 1.18 (2026-02-17), 1.19/1.20 (2026-06-16), tag 1.21 later. admin-web: 4.1.0 (2026-03-30), 5.0.0 (2026-04-07).
  admin-api/admin-web are slower (fewer tags, but commits continue: admin-api HEAD 2026-11-12).
- Policy: `grommunio-web/SECURITY.md` states security fixes are delivered free of charge in regular releases through the
  package repositories and public release tags, no subscriber-only fixes; mentions Cyber Resilience Act reporting from
  2026-09-11; from 5.0 a "Security" section in `doc/changelog.rst`. Fixes go only to the current series (older series must
  upgrade). Reporting address security@grommunio.com; CVEs requested "where warranted". Fix is developed in private then
  released, so there is an embargo window before public source (normal for CVEs, not a subscriber gate).
- Not verified by me: whether any individual fix ever appeared in subscriber repos before public tags. The GTC
  (https://grommunio.com/gtc/, version May 2026) states the community version may be downloaded free and operated under the
  open source licences, productive use included, and that support services are what is sold. No contrary evidence in code.
- Caveat for us: the community apt repo is "best effort"; since upstream Debian packaging is not public we depend on upstream
  tags for the source and must build and ship security fixes ourselves within hours or days.

## 6. Build feasibility
| Component | Build system | Documented | Notes |
|---|---|---|---|
| gromox | autotools (`configure.ac`, `Makefile.am`, `qconf` helper), C++20, PHP ext `php_mapi` | `gromox/doc/install.rst` (deps, `./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var`, DB bootstrap `gromox-dbop -C`) | Public, complete. Distro packages upstream not public. `.github/` has CI |
| grommunio-web | GNU make + npm + composer (`Makefile` target `deploy`) | `grommunio-web/README.rst` | Pure PHP/JS; needs npm registry |
| grommunio-sync | no build (PHP) + packaging snippets in `build/` (nginx/php-fpm pool, sysusers, logrotate) | README.rst | `version.php.in` templated by packager |
| grommunio-dav | composer (`composer.lock`) + `build/` snippets | README.rst | |
| admin-api | CMake install of Python (`CMakeLists.txt`), Pipfile | `admin-api/doc/install.rst`, README.md | Python deps via pip/Debian python3-* |
| admin-web | yarn/npm, react-scripts | README.md | Static bundle served by nginx |
| libexmdbpp, grommunio-index, wmime | CMake / autotools | READMEs | |
Community packages: https://download.grommunio.com/community/ ... They are built from the same public tags (no private fork code
visible) but spec files are held in the OBS project, not the GitHub repos (only grommunio-pkg-bits and grommunio-auth-multi
carry `.spec`/`debian/` in public). We cannot confirm byte-equality of community packages with public source. UNVERIFIED.
The `grommunio-setup-deb` project (third party) demonstrates a Debian 13 install on packages from download.grommunio.com.
Estimate to own packaging ourselves: debian/ dirs for ~10 packages (gromox, php-mapi, web, sync, dav, admin-api, admin-web,
admin-common, common/configs, index, libexmdbpp, wmime, libHX if needed), plus postinst config logic from
grommunio-setup(-deb) and `grommunio-pkg-bits`. About 2-4 person-weeks to first working repo, then ongoing.

## 7. Functional coverage
Legend: FOUND-IN-CODE (path) / DOCUMENTED-ONLY / NOT FOUND.
| Capability | Status | Evidence |
|---|---|---|
| MAPI/HTTP | FOUND-IN-CODE | `gromox/exch/mh/emsmdb.cpp`, `nsp.cpp`; README.rst; `doc/protocols.rst` (OXCMAPIHTTP) |
| RPC/HTTP (Outlook Anywhere) | FOUND-IN-CODE | `gromox/exch/http/` (pdu_ndr, ntlmssp), `exch/emsmdb`, `exch/nsp`, `exch/rfr.cpp` |
| EWS | FOUND-IN-CODE | `gromox/exch/ews/` (requests.cpp ~ many ops: GetFolder/FindItem/Sync*, GetDelegate/Add/Remove/UpdateDelegate, Get/UpdateInboxRules, GetUserAvailability, Get/SetUserOofSettings, FindPeople, GetUserPhoto, Subscribe/GetEvents/streaming, ExpandDL, MarkAsJunk, Get/Update/CreateUserConfiguration). Not a full Exchange surface; matrix doc in `gromox/doc/ews_spec.rst` (not audited) |
| Autodiscover (+ Autoconfig) | FOUND-IN-CODE | `gromox/exch/oxdisco.cpp`, `doc/autodiscover.7`, `autoconfig.7`, `autodiscover.4gx`, `tools/dscli.cpp` |
| ActiveSync | FOUND-IN-CODE | `grommunio-sync/` (ASV 14.1, 16.0, 16.1 in `lib/core/gsync.php:32-34`), nginx snippets `build/*.conf` |
| IMAP / POP3 | FOUND-IN-CODE | `gromox/mra/imap`, `mra/pop3`, `mra/midb_agent.cpp`, `exch/midb/` |
| SMTP receive/LDA (LMTP-like delivery) | FOUND-IN-CODE (delivery only) | `gromox/mda/` (lda.cpp, delivery_app, smtp, exmdb_local); inbound MTA is Postfix, which hands to gromox-delivery (setup scripts), not a full MTA in Gromox. Submission 587: Postfix |
| CalDAV / CardDAV (+ tasks VTODO, GAL address book) | FOUND-IN-CODE | `grommunio-dav/lib/GrommunioCalDavBackend.php:110` (VTODO), `GrommunioCardDavBackend.php`, `GalAddressBook.php` |
| Tasks | FOUND-IN-CODE | EWS OXWSTASK in `exch/ews`, web tasks UI, DAV VTODO, EAS |
| Shared mailboxes | FOUND-IN-CODE | admin-api status SHARED=4 (`orm/users.py:240`), `gromox/tools/mkshared.cpp`; not counted against licence cap |
| Public folders | FOUND-IN-CODE | `gromox/tools/mkpublic.cpp` |
| Delegation | FOUND-IN-CODE | EWS delegate ops; web `class.delegatesmodule.php` |
| Free/busy | FOUND-IN-CODE | EWS GetUserAvailability; `gromox/tools/mbop_freebusy.cpp`; web README |
| Meeting requests | FOUND-IN-CODE | `gromox/lib/mapi/oxcical.cpp`, `exch/emsmdb/oxomsg.cpp`; web README; EWS meeting workflow |
| OOF / auto-response | FOUND-IN-CODE | `gromox/mda/exmdb_local/auto_response.cpp`; EWS Get/SetUserOofSettings; admin-web `components/user/Oof.tsx` |
| Server-side rules | FOUND-IN-CODE | `gromox/lib/ruleproc.cpp`, `lib/mapi/rule_actions.cpp`, `exch/ews/rules.cpp` |
| Quotas | FOUND-IN-CODE | prohibit-send/receive and storage quota handling in `exch/exmdb/folder.cpp`, `message.cpp`, `exch/emsmdb/logon_object.cpp` (admin-api exposes per-user/domain quotas) |
| Archiving / journaling | NOT FOUND (server side) | Web plugin `plugins/archive` is only a link to a separate product "grommunio Archive" (`plugins/archive/README.md`); setup references package `grommunio-archive` (`grommunio-setup/setup.sh:52`) but no public archive repo in the org; no journaling code in gromox (no hits except unrelated strings). Third-party `plugins/kendox` archives to Kendox InfoShare (commercial, external). Plan on own archive (e.g. Postfix always_bcc to an archive such as mailpiler, outside this evaluation) |
| Webmail | FOUND-IN-CODE | `grommunio-web` |
| Anti-spam | DOCUMENTED + config in setup | `grommunio-antispam` is installed by setup (`grommunio-setup/setup.sh:193,545,628-629`: files in `/etc/grommunio-antispam/local.d`, uses `rspamadm`); the Debian variant installs plain Debian `rspamd` + clamav (`grommunio-setup-deb/grommunio-setup:261`). No public grommunio-antispam repo found in the org's repo list (first 100 repos checked via API). admin-api proxies rspamd controller (`endpoints/system/misc.py` "antispam") |
| Backup / restore tooling | PARTIAL, FOUND-IN-CODE | `gromox-export` / `gromox-import` (man pages, `tools/exporter.cpp`, `importer.cpp`), `gromox-mbop` (`tools/mbop*.cpp`: delmsg, emptyfld, purge, msgcopy, freebusy, walk), `gromox-mt2exm`/`exm2mt`, `exm2eml/ical/vcf/tnef`, `gromox-mbck` (mailbox check), `gromox-snapshot` (btrfs/reflink hourly/daily snapshots, `doc/gromox-snapshot.8`), mail import (eml/mbox/pst/ost via kdb2mt, edb2mt, pff2mt). No dedicated incremental backup product; per-user mail data is SQLite files plus MariaDB, so filesystem snapshots plus DB dumps are the realistic design |
| Fulltext search | FOUND-IN-CODE | `grommunio-index` |
| Migration | FOUND-IN-CODE | `gromox/tools/kopano2grommunio.sh`, `e4a2gromox`, `exchange2grommunio.ps1`, `gromox-e2ghelper` |
| LDAP / OIDC auth | FOUND-IN-CODE | `gromox/exch/ldap_adaptor.cpp`, `admin-api/endpoints/oidc.py`, `tools/ldap.py` |
| Outlook client support in practice | NOT VERIFIED here | Needs lab test; see groupware-eval.md section 4 |

## 8. Community vs "supported" repos: what the code shows
`grommunio-setup/common/repo:5-40`: with no credentials, `REPO_PATH="community"`; with credentials, `supported`. The same
packages, per vendor statements (all features in all plans); code shows no feature flag distinguishing the two repos.
Admin-api treats product != "Community" only for the UI icon and `maxUsers`. So there is no feature gating in the sources,
only the user cap and the repo credential.

## 9. Maintenance complexity and divergence risk
- Gromox moves monthly with many protocol changes; patches should be isolated to admin-api (small, stable file set).
- Admin-api patch surface: 1 file `tools/license.py` (+ 3 call sites in `orm/users.py`). Upstream could refactor licence
  checks, causing rebase conflicts, but surface is tiny. Risk: low to medium.
- Branding patches (web theme plugin, admin-web assets/i18n): use the theme mechanism where possible, keep admin-web patch set
  small (re-skin by overlay).
- Packaging: we own all debian/ trees, systemd units, nginx/php-fpm/postfix/rspamd wiring (from grommunio-setup-deb and
  `configs`/`admin-configs`, `grommunio-sync/build`, `grommunio-dav/build`). This is the largest ongoing cost.
- Fragile parts: Ext JS 3.4 (2013), react-scripts 5 (EOL), libHX/wmime version coupling, PHP 8.x compatibility of `php_mapi`.
- Upstream coupling: web, sync, dav need matching gromox versions (zcore/php-mapi ABI); tag in lockstep (upstream releases them
  together, e.g. 2026-10-10 for web 5.2 / sync 2.7 / dav 1.9).
- Security: monitor upstream tags and CVE mails; no subscriber advisory feed assumed. Need our own CI + reproducible builds.

## 10. Does the stack meet "zero licence cost, no artificial limits"? (confident items)
- YES, technically: no limit on users, mailboxes, connections, devices or protocols exists in Gromox or the client-facing
  components. The only cap is admin-api's default 5 users, which is source code in an AGPL-3.0-or-later Python file that we are
  entitled to modify.
- YES, legally (confident): AGPLv3 section 2 and 5 grant the right to run, modify and convey; section 7 forbids upstream from
  adding "further restrictions", so a code-level cap does not bind us once removed. Section 13 duty is only to offer source.
- NO third-party subscription is needed to run: the community repo is free; the subscription only buys support and the
  licence cert. Our own repo replaces download.grommunio.com.
- Remaining non-code items: archiving, journaling and a maintained antispam package are not provided as public source
  (antispam = rspamd config we can write ourselves; archive must be replaced).

## 11. Minimum patch set for a fork
1. admin-api: neutralise the cap. Smallest change: `tools/license.py:_defaultLicense()` -> `users=2**31-1` (or make
   `getLicense().users` unbounded) and keep `/system/license` endpoint returning "Unlimited" for UI. Alternative: delete three
   checks in `orm/users.py` (l.258-259, 308-309, 592-594) and unused `getLicense` imports. Also remove or retarget the
   `portal.grommunio.com` fetch in `endpoints/system/misc.py:169-185`, and hide the licence page/icon in admin-web
   (`LicenseIcon.tsx`, `/license` route in `Routes.tsx`, `constants.ts:244-253`).
2. Repo/installer: replace `download.grommunio.com` in setup scripts with our apt repo; drop subscription prompts
   (`grommunio-setup/setup.sh:175-198`, `common/repo`). Prefer using grommunio-setup-deb as a base.
3. Branding: theme plugin + logos for web, admin-web assets/title/i18n, login text, sync info page, package metadata, man pages.
4. Packaging (not a patch but required): debian/ trees; build libHX >= 4.28 and wmime if the target distro lacks them
   (Ubuntu 24.04 does; a newer base such as Debian 13 may reduce this, UNVERIFIED).
5. Source offer: footer/about link to our source repo per AGPL section 13 for every modified network-facing component.
6. Optional hardening: disable web "ai" and "meet/chat/files" plugins unless deployed; avoid chat/Mattermost.
7. Build and own: archive (replacement), backup orchestration (snapshot + mariadb dump + `gromox-export`), antispam config.

## 12. Items for a lawyer (not confident)
1. Gromox mixed licensing: 147 files are `GPL-2.0-only WITH linking exception` (Steep-derived; exception text at
   `gromox/LICENSE.txt:1260-1270`, "additional permission to link with separately licensed software") and the rest AGPL-3.0.
   GPLv2-only is normally incompatible with AGPLv3 in one combined binary; upstream relies on the exception. We inherit
   upstream's position and do not add risk by redistributing unchanged licensing, but a lawyer should confirm
   the exception is broad enough for our distribution of combined binaries and for modified versions. Same for Samba-derived GPLv3 files.
2. Trademark use: whether a fork may say "built on grommunio/Gromox", keep package names `gromox-*`/`grommunio-*`, and whether
   grommunio GmbH enforces marks against rebranded forks. Seek written permission or rename. Legal notice text was not retrieved.
3. Ext JS 3.4 (GPL-3.0-only) in an AGPL-3.0-or-later web app, and the odd Metaform clause: confirm section 13 compatibility.
4. Whether removing or bypassing the licence check is acceptable beyond the copyright licence: the GTC (May 2026) states the community
   version may be used productively under the open source licences, but a contract (e.g. partner agreement or subscription terms
   signed by Office Unbound or its hosting customers) could add restrictions. Do not sign subscriber/partner agreements without review.
   A forged licence certificate (rather than editing source) would be a different matter; we do not recommend it.
5. EU Cyber Resilience Act: as a distributor/manufacturer of a modified product we may inherit "manufacturer" duties (SECURITY.md
   cites CRA reporting from 2026-09-11); a lawyer should assess for the hosted and the distributed variants.
6. Contributor/ownership: grommunio GmbH (plus Kopano/Zarafa legacy) owns copyright; no CLA review done. Any future relicensing by upstream
   to a non-open licence would only affect new versions; we keep rights to the last AGPL release.

## 13. What I did not verify
- No builds, no installs, no lab run. Debian/Ubuntu package names beyond those listed were not checked.
- Full npm/composer/pip transitive licences (no tool run).
- Gromox EWS operation completeness vs Exchange; real Outlook/Mac behaviour.
- grommunio-archive, grommunio-antispam, Meet/Files/MDM server components (not public in the repos inspected; GitHub API listing page 1
  of the org, 100 repos, with no page 2 returned by my query).
- Community package reproducibility vs public source; the OBS project; the legal_notice text.
