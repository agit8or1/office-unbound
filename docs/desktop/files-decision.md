# Office Unbound Desktop: files (sync engine, Files On-Demand, mapped drive)

Status (ADR-0000): **Implementing**. The `ou-files` crate and its guard/driver were tested on Linux against officeunbound8. **Nothing here is
tested on Windows.** Brief sections 4 and 5, phases 2 and 4. Code: `desktop/crates/ou-files/`. Reviewed sources: `opencloud-eu/desktop`
main at d1c23be (2026-11-25; v4.0.0 is the latest stable, v5.0.0-rc.1 the latest prerelease), rclone v1.76.0, WinFsp `License.txt`.

## 1. Licences and compatibility

| Component | Licence (verified in source) | How we use it | Obligations |
|---|---|---|---|
| OpenCloud Desktop (`libsync`, `opencloudcmd`, GUI) | **GPL-2.0-or-later** (`COPYING` = GPLv2; file headers "version 2 … or (at your option) any later version" and `SPDX-License-Identifier: GPL-2.0-or-later`; one file LGPL-2.1-or-later; `3rdparty/` Qt LGPL exception) | Separate process, started by our agent | Ship the exact corresponding source (with any patches) or a written offer, GPL text, notices. Qt as DLLs (LGPL-3.0 relinking) |
| Windows VFS plugin `src/plugins/vfs/cfapi` | GPL-2.0-or-later (Nextcloud GmbH headers) | Part of the client build | Same as above |
| rclone | MIT | Separate process (mapped drive) | Keep the licence notice |
| WinFsp | GPLv3 **with FLOSS exception** | Unmodified official installer, called through rclone | Exception holds only if: our product is FLOSS (AGPL-3.0: yes); the notice "WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos" plus a link to the WinFsp repository appears **in the UI and user docs**; it is **not distributed with proprietary software** in the same bundle |
| `ou-files` Rust dependencies | MIT / Apache-2.0 (reqwest, rustls/ring, quick-xml, sha1/sha2, unicode-normalization, url, base64, serde, tokio) | Linked | Notices |

**Compatibility with the AGPL-3.0-only app:** compatible. As separate programs started as child processes, the GPL engine and the AGPL app are an
aggregate (GPLv2 §2 / GPLv3 §5 "aggregate"); each keeps its licence. Even linking would be allowed: GPL-2.0-or-later may be used under GPLv3, and
GPLv3 §13 explicitly permits combining with AGPLv3 code (the combination's network-interaction terms then follow AGPLv3). Apache-2.0 deps are
fine because the "or later" lets us use GPLv3 (Apache-2.0 is incompatible with GPLv2-only, not with v3). Nothing here requires a CLA or a
commercial licence.

## 2. Sync engine: reuse decision

| Option | Assessment |
|---|---|
| **A. Drive `opencloudcmd` as a supervised child process** (chosen for Phase 2) | Upstream engine unchanged: discovery, journal, rename/move detection, conflicts, TUS, checksums, Windows long paths and reserved names (`csync_exclude.cpp`) are all reused. Our agent owns sign-in, scheduling, the guard and the UI. **Proven on Linux** with the real 4.0.0 engine against officeunbound8 (section 6). |
| B. Bundle the full OpenCloud GUI client with a managed config | Second tray icon, second sign-in (its own OAuth + keychain), its own UI — breaks "sign in once" and the single-app brief. Branding is possible (`opencloud_theme.json` next to the exe) but the UX duplication remains. Rejected as the main path. |
| C. Small host process around `libsync` (fork of `cmd.cpp` into a long-running daemon) | Needed for Files On-Demand: `opencloudcmd` hard-codes `Vfs::Mode::Off` (cmd.cpp line 168). Same GPL engine, ~1 file of our own C++ (GPL-2.0-or-later). **Recommended for Phase 4**, behind the same driver interface. |
| D. Re-implement sync in Rust over WebDAV | Years of edge cases the engine already handles (journal, rename detection, partial transfers, placeholders). Contradicts "reuse the engine". Rejected; `ou-files::webdav` exists for listings, the guard, the mapped-drive UI and file actions, not as a sync engine. |

Facts found in the upstream source (all to report upstream where they are bugs):
1. **`opencloudcmd` authenticates with HTTP Basic `user:token`** (`src/cmd/tokencredentials.cpp`), not with an OIDC bearer token. Our driver
   therefore mints a **per-run OpenCloud app token** from the OIDC session (`POST /auth-app/tokens?expiry=…&label=…`), passes it through the
   `OPENCLOUD_TOKEN` environment variable (never argv), and deletes it right after the run. Needs `PROXY_ENABLE_APP_AUTH=true` (on in
   officeunbound8; device revocation via `ou-oc-revoke` deletes all app tokens).
2. **No mass-delete protection in the engine:** `promptRemoveAllFiles` is parsed in cmd.cpp but never used; the GUI has no such dialog either.
   The `ou-files::guard` pre-flight (section 4) is the only barrier and runs before every engine run.
3. `--upload-limit` reads the value of `--max-sync-retries` (cmd.cpp ~line 420): we never pass it.
4. After "Another sync is needed, but not done because restart count is exceeded" the process neither quits nor syncs: the driver stops it.
5. `--exclude` **replaces** the default exclude list: the driver writes upstream defaults + our control files.
6. `opencloudcmd` is one-shot (exits after one sync), so the agent triggers cycles (local watcher, remote root ETag poll, backoff 30 s → 30 min).
7. **No Windows binaries on GitHub releases since v2.0.0-rc.4**; upstream builds Windows with KDE Craft in its own CI
   (`windows-2025-vs2026`, MSVC). We must build `opencloudcmd.exe` (and later the cfapi host) ourselves in GitHub Actions — owner decision 1.

## 3. Windows Cloud Files API (Files On-Demand)

**Yes, the OpenCloud client has a Windows cfapi VFS** (verified in source): `src/plugins/vfs/cfapi/` (`vfs_cfapi.cpp`, `cfapiwrapper.cpp`,
`hydrationdevice.cpp`, and a `shellext/` COM shell integration), inherited from Nextcloud (2020), added to OpenCloud in v3.0.0
(PR #305 "Add Windows VFS"), built by default (`VIRTUAL_FILE_SYSTEM_PLUGINS off cfapi`), with hydration fixes in 4.0.0 (#1067 "Abort a
hydration request on failure", #810 pin state). Placeholders, hydration on open, dehydration ("free up space") and pin state ("always keep on
this device") are implemented there. Only the GUI client uses it; `opencloudcmd` forces VFS off. Plan: Phase 4 option C (a cfapi-capable host
around libsync). **Not verified by us on Windows; must not be claimed until tested on a real Windows machine** (winci cannot register a sync
root interactively; the owner's workstation is needed). `ou-files::paths` already treats `IO_REPARSE_TAG_CLOUD*` placeholders as normal
content (not as links), so the guard's local scan will not hydrate or skip them.

## 4. Data-safety layer (`ou-files::guard`, `ou-files::paths`)

Before every engine run: health probe (PROPFIND of the space root) → **Skip** on auth failure, offline, server error, missing or foreign sync
root (no engine run, nothing deleted) → plan against the manifest of the last good run (local scan without following links, remote listing) →
**Hold** when deletions or overwrites exceed the policy (default: >200 items, or >30 % deletes / >50 % modifications of ≥20 known, or *all*
synced items), when a listing was incomplete, when the folder is empty although files were synced, or when the space disappeared. Approval is
bound to the exact plan id. The manifest lives outside the sync folder and is written atomically only after a fully successful run.
Conflict copies use OpenCloud's exact naming (`name (conflicted copy [user ]YYYY-MM-DD HHMMSS).ext`). Windows rules: invalid characters and
controls, trailing dot/space, reserved names (incl. `CONIN$`, `CONOUT$`, `CLOCK$`, `COM0`/`LPT0`, superscript ¹²³), 255-unit components,
260/248 classic and 32,767 extended path limits, NFC + case-fold collisions (every member skipped and reported, none picked), engine/guard
control files, symlinks/junctions/other reparse points never followed (no loops).

Server facts **measured on officeunbound8** (OpenCloud, 2026-11-25): `If-Match` on PUT is honoured (412); **`If-None-Match: *` is ignored —
a second "create" returned 204 and replaced the file.** `ou-files` therefore creates via a hidden `.ou-upload-*.part` temp file plus
`MOVE` with `Overwrite: F` (412 if the target exists, atomic). TUS: creation + creation-with-upload, 10 MB `max_chunk_size`, stale-offset
PATCH refused, HEAD returns the resume offset. Checksums: SHA1 (`oc:checksums`). Trash bin per space (`/dav/spaces/trash-bin/<id>`).

## 5. Mapped drive (`ou-files::mapped`)

rclone `mount` (WebDAV, `vendor = infinitescale`: TUS 10 MiB chunks, OC SHA1, X-OC-Mtime) + WinFsp, HTTPS only. Token via
`bearer_token_command` = our agent printing a fresh access token (config file holds no secret; rclone re-runs it on 401). Drive letter `O:`
by default; a letter present in `GetLogicalDrives` is never taken, fallback Z:→D:. Disconnected persistent network mappings (`HKCU\Network`)
are not in that mask — to add and verify on Windows. Loop rules: no sync root on the mapped letter, the rclone cache never inside a sync root
(and vice versa). Offline writes: with `--vfs-cache-mode writes` rclone acknowledges `close()` before the upload, so the agent polls
`vfs/stats` on the loopback rc port (credentials via environment) and shows "N files not saved to the cloud yet / N failed"; never "saved".
M0 (Linux rclone mount with the same OIDC client) is in `blueprints/research/desktop-connector-m0/`.

## 6. Evidence (2026-11-25, Linux host, officeunbound8 as `doctest`)

- Unit tests: `cd desktop/crates/ou-files && cargo test` → **41 passed** (paths 10, guard 12, webdav 8, engine 5, mapped 6).
- Live protocol tests (`tests/live_opencloud.rs`, env `OU_FILES_LIVE_URL`, `OU_FILES_TOKEN_CMD`): **6 passed** in 69 s — spaces (personal +
  Shares), bad token → `AuthFailed` → guard Skip, small upload/download with SHA-256 and server SHA1 equal, create-only refused on an existing
  file, 25 MiB TUS upload + download intact, interrupted TUS resumed from the server offset, conflict copy kept next to the newer server version,
  mass-delete guard holds with 20 of 30 local files gone and the server keeps all 30, missing root → Skip.
- Live engine test (`tests/live_engine.rs`, plus `OU_FILES_ENGINE_EXE`): **1 passed** — upstream `opencloudcmd` 4.0.0 (Linux AppImage,
  SHA-256 checked against the release's `.sha256`) driven by `engine::sync_cycle`: initial download of a sub-folder incl. a nested folder,
  local edit + new file uploaded intact, simultaneous edit on "two computers" → both versions kept (conflict copy), local mass delete → Held,
  engine not started, server unchanged; missing folder → Skipped; per-run app tokens deleted; marker file never uploaded.
- All `[OU-TEST]` items, their trash entries and app tokens were removed; verified empty afterwards.

## 7. Not verified on Windows (must not be claimed)

`opencloudcmd.exe` build and run on Windows; NTFS behaviour of the path rules (long-path opt-in, reserved names, case collisions on a real
volume); reparse-tag detection (`FindFirstFileW` code is compiled only on Windows and was **not even compiled** here: `ring` needs MSVC);
cfapi placeholders/hydration/pinning and Explorer overlays; rclone + WinFsp mount, `O:` detection incl. persistent mappings, Office save
behaviour on the drive, offline write reporting; ACL/timestamp preservation; file locking.

## 8. Owner decisions (settled 2026-11-25: "go with your recommendations")

1. `opencloudcmd.exe` is built from upstream source in GitHub Actions (winci agent).
2. Files On-Demand: our own host process around libsync with cfapi, Phase 4. Design: [files-on-demand-host.md](files-on-demand-host.md).
3. App tokens stay for `opencloudcmd`. Bearer support is requested upstream (draft 4 in [upstream-issues.md](upstream-issues.md)).
4. WinFsp is bundled, with its notice in About and the docs: [files-winfsp.md](files-winfsp.md). An open risk on the WebView2 loader vs
   the WinFsp FLOSS exception is described there.
5. Tenant admins may adjust the guard thresholds within hard limits: [files-guard-policy.md](files-guard-policy.md), `ou_files::policy`.
6. The upstream bugs are filed only after the owner approves the wording (drafts in [upstream-issues.md](upstream-issues.md), not filed).
