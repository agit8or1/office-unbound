# Files On-Demand: the sync host process (`ou-synchost`), design

Status: **Planned** (owner decision 2026-11-25: our own small host process around the OpenCloud engine library, with cfapi enabled;
Phase 4, after the Windows engine build exists). Nothing here is built or tested. Files On-Demand must not be claimed until it has been
tested on a real Windows machine.

## 1. Why a separate host

`opencloudcmd` is one-shot and hard-codes `Vfs::Mode::Off` (cmd.cpp v4.0.0 line 167). Cloud Files placeholders need a process that stays
connected to the sync root (`CfConnectSyncRoot`). That process serves hydration callbacks whenever any application opens a placeholder,
and it keeps the sync root registered (`StorageProviderSyncRootManager::Register`). The OpenCloud GUI client does this, but it brings its
own UI and sign-in. `ou-synchost` is a headless replacement for that role.

## 2. What it links (OpenCloud v4.x build targets)

| Target | Kind | Role |
|---|---|---|
| `libsync` | shared library (`src/libsync`) | SyncEngine, discovery, propagator, journal (`SyncJournalDb`), `SyncFileStatusTracker`, Graph spaces, TUS, checksums, the `Vfs` interface (`src/libsync/vfs`) |
| `vfs_cfapi` | plugin module (`src/plugins/vfs/cfapi`, built when `VIRTUAL_FILE_SYSTEM_PLUGINS` contains `cfapi`, the default) | Cloud Files API: placeholders, hydration (`hydrationdevice`), dehydration, pin states, sync-root registration |
| `vfs_off` | plugin module | Fallback for folders on volumes without Cloud Files support (non-NTFS, network shares) |
| cfapi `shellext` | COM DLL (`src/plugins/vfs/cfapi/shellext`: CustomStateProvider, ThumbnailProvider) | Explorer custom states and thumbnails. Registered by our installer under our own CLSIDs, branded |
| Qt 6 Core/Network | DLLs (LGPL-3.0) | Runtime. No Qt GUI/Quick, because the host is headless. `OpenCloudResources` is avoided, since it pulls in Qt Quick |

The host's own code is a long-running cousin of `src/cmd/cmd.cpp`, about 1,000 lines of C++. It contains:

- account setup;
- a bearer credentials class;
- one `SyncEngine` per folder with `Vfs::WindowsCfApi`;
- a folder watcher, using upstream's `folderwatcher_win` from `src/gui` (moved or copied, GPL);
- the IPC server.

## 3. Licence and process boundary

- `libsync` and `vfs_cfapi` are GPL-2.0-or-later, so `ou-synchost` is GPL-2.0-or-later (or GPL-3.0-or-later) as a whole, in its own
  directory `desktop/synchost/` with its own `COPYING`.
- It runs as a **separate process**. ou-agent (AGPL-3.0-only) talks to it only over IPC and never links it. Even a combination would be
  allowed (GPLv3 §13), but the process boundary also gives crash isolation and keeps the Rust workspace free of Qt.
- Every release publishes the exact corresponding source: the upstream tag, our host, and any patches. Qt is shipped as DLLs (LGPL
  relinking).

## 4. Authentication (no app tokens here)

Because we write the host, it gets an `AbstractCredentials` subclass that sends `Authorization: Bearer <access token>`. That removes the
app-token workaround that `opencloudcmd` needs. Tokens come from ou-agent over IPC. The host never sees the refresh token. On a 401 the
host sends `NeedToken` and pauses its network jobs until a new `Token` arrives. If none arrives within 60 s it reports `AuthFailed`, and
hydration requests fail cleanly with `STATUS_CLOUD_FILE_AUTHENTICATION_FAILED`, so Explorer shows an error instead of hanging.

## 5. IPC with ou-agent

- **Transport:** a named pipe `\\.\pipe\OfficeUnbound.<user SID>.synchost`. The DACL grants only the current user (and SYSTEM), and
  `PIPE_REJECT_REMOTE_CLIENTS` is set. The agent starts the host and passes a random 32-byte session nonce on stdin. The first message
  must echo it, so another local process cannot impersonate either side.
- **Framing:** JSON lines, in the same style as `ou_core::ipc`. Every message has `{"v":1,"id":…,"type":…}`. Unknown types get an error
  reply and are not dropped silently.
- **Agent → host:** `Hello{nonce, version}`, `Token{access_token, expires_at}`,
  `AddFolder{folder_id, local_path, space_url, remote_folder, vfs: "cfapi"|"off", display_name}`, `RemoveFolder{folder_id, keep_files}`,
  `SetSelective{folder_id, unsynced[]}`, `SetLimits{up_kbps, down_kbps}`, `SetGuard{folder_id, policy}`, `Pause{folder_id}`,
  `Resume{folder_id}`, `Approve{folder_id, plan_id}`, `Pin{path, state: "always"|"online"|"inherit"}`, `SyncNow{folder_id}`, `Shutdown`.
- **Host → agent:** `Ready`, `NeedToken`,
  `Status{folder_id, state: idle|discovering|syncing|held|paused|error|offline, progress{bytes, total, files}, speed}`,
  `Item{folder_id, path, kind, result}` (rate-limited and batched), `Conflict{path, copy}`,
  `Held{folder_id, plan_id, reason, deletes[], modified[]}` (capped list plus counts), `HydrationFailed{path, reason}`, `AuthFailed`,
  `Fatal{reason}`.
- **Lifecycle:** the agent supervises the host and restarts it with backoff (30 s up to 30 min). The host keeps no state the journal
  doesn't already keep, so a restart is safe. If the agent exits, the host stops after its in-flight transfers finish. It never runs
  unsupervised.

## 6. Data-safety guard inside the host

The guard's thresholds and rules stay the same as in `ou_files::guard` and `policy`. The difference is the hook. In the host, the guard
uses the engine's **exact plan** instead of a manifest diff. `SyncEngine` emits `aboutToPropagate(const SyncFileItemSet&)` after
reconciliation and before the propagator is created (syncengine.cpp v4.0.0 line 529). The host counts REMOVE instructions per
direction, plus overwrites (instruction SYNC on files the journal knows), and compares them with the policy.

- **Hold path:** abort the run, send `Held`, and wait for an `Approve` with the same plan id.
- **Open question:** `abort()` from inside that signal happens before `_propagator` exists. This must be verified, or covered by a small
  upstream patch that adds a veto (a callback that returns false to stop before propagation). That patch would be a good upstream PR,
  since the engine has no mass-delete veto today.
- **Fallback:** the manifest-based pre-flight in `ou-files` still runs before the host is asked to sync a folder after any reconnect or
  restart.

## 7. Risks to verify on Windows

1. `StorageProviderSyncRootManager::Register` from an unpackaged Win32 app (OpenCloud's GUI does this today). The navigation-pane
   entry, and whether Windows 11 needs package identity for parts of the shell integration.
2. Placeholder behaviour with Office autosave, antivirus scans (implicit hydration), and `CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION`.
3. "Free up space" and "Always keep on this device" from Explorer reaching the host through pin states.
4. Upgrading from the `opencloudcmd` sync folder: reuse the journal, or re-register the root with placeholders without re-downloading
   files.
5. Uninstall: unregister the sync root and leave fully hydrated files as normal files. Never delete user data.
