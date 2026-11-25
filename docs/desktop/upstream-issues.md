# Upstream issues for opencloud-eu/desktop (drafts, NOT filed)

Status: drafts for owner approval (owner decision 2026-11-25: file only after the wording is approved). Target:
https://github.com/opencloud-eu/desktop/issues. Each block below is the issue title plus a body ready to paste. All three bugs were
**found by reading the source** of `src/cmd/cmd.cpp` (tag v4.0.0 and main at d1c23be, 2026-11-25); bugs 1–3 have not yet been reproduced
at runtime, so the "Observed" lines describe what the code does, and the reproduction steps are what a maintainer can run. No private data:
`cloud.example.com`, `alice`, `/tmp/oc-sync` and the space name are placeholders.

---

## 1. `opencloudcmd --upload-limit` uses the value of `--max-sync-retries`

**Version:** OpenCloud Desktop 4.0.0 (also on main, d1c23be), all platforms.

**Description**

In `src/cmd/cmd.cpp`, `parseOptions()` reads the upload limit from the wrong option:

```cpp
if (parser.isSet(uploadLimitOption)) {
    options.uplimit = parser.value(maxRetriesOption).toInt() * 1000;   // v4.0.0 line 419, main line 420
}
```

`--download-limit` correctly uses `downloadLimitption`.

**Steps to reproduce**

1. `OPENCLOUD_TOKEN=<app token> opencloudcmd --non-interactive -u alice --upload-limit 500 https://cloud.example.com Personal /tmp/oc-sync`
   with a 50 MB new file in `/tmp/oc-sync`.
2. Run again with `--upload-limit 500 --max-sync-retries 3`.

**Expected:** uploads limited to about 500 KB/s in both runs.

**Actual (from the code):** run 1: `--max-sync-retries` is not set, `parser.value()` returns an empty string, the limit becomes 0 (unlimited).
Run 2: the limit becomes 3 × 1000 = 3 KB/s.

**Fix:** `options.uplimit = parser.value(uploadLimitOption).toInt() * 1000;`

---

## 2. `opencloudcmd` never exits after "Another sync is needed, but not done because restart count is exceeded"

**Version:** 4.0.0 (also on main), all platforms.

**Description**

In `sync()` (`src/cmd/cmd.cpp`, v4.0.0 lines 172–190) the `SyncEngine::finished` handler calls `qApp->quit()` only on the
"Sync succeeded" path. When `engine->isAnotherSyncNeeded()` is true and the restart count is exhausted, it logs a warning and returns
without quitting or exiting:

```cpp
if (engine->isAnotherSyncNeeded()) {
    if (*restartCount < ctx.options.restartTimes) { ...; engine->startSync(); return; }
    qWarning() << u"Another sync is needed, but not done because restart count is exceeded" << *restartCount;
} else {
    qInfo() << u"Sync succeeded";
    qApp->quit();
}
```

The event loop keeps running, so scripts and supervisors that wait for the process hang.

**Steps to reproduce**

1. Start `opencloudcmd --non-interactive -u alice --max-sync-retries 0 https://cloud.example.com Personal /tmp/oc-sync`.
2. While it propagates, keep changing a file in `/tmp/oc-sync` (for example `while true; do date >> /tmp/oc-sync/busy.txt; sleep 1; done`),
   so the engine flags that another sync is needed.

**Expected:** the process exits after the warning (with a defined exit code, for example 0 with a note, or a distinct non-zero code).

**Actual (from the code):** the warning is printed and the process stays alive with no further work.

**Fix:** call `qApp->quit()` (or `qApp->exit(<code>)`) after the warning.

---

## 3. `opencloudcmd --exclude` drops the default exclude list

**Version:** 4.0.0 (also on main), all platforms.

**Description**

`src/cmd/cmd.cpp` (v4.0.0 lines 207–212) loads *either* the user's list *or* the default list:

```cpp
if (!ctx.options.exclude.isEmpty()) {
    engine->addExcludeList(ctx.options.exclude);
} else {
    engine->addExcludeList(ConfigFile::defaultExcludeFile());
}
```

The help text ("Path to an exclude list [file]") does not say it replaces the defaults. With `--exclude`, patterns from
`sync-exclude.lst` such as `*.part`, `*.crdownload`, `~$*`, `.~lock.*`, `]Thumbs.db`, `]Desktop.ini`, `].DS_Store` are no longer applied,
so temporary and lock files get uploaded. The GUI client always loads the system list plus the user's list.

**Steps to reproduce**

1. `echo '*.bak' > /tmp/my-excludes.lst`; create `/tmp/oc-sync/report.part` and `/tmp/oc-sync/~$report.docx`.
2. `opencloudcmd --non-interactive -u alice --exclude /tmp/my-excludes.lst https://cloud.example.com Personal /tmp/oc-sync`

**Expected:** `*.bak` is excluded *in addition to* the defaults; `report.part` and `~$report.docx` are not uploaded.

**Actual (from the code):** only `*.bak` is excluded; both files are uploaded.

**Fix:** always add `ConfigFile::defaultExcludeFile()` and add the user's list on top, or document the replacement and add an
`--exclude-replace-defaults` switch.

---

## 4. Feature request: OIDC bearer token authentication for `opencloudcmd`

**Version:** 4.0.0 (also on main).

**Description**

`opencloudcmd` sends `Authorization: Basic base64(user:token)` (`src/cmd/tokencredentials.cpp`, line 28), so it only works with app
tokens, and only on servers with `PROXY_ENABLE_APP_AUTH=true`. Applications that already hold an OIDC access token for the user (from the
same identity provider the GUI client uses) have to mint an app token first via `POST /auth-app/tokens`, keep it alive for the run and
delete it afterwards. A bearer option would:

- work on servers with app auth disabled (the default);
- avoid creating long-lived Basic credentials;
- let a wrapper refresh the token between runs with the standard OIDC refresh flow.

**Proposal**

- `--token-type bearer|basic` (default `basic` for compatibility), or a separate `OPENCLOUD_BEARER_TOKEN` environment variable that sends
  `Authorization: Bearer <token>`, with `-u` optional in that mode (user from `/graph/v1.0/me`).
- On 401, exit with a distinct exit code (for example 3) so a wrapper can refresh the token and rerun, instead of `qFatal`.

**Why it matters:** scripted and embedded sync (CI, headless servers, third-party desktop integrations) without enabling app auth on the
server.
