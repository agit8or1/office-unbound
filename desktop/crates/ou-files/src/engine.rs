//! Driver for the OpenCloud sync engine (`opencloudcmd`, GPL-2.0-or-later, run as a separate process; see
//! docs/desktop/files-decision.md).
//!
//! One sync *cycle* for one sync folder:
//! probe the space → list remote + scan local → guard pre-flight → run `opencloudcmd` once → rescan → write the manifest.
//! The engine is one-shot (it exits after a sync), so the agent runs a cycle when the local watcher or the remote root ETag
//! signals a change, with backoff on failure. The token goes to the engine through `OPENCLOUD_TOKEN` (environment, not argv,
//! so other local users cannot read it from the process list); `--trust` (accept any TLS certificate) is never passed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;

use crate::guard::{preflight, Decision, GuardPolicy, Manifest};
use crate::paths::scan_local;
use crate::webdav::{Client, FilesError, Space};


#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// `opencloudcmd.exe` (or the branded copy) shipped next to the agent.
    pub exe: PathBuf,
    /// Cloud origin, e.g. `https://cloud.example.com`.
    pub server: Url,
    /// Full space id (`<storage>$<space>`); never a display name (names are ambiguous).
    pub space_id: String,
    pub local_dir: PathBuf,
    /// Sub-folder of the space to sync ("" = whole space), `/`-separated.
    pub remote_folder: String,
    /// Shown in engine logs only; the token decides the identity.
    pub username: String,
    /// Directory for the guard manifest, exclude list and selective-sync list: outside the sync folder.
    pub state_dir: PathBuf,
    /// Remote folders not to sync (selective sync), relative to the space root.
    pub unsynced_folders: Vec<String>,
    /// KB/s, 0 = unlimited. Upload limit is deliberately not passed: upstream cmd.cpp reads `--upload-limit` from the
    /// `--max-sync-retries` option (bug, to report upstream), so passing it would set a wrong limit.
    pub download_limit_kbps: u32,
    pub max_sync_retries: u32,
    /// Kill a run that exceeds this (hung network); the next cycle resumes (the engine keeps its journal).
    pub run_timeout: Duration,
}

/// Exclude list passed with `--exclude`. That option *replaces* the engine's default list (cmd.cpp), so the upstream defaults
/// (src/resources/theme/universal/sync-exclude.lst, v4/v5) are repeated here, plus our control and partial files.
/// `]` = "exclude and delete if needed" in upstream syntax; plain patterns keep the file.
pub const EXCLUDES: &[&str] = &[
    // ours
    ".ou-sync-root", ".ou-files-manifest.json*", "*.ou-part", ".ou-upload-*.part",
    // upstream defaults
    "].sync_journal.db*", "].sync_*.db*", "*~", "~$*", ".~lock.*", "~*.tmp", "]*.~*", "]Icon\\r*", "].DS_Store", "].ds_store", "._*",
    "]Thumbs.db", "]Desktop.ini", ".*.sw?", ".*.*sw?", "].TemporaryItems", "].Trashes", "].DocumentRevisions-V100", "].Trash-*[0-9]",
    "].Trash", ".fseventd", ".apdisk", ".directory", "*.part", "*.filepart", "*.crdownload", "*.kate-swp", "*.gnucash.tmp-*",
    ".synkron.*", ".sync.ffs_db", ".symform", ".symform-store", ".fuse_hidden*", "*.unison", ".nfs*", "My Saved Places.",
];

pub fn write_support_files(cfg: &EngineConfig) -> std::io::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    let excl = cfg.state_dir.join("exclude.lst");
    std::fs::write(&excl, EXCLUDES.join("\n") + "\n")?;
    let unsynced = cfg.state_dir.join("unsynced-folders.lst");
    let mut body = String::from("# remote folders excluded from sync (selective sync), one per line\n");
    for f in &cfg.unsynced_folders {
        let f = f.trim_matches('/');
        if f.is_empty() || f.contains('\n') || f.split('/').any(|c| c == "..") {
            continue;
        }
        body.push_str(f);
        body.push_str("/\n");
    }
    std::fs::write(&unsynced, body)?;
    Ok((excl, unsynced))
}

/// Command line for one run. The token is NOT part of it.
pub fn command_args(cfg: &EngineConfig, exclude: &Path, unsynced: &Path) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        "--non-interactive".into(),
        "--user".into(),
        cfg.username.clone().into(),
        "--exclude".into(),
        exclude.into(),
        "--unsynced-folders".into(),
        unsynced.into(),
        "--max-sync-retries".into(),
        cfg.max_sync_retries.to_string().into(),
    ];
    let rf = cfg.remote_folder.trim_matches('/');
    if !rf.is_empty() {
        a.push("--remote-folder".into());
        a.push(format!("/{rf}/").into());
    }
    if cfg.download_limit_kbps > 0 {
        a.push("--download-limit".into());
        a.push(cfg.download_limit_kbps.to_string().into());
    }
    a.push(cfg.server.as_str().into());
    a.push(cfg.space_id.clone().into());
    a.push(cfg.local_dir.clone().into_os_string());
    a
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    Succeeded,
    Failed,
    AuthFailed,
    ConnectError(String),
    ItemError(String),
    Excluded(String),
    /// More changes arrived during the run; the next cycle picks them up.
    AnotherSyncNeeded,
    SpaceNotFound,
    Other(String),
}

/// Parses one line of opencloudcmd output (Qt message handler: info on stdout, `Warning: …`/`Critical: …`/`Fatal: …` on stderr).
pub fn parse_line(line: &str) -> EngineEvent {
    let l = line.trim();
    let body = l.splitn(2, ": ").nth(1).filter(|_| l.starts_with("Warning") || l.starts_with("Critical") || l.starts_with("Fatal") || l.starts_with("Debug")).unwrap_or(l);
    let clean = |s: &str| ou_core::redact::redact(s.trim().trim_matches('"'));
    if body.contains("Sync succeeded") {
        EngineEvent::Succeeded
    } else if body.contains("Authentication failed") {
        EngineEvent::AuthFailed
    } else if body.contains("Failed to sync") {
        EngineEvent::Failed
    } else if body.contains("Another sync is needed") {
        EngineEvent::AnotherSyncNeeded
    } else if body.contains("No spaces found matching") {
        EngineEvent::SpaceNotFound
    } else if let Some(rest) = body.strip_prefix("Sync excluded file:") {
        EngineEvent::Excluded(clean(rest))
    } else if let Some(rest) = body.strip_prefix("Sync error:") {
        EngineEvent::ItemError(clean(rest))
    } else if body.contains("Error connecting to server") || body.contains("Failed to resolve") || body.contains("timed out") || body.contains("Error unsupported server") {
        EngineEvent::ConnectError(clean(body))
    } else {
        EngineEvent::Other(clean(body))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Success { item_errors: Vec<String>, another_sync_needed: bool },
    AuthFailed,
    Offline(String),
    Failed { exit_code: Option<i32>, errors: Vec<String> },
    TimedOut,
}

/// Starts the engine once with the given app token and supervises it until exit or timeout.
pub async fn run_engine(cfg: &EngineConfig, app_token: &str) -> Result<RunOutcome, FilesError> {
    let (excl, unsynced) = write_support_files(cfg)?;
    let token = app_token.to_string();
    let mut child = tokio::process::Command::new(&cfg.exe)
        .args(command_args(cfg, &excl, &unsynced))
        .env("OPENCLOUD_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let (out, err) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    let collect = async {
        let mut events = Vec::new();
        let mut a = BufReader::new(out).lines();
        let mut b = BufReader::new(err).lines();
        let (mut a_done, mut b_done) = (false, false);
        while !(a_done && b_done) {
            tokio::select! {
                l = a.next_line(), if !a_done => match l { Ok(Some(l)) => events.push(parse_line(&l)), _ => a_done = true },
                l = b.next_line(), if !b_done => match l { Ok(Some(l)) => events.push(parse_line(&l)), _ => b_done = true },
            }
            // Upstream cmd.cpp logs "Another sync is needed, but not done because restart count is exceeded" and then neither
            // quits nor syncs again: the process would idle forever. The run itself completed, so stop it here.
            if events.last() == Some(&EngineEvent::AnotherSyncNeeded) {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return (events, None);
            }
        }
        (events, Some(child.wait().await))
    };
    let Ok((events, status)) = tokio::time::timeout(cfg.run_timeout, collect).await else {
        return Ok(RunOutcome::TimedOut); // child is killed on drop
    };
    match status {
        None => Ok(classify(&events, true, None)),
        Some(st) => {
            let st = st?;
            Ok(classify(&events, st.success(), st.code()))
        }
    }
}

pub fn classify(events: &[EngineEvent], exit_ok: bool, code: Option<i32>) -> RunOutcome {
    if events.contains(&EngineEvent::AuthFailed) {
        return RunOutcome::AuthFailed;
    }
    if let Some(EngineEvent::ConnectError(e)) = events.iter().find(|e| matches!(e, EngineEvent::ConnectError(_))) {
        return RunOutcome::Offline(e.clone());
    }
    let item_errors: Vec<String> = events.iter().filter_map(|e| if let EngineEvent::ItemError(m) = e { Some(m.clone()) } else { None }).collect();
    if exit_ok && events.contains(&EngineEvent::Succeeded) {
        return RunOutcome::Success { item_errors, another_sync_needed: false };
    }
    if exit_ok && events.contains(&EngineEvent::AnotherSyncNeeded) {
        return RunOutcome::Success { item_errors, another_sync_needed: true };
    }
    RunOutcome::Failed { exit_code: code, errors: item_errors }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CycleOutcome {
    /// Engine ran and finished; the manifest was updated.
    Synced { item_errors: Vec<String>, another_sync_needed: bool },
    /// Guard decided not to run now (offline, signed out, folder missing); nothing changed.
    Skipped(String),
    /// Guard paused the folder; the UI shows the plan.
    Held { reason: String, plan_id: String, local_deletes: usize, remote_deletes: usize, modified: usize },
    /// Engine ran but did not finish cleanly; the manifest is kept as it was (next cycle re-plans).
    EngineFailed(String),
}

pub const MAX_LISTING: usize = 500_000;

/// One guarded cycle. `account_id` is the ou-core account id written in the folder marker.
pub async fn sync_cycle(client: &Client, space: &Space, cfg: &EngineConfig, account_id: &str, policy: &GuardPolicy) -> Result<CycleOutcome, FilesError> {
    let health = client.probe(space).await;
    let mut manifest = Manifest::load(&cfg.state_dir)?;
    let (local, remote) = if health == crate::guard::Health::Ok && manifest.is_some() {
        (Some(scan_local(&cfg.local_dir)), Some(client.list_tree(space, &cfg.remote_folder, MAX_LISTING).await))
    } else {
        (None, None)
    };
    match preflight(policy, account_id, &cfg.local_dir, &health, manifest.as_ref(), local.as_ref(), remote.as_ref()) {
        Decision::Skip(r) => return Ok(CycleOutcome::Skipped(r)),
        Decision::Hold { reason, plan_id, plan } => {
            return Ok(CycleOutcome::Held {
                reason,
                plan_id,
                local_deletes: plan.local_deletes.len(),
                remote_deletes: plan.remote_deletes.len(),
                modified: plan.local_modified.len() + plan.remote_modified.len(),
            })
        }
        Decision::Run => {}
    }
    if ou_core::safety::check_root(&cfg.local_dir, account_id) == ou_core::safety::RootState::New {
        ou_core::safety::write_marker(&cfg.local_dir, account_id)?;
    }
    // Per-run app token: minted from the OIDC session, valid for the run (+5 min), deleted right after. A crash leaves at most
    // one token that expires on its own; device revocation (ou-oc-revoke) deletes all of them.
    let label = format!("Office Unbound Desktop sync {}", ou_core::oidc::random_token(9));
    let minutes = (cfg.run_timeout.as_secs() / 60) as u32 + 5;
    let app_token = match client.create_app_token(minutes, &label).await {
        Ok(t) => t,
        Err(FilesError::Auth) => return Ok(CycleOutcome::Skipped("sign-in expired; sign in again to resume".into())),
        Err(FilesError::Offline(e)) => return Ok(CycleOutcome::Skipped(format!("offline: {e}"))),
        Err(e) => return Ok(CycleOutcome::EngineFailed(format!("could not get a sync credential from the server: {e}"))),
    };
    let outcome = run_engine(cfg, &app_token).await;
    drop(app_token);
    let _ = client.delete_app_tokens(&label).await;
    match outcome? {
        RunOutcome::Success { item_errors, another_sync_needed } => {
            let local = scan_local(&cfg.local_dir);
            let remote = client.list_tree(space, &cfg.remote_folder, MAX_LISTING).await;
            if local.complete && remote.complete {
                Manifest::from_run(account_id, &space.id, &local, &remote).save(&cfg.state_dir)?;
            } else if let Some(m) = manifest.as_mut() {
                m.approved_plan = None; // consume the approval even if we could not refresh
                m.save(&cfg.state_dir)?;
            }
            Ok(CycleOutcome::Synced { item_errors, another_sync_needed })
        }
        RunOutcome::AuthFailed => Ok(CycleOutcome::Skipped("sign-in expired during sync".into())),
        RunOutcome::Offline(e) => Ok(CycleOutcome::Skipped(format!("connection lost during sync: {e}"))),
        RunOutcome::TimedOut => Ok(CycleOutcome::EngineFailed("sync took too long and was stopped; it resumes next time".into())),
        RunOutcome::Failed { exit_code, errors } => Ok(CycleOutcome::EngineFailed(format!("engine exit {exit_code:?}: {}", errors.join("; ")))),
    }
}

/// Retry delay after consecutive failures: 30 s doubling to 30 min. No busy loops, no thundering herd on reconnect.
pub fn backoff(consecutive_failures: u32) -> Duration {
    Duration::from_secs((30u64 << consecutive_failures.min(6)).min(1800))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> EngineConfig {
        EngineConfig {
            exe: "opencloudcmd".into(),
            server: Url::parse("https://cloud.example.com").unwrap(),
            space_id: "a$b".into(),
            local_dir: "/tmp/x".into(),
            remote_folder: String::new(),
            username: "doc".into(),
            state_dir: std::env::temp_dir().join(format!("ou-files-engine-{}", std::process::id())),
            unsynced_folders: vec!["Big/".into(), "../escape".into(), "".into(), "Media/Raw".into()],
            download_limit_kbps: 0,
            max_sync_retries: 3,
            run_timeout: Duration::from_secs(3600),
        }
    }

    #[test]
    fn args_never_carry_token_or_trust() {
        let c = cfg();
        let a: Vec<String> = command_args(&c, Path::new("e"), Path::new("u")).into_iter().map(|s| s.into_string().unwrap()).collect();
        assert!(a.contains(&"--non-interactive".to_string()));
        assert!(!a.iter().any(|s| s == "--trust" || s == "-t" || s == "--token" || s == "--upload-limit"));
        assert_eq!(&a[a.len() - 3..], ["https://cloud.example.com/", "a$b", "/tmp/x"]);
        let mut c2 = cfg();
        c2.download_limit_kbps = 500;
        let a2: Vec<String> = command_args(&c2, Path::new("e"), Path::new("u")).into_iter().map(|s| s.into_string().unwrap()).collect();
        assert!(a2.windows(2).any(|w| w == ["--download-limit", "500"]));
        let mut c3 = cfg();
        c3.remote_folder = "Team/Docs/".into();
        let a3: Vec<String> = command_args(&c3, Path::new("e"), Path::new("u")).into_iter().map(|s| s.into_string().unwrap()).collect();
        assert!(a3.windows(2).any(|w| w == ["--remote-folder", "/Team/Docs/"]));
    }

    #[test]
    fn selective_sync_file_is_sanitised() {
        let c = cfg();
        let (_, u) = write_support_files(&c).unwrap();
        let body = std::fs::read_to_string(u).unwrap();
        let lines: Vec<&str> = body.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(lines, ["Big/", "Media/Raw/"]);
        std::fs::remove_dir_all(&c.state_dir).unwrap();
    }

    #[test]
    fn output_parsing() {
        assert_eq!(parse_line("Sync succeeded"), EngineEvent::Succeeded);
        assert_eq!(parse_line("Warning: Failed to sync"), EngineEvent::Failed);
        assert_eq!(parse_line("Fatal: Authentication failed please verify your credentials"), EngineEvent::AuthFailed);
        assert_eq!(parse_line("Warning: Sync error: \"Server replied 507\""), EngineEvent::ItemError("Server replied 507".into()));
        assert_eq!(parse_line("Critical: Error connecting to server"), EngineEvent::ConnectError("Error connecting to server".into()));
        assert!(matches!(parse_line("Warning: Sync error: Bearer abc.def.ghi"), EngineEvent::ItemError(m) if !m.contains("abc.def.ghi")));
        assert_eq!(parse_line("Critical: No spaces found matching: \"x\""), EngineEvent::SpaceNotFound);
    }

    #[test]
    fn outcome_classification() {
        assert_eq!(classify(&[EngineEvent::Succeeded], true, Some(0)), RunOutcome::Success { item_errors: vec![], another_sync_needed: false });
        assert_eq!(classify(&[EngineEvent::AuthFailed], false, Some(1)), RunOutcome::AuthFailed);
        assert!(matches!(classify(&[EngineEvent::ConnectError("x".into())], false, Some(1)), RunOutcome::Offline(_)));
        assert!(matches!(classify(&[EngineEvent::ItemError("e".into()), EngineEvent::Failed], false, Some(1)), RunOutcome::Failed { .. }));
        // exit 0 without "Sync succeeded" is not a success (e.g. space listing only).
        assert!(matches!(classify(&[], true, Some(0)), RunOutcome::Failed { .. }));
        assert_eq!(
            classify(&[EngineEvent::AnotherSyncNeeded], true, Some(0)),
            RunOutcome::Success { item_errors: vec![], another_sync_needed: true }
        );
    }

    #[test]
    fn backoff_bounds() {
        assert_eq!(backoff(0), Duration::from_secs(30));
        assert_eq!(backoff(3), Duration::from_secs(240));
        assert_eq!(backoff(50), Duration::from_secs(1800));
    }
}
