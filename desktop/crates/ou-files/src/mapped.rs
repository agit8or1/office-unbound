//! Optional HTTPS mapped drive: rclone (MIT) `mount` over OpenCloud WebDAV with WinFsp (GPLv3 + FLOSS exception) on Windows.
//!
//! - Transport: only `https://cloud.<domain>` (WebDAV) — no SMB/NFS anywhere.
//! - Auth: rclone's `bearer_token_command` runs our agent, which prints a fresh access token (no password, no token in files).
//! - Drive letter: `O:` by default, configurable; a letter in use (local disk, USB, existing network mapping) is never taken.
//! - Loops: the mount point, the rclone cache and every sync root must not contain one another, and no sync root may live on the
//!   mapped letter.
//! - Offline writes: rclone's VFS cache (`writes` mode) acknowledges `close()` before the upload. We therefore read rclone's
//!   `vfs/stats` and report "N files not saved to the cloud yet" / "N failed"; the UI must never show them as saved.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use url::Url;

use crate::webdav::{FilesError, Space};

pub const DEFAULT_LETTER: char = 'O';

/// Letters that are present, from a `GetLogicalDrives` bitmask (bit 0 = A:).
pub fn letters_from_mask(mask: u32) -> Vec<char> {
    (0..26).filter(|i| mask & (1 << i) != 0).map(|i| (b'A' + i as u8) as char).collect()
}

/// Letters currently in use on this machine. Windows: logical drives. Persistent-but-disconnected network mappings are not in
/// that mask; the caller adds the letters from `HKCU\Network` (to verify on real Windows).
#[cfg(windows)]
pub fn used_letters() -> Vec<char> {
    // SAFETY: GetLogicalDrives has no arguments and no preconditions.
    letters_from_mask(unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() })
}

#[cfg(not(windows))]
pub fn used_letters() -> Vec<char> {
    Vec::new()
}

/// The preferred letter if free; otherwise the highest free letter from Z: down to D: (A:–C: are never used).
pub fn choose_letter(preferred: Option<char>, used: &[char]) -> Option<char> {
    let used: Vec<char> = used.iter().map(|c| c.to_ascii_uppercase()).collect();
    let free = |c: char| c.is_ascii_alphabetic() && !matches!(c, 'A' | 'B' | 'C') && !used.contains(&c);
    let p = preferred.unwrap_or(DEFAULT_LETTER).to_ascii_uppercase();
    if free(p) {
        return Some(p);
    }
    ('D'..='Z').rev().find(|&c| free(c))
}

#[derive(Debug, Clone)]
pub struct DriveConfig {
    pub rclone_exe: PathBuf,
    /// Remote name inside the generated config (one per mapped space), e.g. `ou-personal`.
    pub remote_name: String,
    pub space: Space,
    /// Drive letter on Windows (`O`), or a mount directory elsewhere.
    pub mount: MountPoint,
    pub volume_label: String,
    /// Command that prints an access token, e.g. `["C:\\Program Files\\Office Unbound\\ou-agent.exe", "token", "--account", "<id>"]`.
    pub token_command: Vec<String>,
    /// rclone VFS cache, under the per-user app data dir (never inside a sync root).
    pub cache_dir: PathBuf,
    pub config_path: PathBuf,
    pub log_path: PathBuf,
    /// Loopback port for rclone's remote-control API (status only).
    pub rc_port: u16,
    pub bwlimit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPoint {
    Letter(char),
    Dir(PathBuf),
}

impl MountPoint {
    fn arg(&self) -> OsString {
        match self {
            Self::Letter(c) => format!("{}:", c.to_ascii_uppercase()).into(),
            Self::Dir(p) => p.clone().into_os_string(),
        }
    }
}

/// rclone's `SpaceSepList` quoting (CSV rules with a space separator): quote fields with spaces or quotes, double inner quotes.
pub fn space_sep_list(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.is_empty() || a.contains([' ', '"', '\t']) { format!("\"{}\"", a.replace('"', "\"\"")) } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The rclone config file. Contains no secret: the token comes from `bearer_token_command` each time rclone needs one.
pub fn rclone_config(cfg: &DriveConfig) -> Result<String, FilesError> {
    let url = &cfg.space.webdav_url;
    ou_core::http::require_allowed(url).map_err(|e| FilesError::Policy(e.to_string()))?;
    if !cfg.remote_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || cfg.remote_name.is_empty() {
        return Err(FilesError::Policy("invalid remote name".into()));
    }
    let cmd = space_sep_list(&cfg.token_command);
    if cmd.contains('\n') || url.as_str().contains('\n') {
        return Err(FilesError::Policy("newline in config value".into()));
    }
    // vendor = infinitescale: rclone's quirks for oCIS/OpenCloud (TUS uploads in 10 MiB chunks, OC SHA1, X-OC-Mtime).
    Ok(format!(
        "[{name}]\ntype = webdav\nurl = {url}\nvendor = infinitescale\nbearer_token_command = {cmd}\n",
        name = cfg.remote_name,
        url = url.as_str().trim_end_matches('/'),
    ))
}

/// Arguments for `rclone mount`. rc credentials go through the environment (`RCLONE_RC_USER`/`RCLONE_RC_PASS`), not argv.
pub fn mount_args(cfg: &DriveConfig) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        "mount".into(),
        format!("{}:", cfg.remote_name).into(),
        cfg.mount.arg(),
        "--config".into(),
        cfg.config_path.clone().into(),
        "--cache-dir".into(),
        cfg.cache_dir.clone().into(),
        // `writes`: needed for Office/LibreOffice save patterns (random writes, rename-over). Uploads are asynchronous, hence
        // the pending/failed reporting below.
        "--vfs-cache-mode".into(),
        "writes".into(),
        "--vfs-write-back".into(),
        "5s".into(),
        "--dir-cache-time".into(),
        "30s".into(),
        "--log-file".into(),
        cfg.log_path.clone().into(),
        "--log-level".into(),
        "NOTICE".into(),
        "--rc".into(),
        "--rc-addr".into(),
        format!("127.0.0.1:{}", cfg.rc_port).into(),
    ];
    if let MountPoint::Letter(_) = cfg.mount {
        a.push("--volname".into());
        a.push(cfg.volume_label.clone().into());
        a.push("--network-mode".into()); // WinFsp network drive: Explorer shows it as a network location, no recycle bin
    }
    if let Some(bw) = &cfg.bwlimit {
        a.push("--bwlimit".into());
        a.push(bw.clone().into());
    }
    a
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopProblem {
    LetterInUse(char),
    SyncRootOnDrive(PathBuf),
    Overlap(PathBuf, PathBuf),
}

impl std::fmt::Display for LoopProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LetterInUse(c) => write!(f, "drive {c}: is already in use"),
            Self::SyncRootOnDrive(p) => write!(f, "the sync folder {} is on the mapped drive", p.display()),
            Self::Overlap(a, b) => write!(f, "{} and {} contain one another", a.display(), b.display()),
        }
    }
}

fn on_letter(p: &Path, letter: char) -> bool {
    let s = p.to_string_lossy();
    let mut ch = s.chars();
    matches!((ch.next(), ch.next()), (Some(c), Some(':')) if c.eq_ignore_ascii_case(&letter))
}

/// Refuses configurations that could sync the drive into a sync folder (or back), or take a used letter.
pub fn check_no_loops(cfg: &DriveConfig, sync_roots: &[PathBuf], used: &[char]) -> Result<(), LoopProblem> {
    if let MountPoint::Letter(c) = cfg.mount {
        let c = c.to_ascii_uppercase();
        if used.iter().any(|u| u.eq_ignore_ascii_case(&c)) {
            return Err(LoopProblem::LetterInUse(c));
        }
        for r in sync_roots {
            if on_letter(r, c) {
                return Err(LoopProblem::SyncRootOnDrive(r.clone()));
            }
        }
        if on_letter(&cfg.cache_dir, c) {
            return Err(LoopProblem::SyncRootOnDrive(cfg.cache_dir.clone()));
        }
    }
    let mut dirs: Vec<PathBuf> = vec![cfg.cache_dir.clone()];
    if let MountPoint::Dir(d) = &cfg.mount {
        dirs.push(d.clone());
    }
    for d in &dirs {
        for r in sync_roots {
            if ou_core::safety::roots_overlap(d, r) {
                return Err(LoopProblem::Overlap(d.clone(), r.clone()));
            }
        }
    }
    Ok(())
}

/// rclone `vfs/stats` answer (fields from rclone vfs/vfscache/cache.go `Stats`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct VfsStats {
    #[serde(rename = "diskCache", default)]
    pub disk_cache: DiskCache,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DiskCache {
    #[serde(rename = "uploadsInProgress", default)]
    pub uploads_in_progress: u64,
    #[serde(rename = "uploadsQueued", default)]
    pub uploads_queued: u64,
    #[serde(rename = "erroredFiles", default)]
    pub errored_files: u64,
    #[serde(rename = "outOfSpace", default)]
    pub out_of_space: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveWriteState {
    AllSaved,
    /// Written locally, upload pending: must be shown as "not saved to the cloud yet".
    Pending(u64),
    /// Uploads that failed (offline, permission, quota); rclone retries, the user is told.
    Failed { failed: u64, pending: u64 },
    /// The local cache disk is full: new writes fail.
    CacheFull,
}

pub fn write_state(s: &VfsStats) -> DriveWriteState {
    let d = &s.disk_cache;
    let pending = d.uploads_in_progress + d.uploads_queued;
    if d.out_of_space {
        DriveWriteState::CacheFull
    } else if d.errored_files > 0 {
        DriveWriteState::Failed { failed: d.errored_files, pending }
    } else if pending > 0 {
        DriveWriteState::Pending(pending)
    } else {
        DriveWriteState::AllSaved
    }
}

impl DriveWriteState {
    /// Unmounting with pending writes is allowed (rclone resumes them from the cache on the next mount) but must be said.
    pub fn message(&self) -> String {
        match self {
            Self::AllSaved => "All changes are saved to the cloud.".into(),
            Self::Pending(n) => format!("{n} file(s) are not saved to the cloud yet. Keep the drive connected."),
            Self::Failed { failed, pending } => {
                format!("{failed} file(s) could not be saved to the cloud ({pending} waiting). They are kept on this computer and retried.")
            }
            Self::CacheFull => "The local cache disk is full; new changes cannot be saved.".into(),
        }
    }
}

/// URL of rclone's rc endpoint for `vfs/stats` (loopback only).
pub fn rc_stats_url(port: u16, remote_name: &str) -> Url {
    let mut u = Url::parse(&format!("http://127.0.0.1:{port}/vfs/stats")).expect("static");
    u.query_pairs_mut().append_pair("fs", &format!("{remote_name}:"));
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mount: MountPoint) -> DriveConfig {
        DriveConfig {
            rclone_exe: "rclone".into(),
            remote_name: "ou-personal".into(),
            space: Space {
                id: "a$b".into(),
                drive_type: "personal".into(),
                name: "Doc".into(),
                webdav_url: Url::parse("https://cloud.example.com/dav/spaces/a$b").unwrap(),
            },
            mount,
            volume_label: "Office Unbound".into(),
            token_command: vec![r"C:\Program Files\Office Unbound\ou-agent.exe".into(), "token".into(), "--account".into(), "acc1".into()],
            cache_dir: r"C:\Users\a\AppData\Local\Office Unbound\rclone-cache".into(),
            config_path: r"C:\Users\a\AppData\Local\Office Unbound\rclone.conf".into(),
            log_path: r"C:\Users\a\AppData\Local\Office Unbound\rclone.log".into(),
            rc_port: 53682,
            bwlimit: None,
        }
    }

    #[test]
    fn letter_choice() {
        assert_eq!(choose_letter(None, &['C', 'D']), Some('O'));
        assert_eq!(choose_letter(None, &['C', 'O']), Some('Z'));
        assert_eq!(choose_letter(Some('o'), &['c', 'o', 'z']), Some('Y'));
        assert_eq!(choose_letter(Some('C'), &[]), Some('Z'), "system letters never");
        let all: Vec<char> = ('D'..='Z').collect();
        assert_eq!(choose_letter(None, &all), None);
        assert_eq!(letters_from_mask(0b100 | 1 << 14), vec!['C', 'O']);
    }

    #[test]
    fn config_has_no_secret_and_quotes_paths() {
        let c = rclone_config(&cfg(MountPoint::Letter('O'))).unwrap();
        assert!(c.contains("vendor = infinitescale"));
        assert!(c.contains("url = https://cloud.example.com/dav/spaces/a$b\n"));
        assert!(c.contains(r#"bearer_token_command = "C:\Program Files\Office Unbound\ou-agent.exe" token --account acc1"#));
        assert!(!c.to_lowercase().contains("pass") && !c.contains("bearer_token ="));
        let mut bad = cfg(MountPoint::Letter('O'));
        bad.space.webdav_url = Url::parse("http://cloud.example.com/dav").unwrap();
        assert!(rclone_config(&bad).is_err(), "plain HTTP refused");
        bad = cfg(MountPoint::Letter('O'));
        bad.remote_name = "x]\n[y".into();
        assert!(rclone_config(&bad).is_err());
    }

    #[test]
    fn space_sep_quoting() {
        assert_eq!(space_sep_list(&["a".into(), "b c".into(), "say \"hi\"".into()]), r#"a "b c" "say ""hi""""#);
    }

    #[test]
    fn mount_args_shape() {
        let a: Vec<String> = mount_args(&cfg(MountPoint::Letter('o'))).into_iter().map(|s| s.into_string().unwrap()).collect();
        assert_eq!(&a[..3], ["mount", "ou-personal:", "O:"]);
        assert!(a.windows(2).any(|w| w == ["--vfs-cache-mode", "writes"]));
        assert!(a.windows(2).any(|w| w[0] == "--rc-addr" && w[1].starts_with("127.0.0.1:")));
        assert!(a.contains(&"--network-mode".to_string()));
        assert!(!a.iter().any(|s| s.contains("rc-pass") || s.contains("rc-user")));
    }

    #[test]
    fn loops_and_letters_refused() {
        let c = cfg(MountPoint::Letter('O'));
        assert_eq!(check_no_loops(&c, &[r"C:\Users\a\Office Unbound".into()], &['C']), Ok(()));
        assert_eq!(check_no_loops(&c, &[], &['C', 'o']), Err(LoopProblem::LetterInUse('O')));
        assert!(matches!(check_no_loops(&c, &[r"o:\Synced".into()], &['C']), Err(LoopProblem::SyncRootOnDrive(_))));
        // Cache inside a sync root would upload the cache through the sync engine.
        assert!(matches!(check_no_loops(&c, &[r"C:\Users\a\AppData\Local\Office Unbound".into()], &['C']), Err(LoopProblem::Overlap(..))));
        let d = cfg(MountPoint::Dir("/home/a/OfficeUnbound/Drive".into()));
        assert!(matches!(check_no_loops(&d, &["/home/a/OfficeUnbound".into()], &[]), Err(LoopProblem::Overlap(..))));
    }

    #[test]
    fn offline_writes_are_reported_not_hidden() {
        let s: VfsStats = serde_json::from_str(r#"{"diskCache":{"uploadsInProgress":1,"uploadsQueued":2,"erroredFiles":0,"outOfSpace":false,"files":9}}"#).unwrap();
        assert_eq!(write_state(&s), DriveWriteState::Pending(3));
        assert!(write_state(&s).message().contains("not saved"));
        let s: VfsStats = serde_json::from_str(r#"{"diskCache":{"uploadsInProgress":0,"uploadsQueued":1,"erroredFiles":2}}"#).unwrap();
        assert_eq!(write_state(&s), DriveWriteState::Failed { failed: 2, pending: 1 });
        let s: VfsStats = serde_json::from_str(r#"{"diskCache":{"outOfSpace":true}}"#).unwrap();
        assert_eq!(write_state(&s), DriveWriteState::CacheFull);
        assert_eq!(write_state(&VfsStats::default()), DriveWriteState::AllSaved);
        assert_eq!(rc_stats_url(5572, "ou-personal").as_str(), "http://127.0.0.1:5572/vfs/stats?fs=ou-personal%3A");
    }
}
