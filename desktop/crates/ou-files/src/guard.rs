//! Data-safety guard in front of the sync engine.
//!
//! The OpenCloud engine (`opencloudcmd`, upstream main as of 2026-11-25) has **no** mass-delete confirmation: `promptRemoveAllFiles`
//! is parsed in cmd.cpp but never used, and the GUI client has no "remove all files?" dialog either. So this guard is the only
//! barrier, and it runs *before every engine run*:
//!
//! 1. Health: an auth failure, network failure, server error or missing/foreign sync root means **Skip** (no engine run at all).
//!    An absence is never evidence of deletion (ou-core ADR-0022 section 7).
//! 2. Plan: compare the manifest of the last good run with a fresh local scan and a fresh remote listing. Deletions, and
//!    modifications of already-synced files (overwrite/replace, e.g. ransomware encrypting a folder), are counted per side.
//! 3. Threshold: above the policy the folder is **Held** with the affected list; the user approves exactly that plan (by id)
//!    or restores. An approval never carries over to a different plan.
//!
//! The manifest is written only after a run that the engine reported as fully successful.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ou_core::safety::{check_deletes, check_root, DeletePolicy, RootState, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths::{LocalKind, LocalScan};

pub const MANIFEST: &str = ".ou-files-manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub dir: bool,
    pub size: u64,
    pub mtime: i64,
    /// Remote ETag at the time of the last good run (None for directories on servers that omit it).
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub account_id: String,
    pub space_id: String,
    pub entries: BTreeMap<String, ManifestEntry>,
    /// Plan id the user approved (consumed by the next run that matches it).
    #[serde(default)]
    pub approved_plan: Option<String>,
}

impl Manifest {
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(MANIFEST)
    }

    pub fn load(state_dir: &Path) -> std::io::Result<Option<Self>> {
        match std::fs::read(Self::path(state_dir)) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(std::io::Error::other),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Atomic replace: write a sibling temp file, then rename. A crash leaves the old manifest, never a truncated one.
    pub fn save(&self, state_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(state_dir)?;
        let tmp = state_dir.join(format!("{MANIFEST}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec(self).map_err(std::io::Error::other)?)?;
        std::fs::rename(tmp, Self::path(state_dir))
    }

    /// Builds the manifest after a good run from the post-run local scan and remote listing (only paths present on both sides).
    pub fn from_run(account_id: &str, space_id: &str, local: &LocalScan, remote: &RemoteListing) -> Self {
        let mut entries = BTreeMap::new();
        for e in &local.entries {
            if let Some(r) = remote.entries.get(&e.rel) {
                entries.insert(
                    e.rel.clone(),
                    ManifestEntry { dir: e.kind == LocalKind::Dir, size: e.size, mtime: e.mtime, etag: r.etag.clone() },
                );
            }
        }
        Self { account_id: account_id.into(), space_id: space_id.into(), entries, approved_plan: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteItem {
    pub dir: bool,
    pub size: u64,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RemoteListing {
    pub entries: BTreeMap<String, RemoteItem>,
    /// False on any failed or truncated PROPFIND: then remote absences are not deletions.
    pub complete: bool,
}

/// Outcome of the health probe that precedes a run (the caller maps HTTP/IO errors into this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// 401/403 on the space root, or no token: the sign-in expired or the device was revoked.
    AuthFailed,
    /// DNS, TCP, TLS or timeout.
    Offline,
    /// 5xx or an unexpected answer.
    ServerError(String),
    /// The space is gone or no longer shared with the user (404 on the space root): keep local data, ask the user.
    SpaceGone,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GuardPolicy {
    pub deletes: DeletePolicy,
    /// Same shape for modifications of already-synced files.
    pub max_modified_items: usize,
    pub max_modified_fraction: f64,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self { deletes: DeletePolicy::default(), max_modified_items: 500, max_modified_fraction: 0.5 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Synced paths missing locally: the engine would delete them on the server.
    pub local_deletes: Vec<String>,
    /// Synced paths missing remotely: the engine would delete the local copies.
    pub remote_deletes: Vec<String>,
    /// Synced files changed locally (size or mtime): the engine would overwrite the server copy.
    pub local_modified: Vec<String>,
    /// Synced files changed remotely (ETag): the engine would replace the local copy.
    pub remote_modified: Vec<String>,
}

impl Plan {
    /// Stable id over the affected paths: the user's approval is bound to exactly this set.
    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        for (tag, v) in [("ld", &self.local_deletes), ("rd", &self.remote_deletes), ("lm", &self.local_modified), ("rm", &self.remote_modified)]
        {
            for p in v {
                h.update(tag.as_bytes());
                h.update([0]);
                h.update(p.as_bytes());
                h.update([0]);
            }
        }
        h.finalize().iter().take(12).map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Start the engine.
    Run,
    /// Do not start the engine now; retry later. Nothing is deleted. `reason` is user-facing.
    Skip(String),
    /// Paused until the user decides; show `plan` and offer "Apply these changes" (approve `plan_id`) or "Restore".
    Hold { reason: String, plan_id: String, plan: Plan },
}

pub fn compute_plan(manifest: &Manifest, local: &LocalScan, remote: &RemoteListing) -> Plan {
    let local_map: BTreeMap<&str, &crate::paths::LocalEntry> = local.entries.iter().map(|e| (e.rel.as_str(), e)).collect();
    let mut p = Plan::default();
    for (path, m) in &manifest.entries {
        match local_map.get(path.as_str()) {
            None => p.local_deletes.push(path.clone()),
            Some(l) if !m.dir && (l.size != m.size || l.mtime != m.mtime) => p.local_modified.push(path.clone()),
            _ => {}
        }
        match remote.entries.get(path) {
            None => p.remote_deletes.push(path.clone()),
            Some(r) if !m.dir && m.etag.is_some() && r.etag != m.etag => p.remote_modified.push(path.clone()),
            _ => {}
        }
    }
    // A path gone on both sides is a completed deletion, not a pending one.
    let both: BTreeSet<String> = p.local_deletes.iter().filter(|x| p.remote_deletes.contains(x)).cloned().collect();
    p.local_deletes.retain(|x| !both.contains(x));
    p.remote_deletes.retain(|x| !both.contains(x));
    p
}

/// Full pre-flight decision. `root` is the local sync folder, `state_dir` holds the manifest (outside the sync folder).
pub fn preflight(
    policy: &GuardPolicy,
    account_id: &str,
    root: &Path,
    health: &Health,
    manifest: Option<&Manifest>,
    local: Option<&LocalScan>,
    remote: Option<&RemoteListing>,
) -> Decision {
    match health {
        Health::Ok => {}
        Health::AuthFailed => return Decision::Skip("sign-in expired or this device was signed out; sign in again to resume".into()),
        Health::Offline => return Decision::Skip("offline; sync resumes when the connection is back".into()),
        Health::ServerError(e) => return Decision::Skip(format!("the server is not answering correctly ({e}); retrying later")),
        Health::SpaceGone => {
            return Decision::Hold {
                reason: "this library is no longer available to you on the server; your local copy is kept".into(),
                plan_id: String::new(),
                plan: Plan::default(),
            }
        }
    }
    match check_root(root, account_id) {
        RootState::Ready => {}
        RootState::New if manifest.map_or(true, |m| m.entries.is_empty()) => {}
        RootState::New => {
            return Decision::Hold {
                reason: "the sync folder is empty although files were synced before; was it moved or is a drive missing?".into(),
                plan_id: String::new(),
                plan: Plan::default(),
            }
        }
        RootState::Missing => return Decision::Skip("the sync folder is missing (renamed, moved or on a disconnected drive)".into()),
        RootState::OtherAccount => return Decision::Skip("the sync folder belongs to another account".into()),
        RootState::Unmarked => {
            return Decision::Hold {
                reason: "the folder already contains files; confirm that they should be merged with the cloud".into(),
                plan_id: String::new(),
                plan: Plan::default(),
            }
        }
    }
    let Some(manifest) = manifest else { return Decision::Run }; // first run: nothing synced yet, nothing to lose
    if manifest.account_id != account_id {
        return Decision::Skip("the sync state belongs to another account".into());
    }
    let (Some(local), Some(remote)) = (local, remote) else {
        return Decision::Skip("could not list the folder; retrying later".into());
    };
    let plan = compute_plan(manifest, local, remote);
    let known = manifest.entries.len();
    // An incomplete listing on either side may only produce Hold, never deletions.
    let listing_ok = remote.complete && local.complete;
    let mut reason = match check_deletes(&policy.deletes, known, plan.local_deletes.len(), plan.remote_deletes.len(), listing_ok) {
        Verdict::Hold(r) => Some(r),
        Verdict::Proceed => None,
    };
    if reason.is_none() {
        let modified = plan.local_modified.len() + plan.remote_modified.len();
        if modified > policy.max_modified_items
            || (known >= policy.deletes.min_items_for_ratio && modified as f64 / known as f64 > policy.max_modified_fraction)
        {
            reason = Some(format!("{modified} of {known} synced files would be overwritten or replaced"));
        }
    }
    match reason {
        None => Decision::Run,
        Some(r) => {
            let id = plan.id();
            if manifest.approved_plan.as_deref() == Some(id.as_str()) && listing_ok {
                Decision::Run
            } else {
                Decision::Hold { reason: r, plan_id: id, plan }
            }
        }
    }
}

/// Conflict copy name, byte-compatible with OpenCloud's `Utility::makeConflictFileName` so both clients recognise it:
/// `stem (conflicted copy [user ]YYYY-MM-DD HHMMSS).ext`. `unix_secs` is UTC.
pub fn conflict_name(name: &str, unix_secs: i64, user: Option<&str>) -> String {
    let dot = match name.rfind('.') {
        Some(i) if i > 0 => i,
        _ => name.len(),
    };
    let mut marker = String::from(" (conflicted copy ");
    if let Some(u) = user.filter(|u| !u.is_empty()) {
        let clean: String = u.chars().map(|c| if matches!(c, '(' | ')' | '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c }).collect();
        marker.push_str(&clean);
        marker.push(' ');
    }
    let (y, mo, d, h, mi, s) = civil(unix_secs);
    marker.push_str(&format!("{y:04}-{mo:02}-{d:02} {h:02}{mi:02}{s:02})"));
    format!("{}{}{}", &name[..dot], marker, &name[dot..])
}

pub fn is_conflict_name(name: &str) -> bool {
    name.contains("(conflicted copy") || name.contains("_conflict-")
}

/// UTC civil time from Unix seconds (Howard Hinnant's days-from-civil inverse).
fn civil(t: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = t.div_euclid(86_400);
    let sod = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, (sod / 3600) as u32, (sod % 3600 / 60) as u32, (sod % 60) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::LocalEntry;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ou-files-guard-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn world(n: usize) -> (Manifest, LocalScan, RemoteListing) {
        let mut m = Manifest { account_id: "acc".into(), space_id: "sp".into(), ..Default::default() };
        let mut l = LocalScan { complete: true, ..Default::default() };
        let mut r = RemoteListing { complete: true, ..Default::default() };
        for i in 0..n {
            let p = format!("f{i:04}.txt");
            m.entries.insert(p.clone(), ManifestEntry { dir: false, size: 10, mtime: 100, etag: Some(format!("e{i}")) });
            l.entries.push(LocalEntry { rel: p.clone(), kind: LocalKind::File, size: 10, mtime: 100 });
            r.entries.insert(p, RemoteItem { dir: false, size: 10, etag: Some(format!("e{i}")) });
        }
        (m, l, r)
    }

    fn ready_root(tag: &str) -> PathBuf {
        let root = tmp(tag);
        ou_core::safety::write_marker(&root, "acc").unwrap();
        root
    }

    #[test]
    fn unhealthy_never_runs() {
        let root = ready_root("health");
        let (m, l, r) = world(5);
        for h in [Health::AuthFailed, Health::Offline, Health::ServerError("502".into())] {
            assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &h, Some(&m), Some(&l), Some(&r)), Decision::Skip(_)), "{h:?}");
        }
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &Health::SpaceGone, Some(&m), Some(&l), Some(&r)), Decision::Hold { .. }));
    }

    #[test]
    fn missing_or_foreign_root_never_runs() {
        let (m, l, r) = world(5);
        let gone = std::env::temp_dir().join("ou-files-guard-does-not-exist");
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &gone, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Skip(_)));
        let other = tmp("other");
        ou_core::safety::write_marker(&other, "someone-else").unwrap();
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &other, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Skip(_)));
        // Emptied root (marker gone, e.g. folder replaced) with a non-empty manifest: hold, do not "restore by deleting".
        let empty = tmp("empty");
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &empty, &Health::Ok, Some(&m), None, None), Decision::Hold { .. }));
        // Non-empty unmarked folder: explicit merge choice.
        std::fs::write(empty.join("x"), b"1").unwrap();
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &empty, &Health::Ok, None, None, None), Decision::Hold { .. }));
    }

    #[test]
    fn first_run_and_normal_changes_run() {
        let root = ready_root("normal");
        assert_eq!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, None, None, None), Decision::Run);
        let (m, mut l, mut r) = world(100);
        l.entries.retain(|e| e.rel != "f0001.txt"); // one local delete
        r.entries.remove("f0002.txt"); // one remote delete
        r.entries.get_mut("f0003.txt").unwrap().etag = Some("new".into());
        assert_eq!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Run);
    }

    #[test]
    fn mass_local_delete_holds() {
        let root = ready_root("massl");
        let (m, mut l, r) = world(100);
        l.entries.truncate(50); // half the folder vanished locally
        match preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)) {
            Decision::Hold { plan, .. } => assert_eq!(plan.local_deletes.len(), 50),
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn everything_gone_remotely_holds_even_when_small() {
        let root = ready_root("allr");
        let (m, l, mut r) = world(3);
        r.entries.clear(); // e.g. a server returning an empty but "successful" listing
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Hold { .. }));
    }

    #[test]
    fn incomplete_listing_never_deletes() {
        let root = ready_root("incomplete");
        let (m, l, mut r) = world(100);
        r.entries.remove("f0000.txt");
        r.complete = false;
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Hold { .. }));
        let (m, mut l, r) = world(100);
        l.entries.remove(0);
        l.complete = false;
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Hold { .. }));
    }

    #[test]
    fn mass_overwrite_holds() {
        let root = ready_root("massw");
        let (m, mut l, r) = world(100);
        for e in l.entries.iter_mut().take(60) {
            e.size = 4096; // e.g. ransomware rewrote 60 % of the files
        }
        match preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)) {
            Decision::Hold { plan, reason, .. } => {
                assert_eq!(plan.local_modified.len(), 60);
                assert!(reason.contains("overwritten"));
            }
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn approval_is_bound_to_the_exact_plan() {
        let root = ready_root("approve");
        let (mut m, mut l, r) = world(100);
        l.entries.truncate(40);
        let Decision::Hold { plan_id, .. } = preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)) else {
            panic!()
        };
        m.approved_plan = Some(plan_id);
        assert_eq!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Run);
        l.entries.truncate(30); // more vanished after approval: a new plan, hold again
        assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &Health::Ok, Some(&m), Some(&l), Some(&r)), Decision::Hold { .. }));
    }

    #[test]
    fn deleted_on_both_sides_is_not_pending() {
        let (m, mut l, mut r) = world(10);
        l.entries.retain(|e| e.rel != "f0001.txt");
        r.entries.remove("f0001.txt");
        let p = compute_plan(&m, &l, &r);
        assert!(p.local_deletes.is_empty() && p.remote_deletes.is_empty());
    }

    #[test]
    fn manifest_roundtrip_atomic() {
        let dir = tmp("manifest");
        let (m, _, _) = world(3);
        m.save(&dir).unwrap();
        assert_eq!(Manifest::load(&dir).unwrap().unwrap(), m);
        assert!(!dir.join(format!("{MANIFEST}.tmp")).exists());
        assert_eq!(Manifest::load(&tmp("nomanifest")).unwrap(), None);
    }

    #[test]
    fn conflict_names_match_opencloud() {
        // 2026-11-25 10:11:12 UTC
        let t = 1_795_601_472;
        assert_eq!(conflict_name("report.docx", t, None), "report (conflicted copy 2026-11-25 101112).docx");
        assert_eq!(conflict_name("archive.tar.gz", t, Some("Doc (Test)")), "archive.tar (conflicted copy Doc _Test_ 2026-11-25 101112).gz");
        assert_eq!(conflict_name(".hidden", t, None), ".hidden (conflicted copy 2026-11-25 101112)");
        assert_eq!(conflict_name("Makefile", 0, None), "Makefile (conflicted copy 1970-01-01 000000)");
        assert!(is_conflict_name(&conflict_name("a.txt", t, None)));
        assert!(!is_conflict_name("a.txt"));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil(-1), (1969, 12, 31, 23, 59, 59));
    }
}
