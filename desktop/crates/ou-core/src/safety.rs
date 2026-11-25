//! Data-safety rules applied before any sync run or bulk change (ADR-0022 section 7). The principle: an *absence* (missing folder,
//! empty listing, failed request, expired token) is never evidence that the user deleted something.

use std::collections::HashMap;
use std::path::Path;

pub const MARKER: &str = ".ou-sync-root";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootState {
    /// Marker present and names this account: safe to sync.
    Ready,
    /// Folder empty and no marker: a new sync root; the agent writes the marker before the first run.
    New,
    /// The folder does not exist (unplugged disk, renamed folder, unmounted volume): never sync, never "restore by deleting".
    Missing,
    /// Marker of another account: two accounts must not share one folder.
    OtherAccount,
    /// Non-empty folder without marker: needs the user's explicit choice (merge), never silent.
    Unmarked,
}

pub fn check_root(root: &Path, account_id: &str) -> RootState {
    let Ok(meta) = std::fs::symlink_metadata(root) else { return RootState::Missing };
    if !meta.is_dir() {
        return RootState::Missing;
    }
    match std::fs::read_to_string(root.join(MARKER)) {
        Ok(s) if s.trim() == account_id => RootState::Ready,
        Ok(_) => RootState::OtherAccount,
        Err(_) => {
            let empty = std::fs::read_dir(root).map(|mut d| d.next().is_none()).unwrap_or(false);
            if empty {
                RootState::New
            } else {
                RootState::Unmarked
            }
        }
    }
}

pub fn write_marker(root: &Path, account_id: &str) -> std::io::Result<()> {
    std::fs::write(root.join(MARKER), format!("{account_id}\n"))
}

/// Sync loops: a sync root must not be inside another account's root, a mapped drive, or vice versa.
pub fn roots_overlap(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().replace('\\', "/").trim_end_matches('/').to_ascii_lowercase() + "/";
    let (x, y) = (norm(a), norm(b));
    x.starts_with(&y) || y.starts_with(&x)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeletePolicy {
    /// Hold when more than this many items would be deleted in one run...
    pub max_items: usize,
    /// ...or when this fraction of the known items would be deleted (with at least `min_items_for_ratio` known).
    pub max_fraction: f64,
    pub min_items_for_ratio: usize,
}

impl Default for DeletePolicy {
    fn default() -> Self {
        Self { max_items: 200, max_fraction: 0.3, min_items_for_ratio: 20 }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Proceed,
    /// Paused; the user must confirm in the app (with the list), or restore. Nothing was deleted.
    Hold(String),
}

/// Evaluates a planned run. `known` = items in the sync journal; deletes in either direction count.
pub fn check_deletes(policy: &DeletePolicy, known: usize, local_deletes: usize, remote_deletes: usize, remote_listing_ok: bool) -> Verdict {
    let total = local_deletes + remote_deletes;
    if total == 0 {
        return Verdict::Proceed;
    }
    if !remote_listing_ok {
        return Verdict::Hold("the server listing was incomplete; deletions are postponed".into());
    }
    if known > 0 && total >= known {
        return Verdict::Hold(format!("all {known} synced items would be deleted"));
    }
    if total > policy.max_items {
        return Verdict::Hold(format!("{total} items would be deleted (limit {})", policy.max_items));
    }
    if known >= policy.min_items_for_ratio && (total as f64) / (known as f64) > policy.max_fraction {
        return Verdict::Hold(format!("{total} of {known} items would be deleted"));
    }
    Verdict::Proceed
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Why a remote name cannot be created as-is on NTFS/Windows (the engine then skips it and reports it; never renames silently).
pub fn windows_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("empty name");
    }
    if name.chars().any(|c| matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (c as u32) < 32) {
        return Some("contains a character Windows does not allow");
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return Some("ends with a space or dot");
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return Some("reserved device name on Windows");
    }
    if name.encode_utf16().count() > 255 {
        return Some("name longer than 255 characters");
    }
    None
}

/// Groups of names in one folder that collide on case-insensitive Windows filesystems ("Report.docx" vs "report.DOCX").
pub fn case_collisions<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for n in names {
        m.entry(n.to_lowercase()).or_default().push(n.to_string());
    }
    let mut v: Vec<Vec<String>> = m.into_values().filter(|g| g.len() > 1).collect();
    v.iter_mut().for_each(|g| g.sort());
    v.sort();
    v
}

/// Full path length check: classic MAX_PATH is 260; the engine must use `\\?\` paths or skip with a report beyond it.
pub fn exceeds_max_path(root: &Path, relative: &str) -> bool {
    root.to_string_lossy().encode_utf16().count() + 1 + relative.encode_utf16().count() >= 260
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_states() {
        let base = std::env::temp_dir().join(format!("ou-safety-{}", crate::accounts::new_account_id()));
        assert_eq!(check_root(&base, "acc1"), RootState::Missing);
        std::fs::create_dir_all(&base).unwrap();
        assert_eq!(check_root(&base, "acc1"), RootState::New);
        std::fs::write(base.join("file.txt"), b"x").unwrap();
        assert_eq!(check_root(&base, "acc1"), RootState::Unmarked);
        write_marker(&base, "acc1").unwrap();
        assert_eq!(check_root(&base, "acc1"), RootState::Ready);
        assert_eq!(check_root(&base, "acc2"), RootState::OtherAccount);
        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(check_root(&base, "acc1"), RootState::Missing, "vanished root is Missing, not 'everything deleted'");
    }

    #[test]
    fn delete_guard() {
        let p = DeletePolicy::default();
        assert_eq!(check_deletes(&p, 1000, 3, 2, true), Verdict::Proceed);
        assert!(matches!(check_deletes(&p, 1000, 0, 5, false), Verdict::Hold(_)), "incomplete listing");
        assert!(matches!(check_deletes(&p, 10, 10, 0, true), Verdict::Hold(_)), "everything");
        assert!(matches!(check_deletes(&p, 5000, 201, 0, true), Verdict::Hold(_)), "absolute");
        assert!(matches!(check_deletes(&p, 100, 0, 31, true), Verdict::Hold(_)), "fraction");
        assert_eq!(check_deletes(&p, 10, 5, 0, true), Verdict::Proceed, "small folders: ratio not applied below 20 items");
        assert_eq!(check_deletes(&p, 0, 0, 0, false), Verdict::Proceed);
    }

    #[test]
    fn windows_names() {
        assert_eq!(windows_name_problem("report.docx"), None);
        assert!(windows_name_problem("a:b").is_some());
        assert!(windows_name_problem("CON").is_some());
        assert!(windows_name_problem("con.txt").is_some());
        assert!(windows_name_problem("Lpt9.tar.gz").is_some());
        assert_eq!(windows_name_problem("CONSOLE.txt"), None);
        assert!(windows_name_problem("trailing.").is_some());
        assert!(windows_name_problem("trailing ").is_some());
        assert!(windows_name_problem(&"x".repeat(256)).is_some());
        assert!(windows_name_problem("tab\there").is_some());
    }

    #[test]
    fn collisions_and_paths() {
        let c = case_collisions(["Report.docx", "report.DOCX", "other.txt", "Ä.txt", "ä.txt"]);
        assert_eq!(c.len(), 2);
        assert!(exceeds_max_path(Path::new("C:\\Users\\u\\Office Unbound"), &"d/".repeat(120)));
        assert!(!exceeds_max_path(Path::new("C:\\Users\\u\\Office Unbound"), "Documents/a.docx"));
        assert!(roots_overlap(Path::new("C:\\Users\\u\\OU"), Path::new("c:/users/u/ou/sub")));
        assert!(!roots_overlap(Path::new("C:\\Users\\u\\OU"), Path::new("C:\\Users\\u\\OU2")));
    }
}
