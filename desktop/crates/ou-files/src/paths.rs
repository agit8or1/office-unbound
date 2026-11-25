//! Windows path and filename rules for the sync folder and the mapped drive.
//!
//! Applied to every *remote* name before it is materialised locally and to every *local* entry before it is uploaded. A name that
//! breaks a rule is skipped and reported to the user; it is never renamed silently and never treated as deleted.
//! Rules are pure functions (testable on any OS); only [`classify_local`] touches the filesystem.

use std::collections::BTreeMap;
use std::path::Path;

use unicode_normalization::UnicodeNormalization;

/// Classic Win32 limit: MAX_PATH = 260 UTF-16 units including the terminating NUL.
pub const MAX_PATH: usize = 260;
/// CreateDirectoryW without `\\?\`: MAX_PATH minus room for an 8.3 file name (12).
pub const MAX_DIR_PATH: usize = MAX_PATH - 12;
/// Extended-length paths (`\\?\` prefix or LongPathsEnabled + manifest): 32,767 UTF-16 units.
pub const MAX_LONG_PATH: usize = 32_767;
/// NTFS component limit (UTF-16 units).
pub const MAX_COMPONENT: usize = 255;

/// Device names Windows reserves in every directory, with or without an extension ("CON.txt" is also reserved).
/// Windows 10+ also reserves COM/LPT with superscript digits 1-3 (U+00B9, U+00B2, U+00B3).
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM\u{b9}", "COM\u{b2}", "COM\u{b3}", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    "LPT\u{b9}", "LPT\u{b2}", "LPT\u{b3}",
];

/// Names the sync layer owns locally; a remote item with such a name would clobber engine or guard state.
const LOCAL_CONTROL: &[&str] = &[".ou-sync-root", ".ou-files-manifest.json", "desktop.ini", "$recycle.bin", "system volume information"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameProblem {
    Empty,
    /// `<>:"/\|?*` or a control character (U+0000..U+001F).
    InvalidChar(char),
    TrailingDotOrSpace,
    Reserved(String),
    TooLong(usize),
    /// Collides with a file the sync engine or this guard keeps in the folder.
    ControlFile,
    /// `.sync_*.db` journals of the OpenCloud engine and its `-wal`/`-shm` companions.
    EngineJournal,
}

impl std::fmt::Display for NameProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty name"),
            Self::InvalidChar(c) => write!(f, "contains the character {c:?}, which Windows does not allow"),
            Self::TrailingDotOrSpace => write!(f, "ends with a dot or space, which Windows removes"),
            Self::Reserved(n) => write!(f, "{n} is a reserved device name on Windows"),
            Self::TooLong(n) => write!(f, "name is {n} characters long (Windows allows {MAX_COMPONENT})"),
            Self::ControlFile => write!(f, "name is used by the sync folder itself"),
            Self::EngineJournal => write!(f, "name is used by the sync engine's journal"),
        }
    }
}

/// Checks one path component (file or folder name).
pub fn name_problem(name: &str) -> Option<NameProblem> {
    if name.is_empty() || name == "." || name == ".." {
        return Some(NameProblem::Empty);
    }
    if let Some(c) = name.chars().find(|&c| matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (c as u32) < 32) {
        return Some(NameProblem::InvalidChar(c));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some(NameProblem::TrailingDotOrSpace);
    }
    // Windows strips trailing spaces of the stem and ignores everything after the first dot for device names: "nul .txt", "Com1.tar.gz".
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_uppercase();
    if RESERVED.contains(&upper.as_str()) {
        return Some(NameProblem::Reserved(stem.to_string()));
    }
    let units = name.encode_utf16().count();
    if units > MAX_COMPONENT {
        return Some(NameProblem::TooLong(units));
    }
    let lower = name.to_lowercase();
    if LOCAL_CONTROL.contains(&lower.as_str()) {
        return Some(NameProblem::ControlFile);
    }
    if lower.starts_with(".sync_") && (lower.ends_with(".db") || lower.ends_with(".db-wal") || lower.ends_with(".db-shm")) {
        return Some(NameProblem::EngineJournal);
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathProblem {
    Name { component: String, problem: NameProblem },
    /// Full local path length in UTF-16 units and the limit that applies.
    TooLong { units: usize, limit: usize },
    /// `..` or an absolute component in a server-supplied relative path: refused (path traversal).
    Traversal,
}

impl std::fmt::Display for PathProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name { component, problem } => write!(f, "\"{component}\": {problem}"),
            Self::TooLong { units, limit } => write!(f, "path is {units} characters long (limit {limit})"),
            Self::Traversal => write!(f, "path leaves the sync folder"),
        }
    }
}

/// Whether the engine can use extended-length paths. OpenCloud's engine prefixes `\\?\` itself (filesystembase.cpp), so the sync
/// folder can go beyond MAX_PATH; Explorer and many applications still cannot open such files, which is why the UI warns at 260.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathLimits {
    pub long_paths: bool,
}

impl PathLimits {
    pub fn limit(&self, kind: Kind) -> usize {
        match (self.long_paths, kind) {
            (true, _) => MAX_LONG_PATH - 4, // room for the `\\?\` prefix
            (false, Kind::Dir) => MAX_DIR_PATH - 1,
            (false, Kind::File) => MAX_PATH - 1, // NUL terminator
        }
    }
}

/// Validates a server-relative path (`/`-separated) for materialisation under the Windows folder `root` (e.g. `C:\Users\a\Office Unbound`).
pub fn check_relative(root: &str, rel: &str, kind: Kind, limits: PathLimits) -> Result<(), PathProblem> {
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        if comp == ".." || comp == "." {
            return Err(PathProblem::Traversal);
        }
        if let Some(problem) = name_problem(comp) {
            return Err(PathProblem::Name { component: comp.to_string(), problem });
        }
    }
    let root = root.trim_end_matches(['\\', '/']);
    let rel = rel.trim_matches('/');
    let units = root.encode_utf16().count() + 1 + rel.encode_utf16().count();
    let limit = limits.limit(kind);
    if units > limit {
        return Err(PathProblem::TooLong { units, limit });
    }
    Ok(())
}

/// The key NTFS (case-insensitive, case-preserving) and cross-platform clients effectively compare by: NFC + lower case.
/// "Report.docx" / "report.DOCX" and "Cafe\u{301}" (NFD, from macOS) / "Café" (NFC) collide.
pub fn fold_key(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

/// Groups of sibling names that would land on the same NTFS entry. Every member of a group is skipped and reported, none is
/// chosen arbitrarily (choosing one would silently hide the others' data).
pub fn collisions<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in names {
        m.entry(fold_key(n)).or_default().push(n.to_string());
    }
    m.into_values()
        .filter(|g| g.len() > 1)
        .map(|mut g| {
            g.sort();
            g
        })
        .collect()
}

/// What a local directory entry is, without following it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalKind {
    File,
    Dir,
    Symlink,
    /// NTFS junction or volume mount point (IO_REPARSE_TAG_MOUNT_POINT): followed, it can loop or escape the sync root.
    Junction,
    /// Cloud Files placeholder (IO_REPARSE_TAG_CLOUD*): normal content of a Files On-Demand root, not a link.
    CloudPlaceholder,
    /// Any other reparse point (dedup, WSL, OneDrive of another provider...): skipped.
    OtherReparse(u32),
}

impl LocalKind {
    /// Only plain files, directories and our own placeholders are synced. Links are reported and never followed (no loops).
    pub fn syncable(self) -> bool {
        matches!(self, Self::File | Self::Dir | Self::CloudPlaceholder)
    }
}

pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub const IO_REPARSE_TAG_CLOUD: u32 = 0x9000_001A;
const IO_REPARSE_TAG_CLOUD_MASK: u32 = 0x0000_F000;

/// Maps a reparse tag (Windows) to the kind. Pure so it is tested everywhere.
pub fn kind_from_reparse_tag(tag: u32, is_dir: bool) -> LocalKind {
    match tag {
        IO_REPARSE_TAG_SYMLINK => LocalKind::Symlink,
        IO_REPARSE_TAG_MOUNT_POINT => LocalKind::Junction,
        t if t & !IO_REPARSE_TAG_CLOUD_MASK == IO_REPARSE_TAG_CLOUD => {
            let _ = is_dir;
            LocalKind::CloudPlaceholder
        }
        t => LocalKind::OtherReparse(t),
    }
}

/// Classifies `path` without following links.
pub fn classify_local(path: &Path) -> std::io::Result<LocalKind> {
    let meta = std::fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            let tag = win::reparse_tag(path)?;
            return Ok(kind_from_reparse_tag(tag, meta.is_dir()));
        }
    }
    let ft = meta.file_type();
    Ok(if ft.is_symlink() {
        LocalKind::Symlink
    } else if ft.is_dir() {
        LocalKind::Dir
    } else {
        LocalKind::File
    })
}

#[cfg(windows)]
mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};

    /// FindFirstFileW reports the reparse tag in dwReserved0 without opening the file (no hydration of placeholders).
    pub fn reparse_tag(path: &Path) -> std::io::Result<u32> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `data` is a plain out-struct; the handle is closed below.
        unsafe {
            let mut data: WIN32_FIND_DATAW = std::mem::zeroed();
            let h = FindFirstFileW(wide.as_ptr(), &mut data);
            if h == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            FindClose(h);
            Ok(data.dwReserved0)
        }
    }
}

/// One entry of a local scan, path relative to the root with `/` separators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    pub rel: String,
    pub kind: LocalKind,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Debug, Default)]
pub struct LocalScan {
    pub entries: Vec<LocalEntry>,
    /// Entries skipped with the reason (links, junctions, unreadable folders). Not syncable, not deleted.
    pub skipped: Vec<(String, String)>,
    /// False if any directory could not be read: such a scan must never be used as evidence of deletion.
    pub complete: bool,
}

/// Walks `root` without following links or junctions, so filesystem loops cannot occur. Control files are left out.
pub fn scan_local(root: &Path) -> LocalScan {
    let mut out = LocalScan { complete: true, ..Default::default() };
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                out.complete = false;
                out.skipped.push((prefix.clone(), format!("cannot read folder: {e}")));
                continue;
            }
        };
        for ent in rd {
            let Ok(ent) = ent else {
                out.complete = false;
                continue;
            };
            let name = ent.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if matches!(name_problem(&name), Some(NameProblem::ControlFile | NameProblem::EngineJournal)) {
                continue;
            }
            let path = ent.path();
            let kind = match classify_local(&path) {
                Ok(k) => k,
                Err(e) => {
                    out.complete = false;
                    out.skipped.push((rel, format!("cannot inspect: {e}")));
                    continue;
                }
            };
            if !kind.syncable() {
                out.skipped.push((rel, format!("{kind:?} is not followed")));
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).ok();
            let size = meta.as_ref().map(|m| if m.is_dir() { 0 } else { m.len() }).unwrap_or(0);
            let mtime = meta
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if kind == LocalKind::Dir {
                stack.push((path, rel.clone()));
            }
            out.entries.push(LocalEntry { rel, kind, size, mtime });
        }
    }
    out.entries.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_characters_and_controls() {
        for c in ['<', '>', ':', '"', '\\', '|', '?', '*', '\u{1}', '\u{1f}'] {
            assert_eq!(name_problem(&format!("a{c}b")), Some(NameProblem::InvalidChar(c)), "{c:?}");
        }
        assert_eq!(name_problem("a/b"), Some(NameProblem::InvalidChar('/')));
        assert_eq!(name_problem("normal name (1).docx"), None);
        assert_eq!(name_problem("emoji \u{1F600}.txt"), None);
    }

    #[test]
    fn trailing_dot_space_and_empty() {
        assert_eq!(name_problem("report."), Some(NameProblem::TrailingDotOrSpace));
        assert_eq!(name_problem("report "), Some(NameProblem::TrailingDotOrSpace));
        assert_eq!(name_problem(""), Some(NameProblem::Empty));
        assert_eq!(name_problem(".."), Some(NameProblem::Empty));
        assert_eq!(name_problem(".hidden"), None, "leading dot is fine");
    }

    #[test]
    fn reserved_device_names() {
        for n in ["CON", "con", "Con.txt", "nul .txt", "COM1.tar.gz", "lpt9", "CONIN$", "conout$", "CLOCK$", "COM\u{b9}", "lpt\u{b3}.log", "COM0"]
        {
            assert!(matches!(name_problem(n), Some(NameProblem::Reserved(_))), "{n}");
        }
        for n in ["CONSOLE", "COM10", "LPT", "auxiliary.txt", "xCON"] {
            assert_eq!(name_problem(n), None, "{n}");
        }
    }

    #[test]
    fn component_length() {
        assert_eq!(name_problem(&"a".repeat(255)), None);
        assert_eq!(name_problem(&"a".repeat(256)), Some(NameProblem::TooLong(256)));
        // UTF-16 units, not bytes: 128 emoji = 256 units.
        assert_eq!(name_problem(&"\u{1F600}".repeat(128)), Some(NameProblem::TooLong(256)));
    }

    #[test]
    fn control_files_are_never_materialised() {
        assert_eq!(name_problem(".ou-sync-root"), Some(NameProblem::ControlFile));
        assert_eq!(name_problem("Desktop.ini"), Some(NameProblem::ControlFile));
        assert_eq!(name_problem(".sync_ab12.db"), Some(NameProblem::EngineJournal));
        assert_eq!(name_problem(".sync_.db-wal"), Some(NameProblem::EngineJournal));
        assert_eq!(name_problem(".sync_notes.txt"), None);
    }

    #[test]
    fn path_limits() {
        let root = r"C:\Users\alice\Office Unbound"; // 29 units
        let short = PathLimits { long_paths: false };
        let long = PathLimits { long_paths: true };
        let ok = "a".repeat(259 - 30);
        assert_eq!(check_relative(root, &ok, Kind::File, short), Ok(()));
        let too = "a".repeat(260 - 30);
        assert_eq!(check_relative(root, &too, Kind::File, short), Err(PathProblem::TooLong { units: 260, limit: 259 }));
        // Directories need room for an 8.3 child: limit 247.
        let dir = format!("{}/{}", "d".repeat(200), "e".repeat(30));
        assert!(matches!(check_relative(root, &dir, Kind::Dir, short), Err(PathProblem::TooLong { limit: 247, .. })));
        assert_eq!(check_relative(root, &dir, Kind::Dir, long), Ok(()));
        let huge = vec!["x".repeat(200); 170].join("/");
        assert!(matches!(check_relative(root, &huge, Kind::File, long), Err(PathProblem::TooLong { limit: 32763, .. })));
    }

    #[test]
    fn traversal_and_bad_components_in_paths() {
        let l = PathLimits { long_paths: true };
        assert_eq!(check_relative(r"C:\s", "a/../../Windows", Kind::File, l), Err(PathProblem::Traversal));
        assert!(matches!(check_relative(r"C:\s", "ok/AUX/file", Kind::File, l), Err(PathProblem::Name { .. })));
        assert!(matches!(check_relative(r"C:\s", "ok/dir./file", Kind::File, l), Err(PathProblem::Name { .. })));
        assert_eq!(check_relative(r"C:\s\", "/ok/fine.txt", Kind::File, l), Ok(()));
    }

    #[test]
    fn case_and_unicode_collisions() {
        let g = collisions(["Report.docx", "report.DOCX", "other.txt", "Caf\u{e9}", "Cafe\u{301}", "\u{130}"]);
        assert_eq!(g.len(), 2);
        assert!(g.contains(&vec!["Report.docx".to_string(), "report.DOCX".to_string()]));
        assert!(g.iter().any(|x| x.len() == 2 && x.iter().all(|n| n.starts_with("Caf"))));
        assert!(collisions(["a", "b", "c"]).is_empty());
    }

    #[test]
    fn reparse_tags() {
        assert_eq!(kind_from_reparse_tag(IO_REPARSE_TAG_SYMLINK, false), LocalKind::Symlink);
        assert_eq!(kind_from_reparse_tag(IO_REPARSE_TAG_MOUNT_POINT, true), LocalKind::Junction);
        assert_eq!(kind_from_reparse_tag(0x9000_001A, false), LocalKind::CloudPlaceholder);
        assert_eq!(kind_from_reparse_tag(0x9000_301A, true), LocalKind::CloudPlaceholder, "IO_REPARSE_TAG_CLOUD_3");
        assert_eq!(kind_from_reparse_tag(0x8000_0013, false), LocalKind::OtherReparse(0x8000_0013), "dedup");
        assert!(!LocalKind::Junction.syncable() && !LocalKind::Symlink.syncable() && LocalKind::CloudPlaceholder.syncable());
    }

    #[cfg(unix)]
    #[test]
    fn scan_never_follows_links_so_loops_cannot_happen() {
        let base = std::env::temp_dir().join(format!("ou-files-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        std::fs::write(base.join("a/b/f.txt"), b"hello").unwrap();
        std::fs::write(base.join(".ou-sync-root"), b"acc").unwrap();
        std::os::unix::fs::symlink(&base, base.join("a/b/loop")).unwrap(); // a loop back to the root
        std::os::unix::fs::symlink("/etc", base.join("escape")).unwrap();
        let s = scan_local(&base);
        assert!(s.complete);
        let rels: Vec<_> = s.entries.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(rels, ["a", "a/b", "a/b/f.txt"]);
        assert_eq!(s.entries[2].size, 5);
        assert_eq!(s.skipped.len(), 2);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
