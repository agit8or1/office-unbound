//! Agent log: `<root>/logs/agent.log`, every line passed through `redact`, rotated at 1 MiB (one old file kept).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static LOG: Mutex<Option<PathBuf>> = Mutex::new(None);
const MAX: u64 = 1024 * 1024;

pub fn init(root: &std::path::Path) {
    let dir = root.join("logs");
    let _ = std::fs::create_dir_all(&dir);
    *LOG.lock().unwrap() = Some(dir.join("agent.log"));
}

pub fn line(level: &str, msg: &str) {
    let clean = ou_core::redact::redact(msg).replace(['\r', '\n'], " ");
    let text = format!("{} {level} {clean}\n", ou_core::oidc::now());
    let guard = LOG.lock().unwrap();
    let Some(p) = guard.as_ref() else {
        eprint!("{text}");
        return;
    };
    if std::fs::metadata(p).map(|m| m.len() > MAX).unwrap_or(false) {
        let _ = std::fs::rename(p, p.with_extension("log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
        let _ = f.write_all(text.as_bytes());
    }
}

#[macro_export]
macro_rules! info { ($($t:tt)*) => { $crate::log::line("INFO", &format!($($t)*)) } }
#[macro_export]
macro_rules! warn { ($($t:tt)*) => { $crate::log::line("WARN", &format!($($t)*)) } }
