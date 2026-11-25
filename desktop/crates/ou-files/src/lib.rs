//! Office Unbound Desktop — files.
//!
//! - [`webdav`]: OpenCloud client (Graph spaces, WebDAV, TUS, ETags, checksums, trash bin).
//! - [`guard`]: data-safety pre-flight in front of every sync run (mass delete/overwrite hold, never delete on failure).
//! - [`paths`]: Windows path and filename rules, link/junction classification, loop-free local scan.
//! - [`engine`]: driver for the OpenCloud sync engine (`opencloudcmd`) as a supervised child process.
//! - [`mapped`]: rclone + WinFsp mapped drive (config, letter choice, loop checks, pending-write reporting).
//!
//! Decision record: docs/desktop/files-decision.md.

pub mod engine;
pub mod guard;
pub mod mapped;
pub mod paths;
pub mod webdav;
