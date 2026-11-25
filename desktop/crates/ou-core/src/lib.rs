//! Office Unbound Desktop core: the platform-neutral code shared by the background agent and the GUI.
//!
//! Nothing here talks to Windows directly except `secrets::wincred` (cfg(windows)). Protocol code (discovery, OIDC, WebDAV,
//! Matrix later) stays here so the future macOS/Linux/mobile clients can reuse it (ADR-0022, Phase 7).

pub mod accounts;
pub mod discovery;
pub mod http;
pub mod ipc;
pub mod oidc;
pub mod redact;
pub mod safety;
pub mod secrets;
pub mod urlpolicy;

/// Product version reported to the agent/GUI and in diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
