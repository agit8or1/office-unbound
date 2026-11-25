//! Office Unbound Desktop background agent: a per-user process that owns accounts, tokens and (later) sync/chat background work.
//! It runs without the GUI; the GUI and the `--status` CLI are clients of its local endpoint (ADR-0022 section 3).

pub mod browser;
#[cfg(feature = "chat")]
pub mod chat;
pub mod client;
pub mod endpoint;
pub mod events;
pub mod log;
pub mod server;
pub mod state;
