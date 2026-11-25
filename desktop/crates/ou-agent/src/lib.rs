//! Office Unbound Desktop background agent: a per-user process that owns accounts, tokens and (later) sync/chat background work.
//! It runs without the GUI; the GUI and the `--status` CLI are clients of its local endpoint (ADR-0022 section 3).

pub mod browser;
pub mod client;
pub mod endpoint;
pub mod log;
pub mod server;
pub mod state;
