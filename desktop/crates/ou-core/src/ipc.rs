//! GUI <-> agent protocol: newline-delimited JSON over a per-user local endpoint (Windows named pipe with an owner-only DACL,
//! remote clients rejected; Unix socket 0600 in development). A closed set of typed requests; no generic "run"/"exec"/"fetch".
//! Tokens never cross this boundary: the GUI receives status, never secrets.

use serde::{Deserialize, Serialize};

use crate::discovery::Deployment;

pub const MAX_LINE: usize = 64 * 1024;
pub const PROTOCOL: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Portal,
    Files,
    Chat,
    Mail,
    Calendar,
    Contacts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Hello { protocol: u32, client: String },
    Status {},
    Discover { input: String },
    SignIn { discovery_id: String },
    SignOut { account_id: String },
    RemoveAccount { account_id: String },
    OpenService { account_id: String, service: Service },
    OpenExternal { account_id: String, url: String },
    SetPaused { paused: bool },
    /// Exits the agent (tray "Quit Office Unbound"); closing the window does not send this.
    Shutdown {},
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    SignedIn,
    SigningIn,
    /// Refresh token missing, expired or revoked: the user must sign in again. Sync is paused, nothing is deleted.
    SignedOut,
    /// Server unreachable; retrying with backoff.
    Offline,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountStatus {
    pub id: String,
    pub label: String,
    pub deployment: String,
    pub domain: String,
    pub state: SessionState,
    pub detail: Option<String>,
    pub services: Vec<Service>,
    pub files_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Hello { protocol: u32, agent: String },
    Status { accounts: Vec<AccountStatus>, paused: bool, agent: String },
    Discovered { discovery_id: String, deployment: Deployment },
    SignInStarted,
    SignedIn { account: AccountStatus },
    Ok,
    Error { message: String },
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum IpcError {
    #[error("message too large")]
    TooLarge,
    #[error("invalid message")]
    Invalid,
}

pub fn decode_request(line: &str) -> Result<Request, IpcError> {
    if line.len() > MAX_LINE {
        return Err(IpcError::TooLarge);
    }
    serde_json::from_str(line).map_err(|_| IpcError::Invalid)
}

pub fn decode_line<T: serde::de::DeserializeOwned>(line: &str) -> Result<T, IpcError> {
    if line.len() > MAX_LINE {
        return Err(IpcError::TooLarge);
    }
    serde_json::from_str(line).map_err(|_| IpcError::Invalid)
}

pub fn encode<T: Serialize>(m: &T) -> String {
    let mut s = serde_json::to_string(m).expect("serialisable");
    s.push('\n');
    s
}

/// Validates ids received over IPC before they are used as map keys or path components.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_request_set() {
        assert_eq!(decode_request(r#"{"type":"status"}"#).unwrap(), Request::Status {});
        assert_eq!(decode_request(r#"{"type":"exec","cmd":"calc.exe"}"#), Err(IpcError::Invalid));
        assert_eq!(decode_request(r#"{"type":"status","extra":1}"#), Err(IpcError::Invalid), "unknown fields refused");
        assert_eq!(decode_request(&"x".repeat(MAX_LINE + 1)), Err(IpcError::TooLarge));
        let r = Request::OpenService { account_id: "ab12".into(), service: Service::Chat };
        assert_eq!(decode_request(encode(&r).trim_end()).unwrap(), r);
    }

    #[test]
    fn ids() {
        assert!(valid_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_id("../../etc"));
        assert!(!valid_id(""));
    }
}
