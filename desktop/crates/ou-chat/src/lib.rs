//! Office Unbound Desktop chat: a native Matrix client on matrix-rust-sdk (Apache-2.0) for the deployment's Synapse + MAS.
//!
//! Decision and rationale: `docs/desktop/chat-architecture.md`. In short: the Rust SDK gives Element's own crypto (vodozemac,
//! key backup, recovery, cross-signing) in-process, sign-in through MAS in the system browser (same Keycloak SSO session as the
//! rest of the app), background sync and notifications in the agent, and no second web app inside the shell.
//!
//! Module map: [`auth`] sign-in and token storage, [`rooms`] room list and unread counts, [`messages`] timeline and sending,
//! [`media`] attachments, [`notify`] desktop-notification hook, [`search`] server-side search, [`meet`] meeting links,
//! [`crypto`] key backup / recovery status.
//!
//! Chat is independent of file sync: nothing here depends on `ou-files`, and it runs with its own MAS session.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use matrix_sdk::config::SyncSettings;
use matrix_sdk::{AuthSession, Client};
use ou_core::secrets::SecretStore;
use url::Url;

pub mod auth;
pub mod crypto;
pub mod media;
pub mod meet;
pub mod messages;
pub mod notify;
pub mod rooms;
pub mod search;

pub use auth::ChatAccount;
pub use matrix_sdk;

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("chat configuration: {0}")]
    Config(String),
    #[error("chat sign-in failed: {0}")]
    Login(String),
    #[error("signed out of chat: sign in again")]
    SignedOut,
    #[error("credential store: {0}")]
    Store(String),
    #[error("room not found")]
    NoSuchRoom,
    #[error("file is larger than the server allows ({limit} bytes)")]
    TooLarge { limit: u64 },
    #[error("not allowed: {0}")]
    Refused(String),
    #[error("chat server: {0}")]
    Matrix(String),
}

pub(crate) fn mx(e: impl std::fmt::Display) -> ChatError {
    ChatError::Matrix(ou_core::redact::redact(&e.to_string()))
}

/// One signed-in chat account.
pub struct ChatClient {
    client: Client,
    account: ChatAccount,
    store: Arc<dyn SecretStore>,
    store_name: String,
}

impl ChatClient {
    /// Restores the saved session for `account`, if any. Returns `Ok(None)` when the user must sign in.
    pub async fn restore(account: ChatAccount, http: matrix_sdk::reqwest::Client, store: Arc<dyn SecretStore>) -> Result<Option<Self>, ChatError> {
        let s = auth::secrets(store.as_ref(), &account)?;
        let Some(saved) = auth::load_session(&s)? else { return Ok(None) };
        let pass = auth::store_passphrase(&s)?;
        let dir = auth::store_dir(&account.data_dir, &saved.store)?;
        let client = auth::build_client(&account, http, &dir, &pass).await?;
        client.restore_session(AuthSession::OAuth(Box::new(saved.session.clone()))).await.map_err(mx)?;
        let store_name = saved.store;
        drop(s);
        Ok(Some(Self { client, account, store, store_name }))
    }

    /// Interactive sign-in through MAS in the system browser. Each sign-in is a new Matrix device with a fresh encrypted store.
    pub async fn sign_in<F>(account: ChatAccount, http: matrix_sdk::reqwest::Client, store: Arc<dyn SecretStore>, timeout: Duration, open_browser: F) -> Result<Self, ChatError>
    where
        F: FnOnce(&Url) -> Result<(), String>,
    {
        let s = auth::secrets(store.as_ref(), &account)?;
        let pass = auth::store_passphrase(&s)?;
        let store_name = format!("device-{}", ou_core::oidc::random_token(9).replace(['-', '_'], "x"));
        let dir = auth::store_dir(&account.data_dir, &store_name)?;
        let client = auth::build_client(&account, http, &dir, &pass).await?;
        let session = match auth::login(&client, &account, &s, timeout, open_browser).await {
            Ok(x) => x,
            Err(e) => {
                drop(client);
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        auth::save_session(&s, &auth::StoredSession { v: 1, store: store_name.clone(), session })?;
        drop(s);
        Ok(Self { client, account, store, store_name })
    }

    /// Starts token persistence and the revoke watcher. Call once after `restore`/`sign_in`.
    pub fn watch_session(&self, on_signed_out: Arc<dyn Fn() + Send + Sync>) {
        auth::spawn_session_persister(self.client.clone(), self.store.clone(), self.account.clone(), self.store_name.clone(), on_signed_out);
    }

    pub fn user_id(&self) -> Option<String> {
        self.client.user_id().map(|u| u.to_string())
    }

    pub fn device_id(&self) -> Option<String> {
        self.client.device_id().map(|d| d.to_string())
    }

    /// The underlying SDK client, for features not wrapped yet.
    pub fn sdk(&self) -> &Client {
        &self.client
    }

    /// One sync round (initial or incremental). `timeout` is the server long-poll time.
    pub async fn sync_once(&self, timeout: Duration) -> Result<(), ChatError> {
        self.client.sync_once(SyncSettings::default().timeout(timeout)).await.map(|_| ()).map_err(mx)
    }

    /// Runs the sync loop until the session ends. Notifications reach `notify::register` handlers.
    pub async fn sync_forever(&self) -> Result<(), ChatError> {
        self.client.sync(SyncSettings::default().timeout(Duration::from_secs(30))).await.map_err(mx)
    }

    /// Signs out at MAS (revokes the tokens, removes the device) and deletes this device's local store and credentials.
    pub async fn sign_out(self) -> Result<(), ChatError> {
        let _ = self.client.oauth().logout().await;
        let s = auth::secrets(self.store.as_ref(), &self.account)?;
        s.delete(auth::SESSION_SECRET).map_err(|e| ChatError::Store(e.to_string()))?;
        let dir = auth::store_dir(&self.account.data_dir, &self.store_name)?;
        drop(self.client);
        remove_store(&dir);
        Ok(())
    }
}

fn remove_store(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}
