//! Sign-in to Matrix through the Matrix Authentication Service (MAS, next-generation auth / MSC3861).
//!
//! * Discovery: the homeserver's `/_matrix/client/v1/auth_metadata` (MSC2965), done by matrix-sdk.
//! * Registration: dynamic client registration (MSC2966 / RFC 7591) as a **native** public client with the RFC 8252 loopback
//!   redirect `http://127.0.0.1/callback`. MAS's default policy accepts exactly this for `application_type: native` and ignores
//!   the port when matching loopback redirects, so no MAS configuration change is needed. The client id is kept per account and
//!   reused, so signing in again does not register another client.
//! * Authorization code + PKCE (S256) in the **system browser** (MSC2964). MAS sends the user to the deployment's Keycloak, whose
//!   SSO cookie from the desktop's first sign-in makes this step silent: one sign-in for files and chat.
//! * Tokens: matrix-sdk refreshes them; every rotation is written to the `SecretStore` (Windows Credential Manager) before the
//!   old one is forgotten. Nothing is written to a plaintext file.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use matrix_sdk::authentication::oauth::registration::{ApplicationType, ClientMetadata, Localized, OAuthGrantType};
use matrix_sdk::authentication::oauth::{ClientId, ClientRegistrationData, OAuthSession};
use matrix_sdk::ruma::serde::Raw;
use matrix_sdk::utils::UrlOrQuery;
use base64::Engine;
use matrix_sdk::{Client, SessionChange, SqliteStoreConfig};
use ou_core::secrets::{AccountSecrets, SecretStore};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ChatError;

/// Secret names inside the account's namespace (`OfficeUnbound/<account>/...`).
pub const SESSION_SECRET: &str = "matrix-session";
pub const STORE_KEY_SECRET: &str = "matrix-store-key";
pub const CLIENT_ID_SECRET: &str = "matrix-client-id";

/// Registered redirect. MAS matches loopback redirects without the port (RFC 8252 section 7.3).
pub const REDIRECT_PATH: &str = "/callback";
pub const REGISTERED_REDIRECT: &str = "http://127.0.0.1/callback";

pub const CLIENT_NAME: &str = "Office Unbound Desktop";

/// Everything ou-chat needs to know about one account. Built by the shell from `ou_core::discovery::Deployment`.
#[derive(Debug, Clone)]
pub struct ChatAccount {
    pub account_id: String,
    /// Matrix client-server base URL (discovery `matrix_url`, e.g. `https://matrix.company.com/`).
    pub homeserver: Url,
    /// `client_uri` for the registration: the deployment's portal (https). MAS requires https and shows it on its consent page.
    pub client_uri: Url,
    /// Per-account directory for the encrypted Matrix store (state, crypto keys, event and media cache).
    pub data_dir: PathBuf,
}

/// What is kept in the credential store for a signed-in device. `Debug` is redacted.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSession {
    pub v: u32,
    /// Directory name under `data_dir` that holds this device's store (one per device: a new sign-in is a new device).
    pub store: String,
    pub session: OAuthSession,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession").field("store", &self.store).field("user", &self.session.user.meta.user_id).finish_non_exhaustive()
    }
}

/// The registration document. No logo/tos/policy URIs: MAS requires them on the client_uri host and they add nothing.
pub fn client_metadata(client_uri: &Url) -> Result<Raw<ClientMetadata>, ChatError> {
    if client_uri.scheme() != "https" {
        return Err(ChatError::Config("client_uri must be https".into()));
    }
    let redirect = Url::parse(REGISTERED_REDIRECT).expect("constant");
    let mut md = ClientMetadata::new(
        ApplicationType::Native,
        vec![OAuthGrantType::AuthorizationCode { redirect_uris: vec![redirect] }],
        Localized::new(client_uri.clone(), []),
    );
    md.client_name = Some(Localized::new(CLIENT_NAME.to_owned(), []));
    Raw::new(&md).map_err(|e| ChatError::Config(e.to_string()))
}

pub(crate) fn secrets<'a>(store: &'a dyn SecretStore, account: &ChatAccount) -> Result<AccountSecrets<'a>, ChatError> {
    AccountSecrets::new(store, &account.account_id).map_err(|e| ChatError::Store(e.to_string()))
}

fn store_err(e: impl std::fmt::Display) -> ChatError {
    ChatError::Store(e.to_string())
}

/// The passphrase that encrypts the Matrix SQLite store (matrix-sdk's store cipher). Created once per account, kept in the
/// credential store, so a copied profile directory is unreadable without this user's Windows logon.
pub(crate) fn store_passphrase(s: &AccountSecrets<'_>) -> Result<String, ChatError> {
    if let Some(v) = s.get(STORE_KEY_SECRET).map_err(store_err)? {
        return String::from_utf8(v).map_err(|_| ChatError::Store("store key is not text".into()));
    }
    let p = ou_core::oidc::random_token(32);
    s.set(STORE_KEY_SECRET, p.as_bytes()).map_err(store_err)?;
    Ok(p)
}

pub(crate) fn load_session(s: &AccountSecrets<'_>) -> Result<Option<StoredSession>, ChatError> {
    match s.get(SESSION_SECRET).map_err(store_err)? {
        None => Ok(None),
        Some(v) => serde_json::from_slice(&v).map(Some).map_err(|_| ChatError::Store("stored chat session is unreadable".into())),
    }
}

pub(crate) fn save_session(s: &AccountSecrets<'_>, st: &StoredSession) -> Result<(), ChatError> {
    let v = serde_json::to_vec(st).map_err(store_err)?;
    s.set(SESSION_SECRET, &v).map_err(store_err)
}

/// Directory names are generated by us; this guards a tampered credential entry from pointing outside `data_dir`.
pub(crate) fn store_dir(data_dir: &Path, name: &str) -> Result<PathBuf, ChatError> {
    let ok = name.len() <= 64 && !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        return Err(ChatError::Store("invalid store name".into()));
    }
    Ok(data_dir.join(name))
}

pub(crate) async fn build_client(account: &ChatAccount, http: matrix_sdk::reqwest::Client, dir: &Path, passphrase: &str) -> Result<Client, ChatError> {
    ou_core::http::require_allowed(&account.homeserver).map_err(|e| ChatError::Config(e.to_string()))?;
    std::fs::create_dir_all(dir).map_err(|e| ChatError::Store(format!("chat store directory: {e}")))?;
    // The secret is 32 random bytes, so it is used as the store key directly (no password-stretching KDF needed).
    let key = zeroize::Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(passphrase).map_err(|_| ChatError::Store("store key".into()))?);
    if key.len() != 32 {
        return Err(ChatError::Store("store key has the wrong length".into()));
    }
    Client::builder()
        .homeserver_url(account.homeserver.as_str())
        .http_client(http)
        .sqlite_store_with_config_and_cache_path(SqliteStoreConfig::new(dir).key(Some(&key)), None::<&Path>)
        .handle_refresh_tokens()
        .build()
        .await
        .map_err(|e| ChatError::Matrix(e.to_string()))
}

/// MAS redirect listener: ou-core's shared loopback listener on `/callback` (same rules as the Keycloak sign-in: state check in
/// constant time, stray requests ignored, 8 KiB cap, no-store/no-script page).
pub struct Loopback(ou_core::oidc::Loopback);

impl Loopback {
    pub async fn bind() -> Result<Self, ChatError> {
        ou_core::oidc::Loopback::bind(REDIRECT_PATH).await.map(Self).map_err(|e| ChatError::Login(format!("loopback: {e}")))
    }

    pub fn redirect_uri(&self) -> Url {
        Url::parse(&self.0.redirect_uri()).expect("loopback url")
    }

    /// Returns the redirect's query string (`code=...&state=...` or `error=...&state=...`).
    pub async fn wait(&self, state: &str, timeout: Duration) -> Result<String, ChatError> {
        self.0.wait_query(state, timeout).await.map_err(|e| match e {
            ou_core::oidc::OidcError::Timeout => ChatError::Login("sign-in timed out".into()),
            e => ChatError::Login(format!("loopback: {e}")),
        })
    }
}

/// Interactive sign-in. `open_browser` gets the MAS authorization URL (https, MAS's origin) and opens the system browser.
pub(crate) async fn login<F>(client: &Client, account: &ChatAccount, s: &AccountSecrets<'_>, timeout: Duration, open_browser: F) -> Result<OAuthSession, ChatError>
where
    F: FnOnce(&Url) -> Result<(), String>,
{
    let oauth = client.oauth();
    // Reuse this account's registered client id (one MAS client per installation and account).
    if let Some(id) = s.get(CLIENT_ID_SECRET).map_err(store_err)? {
        let id = String::from_utf8(id).map_err(|_| ChatError::Store("client id".into()))?;
        oauth.restore_registered_client(ClientId::new(id));
    }
    let lb = Loopback::bind().await?;
    let registration: ClientRegistrationData = client_metadata(&account.client_uri)?.into();
    let data = oauth
        .login(lb.redirect_uri(), None, Some(registration), None)
        .build()
        .await
        .map_err(|e| ChatError::Login(e.to_string()))?;
    // https only (plain http only to loopback mock servers, and only in test builds: ou-core's rule).
    if ou_core::http::require_allowed(&data.url).is_err() {
        oauth.abort_login(&data.state).await;
        return Err(ChatError::Login("authorization URL is not https".into()));
    }
    if let Some(id) = oauth.client_id() {
        s.set(CLIENT_ID_SECRET, id.as_str().as_bytes()).map_err(store_err)?;
    }
    if let Err(e) = open_browser(&data.url) {
        oauth.abort_login(&data.state).await;
        return Err(ChatError::Login(format!("could not open the browser: {e}")));
    }
    let query = match lb.wait(data.state.secret(), timeout).await {
        Ok(q) => q,
        Err(e) => {
            oauth.abort_login(&data.state).await;
            return Err(e);
        }
    };
    oauth.finish_login(UrlOrQuery::Query(query)).await.map_err(|e| ChatError::Login(e.to_string()))?;
    oauth.full_session().ok_or_else(|| ChatError::Login("no session after sign-in".into()))
}

/// Writes every token rotation to the credential store; reports a revoked session once.
pub(crate) fn spawn_session_persister(client: Client, store: Arc<dyn SecretStore>, account: ChatAccount, store_name: String, on_signed_out: Arc<dyn Fn() + Send + Sync>) {
    let mut rx = client.subscribe_to_session_changes();
    tokio::spawn(async move {
        while let Ok(change) = rx.recv().await {
            let Ok(s) = secrets(store.as_ref(), &account) else { continue };
            match change {
                SessionChange::TokensRefreshed => {
                    if let Some(session) = client.oauth().full_session() {
                        let _ = save_session(&s, &StoredSession { v: 1, store: store_name.clone(), session });
                    }
                }
                SessionChange::UnknownToken(_) => {
                    // Revoked device/user or expired refresh token: forget the dead tokens, keep the encrypted store (it holds
                    // this device's room keys; the user may still want to export them) and ask for a new sign-in.
                    let _ = s.delete(SESSION_SECRET);
                    on_signed_out();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_document_is_native_loopback() {
        let raw = client_metadata(&Url::parse("https://app.company.com/").unwrap()).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.json().get()).unwrap();
        assert_eq!(v["application_type"], "native");
        assert_eq!(v["redirect_uris"], serde_json::json!(["http://127.0.0.1/callback"]));
        assert_eq!(v["token_endpoint_auth_method"], "none", "public client: no secret to store");
        assert!(v["grant_types"].as_array().unwrap().iter().any(|g| g == "authorization_code"));
        assert!(v["grant_types"].as_array().unwrap().iter().any(|g| g == "refresh_token"));
        assert_eq!(v["client_uri"], "https://app.company.com/");
        assert!(v.get("logo_uri").is_none() && v.get("tos_uri").is_none() && v.get("policy_uri").is_none());
        assert!(client_metadata(&Url::parse("http://app.company.com/").unwrap()).is_err());
    }

    #[test]
    fn store_dir_names_are_confined() {
        let d = Path::new("/data");
        assert!(store_dir(d, "s-abc_123").is_ok());
        for bad in ["", "..", "../x", "a/b", "a\\b", "C:", &"x".repeat(65)] {
            assert!(store_dir(d, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stored_session_debug_has_no_tokens() {
        let json = serde_json::json!({"v":1,"store":"s1","session":{"client_id":"01ABC","user_id":"@doc:m.example","device_id":"DEV","access_token":"mat_SECRETA","refresh_token":"mar_SECRETR"}});
        let st: StoredSession = serde_json::from_value(json).unwrap();
        let d = format!("{st:?}");
        assert!(!d.contains("SECRET"), "{d}");
        assert!(serde_json::to_vec(&st).unwrap().len() < ou_core::secrets::MAX_SECRET_BYTES);
    }

    #[tokio::test]
    async fn loopback_ignores_strays_and_checks_state() {
        let lb = Loopback::bind().await.unwrap();
        let port = lb.redirect_uri().port().unwrap();
        assert_eq!(lb.redirect_uri().path(), "/callback");
        let waiter = tokio::spawn(async move { lb.wait("STATE123", Duration::from_secs(10)).await });
        let http = ou_core::http::test_client();
        let base = format!("http://127.0.0.1:{port}");
        assert_eq!(http.get(format!("{base}/favicon.ico")).send().await.unwrap().status(), 404);
        assert_eq!(http.get(format!("{base}/callback?code=x&state=WRONG")).send().await.unwrap().status(), 400);
        let ok = http.get(format!("{base}/callback?code=abc&state=STATE123")).send().await.unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.headers()["cache-control"], "no-store");
        assert_eq!(waiter.await.unwrap().unwrap(), "code=abc&state=STATE123");
    }

    #[tokio::test]
    async fn loopback_times_out() {
        let lb = Loopback::bind().await.unwrap();
        assert!(matches!(lb.wait("s", Duration::from_millis(50)).await, Err(ChatError::Login(_))));
    }
}
