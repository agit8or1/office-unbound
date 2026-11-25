//! Stable API for feature modules (`ou-files`, `ou-chat`, later mail/calendar): an account's authenticated session.
//!
//! A module never sees the refresh token. It asks the `TokenProvider` for an access token *for a specific URL*; the provider
//! refuses URLs outside the account's deployment origins (tenant isolation), refreshes when the token is near expiry, persists the
//! rotated refresh token to the `SecretStore` before handing out the new access token, and reports `SignedOut` when the IdP
//! refuses the refresh (revoked device/user). Modules must treat `SignedOut` as "pause", never as "delete local data".
//!
//! Matrix uses its own OAuth issuer (MAS); `ou-chat` builds a second `Session` for the MAS issuer with the same store and a
//! different secret name, so both sessions are revoked independently and shown separately in the UI.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use url::Url;

use crate::oidc::{self, OidcError, ProviderMetadata, TokenSet};
use crate::secrets::{AccountSecrets, SecretStore};
use crate::urlpolicy::{may_send_token, OriginSet};

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("this address is not part of the account's deployment")]
    ForeignOrigin,
    #[error("signed out: sign in again")]
    SignedOut,
    #[error("server unreachable: {0}")]
    Offline(String),
    #[error("credential store: {0}")]
    Store(String),
}

pub type TokenFuture<'a> = Pin<Box<dyn Future<Output = Result<String, TokenError>> + Send + 'a>>;

/// What feature modules depend on. Object-safe so modules can hold `Arc<dyn TokenProvider>`.
pub trait TokenProvider: Send + Sync {
    /// A bearer token valid for at least ~60 s, for a request to `target`.
    fn access_token<'a>(&'a self, target: &'a Url) -> TokenFuture<'a>;
    /// Origins this account may talk to with its token.
    fn origins(&self) -> &OriginSet;
}

/// Name of the refresh-token secret for a session (`refresh` for Keycloak, `refresh-matrix` for MAS, ...).
pub const KEYCLOAK_SECRET: &str = "refresh";

pub struct Session {
    account_id: String,
    secret_name: String,
    client_id: String,
    meta: ProviderMetadata,
    origins: OriginSet,
    http: reqwest::Client,
    store: Arc<dyn SecretStore>,
    cache: Mutex<Option<TokenSet>>,
}

impl Session {
    pub fn new(
        account_id: &str,
        secret_name: &str,
        client_id: &str,
        meta: ProviderMetadata,
        origins: OriginSet,
        http: reqwest::Client,
        store: Arc<dyn SecretStore>,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            secret_name: secret_name.into(),
            client_id: client_id.into(),
            meta,
            origins,
            http,
            store,
            cache: Mutex::new(None),
        }
    }

    fn secrets(&self) -> Result<AccountSecrets<'_>, TokenError> {
        AccountSecrets::new(self.store.as_ref(), &self.account_id).map_err(|e| TokenError::Store(e.to_string()))
    }

    /// Stores tokens after an interactive sign-in.
    pub async fn adopt(&self, t: TokenSet) -> Result<(), TokenError> {
        let rt = t.refresh_token.as_deref().ok_or(TokenError::SignedOut)?;
        self.secrets()?.set(&self.secret_name, rt.as_bytes()).map_err(|e| TokenError::Store(e.to_string()))?;
        *self.cache.lock().await = Some(t);
        Ok(())
    }

    pub fn has_refresh_token(&self) -> bool {
        matches!(self.secrets().and_then(|s| s.get(&self.secret_name).map_err(|e| TokenError::Store(e.to_string()))), Ok(Some(_)))
    }

    async fn current(&self) -> Result<String, TokenError> {
        let mut cache = self.cache.lock().await;
        if let Some(t) = cache.as_ref() {
            if !t.expiring(Duration::from_secs(60)) {
                return Ok(t.access_token.clone());
            }
        }
        let secrets = self.secrets()?;
        let rt = secrets.get(&self.secret_name).map_err(|e| TokenError::Store(e.to_string()))?.ok_or(TokenError::SignedOut)?;
        let rt = String::from_utf8(rt).map_err(|_| TokenError::Store("stored token is not text".into()))?;
        match oidc::refresh(&self.http, &self.meta, &self.client_id, &rt).await {
            Ok(t) => {
                if let Some(new_rt) = &t.refresh_token {
                    if *new_rt != rt {
                        // Persist the rotated token first: losing it would sign the user out at the next start.
                        secrets.set(&self.secret_name, new_rt.as_bytes()).map_err(|e| TokenError::Store(e.to_string()))?;
                    }
                }
                let at = t.access_token.clone();
                *cache = Some(t);
                Ok(at)
            }
            Err(OidcError::TokenRefused { status, .. }) if (400..500).contains(&status) => {
                // invalid_grant: revoked, expired or user disabled. Forget the dead token; keep all local files.
                let _ = secrets.delete(&self.secret_name);
                *cache = None;
                Err(TokenError::SignedOut)
            }
            Err(e) => Err(TokenError::Offline(e.to_string())),
        }
    }

    /// Ends this session at the IdP (best effort) and removes the stored token in every case.
    pub async fn sign_out(&self) -> Result<(), TokenError> {
        let secrets = self.secrets()?;
        if let Ok(Some(rt)) = secrets.get(&self.secret_name) {
            if let Ok(rt) = String::from_utf8(rt) {
                let _ = oidc::revoke(&self.http, &self.meta, &self.client_id, &rt).await;
            }
        }
        secrets.delete(&self.secret_name).map_err(|e| TokenError::Store(e.to_string()))?;
        *self.cache.lock().await = None;
        Ok(())
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.meta
    }
}

impl TokenProvider for Session {
    fn access_token<'a>(&'a self, target: &'a Url) -> TokenFuture<'a> {
        Box::pin(async move {
            if !may_send_token(target, &self.origins) {
                return Err(TokenError::ForeignOrigin);
            }
            self.current().await
        })
    }

    fn origins(&self) -> &OriginSet {
        &self.origins
    }
}

/// Convenience for modules: a GET with the bearer token for `url`, through the verified client.
pub async fn authorized(p: &dyn TokenProvider, http: &reqwest::Client, method: reqwest::Method, url: &Url) -> Result<reqwest::RequestBuilder, TokenError> {
    let t = p.access_token(url).await?;
    Ok(http.request(method, url.clone()).bearer_auth(t))
}
