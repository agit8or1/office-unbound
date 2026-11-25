//! OIDC Authorization Code + PKCE (S256) for a native app (RFC 8252): the system browser opens the IdP, the redirect comes back
//! to a one-shot loopback listener on 127.0.0.1 with an ephemeral port. Works for Keycloak (files, portal, ...) and for Matrix
//! Authentication Service (MSC2964), which delegates to the same Keycloak, so the browser's Keycloak SSO cookie makes the second
//! sign-in silent (no second password or MFA prompt).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use crate::http::require_allowed;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("network error: {0}")]
    Network(String),
    #[error("identity provider metadata is invalid: {0}")]
    Metadata(String),
    #[error("sign-in was cancelled or refused by the identity provider ({0})")]
    Denied(String),
    #[error("sign-in response did not match this request (state)")]
    StateMismatch,
    #[error("sign-in timed out")]
    Timeout,
    #[error("token endpoint refused the request (HTTP {status}, {error})")]
    TokenRefused { status: u16, error: String },
    #[error("ID token is invalid: {0}")]
    IdToken(String),
    #[error("could not open the browser: {0}")]
    Browser(String),
    #[error("local listener error: {0}")]
    Listener(String),
}

fn net(e: reqwest::Error) -> OidcError {
    // reqwest errors can include the URL; our URLs never carry secrets in the query except the redirect (handled locally).
    OidcError::Network(crate::redact::redact(&e.to_string()))
}

pub fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS random number generator");
    b64url(&buf)
}

/// PKCE pair. The verifier is 64 base64url chars (48 random bytes), within RFC 7636's 43..128.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Self {
        let verifier = random_token(48);
        let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));
        Self { verifier, challenge }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.origin() == b.origin()
}

impl ProviderMetadata {
    /// Fetches `<issuer>/.well-known/openid-configuration` and validates it: exact issuer match (OIDC Discovery 4.3), S256 offered,
    /// every endpoint https (loopback http in tests) and on the issuer's origin, so a tampered document cannot send the code or
    /// the verifier elsewhere.
    pub async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Self, OidcError> {
        let iss = Url::parse(issuer).map_err(|_| OidcError::Metadata("issuer is not a URL".into()))?;
        require_allowed(&iss).map_err(|e| OidcError::Metadata(e.to_string()))?;
        let well_known = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let r = http.get(&well_known).send().await.map_err(net)?;
        if !r.status().is_success() {
            return Err(OidcError::Metadata(format!("HTTP {}", r.status().as_u16())));
        }
        let m: ProviderMetadata = r.json().await.map_err(net)?;
        m.validate(issuer)?;
        Ok(m)
    }

    pub fn validate(&self, expected_issuer: &str) -> Result<(), OidcError> {
        if self.issuer != expected_issuer {
            return Err(OidcError::Metadata("issuer does not match".into()));
        }
        if !self.code_challenge_methods_supported.iter().any(|m| m == "S256") {
            return Err(OidcError::Metadata("PKCE S256 is not offered".into()));
        }
        let iss = Url::parse(&self.issuer).map_err(|_| OidcError::Metadata("issuer".into()))?;
        let mut eps = vec![&self.authorization_endpoint, &self.token_endpoint];
        eps.extend(self.revocation_endpoint.iter());
        eps.extend(self.end_session_endpoint.iter());
        for e in eps {
            let u = Url::parse(e).map_err(|_| OidcError::Metadata("endpoint is not a URL".into()))?;
            require_allowed(&u).map_err(|e| OidcError::Metadata(e.to_string()))?;
            if !same_origin(&u, &iss) {
                return Err(OidcError::Metadata("endpoint is on another origin than the issuer".into()));
            }
        }
        Ok(())
    }
}

/// Everything about one pending sign-in. Not serialisable on purpose: it never leaves the agent process.
pub struct AuthRequest {
    pub url: Url,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub pkce: Pkce,
    loopback: Loopback,
}

/// One-shot RFC 8252 loopback listener on `127.0.0.1:<ephemeral><path>`, shared by the Keycloak sign-in (path "", because the
/// catalog client registers `http://127.0.0.1` and Keycloak ignores only the port) and ou-chat's MAS sign-in (`/callback`).
/// Only `GET <path>?...` carrying the expected `state` completes; anything else (favicon, probes, forged state from a local page)
/// gets 404/400 and the wait continues, so a stray request can neither finish nor abort the sign-in. Requests capped at 8 KiB.
pub struct Loopback {
    listener: TcpListener,
    port: u16,
    path: String,
}

impl Loopback {
    /// `path` is "" or starts with "/" (e.g. "/callback").
    pub async fn bind(path: &str) -> Result<Self, OidcError> {
        if !(path.is_empty() || (path.starts_with('/') && path.len() < 64 && path.chars().all(|c| c.is_ascii_alphanumeric() || "/-_".contains(c)))) {
            return Err(OidcError::Listener("invalid redirect path".into()));
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| OidcError::Listener(e.to_string()))?;
        let port = listener.local_addr().map_err(|e| OidcError::Listener(e.to_string()))?.port();
        Ok(Self { listener, port, path: path.to_string() })
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{}", self.port, self.path)
    }

    /// Waits for the redirect and returns its raw query string (`code=...&state=...` or `error=...&state=...`).
    pub async fn wait_query(&self, state: &str, timeout: Duration) -> Result<String, OidcError> {
        let want_path = if self.path.is_empty() { "/" } else { self.path.as_str() };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let accept = tokio::time::timeout_at(deadline, self.listener.accept()).await.map_err(|_| OidcError::Timeout)?;
            let (mut sock, _) = accept.map_err(|e| OidcError::Listener(e.to_string()))?;
            let mut buf = vec![0u8; 8192];
            let mut n = 0;
            while n < buf.len() {
                match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf[n..])).await {
                    Ok(Ok(k)) if k > 0 => {
                        n += k;
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = head.lines().next().and_then(|l| {
                let mut p = l.split(' ');
                match (p.next(), p.next()) {
                    (Some("GET"), Some(t)) => Some(t.to_string()),
                    _ => None,
                }
            });
            let parsed = target.and_then(|t| Url::parse(&format!("http://127.0.0.1{t}")).ok());
            let Some(u) = parsed.filter(|u| u.path() == want_path && u.query().is_some()) else {
                let _ = respond(&mut sock, 404, "Not found").await;
                continue;
            };
            let got = u.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).unwrap_or_default();
            if !ct_eq(got.as_bytes(), state.as_bytes()) {
                let _ = respond(&mut sock, 400, "This sign-in response does not belong to Office Unbound Desktop.").await;
                continue;
            }
            let failed = u.query_pairs().any(|(k, _)| k == "error");
            let msg = if failed { "Sign-in was not completed. You can close this window." } else { "Signed in to Office Unbound Desktop. You can close this window." };
            let _ = respond(&mut sock, 200, msg).await;
            return Ok(u.query().unwrap_or_default().to_string());
        }
    }
}

pub struct ClientConfig {
    pub client_id: String,
    pub scopes: Vec<String>,
}

impl AuthRequest {
    /// Binds the loopback listener (127.0.0.1, ephemeral port) and builds the authorization URL.
    pub async fn new(meta: &ProviderMetadata, client: &ClientConfig, login_hint: Option<&str>) -> Result<Self, OidcError> {
        // No path: the catalog client registers `http://127.0.0.1` and Keycloak ignores only the port for loopback (verified live,
        // 2026-11-25: a trailing "/" is refused with "Invalid parameter: redirect_uri").
        let loopback = Loopback::bind("").await?;
        let redirect_uri = loopback.redirect_uri();
        let pkce = Pkce::new();
        let state = random_token(24);
        let nonce = random_token(24);
        let mut url = Url::parse(&meta.authorization_endpoint).map_err(|_| OidcError::Metadata("authorization_endpoint".into()))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &client.client_id)
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("scope", &client.scopes.join(" "))
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(h) = login_hint {
                q.append_pair("login_hint", h);
            }
        }
        Ok(Self { url, redirect_uri, state, nonce, pkce, loopback })
    }

    /// Waits for the browser redirect (see `Loopback`) and returns the authorization code.
    pub async fn wait_for_code(&self, timeout: Duration) -> Result<String, OidcError> {
        let query = self.loopback.wait_query(&self.state, timeout).await?;
        let q: std::collections::HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
        if let Some(err) = q.get("error") {
            return Err(OidcError::Denied(sanitize_short(err)));
        }
        match q.get("code") {
            Some(c) if !c.is_empty() && c.len() < 4096 => Ok(c.clone()),
            _ => Err(OidcError::Denied("no code".into())),
        }
    }
}

fn sanitize_short(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn respond(sock: &mut tokio::net::TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Office Unbound</title><body style=\"font:15px system-ui;margin:3em\"><p>{}</p>",
        msg.replace('<', "&lt;")
    );
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.shutdown().await
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// Tokens in memory. `Debug` is redacted so a stray `{:?}` cannot log them.
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub expires_at: u64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("expires_at", &self.expires_at)
            .field("has_refresh", &self.refresh_token.is_some())
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl TokenSet {
    /// True if the access token expires within `margin`.
    pub fn expiring(&self, margin: Duration) -> bool {
        now() + margin.as_secs() >= self.expires_at
    }
}

async fn token_request(http: &reqwest::Client, meta: &ProviderMetadata, form: &[(&str, &str)]) -> Result<TokenSet, OidcError> {
    let r = http.post(&meta.token_endpoint).form(form).send().await.map_err(net)?;
    let status = r.status().as_u16();
    if !(200..300).contains(&status) {
        let err = r.json::<serde_json::Value>().await.ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(sanitize_short));
        return Err(OidcError::TokenRefused { status, error: err.unwrap_or_else(|| "unknown".into()) });
    }
    let t: TokenResponse = r.json().await.map_err(net)?;
    Ok(TokenSet {
        access_token: t.access_token,
        expires_at: now() + t.expires_in.unwrap_or(60),
        refresh_token: t.refresh_token,
        id_token: t.id_token,
        scope: t.scope,
    })
}

pub async fn exchange_code(
    http: &reqwest::Client,
    meta: &ProviderMetadata,
    client: &ClientConfig,
    req: &AuthRequest,
    code: &str,
) -> Result<TokenSet, OidcError> {
    token_request(
        http,
        meta,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &client.client_id),
            ("code", code),
            ("redirect_uri", &req.redirect_uri),
            ("code_verifier", &req.pkce.verifier),
        ],
    )
    .await
}

/// Refresh. Keycloak and MAS rotate refresh tokens; the caller must persist the new one before using the access token.
pub async fn refresh(http: &reqwest::Client, meta: &ProviderMetadata, client_id: &str, refresh_token: &str) -> Result<TokenSet, OidcError> {
    let mut t = token_request(http, meta, &[("grant_type", "refresh_token"), ("client_id", client_id), ("refresh_token", refresh_token)]).await?;
    if t.refresh_token.is_none() {
        t.refresh_token = Some(refresh_token.to_string());
    }
    Ok(t)
}

/// Sign-out of this device: RFC 7009 revocation of the refresh token (ends the offline session in Keycloak / the MAS session).
pub async fn revoke(http: &reqwest::Client, meta: &ProviderMetadata, client_id: &str, refresh_token: &str) -> Result<(), OidcError> {
    let Some(ep) = &meta.revocation_endpoint else {
        return Err(OidcError::Metadata("no revocation endpoint".into()));
    };
    let r = http
        .post(ep)
        .form(&[("client_id", client_id), ("token", refresh_token), ("token_type_hint", "refresh_token")])
        .send()
        .await
        .map_err(net)?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(OidcError::TokenRefused { status: r.status().as_u16(), error: "revoke".into() })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct IdClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: u64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Checks the ID token received directly from the token endpoint over verified TLS (OIDC Core 3.1.3.7: TLS server validation may
/// be used instead of signature validation for this flow). Checks iss, aud, exp and nonce. Used only to label the account; the
/// servers authorise every request themselves.
pub fn check_id_token(id_token: &str, issuer: &str, client_id: &str, nonce: &str) -> Result<IdClaims, OidcError> {
    let payload = id_token.split('.').nth(1).ok_or_else(|| OidcError::IdToken("not a JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| OidcError::IdToken("payload".into()))?;
    let c: IdClaims = serde_json::from_slice(&bytes).map_err(|_| OidcError::IdToken("claims".into()))?;
    if c.iss != issuer {
        return Err(OidcError::IdToken("issuer".into()));
    }
    let aud_ok = match &c.aud {
        serde_json::Value::String(s) => s == client_id,
        serde_json::Value::Array(a) => a.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(OidcError::IdToken("audience".into()));
    }
    if c.exp + 60 < now() {
        return Err(OidcError::IdToken("expired".into()));
    }
    if c.nonce.as_deref() != Some(nonce) {
        return Err(OidcError::IdToken("nonce".into()));
    }
    Ok(c)
}

/// Full interactive sign-in: build request, hand the URL to `open_browser`, wait for the redirect, exchange the code.
pub async fn sign_in<F>(
    http: &reqwest::Client,
    meta: &ProviderMetadata,
    client: &ClientConfig,
    login_hint: Option<&str>,
    timeout: Duration,
    open_browser: F,
) -> Result<(TokenSet, Option<IdClaims>), OidcError>
where
    F: FnOnce(&Url) -> Result<(), String>,
{
    let req = AuthRequest::new(meta, client, login_hint).await?;
    open_browser(&req.url).map_err(OidcError::Browser)?;
    let code = req.wait_for_code(timeout).await?;
    let t = exchange_code(http, meta, client, &req, &code).await?;
    let claims = match &t.id_token {
        Some(id) => Some(check_id_token(id, &meta.issuer, &client.client_id, &req.nonce)?),
        None => None,
    };
    Ok((t, claims))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_shape() {
        let p = Pkce::new();
        assert_eq!(p.verifier.len(), 64);
        assert!(p.verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_eq!(p.challenge, b64url(&sha2::Sha256::digest(p.verifier.as_bytes())));
        assert_ne!(Pkce::new().verifier, p.verifier);
    }

    #[test]
    fn rfc7636_appendix_b_vector() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(b64url(&sha2::Sha256::digest(v.as_bytes())), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn metadata_validation() {
        let good = ProviderMetadata {
            issuer: "https://auth.a.example/realms/ou".into(),
            authorization_endpoint: "https://auth.a.example/realms/ou/protocol/openid-connect/auth".into(),
            token_endpoint: "https://auth.a.example/realms/ou/protocol/openid-connect/token".into(),
            revocation_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: vec!["plain".into(), "S256".into()],
            registration_endpoint: None,
        };
        good.validate("https://auth.a.example/realms/ou").unwrap();
        assert!(good.validate("https://auth.b.example/realms/ou").is_err(), "issuer mismatch");
        let mut m = good.clone();
        m.token_endpoint = "https://evil.example/token".into();
        assert!(m.validate(&good.issuer).is_err(), "foreign token endpoint");
        let mut m = good.clone();
        m.authorization_endpoint = "http://auth.a.example/realms/ou/auth".into();
        assert!(m.validate(&good.issuer).is_err(), "plain http endpoint");
        let mut m = good.clone();
        m.code_challenge_methods_supported = vec!["plain".into()];
        assert!(m.validate(&good.issuer).is_err(), "no S256");
    }

    fn jwt(claims: serde_json::Value) -> String {
        format!("eyJhbGciOiJub25lIn0.{}.sig", b64url(claims.to_string().as_bytes()))
    }

    #[test]
    fn id_token_checks() {
        let iss = "https://auth.a.example/realms/ou";
        let ok = jwt(serde_json::json!({"iss": iss, "sub": "u1", "aud": ["x", "ou-desktop"], "exp": now() + 300, "nonce": "n1",
            "email": "u@a.example"}));
        let c = check_id_token(&ok, iss, "ou-desktop", "n1").unwrap();
        assert_eq!(c.email.as_deref(), Some("u@a.example"));
        assert!(check_id_token(&ok, iss, "ou-desktop", "n2").is_err(), "nonce");
        assert!(check_id_token(&ok, "https://auth.b.example/realms/ou", "ou-desktop", "n1").is_err(), "issuer");
        assert!(check_id_token(&ok, iss, "other", "n1").is_err(), "audience");
        let old = jwt(serde_json::json!({"iss": iss, "sub": "u1", "aud": "ou-desktop", "exp": 1000, "nonce": "n1"}));
        assert!(check_id_token(&old, iss, "ou-desktop", "n1").is_err(), "expired");
    }

    #[test]
    fn tokenset_debug_is_redacted() {
        let t = TokenSet { access_token: "AT-SECRET".into(), expires_at: 1, refresh_token: Some("RT-SECRET".into()), id_token: None, scope: None };
        let s = format!("{t:?}");
        assert!(!s.contains("SECRET"), "{s}");
    }
}
