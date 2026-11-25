//! Read-only live check against a real deployment (owner-authorised test account only). Prints no secret.
//!   OU_LIVE_EMAIL=doctest@officeunbound.com OU_LIVE_PWFILE=/path/0600-file OU_LIVE_BROWSER=desktop/scripts/live-browser.cjs \
//!   cargo run -p ou-core --example live_check
//! Steps: discovery from the e-mail, provider metadata, PKCE sign-in (the "browser" is Playwright driving the real Keycloak page),
//! ID token checks, refresh rotation, WebDAV PROPFIND Depth 0 through the TokenProvider, foreign-origin refusal, revocation.
use std::sync::Arc;
use std::time::{Duration, Instant};

use ou_core::discovery::{discover, parse_input, HttpFetcher};
use ou_core::oidc::{self, ClientConfig, ProviderMetadata};
use ou_core::secrets::{MemoryStore, SecretStore};
use ou_core::session::{authorized, Session, TokenError, TokenProvider, KEYCLOAK_SECRET};

fn step(name: &str, ok: bool, detail: impl std::fmt::Display) {
    println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
    if !ok {
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    let email = std::env::var("OU_LIVE_EMAIL").expect("OU_LIVE_EMAIL");
    let pw = std::env::var("OU_LIVE_PWFILE").expect("OU_LIVE_PWFILE");
    let browser = std::env::var("OU_LIVE_BROWSER").expect("OU_LIVE_BROWSER");
    let http = ou_core::http::client().unwrap();

    let t0 = Instant::now();
    let d = discover(&HttpFetcher(http.clone()), &parse_input(&email).unwrap()).await.unwrap();
    step("discovery", d.foreign_hosts.is_empty(), format!("{:?} issuer={} files={} matrix={:?} chat={:?} mail={:?} ({} ms)",
        d.source, d.issuer, d.files_url, d.matrix_url, d.chat_web_url, d.mail_web_url, t0.elapsed().as_millis()));

    let meta = ProviderMetadata::discover(&http, &d.issuer).await.unwrap();
    step("metadata", meta.revocation_endpoint.is_some(), "issuer exact, S256, endpoints on the issuer origin");

    let client = ClientConfig { client_id: d.client_id.clone(), scopes: ["openid", "profile", "email", "offline_access"].map(String::from).to_vec() };
    let t0 = Instant::now();
    let (tok, claims) = oidc::sign_in(&http, &meta, &client, d.login_hint.as_deref(), Duration::from_secs(120), |u| {
        std::process::Command::new("node").arg(&browser).env("U", u.as_str()).env("F", &pw).spawn().map(|_| ()).map_err(|e| e.to_string())
    })
    .await
    .unwrap();
    let claims = claims.expect("id token");
    step("pkce sign-in", tok.refresh_token.is_some(), format!("client={} sub=<{} chars> email={:?} access_token_lifetime={}s ({} ms)",
        d.client_id, claims.sub.len(), claims.email, tok.expires_at.saturating_sub(oidc::now()), t0.elapsed().as_millis()));
    let offline = tok.refresh_token.as_deref().and_then(|r| r.split('.').nth(1)).and_then(|p| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok()
    }).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).and_then(|v| v.get("typ").and_then(|t| t.as_str()).map(String::from));
    step("refresh token type", offline.as_deref() == Some("Offline"), format!("{offline:?}"));

    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let mut origins = ou_core::urlpolicy::OriginSet::new();
    for u in [&d.issuer, &d.files_url] {
        origins.add(&url::Url::parse(u).unwrap());
    }
    let sess = Session::new("1ive", KEYCLOAK_SECRET, &d.client_id, meta.clone(), origins, http.clone(), store.clone());
    let mut t = tok.clone();
    t.expires_at = 0; // force a refresh through the session
    sess.adopt(t).await.unwrap();
    let dav = url::Url::parse(&format!("{}remote.php/webdav/", d.files_url)).unwrap();
    let r = authorized(&sess, &http, reqwest::Method::from_bytes(b"PROPFIND").unwrap(), &dav).await.unwrap()
        .header("Depth", "0").send().await.unwrap();
    step("webdav propfind via TokenProvider (after refresh)", r.status().as_u16() == 207, r.status());
    let foreign = url::Url::parse("https://example.com/").unwrap();
    step("foreign origin refused", matches!(sess.access_token(&foreign).await, Err(TokenError::ForeignOrigin)), "ForeignOrigin");

    let t0 = Instant::now();
    sess.sign_out().await.unwrap();
    step("sign-out (RFC 7009 revoke)", !sess.has_refresh_token(), format!("{} ms", t0.elapsed().as_millis()));
    let again = oidc::refresh(&http, &meta, &d.client_id, tok.refresh_token.as_deref().unwrap()).await;
    step("revoked token refused", again.is_err(), format!("{:?}", again.err().map(|e| e.to_string())));
}
