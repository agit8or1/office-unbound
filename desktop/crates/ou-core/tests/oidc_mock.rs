//! OIDC Authorization Code + PKCE against an in-process mock IdP that enforces what Keycloak/MAS enforce: exact redirect URI,
//! S256 verifier check, single-use codes, refresh-token rotation and revocation. The "browser" is a plain HTTP client that follows
//! the IdP's 302 to the loopback listener, exactly what the system browser does after the user signs in.

use std::sync::Arc;
use std::time::Duration;

use ou_core::oidc::{self, ClientConfig, OidcError, ProviderMetadata};
use ou_core::testing::{browser, start};

fn client() -> ClientConfig {
    ClientConfig { client_id: "ou-desktop".into(), scopes: vec!["openid".into(), "offline_access".into()] }
}

#[tokio::test]
async fn full_sign_in_refresh_rotation_and_revoke() {
    let s = start().await;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    let meta = ProviderMetadata::discover(&http, &base).await.unwrap();
    let (t, claims) = oidc::sign_in(&http, &meta, &client(), Some("doc@a.example"), Duration::from_secs(10), browser(http.clone()))
        .await
        .unwrap();
    assert_eq!(t.access_token, "at-1");
    let claims = claims.unwrap();
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.email.as_deref(), Some("doc@a.example"));

    let rt0 = t.refresh_token.clone().unwrap();
    let t2 = oidc::refresh(&http, &meta, "ou-desktop", &rt0).await.unwrap();
    let rt1 = t2.refresh_token.clone().unwrap();
    assert_ne!(rt0, rt1, "rotated");
    assert!(matches!(oidc::refresh(&http, &meta, "ou-desktop", &rt0).await, Err(OidcError::TokenRefused { status: 400, .. })), "old one spent");

    oidc::revoke(&http, &meta, "ou-desktop", &rt1).await.unwrap();
    assert!(matches!(oidc::refresh(&http, &meta, "ou-desktop", &rt1).await, Err(OidcError::TokenRefused { .. })), "revoked = signed out");
}

#[tokio::test]
async fn denied_sign_in_is_reported() {
    let s = start().await;
    s.lock().unwrap().deny = true;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    let meta = ProviderMetadata::discover(&http, &base).await.unwrap();
    let r = oidc::sign_in(&http, &meta, &client(), None, Duration::from_secs(10), browser(http.clone())).await;
    assert!(matches!(r, Err(OidcError::Denied(ref e)) if e == "access_denied"), "{r:?}");
    assert_eq!(s.lock().unwrap().token_calls, 0);
}

#[tokio::test]
async fn forged_state_never_reaches_token_endpoint() {
    let s = start().await;
    s.lock().unwrap().wrong_state = true;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    let meta = ProviderMetadata::discover(&http, &base).await.unwrap();
    let r = oidc::sign_in(&http, &meta, &client(), None, Duration::from_secs(2), browser(http.clone())).await;
    // A forged state is refused and the listener keeps waiting for the real redirect (here: until the timeout).
    assert!(matches!(r, Err(OidcError::Timeout)), "{r:?}");
    assert_eq!(s.lock().unwrap().token_calls, 0, "code not redeemed");
}

#[tokio::test]
async fn listener_ignores_probes_and_times_out() {
    let s = start().await;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    let meta = ProviderMetadata::discover(&http, &base).await.unwrap();
    let req = oidc::AuthRequest::new(&meta, &client(), None).await.unwrap();
    let probe = format!("{}/favicon.ico", req.redirect_uri);
    let h2 = http.clone();
    tokio::spawn(async move {
        let r = h2.get(probe).send().await.unwrap();
        assert_eq!(r.status(), 404);
    });
    let r = req.wait_for_code(Duration::from_millis(800)).await;
    assert!(matches!(r, Err(OidcError::Timeout)), "{r:?}");
}

#[tokio::test]
async fn issuer_mismatch_in_metadata_is_refused() {
    let s = start().await;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    s.lock().unwrap().base = "http://127.0.0.1:1".into(); // metadata now claims another issuer
    assert!(matches!(ProviderMetadata::discover(&http, &base).await, Err(OidcError::Metadata(_))));
}

#[tokio::test]
async fn session_token_provider_contract() {
    use ou_core::secrets::{AccountSecrets, MemoryStore, SecretStore};
    use ou_core::session::{Session, TokenError, TokenProvider, KEYCLOAK_SECRET};
    use ou_core::urlpolicy::OriginSet;
    let s = start().await;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    let meta = ProviderMetadata::discover(&http, &base).await.unwrap();
    let (mut t, _) = oidc::sign_in(&http, &meta, &client(), None, Duration::from_secs(10), browser(http.clone())).await.unwrap();
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let mut origins = OriginSet::new();
    let files = url::Url::parse(&format!("{base}/remote.php/dav/files/doc/")).unwrap();
    origins.add(&files);
    let sess = Session::new("aa01", KEYCLOAK_SECRET, "ou-desktop", meta, origins, http.clone(), store.clone());
    t.expires_at = 0; // force a refresh on first use
    let rt0 = t.refresh_token.clone().unwrap();
    sess.adopt(t).await.unwrap();

    let foreign = url::Url::parse("https://cloud.other-tenant.example/").unwrap();
    assert!(matches!(sess.access_token(&foreign).await, Err(TokenError::ForeignOrigin)));
    assert_eq!(sess.access_token(&files).await.unwrap(), "at-2", "refreshed");
    let stored = String::from_utf8(AccountSecrets::new(store.as_ref(), "aa01").unwrap().get(KEYCLOAK_SECRET).unwrap().unwrap()).unwrap();
    assert_ne!(stored, rt0, "rotated refresh token persisted");
    assert_eq!(sess.access_token(&files).await.unwrap(), "at-2", "cached, no new refresh");

    // Server-side revocation (admin disables the device): next refresh fails -> SignedOut, dead token forgotten.
    s.lock().unwrap().refresh.insert(stored.clone(), false);
    let sess2 = Session::new("aa01", KEYCLOAK_SECRET, "ou-desktop", sess.metadata().clone(), sess.origins().clone(), http.clone(), store.clone());
    assert!(matches!(sess2.access_token(&files).await, Err(TokenError::SignedOut)));
    assert!(!sess2.has_refresh_token());
}

#[tokio::test]
async fn loopback_with_path_for_chat() {
    let lb = oidc::Loopback::bind("/callback").await.unwrap();
    assert!(lb.redirect_uri().ends_with("/callback"));
    assert!(oidc::Loopback::bind("callback").await.is_err());
    assert!(oidc::Loopback::bind("/a b").await.is_err());
    let http = ou_core::http::test_client();
    let base = lb.redirect_uri();
    tokio::spawn(async move {
        assert_eq!(http.get(format!("{}?code=x&state=s1", base.trim_end_matches("/callback"))).send().await.unwrap().status(), 404, "wrong path");
        assert_eq!(http.get(format!("{base}?code=x&state=forged")).send().await.unwrap().status(), 400);
        assert_eq!(http.get(format!("{base}?code=abc&state=s1")).send().await.unwrap().status(), 200);
    });
    let q = lb.wait_query("s1", Duration::from_secs(5)).await.unwrap();
    assert_eq!(q, "code=abc&state=s1");
}
