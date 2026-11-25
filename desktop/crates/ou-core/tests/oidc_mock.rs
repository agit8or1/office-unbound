//! OIDC Authorization Code + PKCE against an in-process mock IdP that enforces what Keycloak/MAS enforce: exact redirect URI,
//! S256 verifier check, single-use codes, refresh-token rotation and revocation. The "browser" is a plain HTTP client that follows
//! the IdP's 302 to the loopback listener, exactly what the system browser does after the user signs in.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use ou_core::oidc::{self, b64url, ClientConfig, OidcError, ProviderMetadata};
use sha2::Digest;

#[derive(Default)]
struct Idp {
    base: String,
    codes: HashMap<String, (String, String, String, String)>, // code -> (challenge, redirect, client, nonce)
    refresh: HashMap<String, bool>,                            // refresh token -> active
    deny: bool,
    wrong_state: bool,
    token_calls: usize,
}

type S = Arc<Mutex<Idp>>;

async fn metadata(State(s): State<S>) -> Json<serde_json::Value> {
    let b = s.lock().unwrap().base.clone();
    Json(serde_json::json!({
        "issuer": b, "authorization_endpoint": format!("{b}/auth"), "token_endpoint": format!("{b}/token"),
        "revocation_endpoint": format!("{b}/revoke"), "code_challenge_methods_supported": ["plain", "S256"]
    }))
}

async fn authorize(State(s): State<S>, Query(q): Query<HashMap<String, String>>) -> Response {
    let mut st = s.lock().unwrap();
    assert_eq!(q.get("code_challenge_method").map(String::as_str), Some("S256"));
    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
    let redirect = q["redirect_uri"].clone();
    assert!(redirect.starts_with("http://127.0.0.1:") && redirect.ends_with('/'), "RFC 8252 loopback redirect: {redirect}");
    let state = if st.wrong_state { "forged".to_string() } else { q["state"].clone() };
    let loc = if st.deny {
        format!("{redirect}?error=access_denied&state={state}")
    } else {
        let code = format!("code-{}", st.codes.len());
        st.codes.insert(code.clone(), (q["code_challenge"].clone(), redirect.clone(), q["client_id"].clone(), q["nonce"].clone()));
        format!("{redirect}?code={code}&state={state}&session_state=x")
    };
    (StatusCode::FOUND, [(header::LOCATION, loc)]).into_response()
}

fn id_token(iss: &str, aud: &str, nonce: &str) -> String {
    let c = serde_json::json!({"iss": iss, "sub": "user-1", "aud": aud, "exp": oidc::now() + 300, "nonce": nonce,
        "email": "doc@a.example", "preferred_username": "doc"});
    format!("eyJhbGciOiJub25lIn0.{}.", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(c.to_string()))
}

async fn token(State(s): State<S>, Form(f): Form<HashMap<String, String>>) -> Response {
    let mut st = s.lock().unwrap();
    st.token_calls += 1;
    let bad = |e: &str| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response();
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some((challenge, redirect, client, nonce)) = st.codes.remove(&f["code"]) else { return bad("invalid_grant") };
            if f["redirect_uri"] != redirect || f["client_id"] != client {
                return bad("invalid_grant");
            }
            if b64url(&sha2::Sha256::digest(f["code_verifier"].as_bytes())) != challenge {
                return bad("invalid_grant");
            }
            let rt = format!("rt-{}", st.refresh.len());
            st.refresh.insert(rt.clone(), true);
            let iss = st.base.clone();
            Json(serde_json::json!({"access_token": "at-1", "expires_in": 300, "refresh_token": rt,
                "id_token": id_token(&iss, &client, &nonce), "token_type": "Bearer"}))
            .into_response()
        }
        Some("refresh_token") => {
            let rt = &f["refresh_token"];
            if st.refresh.get(rt) != Some(&true) {
                return bad("invalid_grant");
            }
            st.refresh.insert(rt.clone(), false); // rotation: the old one is spent
            let new = format!("rt-{}", st.refresh.len());
            st.refresh.insert(new.clone(), true);
            Json(serde_json::json!({"access_token": "at-2", "expires_in": 300, "refresh_token": new})).into_response()
        }
        _ => bad("unsupported_grant_type"),
    }
}

async fn revoke(State(s): State<S>, Form(f): Form<HashMap<String, String>>) -> StatusCode {
    s.lock().unwrap().refresh.insert(f["token"].clone(), false);
    StatusCode::OK
}

async fn start() -> S {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s: S = Arc::new(Mutex::new(Idp { base: format!("http://{}", l.local_addr().unwrap()), ..Default::default() }));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(metadata))
        .route("/auth", get(authorize))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .with_state(s.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    s
}

/// The "system browser": GET the authorization URL, follow its redirect to the loopback listener.
fn browser(http: reqwest::Client) -> impl FnOnce(&url::Url) -> Result<(), String> {
    move |u: &url::Url| {
        let u = u.clone();
        tokio::spawn(async move {
            let r = http.get(u).send().await.unwrap();
            let loc = r.headers()[reqwest::header::LOCATION].to_str().unwrap().to_string();
            let _ = http.get(loc).send().await;
        });
        Ok(())
    }
}

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
    let r = oidc::sign_in(&http, &meta, &client(), None, Duration::from_secs(10), browser(http.clone())).await;
    assert!(matches!(r, Err(OidcError::StateMismatch)), "{r:?}");
    assert_eq!(s.lock().unwrap().token_calls, 0, "code not redeemed");
}

#[tokio::test]
async fn listener_ignores_probes_and_times_out() {
    let s = start().await;
    let http = ou_core::http::test_client();
    let base = s.lock().unwrap().base.clone();
    let meta = ProviderMetadata::discover(&http, &base).await.unwrap();
    let req = oidc::AuthRequest::new(&meta, &client(), None).await.unwrap();
    let probe = format!("{}favicon.ico", req.redirect_uri);
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
