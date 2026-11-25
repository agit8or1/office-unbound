//! Test support (feature `test-support`): an in-process mock OIDC provider that enforces what Keycloak/MAS enforce (exact
//! redirect URI, S256 verifier, single-use codes, refresh rotation, revocation) and a "browser" that follows its redirect.
//! Used by ou-core, ou-agent and the feature crates' tests. Never compiled into release builds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use sha2::Digest;

use crate::oidc::{self, b64url};

#[derive(Default)]
pub struct Idp {
    pub base: String,
    pub codes: HashMap<String, (String, String, String, String)>, // code -> (challenge, redirect, client, nonce)
    pub refresh: HashMap<String, bool>,                            // refresh token -> active
    pub deny: bool,
    pub wrong_state: bool,
    pub token_calls: usize,
}

pub type S = Arc<Mutex<Idp>>;

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

pub async fn start() -> S {
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
pub fn browser(http: reqwest::Client) -> impl FnOnce(&url::Url) -> Result<(), String> {
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

