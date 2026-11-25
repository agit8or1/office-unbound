//! Mock homeserver + MAS (matrix-sdk's wiremock MatrixMockServer): sign-in with dynamic registration through the loopback
//! redirect, token storage, restore, room list + unread counts, notifications, send, attachments, search, revoke, sign-out.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use matrix_sdk::ruma::{event_id, mxc_uri, owned_room_id, uint};
use matrix_sdk::test_utils::mocks::MatrixMockServer;
use matrix_sdk::ruma::events::AnySyncTimelineEvent;
use matrix_sdk::ruma::serde::Raw;
use matrix_sdk_test::{JoinedRoomBuilder, TestAuthToken};
use ou_chat::notify::{ChatNotification, Notifier};
use ou_chat::{auth, ChatAccount, ChatClient, ChatError};
use ou_core::secrets::{AccountSecrets, MemoryStore, SecretStore};
use url::Url;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, ResponseTemplate};

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ou-chat-mock-{}", ou_core::oidc::random_token(6)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn account(server: &MatrixMockServer, dir: &std::path::Path) -> ChatAccount {
    ChatAccount {
        account_id: "acct1".into(),
        homeserver: Url::parse(&server.uri()).unwrap(),
        client_uri: Url::parse("https://app.company.test/").unwrap(),
        data_dir: dir.to_path_buf(),
    }
}

/// Plays MAS + the browser: checks the authorization request and redirects to the loopback with a code.
fn fake_browser(seen: Arc<Mutex<Option<Url>>>) -> impl FnOnce(&Url) -> Result<(), String> {
    move |u: &Url| {
        *seen.lock().unwrap() = Some(u.clone());
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        let redirect = q.get("redirect_uri").cloned().ok_or("no redirect_uri")?;
        let state = q.get("state").cloned().ok_or("no state")?;
        tokio::spawn(async move {
            let http = ou_core::http::test_client();
            let _ = http.get(format!("{redirect}?code=AUTHCODE&state={state}")).send().await;
        });
        Ok(())
    }
}

async fn mount_auth(server: &MatrixMockServer) {
    server.mock_versions().ok().mount().await;
    server.oauth().mock_server_metadata().ok().mount().await;
    server.oauth().mock_registration().ok().expect(1).named("registration").mount().await;
    server.oauth().mock_token().ok().mount().await;
    server.mock_who_am_i().ok().mount().await;
}

#[derive(Default)]
struct Collect(Mutex<Vec<ChatNotification>>);
impl Notifier for Collect {
    fn notify(&self, n: ChatNotification) {
        self.0.lock().unwrap().push(n);
    }
}

fn files_contain(dir: &std::path::Path, needle: &[u8]) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p) {
                if b.windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_restore_rooms_notify_send_attach_search_sign_out() {
    let server = MatrixMockServer::new().await;
    mount_auth(&server).await;
    let dir = tmpdir();
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let seen = Arc::new(Mutex::new(None));
    let t0 = std::time::Instant::now();

    let chat = ChatClient::sign_in(account(&server, &dir), ou_core::http::test_client(), store.clone(), Duration::from_secs(20), fake_browser(seen.clone()))
        .await
        .expect("sign-in");
    assert!(chat.user_id().is_some());
    eprintln!("t signed in {:?}", t0.elapsed());

    // The authorization request: PKCE S256, Matrix API + device scopes, loopback redirect on /callback, registered client id.
    let u = seen.lock().unwrap().clone().unwrap();
    let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["client_id"], "test_client_id");
    assert!(q["scope"].contains("urn:matrix:client:api:*"), "{}", q["scope"]);
    assert!(q["scope"].contains("urn:matrix:client:device:"));
    let r = Url::parse(&q["redirect_uri"]).unwrap();
    assert_eq!((r.host_str(), r.path()), (Some("127.0.0.1"), "/callback"));

    // Tokens live only in the credential store; the store directory holds no token in clear.
    let s = AccountSecrets::new(store.as_ref(), "acct1").unwrap();
    assert!(s.get(auth::SESSION_SECRET).unwrap().is_some());
    assert_eq!(s.get(auth::CLIENT_ID_SECRET).unwrap().unwrap(), b"test_client_id");
    assert!(s.get(auth::STORE_KEY_SECRET).unwrap().is_some());
    let access: &str = TestAuthToken::AccessDefault.into();
    let refresh: &str = TestAuthToken::RefreshDefault.into();
    assert!(!files_contain(&dir, access.as_bytes()) && !files_contain(&dir, refresh.as_bytes()), "token found in a file");
    drop(chat);

    // Restart: restore without another registration or browser.
    let chat = ChatClient::restore(account(&server, &dir), ou_core::http::test_client(), store.clone()).await.unwrap().expect("restored");
    eprintln!("t restored {:?}", t0.elapsed());
    let notes = Arc::new(Collect::default());
    chat.register_notifier(notes.clone()).await;

    // Sync: one room with a message that mentions us, server counts 2/1.
    let me = chat.user_id().unwrap();
    let room = owned_room_id!("!team:example.org");
    server
        .mock_sync()
        .ok_and_run(chat.sdk(), |b| {
            let f = matrix_sdk_test::event_factory::EventFactory::new().room(&room);
            let uid = matrix_sdk::ruma::UserId::parse(me.as_str()).unwrap();
            b.add_joined_room(
                JoinedRoomBuilder::new(&room)
                    .add_state_bulk([f.member(&uid).display_name("Doc").into_raw_sync_state()])
                    .add_timeline_event(Raw::new(&serde_json::json!({"type":"m.room.message","event_id":"$m1","sender":"@bob:example.org","origin_server_ts":1700000000000u64,
                        "content":{"msgtype":"m.text","body":"Hi, please review","m.mentions":{"user_ids":[me.clone()]}}})).unwrap().cast_unchecked::<AnySyncTimelineEvent>())
                    .set_unread_notifications_count(serde_json::json!({"notification_count":2,"highlight_count":1})),
            );
        })
        .await;
    let rooms = chat.rooms().await;
    assert_eq!(rooms.len(), 1);
    assert_eq!((rooms[0].notifications, rooms[0].highlights), (2, 1));
    assert_eq!(ou_chat::rooms::badge_count(&rooms), 2);
    let n = notes.0.lock().unwrap().clone();
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].highlight);
    assert_eq!(n[0].preview.as_deref(), Some("Hi, please review"));
    assert_eq!(n[0].sender, "@bob:example.org");

    eprintln!("t synced {:?}", t0.elapsed());
    // Send text (the SDK checks the room's encryption state first).
    server.mock_room_state_encryption().plain().mount().await;
    server.mock_room_send().ok(event_id!("$sent1")).mock_once().mount().await;
    assert_eq!(chat.send_text(room.as_str(), "On it").await.unwrap(), "$sent1");
    assert!(matches!(chat.send_text(room.as_str(), "   ").await, Err(ChatError::Refused(_))));
    assert!(matches!(chat.send_text("!nope:example.org", "x").await, Err(ChatError::NoSuchRoom)));

    // Attachment: limit enforced locally, upload captured, then a file event.
    server.mock_authenticated_media_config().ok(uint!(64)).mount().await;
    assert!(matches!(chat.send_file(room.as_str(), "big.bin", None, vec![0; 65]).await, Err(ChatError::TooLarge { limit: 64 })));
    let (rx, upload) = server.mock_upload().expect_mime_type("text/plain").ok_with_capture(mxc_uri!("mxc://example.org/file1"));
    upload.mock_once().mount().await;
    server.mock_room_send().ok(event_id!("$file1")).mock_once().mount().await;
    assert_eq!(chat.send_file(room.as_str(), "..\\notes.txt", None, b"hello file".to_vec()).await.unwrap(), "$file1");
    assert_eq!(rx.await.unwrap(), b"hello file");

    eprintln!("t attached {:?}", t0.elapsed());
    // Search (unencrypted room -> server search).
    Mock::given(method("POST"))
        .and(path("/_matrix/client/v3/search"))
        .and(body_partial_json(serde_json::json!({"search_categories":{"room_events":{"search_term":"review"}}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"search_categories":{"room_events":{"count":1,"results":[{"rank":1.0,
            "result":{"type":"m.room.message","event_id":"$m1","room_id":"!team:example.org","sender":"@bob:example.org","origin_server_ts":1700000000000u64,
            "content":{"msgtype":"m.text","body":"Hi, please review"}}}]}}})))
        .expect(1)
        .mount(server.server())
        .await;
    let res = chat.search("review", &[]).await.unwrap();
    assert_eq!(res.total, Some(1));
    assert_eq!(res.hits.len(), 1);
    assert_eq!(res.hits[0].event_id, "$m1");
    assert!(res.not_searched.is_empty());

    // Sign-out: revocation at MAS, credentials and the device store removed.
    server.oauth().mock_revocation().ok().mount().await;
    chat.sign_out().await.unwrap();
    let s = AccountSecrets::new(store.as_ref(), "acct1").unwrap();
    assert!(s.get(auth::SESSION_SECRET).unwrap().is_none());
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "device store deleted");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_session_signals_signed_out_and_keeps_the_store() {
    let server = MatrixMockServer::new().await;
    mount_auth(&server).await;
    let dir = tmpdir();
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let chat = ChatClient::sign_in(account(&server, &dir), ou_core::http::test_client(), store.clone(), Duration::from_secs(20), fake_browser(Arc::new(Mutex::new(None))))
        .await
        .unwrap();
    let signed_out = Arc::new(AtomicUsize::new(0));
    let so = signed_out.clone();
    chat.watch_session(Arc::new(move || {
        so.fetch_add(1, Ordering::SeqCst);
    }));

    // Admin revoked the device: the access token is unknown and the refresh token is refused.
    server.mock_sync().error_unknown_token(false).mount().await;
    server.oauth().mock_token().invalid_grant().with_priority(1).mount().await;
    assert!(chat.sync_once(Duration::from_secs(0)).await.is_err());
    for _ in 0..50 {
        if signed_out.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(signed_out.load(Ordering::SeqCst), 1);
    let s = AccountSecrets::new(store.as_ref(), "acct1").unwrap();
    assert!(s.get(auth::SESSION_SECRET).unwrap().is_none(), "dead tokens forgotten");
    assert!(std::fs::read_dir(&dir).unwrap().next().is_some(), "encrypted store kept (room keys)");
    assert!(ChatClient::restore(account(&server, &dir), ou_core::http::test_client(), store.clone()).await.unwrap().is_none(), "asks for sign-in");
    drop(chat);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn second_sign_in_reuses_the_registered_client() {
    let server = MatrixMockServer::new().await;
    mount_auth(&server).await; // registration expect(1) is verified when the server drops
    let dir = tmpdir();
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    for _ in 0..2 {
        let c = ChatClient::sign_in(account(&server, &dir), ou_core::http::test_client(), store.clone(), Duration::from_secs(20), fake_browser(Arc::new(Mutex::new(None))))
            .await
            .unwrap();
        drop(c);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_failure_cleans_up() {
    let server = MatrixMockServer::new().await;
    server.mock_versions().ok().mount().await;
    server.oauth().mock_server_metadata().ok().mount().await;
    server.oauth().mock_registration().ok().mount().await;
    let dir = tmpdir();
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let r = ChatClient::sign_in(account(&server, &dir), ou_core::http::test_client(), store.clone(), Duration::from_secs(5), |_| Err("no browser".into())).await;
    assert!(matches!(r, Err(ChatError::Login(_))));
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "no half-created device store");
    std::fs::remove_dir_all(&dir).unwrap();
}
