//! Live protocol test against a real deployment (officeunbound8). Ignored by default; run with
//!   OU_CHAT_LIVE=1 OU_TEST_DOMAIN=officeunbound.com OU_TEST_USER=doctest OU_TEST_PASSWORD_FILE=... \
//!   cargo test -p ou-chat --test live_matrix -- --ignored --nocapture
//! Creates only `[OU-TEST]` rooms; redacts its messages, leaves and forgets the rooms, signs the device out.
//! The "browser" is tests/live/mas_browser.py (MAS -> Keycloak -> MAS consent -> loopback).

use std::sync::Arc;
use std::time::Duration;

use ou_chat::messages::Body;
use ou_chat::{ChatAccount, ChatClient};
use ou_core::secrets::{MemoryStore, SecretStore};
use url::Url;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live deployment; needs OU_CHAT_LIVE=1 and the test account"]
async fn live_sign_in_room_send_receive_attach_cleanup() {
    if std::env::var("OU_CHAT_LIVE").as_deref() != Ok("1") {
        eprintln!("SKIP: OU_CHAT_LIVE not set");
        return;
    }
    let domain = env("OU_TEST_DOMAIN");
    let dir = std::env::temp_dir().join(format!("ou-chat-live-{}", ou_core::oidc::random_token(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let account = ChatAccount {
        account_id: "live1".into(),
        homeserver: Url::parse(&format!("https://matrix.{domain}/")).unwrap(),
        client_uri: Url::parse(&format!("https://app.{domain}/")).unwrap(),
        data_dir: dir.clone(),
    };
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let http = ou_core::http::client().unwrap(); // production client: https only, verified TLS
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/live/mas_browser.py");

    let t0 = std::time::Instant::now();
    let chat = ChatClient::sign_in(account, http, store.clone(), Duration::from_secs(90), |u| {
        let u = u.to_string();
        std::thread::spawn(move || {
            let st = std::process::Command::new("python3").arg("-I").arg(script).arg(u).status();
            eprintln!("browser driver exit: {st:?}");
        });
        Ok(())
    })
    .await
    .expect("sign-in");
    eprintln!("signed in as {} device {} in {:?}", chat.user_id().unwrap(), chat.device_id().unwrap(), t0.elapsed());

    chat.sync_once(Duration::from_secs(0)).await.expect("initial sync");
    eprintln!("rooms after initial sync: {}; recovery: {:?}", chat.rooms().await.len(), chat.recovery_state());

    let stamp = ou_core::oidc::now();
    let enc_room = chat.create_room(&format!("[OU-TEST] desktop chat e2ee {stamp}"), true, &[]).await.expect("create encrypted room");
    let plain_room = chat.create_room(&format!("[OU-TEST] desktop chat search {stamp}"), false, &[]).await.expect("create plain room");
    chat.sync_once(Duration::from_secs(0)).await.unwrap();
    let rooms = chat.rooms().await;
    let er = rooms.iter().find(|r| r.room_id == enc_room.as_str()).expect("encrypted room listed");
    assert!(er.encrypted, "room is end-to-end encrypted");
    eprintln!("room list ok: {} rooms, test room encrypted={}", rooms.len(), er.encrypted);

    let text = format!("[OU-TEST] hello from ou-chat {stamp}");
    let e1 = chat.send_text(enc_room.as_str(), &text).await.expect("send encrypted text");
    let e2 = chat.send_file(enc_room.as_str(), "ou-test-attachment.txt", Some("text/plain"), b"[OU-TEST] small attachment".to_vec()).await.expect("upload encrypted attachment");
    let marker = format!("ouchatsearch{stamp}");
    let e3 = chat.send_text(plain_room.as_str(), &format!("[OU-TEST] {marker}")).await.expect("send plain text");
    chat.sync_once(Duration::from_secs(1)).await.unwrap();

    let hist = chat.history(enc_room.as_str(), 20).await.expect("history");
    let got_text = hist.iter().find(|m| m.event_id == e1).expect("text in history");
    assert_eq!(got_text.body, Body::Text { body: text.clone() });
    assert!(got_text.encrypted, "came back as an encrypted event and was decrypted locally");
    let got_file = hist.iter().find(|m| m.event_id == e2).expect("file in history");
    let Body::File { attachment } = &got_file.body else { panic!("{:?}", got_file.body) };
    assert!(attachment.encrypted, "attachment uploaded as ciphertext");
    let bytes = chat.download(attachment).await.expect("download + decrypt");
    let by_id = chat.attachment_of(enc_room.as_str(), &e2).await.expect("attachment by event id");
    assert_eq!(chat.download(&by_id).await.unwrap(), bytes);
    assert_eq!(bytes, b"[OU-TEST] small attachment");
    eprintln!("receive ok: text decrypted, attachment {} bytes decrypted", bytes.len());

    // Search: server-side index may lag; try a few times.
    let mut found = false;
    for _ in 0..10 {
        let r = chat.search(&marker, &[plain_room.to_string(), enc_room.to_string()]).await.expect("search");
        assert!(r.not_searched.contains(&enc_room.to_string()));
        if r.hits.iter().any(|h| h.event_id == e3) {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("search ok: {found}");
    assert!(found, "server search finds the message in the unencrypted room");

    // Cleanup: redact our events, leave + forget both rooms, sign the device out.
    for (room, ev) in [(&enc_room, &e1), (&enc_room, &e2), (&plain_room, &e3)] {
        chat.redact(room.as_str(), ev, Some("[OU-TEST] cleanup")).await.expect("redact");
    }
    for room in [&enc_room, &plain_room] {
        chat.leave_and_forget(room.as_str()).await.expect("leave+forget");
    }
    chat.sync_once(Duration::from_secs(0)).await.unwrap();
    assert!(!chat.rooms().await.iter().any(|r| r.room_id == enc_room.as_str() || r.room_id == plain_room.as_str()));
    chat.sign_out().await.expect("sign out");
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("cleanup ok: 3 events redacted, 2 rooms left+forgotten, device signed out");
}
