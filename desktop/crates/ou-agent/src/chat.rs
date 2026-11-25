//! Chat in the agent: one `ou_chat::ChatClient` per account, its sync loop, notifications and badge as GUI events. Chat is
//! independent of file sync and of the Keycloak session object: it has its own MAS session, owned by matrix-sdk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ou_chat::notify::{ChatNotification, Notifier};
use ou_chat::{ChatAccount, ChatClient};
use ou_core::accounts::Account;
use ou_core::ipc::{valid_event_id, valid_room_id, Event, Response, SessionState};
use ou_core::secrets::SecretStore;
use tokio::sync::Mutex;

use crate::events::Events;
use crate::{info, warn};

const MAX_BODY: usize = 32 * 1024;

#[derive(Default)]
pub struct ChatHub {
    clients: Mutex<HashMap<String, Arc<ChatClient>>>,
    state: Mutex<HashMap<String, SessionState>>,
}

fn err(m: impl std::fmt::Display) -> Response {
    Response::Error { message: m.to_string() }
}

pub fn chat_account(a: &Account, root: &Path) -> Option<ChatAccount> {
    let hs = url::Url::parse(a.deployment.matrix_url.as_deref()?).ok()?;
    let client_uri = url::Url::parse(a.deployment.portal_url.as_deref().unwrap_or(&a.deployment.files_url)).ok()?;
    Some(ChatAccount { account_id: a.id.clone(), homeserver: hs, client_uri, data_dir: a.data_dir(root).join("chat") })
}

fn http() -> Result<ou_chat::matrix_sdk::reqwest::Client, String> {
    // No total timeout: sync is a 30 s long poll and matrix-sdk sets per-request timeouts itself.
    ou_core::http::transfer_client().map_err(|e| e.to_string())
}

struct EventNotifier {
    account_id: String,
    events: Arc<Events>,
}

impl Notifier for EventNotifier {
    fn notify(&self, n: ChatNotification) {
        self.events.push(Event::ChatNotification {
            account_id: self.account_id.clone(),
            notification: serde_json::to_value(&n).unwrap_or_default(),
        });
    }
}

impl ChatHub {
    pub async fn state(&self, account_id: &str) -> Option<SessionState> {
        self.state.lock().await.get(account_id).copied()
    }

    async fn set(&self, id: &str, s: SessionState) {
        self.state.lock().await.insert(id.to_string(), s);
    }

    async fn client(&self, id: &str) -> Result<Arc<ChatClient>, Response> {
        self.clients.lock().await.get(id).cloned().ok_or_else(|| err("not signed in to chat"))
    }

    /// Restores a saved chat session at agent start (no browser).
    pub async fn restore(self: &Arc<Self>, a: &Account, root: &Path, store: Arc<dyn SecretStore>, events: Arc<Events>) {
        let Some(ca) = chat_account(a, root) else { return };
        let http = match http() {
            Ok(h) => h,
            Err(e) => return warn!("chat http client: {e}"),
        };
        match ChatClient::restore(ca, http, store).await {
            Ok(Some(c)) => self.start(a.id.clone(), c, events).await,
            Ok(None) => self.set(&a.id, SessionState::SignedOut).await,
            Err(e) => {
                warn!("account {}: chat restore failed: {e}", a.id);
                self.set(&a.id, SessionState::Error).await;
            }
        }
    }

    pub async fn sign_in(self: &Arc<Self>, a: Account, root: PathBuf, store: Arc<dyn SecretStore>, events: Arc<Events>) -> Response {
        let Some(ca) = chat_account(&a, &root) else { return err("this deployment has no chat") };
        if self.clients.lock().await.contains_key(&a.id) {
            return Response::Ok;
        }
        let http = match http() {
            Ok(h) => h,
            Err(e) => return err(e),
        };
        self.set(&a.id, SessionState::SigningIn).await;
        let me = self.clone();
        tokio::spawn(async move {
            match ChatClient::sign_in(ca, http, store, crate::state::SIGN_IN_TIMEOUT, crate::browser::open).await {
                Ok(c) => {
                    info!("account {}: chat signed in", a.id);
                    me.start(a.id.clone(), c, events.clone()).await;
                    events.push(Event::ChatSignedIn { account_id: a.id.clone() });
                }
                Err(e) => {
                    warn!("account {}: chat sign-in failed: {e}", a.id);
                    me.set(&a.id, SessionState::SignedOut).await;
                }
            }
        });
        Response::SignInStarted
    }

    async fn start(self: &Arc<Self>, id: String, c: ChatClient, events: Arc<Events>) {
        let c = Arc::new(c);
        let (me, ev, id2) = (self.clone(), events.clone(), id.clone());
        c.watch_session(Arc::new(move || {
            let (me, ev, id) = (me.clone(), ev.clone(), id2.clone());
            tokio::spawn(async move {
                me.clients.lock().await.remove(&id);
                me.set(&id, SessionState::SignedOut).await;
                ev.push(Event::ChatSignedOut { account_id: id });
            });
        }));
        c.register_notifier(Arc::new(EventNotifier { account_id: id.clone(), events: events.clone() })).await;
        self.clients.lock().await.insert(id.clone(), c.clone());
        self.set(&id, SessionState::SignedIn).await;
        let me = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(5);
            loop {
                if !me.clients.lock().await.contains_key(&id) {
                    return;
                }
                let res = c.sync_once(Duration::from_secs(30)).await;
                match res {
                    Ok(()) => {
                        backoff = Duration::from_secs(5);
                        me.set(&id, SessionState::SignedIn).await;
                        let rooms = c.rooms().await;
                        events.push(Event::ChatBadge { account_id: id.clone(), count: ou_chat::rooms::badge_count(&rooms) });
                    }
                    Err(e) => {
                        warn!("account {id}: chat sync: {e}");
                        me.set(&id, SessionState::Offline).await;
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(300));
                    }
                }
            }
        });
    }

    pub async fn sign_out(&self, id: &str) -> Response {
        let c = self.clients.lock().await.remove(id);
        self.set(id, SessionState::SignedOut).await;
        match c {
            Some(c) => match Arc::try_unwrap(c) {
                Ok(c) => match c.sign_out().await {
                    Ok(()) => Response::Ok,
                    Err(e) => err(e),
                },
                // The sync task still holds a reference: it ends at its next round; sign out of MAS through the SDK now.
                Err(c) => {
                    let _ = c.sdk().oauth().logout().await;
                    Response::Ok
                }
            },
            None => Response::Ok,
        }
    }

    pub async fn rooms(&self, id: &str) -> Response {
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let mut rooms = c.rooms().await;
        ou_chat::rooms::sort_for_list(&mut rooms);
        let badge = ou_chat::rooms::badge_count(&rooms);
        Response::ChatRooms { rooms: serde_json::to_value(&rooms).unwrap_or_default(), badge }
    }

    pub async fn history(&self, id: &str, room: &str, limit: u32) -> Response {
        if !valid_room_id(room) {
            return err("invalid room");
        }
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        match c.history(room, limit.clamp(1, 200)).await {
            Ok(m) => Response::ChatHistory { messages: serde_json::to_value(&m).unwrap_or_default() },
            Err(e) => err(e),
        }
    }

    pub async fn send(&self, id: &str, room: &str, body: &str) -> Response {
        if !valid_room_id(room) || body.trim().is_empty() || body.len() > MAX_BODY {
            return err("invalid message");
        }
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        match c.send_text(room, body).await {
            Ok(event_id) => Response::ChatSent { event_id },
            Err(e) => err(e),
        }
    }

    /// Uploads a file the user chose. Only a regular file (no directory, device path or link), read once, size-checked first.
    pub async fn send_file(&self, id: &str, room: &str, path: &str) -> Response {
        if !valid_room_id(room) {
            return err("invalid room");
        }
        let p = PathBuf::from(path);
        if !p.is_absolute() || path.starts_with(r"\\.\") || path.starts_with(r"\\?\GLOBALROOT") {
            return err("choose a file on this computer");
        }
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_file() => m,
            _ => return err("not a regular file"),
        };
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        match c.max_upload().await {
            Ok(limit) if meta.len() > limit => return err(format!("file is larger than the server allows ({limit} bytes)")),
            _ => {}
        }
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
        let data = match tokio::fs::read(&p).await {
            Ok(d) => d,
            Err(e) => return err(e),
        };
        match c.send_file(room, &name, None, data).await {
            Ok(event_id) => Response::ChatSent { event_id },
            Err(e) => err(e),
        }
    }

    pub async fn download(&self, id: &str, room: &str, event: &str) -> Response {
        if !valid_room_id(room) || !valid_event_id(event) {
            return err("invalid attachment");
        }
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let dir = downloads_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return err(e);
        }
        let a = match c.attachment_of(room, event).await {
            Ok(a) => a,
            Err(e) => return err(e),
        };
        match c.download_to(&a, &dir).await {
            Ok(p) => Response::ChatDownloaded { path: p.display().to_string() },
            Err(e) => err(e),
        }
    }

    pub async fn search(&self, id: &str, q: &str) -> Response {
        if q.trim().is_empty() || q.len() > 512 {
            return err("invalid search");
        }
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        match c.search(q, &[]).await {
            Ok(r) => Response::ChatSearch { result: serde_json::to_value(&r).unwrap_or_default() },
            Err(e) => err(e),
        }
    }

    pub async fn mark_read(&self, id: &str, room: &str, event: &str) -> Response {
        if !valid_room_id(room) || !valid_event_id(event) {
            return err("invalid event");
        }
        let c = match self.client(id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        match c.mark_read(room, event).await {
            Ok(()) => Response::Ok,
            Err(e) => err(e),
        }
    }

    pub async fn start_meeting(&self, a: &Account, room: &str) -> Response {
        if !valid_room_id(room) {
            return err("invalid room");
        }
        let Some(meet) = a.deployment.meet_url.as_deref().and_then(|m| url::Url::parse(m).ok()) else {
            return err("meetings are not available on this deployment");
        };
        let c = match self.client(&a.id).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        match c.start_meeting(room, &meet, &a.origins(), crate::browser::open).await {
            Ok(u) => Response::ChatMeeting { url: u.to_string() },
            Err(e) => err(e),
        }
    }
}

fn downloads_dir() -> PathBuf {
    #[cfg(windows)]
    if let Ok(p) = std::env::var("USERPROFILE") {
        return PathBuf::from(p).join("Downloads");
    }
    std::env::var("HOME").map(|h| PathBuf::from(h).join("Downloads")).unwrap_or_else(|_| std::env::temp_dir())
}
