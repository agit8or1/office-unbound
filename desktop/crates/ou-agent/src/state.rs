//! Agent state and request handling. One `Agent` per user; the GUI is only a client.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ou_core::accounts::{new_account_id, Account, Modules, Registry};
use ou_core::discovery::{self, Deployment};
use ou_core::ipc::{valid_id, AccountStatus, Request, Response, Service, SessionState, PROTOCOL};
use ou_core::oidc::{self, ClientConfig, ProviderMetadata};
use ou_core::secrets::{AccountSecrets, SecretStore};
use ou_core::session::{Session, TokenError, TokenProvider, KEYCLOAK_SECRET};
use ou_core::urlpolicy;
use tokio::sync::Mutex;

use crate::{info, warn};

pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
/// Keycloak offline sessions expire after an idle period (30 days by default); one refresh per 12 h keeps them alive without
/// polling the server more often.
pub const KEEPALIVE: Duration = Duration::from_secs(12 * 3600);
const DISCOVERY_TTL: Duration = Duration::from_secs(600);
pub const SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

struct Live {
    session: Arc<Session>,
    state: SessionState,
    detail: Option<String>,
}

pub struct Agent {
    pub root: PathBuf,
    store: Arc<dyn SecretStore>,
    http: ou_core::reqwest::Client,
    registry: Mutex<Registry>,
    live: Mutex<HashMap<String, Live>>,
    pending: Mutex<HashMap<String, (Deployment, Instant)>>,
    signing_in: Mutex<Option<String>>,
    paused: Mutex<bool>,
    pub shutdown: tokio::sync::Notify,
}

fn http_client() -> ou_core::reqwest::Client {
    #[cfg(feature = "test-support")]
    {
        ou_core::http::test_client()
    }
    #[cfg(not(feature = "test-support"))]
    {
        ou_core::http::client().expect("HTTP client")
    }
}

fn status_of(a: &Account, l: Option<&Live>) -> AccountStatus {
    let mut services = vec![Service::Portal, Service::Files];
    if a.deployment.chat_web_url.is_some() && a.modules.chat {
        services.push(Service::Chat);
    }
    if a.deployment.mail_web_url.is_some() {
        services.extend([Service::Mail, Service::Calendar, Service::Contacts]);
    }
    AccountStatus {
        id: a.id.clone(),
        label: a.label.clone(),
        deployment: a.deployment.name.clone(),
        domain: a.deployment.domain.clone(),
        state: l.map(|l| l.state).unwrap_or(SessionState::SignedOut),
        detail: l.and_then(|l| l.detail.clone()),
        services,
        files_url: a.deployment.files_url.clone(),
    }
}

pub fn service_url(a: &Account, s: Service) -> Option<String> {
    let d = &a.deployment;
    match s {
        Service::Portal => d.portal_url.clone(),
        Service::Files => Some(d.files_url.clone()),
        Service::Chat => d.chat_web_url.clone(),
        Service::Mail => d.mail_web_url.clone(),
        // grommunio-web serves calendar and contacts inside the webmail app.
        Service::Calendar | Service::Contacts => d.mail_web_url.clone(),
    }
}

impl Agent {
    pub fn new(root: PathBuf, store: Arc<dyn SecretStore>) -> Result<Arc<Self>, String> {
        let registry = Registry::load(&root).map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            root,
            store,
            http: http_client(),
            registry: Mutex::new(registry),
            live: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            signing_in: Mutex::new(None),
            paused: Mutex::new(false),
            shutdown: tokio::sync::Notify::new(),
        }))
    }

    /// At start: rebuild sessions for accounts that have a stored refresh token and check each once.
    pub async fn restore(self: &Arc<Self>) {
        let accounts = self.registry.lock().await.accounts.clone();
        for a in accounts {
            let me = self.clone();
            tokio::spawn(async move { me.check_account(&a).await });
        }
    }

    async fn check_account(&self, a: &Account) {
        let has = AccountSecrets::new(self.store.as_ref(), &a.id).ok().and_then(|s| s.get(KEYCLOAK_SECRET).ok().flatten()).is_some();
        if !has {
            return;
        }
        let meta = match ProviderMetadata::discover(&self.http, &a.deployment.issuer).await {
            Ok(m) => m,
            Err(e) => {
                warn!("account {}: identity provider unreachable: {e}", a.id);
                self.set_live_state(a, None, SessionState::Offline, Some("server unreachable, retrying".into())).await;
                return;
            }
        };
        let session = Arc::new(Session::new(&a.id, KEYCLOAK_SECRET, &a.deployment.client_id, meta, a.origins(), self.http.clone(), self.store.clone()));
        let files = url::Url::parse(&a.deployment.files_url).expect("validated at discovery");
        let (state, detail) = match session.access_token(&files).await {
            Ok(_) => (SessionState::SignedIn, None),
            Err(TokenError::SignedOut) => (SessionState::SignedOut, Some("sign in again".into())),
            Err(TokenError::Offline(e)) => (SessionState::Offline, Some(e)),
            Err(e) => (SessionState::Error, Some(e.to_string())),
        };
        info!("account {}: {:?}", a.id, state);
        self.set_live_state(a, Some(session), state, detail).await;
    }

    async fn set_live_state(&self, a: &Account, session: Option<Arc<Session>>, state: SessionState, detail: Option<String>) {
        let mut live = self.live.lock().await;
        match (live.get_mut(&a.id), session) {
            (Some(l), Some(s)) => {
                l.session = s;
                l.state = state;
                l.detail = detail;
            }
            (Some(l), None) => {
                l.state = state;
                l.detail = detail;
            }
            (None, Some(s)) => {
                live.insert(a.id.clone(), Live { session: s, state, detail });
            }
            (None, None) => {}
        }
    }

    /// Periodic keep-alive (one refresh per account every KEEPALIVE); no other background polling.
    pub async fn keepalive_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(KEEPALIVE);
        tick.tick().await;
        loop {
            tick.tick().await;
            if *self.paused.lock().await {
                continue;
            }
            let accounts = self.registry.lock().await.accounts.clone();
            for a in accounts {
                self.check_account(&a).await;
            }
        }
    }

    pub async fn status(&self) -> Response {
        let reg = self.registry.lock().await;
        let live = self.live.lock().await;
        let signing = self.signing_in.lock().await.clone();
        let mut accounts: Vec<AccountStatus> = reg.accounts.iter().map(|a| status_of(a, live.get(&a.id))).collect();
        if let Some(name) = signing {
            accounts.push(AccountStatus {
                id: String::new(),
                label: name.clone(),
                deployment: name,
                domain: String::new(),
                state: SessionState::SigningIn,
                detail: Some("finish signing in in your browser".into()),
                services: vec![],
                files_url: String::new(),
            });
        }
        Response::Status { accounts, paused: *self.paused.lock().await, agent: ou_core::VERSION.into() }
    }

    async fn discover(&self, input: &str) -> Response {
        let d = match self.discover_inner(input).await {
            Ok(d) => d,
            Err(e) => return Response::Error { message: e },
        };
        let id = new_account_id();
        let mut p = self.pending.lock().await;
        p.retain(|_, (_, t)| t.elapsed() < DISCOVERY_TTL);
        p.insert(id.clone(), (d.clone(), Instant::now()));
        Response::Discovered { discovery_id: id, deployment: d }
    }

    async fn discover_inner(&self, input: &str) -> Result<Deployment, String> {
        #[cfg(feature = "test-support")]
        if let Ok(j) = std::env::var("OU_TEST_DISCOVERY_JSON") {
            return serde_json::from_str(&j).map_err(|e| e.to_string());
        }
        let parsed = discovery::parse_input(input).map_err(|e| e.to_string())?;
        discovery::discover(&discovery::HttpFetcher(self.http.clone()), &parsed).await.map_err(|e| e.to_string())
    }

    async fn sign_in(self: &Arc<Self>, discovery_id: &str) -> Response {
        let Some((d, _)) = self.pending.lock().await.remove(discovery_id) else {
            return Response::Error { message: "this sign-in request expired; enter your address again".into() };
        };
        {
            let mut s = self.signing_in.lock().await;
            if s.is_some() {
                return Response::Error { message: "another sign-in is in progress".into() };
            }
            *s = Some(d.name.clone());
        }
        let me = self.clone();
        tokio::spawn(async move {
            let r = me.sign_in_flow(d).await;
            *me.signing_in.lock().await = None;
            match r {
                Ok(id) => info!("account {id}: signed in"),
                Err(e) => warn!("sign-in failed: {e}"),
            }
        });
        Response::SignInStarted
    }

    async fn sign_in_flow(&self, d: Deployment) -> Result<String, String> {
        let meta = ProviderMetadata::discover(&self.http, &d.issuer).await.map_err(|e| e.to_string())?;
        let client = ClientConfig { client_id: d.client_id.clone(), scopes: SCOPES.iter().map(|s| s.to_string()).collect() };
        let (tokens, claims) =
            oidc::sign_in(&self.http, &meta, &client, d.login_hint.as_deref(), SIGN_IN_TIMEOUT, crate::browser::open).await.map_err(|e| e.to_string())?;
        let claims = claims.ok_or("the identity provider returned no ID token")?;
        let label = claims.email.clone().or(claims.preferred_username.clone()).unwrap_or_else(|| claims.sub.clone());
        let mut reg = self.registry.lock().await;
        // Same person signing in again: reuse the account (keeps its sync settings), new tokens.
        let account = match reg.accounts.iter().find(|a| a.deployment.issuer == d.issuer && a.subject == claims.sub) {
            Some(a) => a.clone(),
            None => {
                let a = Account {
                    id: new_account_id(),
                    deployment: d,
                    subject: claims.sub.clone(),
                    label,
                    created_at: oidc::now(),
                    modules: Modules::default(),
                    sync_root: None,
                };
                reg.add(a.clone()).map_err(|e| e.to_string())?;
                reg.save(&self.root).map_err(|e| e.to_string())?;
                a
            }
        };
        drop(reg);
        let session = Arc::new(Session::new(&account.id, KEYCLOAK_SECRET, &account.deployment.client_id, meta, account.origins(), self.http.clone(), self.store.clone()));
        session.adopt(tokens).await.map_err(|e| e.to_string())?;
        let mut live = self.live.lock().await;
        live.insert(account.id.clone(), Live { session, state: SessionState::SignedIn, detail: None });
        Ok(account.id)
    }

    async fn account(&self, id: &str) -> Option<Account> {
        if !valid_id(id) {
            return None;
        }
        self.registry.lock().await.get(id).cloned()
    }

    async fn sign_out(&self, id: &str) -> Response {
        let Some(a) = self.account(id).await else { return Response::Error { message: "unknown account".into() } };
        let session = self.live.lock().await.get(&a.id).map(|l| l.session.clone());
        match session {
            Some(s) => {
                if let Err(e) = s.sign_out().await {
                    return Response::Error { message: e.to_string() };
                }
            }
            None => {
                let _ = AccountSecrets::new(self.store.as_ref(), &a.id).map(|s| s.delete(KEYCLOAK_SECRET));
            }
        }
        self.set_live_state(&a, None, SessionState::SignedOut, Some("signed out".into())).await;
        info!("account {}: signed out", a.id);
        Response::Ok
    }

    /// Removes the account from this computer: signs out, deletes its secrets and its cache directory. The user's sync folder is
    /// never deleted by the app (brief: no promise of remote/local wipe without a verified feature).
    async fn remove(&self, id: &str) -> Response {
        let Some(a) = self.account(id).await else { return Response::Error { message: "unknown account".into() } };
        let _ = self.sign_out(id).await;
        if let Ok(s) = AccountSecrets::new(self.store.as_ref(), &a.id) {
            let _ = s.purge();
        }
        self.live.lock().await.remove(&a.id);
        let mut reg = self.registry.lock().await;
        let _ = reg.remove(&a.id);
        if let Err(e) = reg.save(&self.root) {
            return Response::Error { message: e.to_string() };
        }
        let dir = a.data_dir(&self.root);
        if dir.starts_with(self.root.join("accounts")) {
            let _ = std::fs::remove_dir_all(dir);
        }
        info!("account {}: removed", a.id);
        Response::Ok
    }

    async fn open_service(&self, id: &str, s: Service) -> Response {
        let Some(a) = self.account(id).await else { return Response::Error { message: "unknown account".into() } };
        let Some(u) = service_url(&a, s) else { return Response::Error { message: "this service is not available".into() } };
        self.open_external(&a, &u)
    }

    fn open_external(&self, a: &Account, raw: &str) -> Response {
        match urlpolicy::open_external(raw, &a.origins()) {
            Ok(u) => match crate::browser::open(&u) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error { message: e },
            },
            Err(e) => Response::Error { message: e.to_string() },
        }
    }

    pub async fn handle(self: &Arc<Self>, req: Request) -> Response {
        match req {
            Request::Hello { protocol, .. } => {
                if protocol != PROTOCOL {
                    return Response::Error { message: format!("protocol {protocol} not supported (agent speaks {PROTOCOL})") };
                }
                Response::Hello { protocol: PROTOCOL, agent: ou_core::VERSION.into() }
            }
            Request::Status {} => self.status().await,
            Request::Discover { input } => self.discover(&input).await,
            Request::SignIn { discovery_id } => self.sign_in(&discovery_id).await,
            Request::SignOut { account_id } => self.sign_out(&account_id).await,
            Request::RemoveAccount { account_id } => self.remove(&account_id).await,
            Request::OpenService { account_id, service } => self.open_service(&account_id, service).await,
            Request::OpenExternal { account_id, url } => match self.account(&account_id).await {
                Some(a) => self.open_external(&a, &url),
                None => Response::Error { message: "unknown account".into() },
            },
            Request::SetPaused { paused } => {
                *self.paused.lock().await = paused;
                Response::Ok
            }
            Request::Shutdown {} => {
                self.shutdown.notify_one();
                Response::Ok
            }
        }
    }
}
