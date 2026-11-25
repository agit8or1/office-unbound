//! Account discovery: from a work e-mail address or a server URL to a verified Office Unbound deployment (ADR-0022 section 5).
//!
//! No new DNS record is needed. Order of attempts, all over HTTPS with full certificate validation:
//!   1. `https://autodiscover.<domain>/.well-known/office-unbound/client.json` - the client document, served by the deployment's
//!      gateway on the name every tenant already publishes for mail autodiscover (proposal: gateway route, ADR-0022).
//!   2. OpenCloud WebFinger on `https://cloud.<domain>` (works today; returns the OIDC issuer for `acct:<email>`).
//!   3. For a URL: the same two documents on the host the user typed.
//! Plain DNS (TXT/SRV) is never used to choose the server. The result is always shown to the user for confirmation before the
//! browser opens, and every service host must be the domain itself or a subdomain of it, otherwise it is flagged.

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DiscoveryError {
    #[error("enter a work e-mail address (name@company.com) or a server address (https://cloud.company.com)")]
    BadInput,
    #[error("no Office Unbound deployment was found for {0}")]
    NotFound(String),
    #[error("the deployment answered with an invalid document: {0}")]
    Invalid(String),
}

/// Fetches JSON over the verified HTTPS client. A trait so unit tests can run without a network.
#[allow(async_fn_in_trait)]
pub trait Fetcher {
    /// Ok(None) for 404/410 and other "not here" answers; Err for transport errors.
    async fn get_json(&self, url: &Url) -> Result<Option<serde_json::Value>, String>;
}

pub struct HttpFetcher(pub reqwest::Client);

impl Fetcher for HttpFetcher {
    async fn get_json(&self, url: &Url) -> Result<Option<serde_json::Value>, String> {
        crate::http::require_allowed(url).map_err(|e| e.to_string())?;
        let r = self.0.get(url.clone()).header("Accept", "application/json, application/jrd+json").send().await.map_err(|e| {
            crate::redact::redact(&e.to_string())
        })?;
        if !r.status().is_success() {
            return Ok(None);
        }
        // Bound the size: discovery documents are tiny.
        let bytes = r.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("discovery document too large".into());
        }
        Ok(serde_json::from_slice(&bytes).ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Email { user: String, domain: String },
    Server { url: Url, domain: String },
}

fn valid_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !l.starts_with('-'))
}

/// The parent domain used for service names: `cloud.company.com` -> `company.com`; a bare `company.com` stays.
fn parent_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() > 2 {
        labels[1..].join(".")
    } else {
        host.to_string()
    }
}

pub fn parse_input(raw: &str) -> Result<Input, DiscoveryError> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 320 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(DiscoveryError::BadInput);
    }
    if !s.contains("://") {
        if let Some((user, domain)) = s.rsplit_once('@') {
            let domain = domain.to_ascii_lowercase();
            if user.is_empty() || user.contains('/') || !valid_domain(&domain) {
                return Err(DiscoveryError::BadInput);
            }
            return Ok(Input::Email { user: user.to_string(), domain });
        }
    }
    let with_scheme = if s.contains("://") { s.to_string() } else { format!("https://{s}") };
    let url = Url::parse(&with_scheme).map_err(|_| DiscoveryError::BadInput)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(DiscoveryError::BadInput);
    }
    let host = url.host_str().ok_or(DiscoveryError::BadInput)?.to_ascii_lowercase();
    if !valid_domain(&host) {
        return Err(DiscoveryError::BadInput);
    }
    let base = Url::parse(&format!("https://{host}{}/", url.port().map(|p| format!(":{p}")).unwrap_or_default())).unwrap();
    Ok(Input::Server { domain: parent_domain(&host), url: base })
}

/// The client document (`/.well-known/office-unbound/client.json`). Schema version 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientDocument {
    pub version: u32,
    #[serde(default)]
    pub name: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub files: String,
    #[serde(default)]
    pub portal: Option<String>,
    #[serde(default)]
    pub matrix: Option<String>,
    /// Webmail / calendar / contacts web app.
    #[serde(default)]
    pub mail: Option<String>,
    /// Chat web app (Element), for "open in browser".
    #[serde(default)]
    pub chat_web: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    ClientDocument,
    WebFinger,
}

/// A verified deployment proposal, shown to the user before sign-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Deployment {
    pub domain: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub files_url: String,
    pub portal_url: Option<String>,
    pub matrix_url: Option<String>,
    #[serde(default)]
    pub chat_web_url: Option<String>,
    #[serde(default)]
    pub mail_web_url: Option<String>,
    pub source: Source,
    pub login_hint: Option<String>,
    /// Hosts outside `domain` (allowed only after explicit confirmation; shown in the UI).
    pub foreign_hosts: Vec<String>,
}

/// Default client of every catalog realm today (public, PKCE S256, loopback). A dedicated `ou-desktop` client is proposed
/// (ADR-0022, owner decision) and is announced through the client document once it exists.
pub const FALLBACK_CLIENT_ID: &str = "OpenCloudDesktop";

fn https_url(s: &str, what: &str) -> Result<Url, DiscoveryError> {
    let u = Url::parse(s).map_err(|_| DiscoveryError::Invalid(format!("{what} is not a URL")))?;
    if !crate::http::allowed_scheme(&u) || !u.username().is_empty() {
        return Err(DiscoveryError::Invalid(format!("{what} must be https")));
    }
    Ok(u)
}

fn in_domain(host: &str, domain: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == domain || h.ends_with(&format!(".{domain}"))
}

fn base_of(domain: &str, sub: &str) -> Url {
    Url::parse(&format!("https://{sub}.{domain}/")).expect("valid domain")
}

fn finish(domain: &str, doc: ClientDocument, source: Source, login_hint: Option<String>) -> Result<Deployment, DiscoveryError> {
    let mut foreign = vec![];
    let mut check = |s: &str, what: &str| -> Result<String, DiscoveryError> {
        let u = https_url(s, what)?;
        let h = u.host_str().unwrap_or("").to_string();
        if !in_domain(&h, domain) && !crate::http::is_loopback(&u) && !foreign.contains(&h) {
            foreign.push(h);
        }
        Ok(u.to_string())
    };
    let issuer = check(&doc.issuer, "issuer")?.trim_end_matches('/').to_string();
    // Keep the issuer exactly as published: OIDC requires an exact match.
    let issuer = if doc.issuer.ends_with('/') { format!("{issuer}/") } else { issuer };
    let files_url = check(&doc.files, "files")?;
    let portal_url = doc.portal.as_deref().map(|p| check(p, "portal")).transpose()?;
    let matrix_url = doc.matrix.as_deref().map(|m| check(m, "matrix")).transpose()?;
    let chat_web_url = doc.chat_web.as_deref().map(|m| check(m, "chat_web")).transpose()?;
    let mail_web_url = doc.mail.as_deref().map(|m| check(m, "mail")).transpose()?;
    if doc.client_id.is_empty() || doc.client_id.len() > 128 || !doc.client_id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return Err(DiscoveryError::Invalid("client_id".into()));
    }
    Ok(Deployment {
        domain: domain.to_string(),
        name: doc.name.filter(|n| !n.is_empty() && n.len() <= 80).unwrap_or_else(|| domain.to_string()),
        issuer,
        client_id: doc.client_id,
        files_url,
        portal_url,
        matrix_url,
        chat_web_url,
        mail_web_url,
        source,
        login_hint,
        foreign_hosts: foreign,
    })
}

fn parse_client_doc(v: serde_json::Value) -> Result<ClientDocument, DiscoveryError> {
    let d: ClientDocument = serde_json::from_value(v).map_err(|_| DiscoveryError::Invalid("client document".into()))?;
    if d.version != 1 {
        return Err(DiscoveryError::Invalid(format!("unsupported client document version {}", d.version)));
    }
    Ok(d)
}

const ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";

fn webfinger_url(base: &Url, resource: &str) -> Url {
    let mut u = base.join(".well-known/webfinger").unwrap();
    u.query_pairs_mut().append_pair("resource", resource).append_pair("rel", ISSUER_REL);
    u
}

fn webfinger_issuer(v: &serde_json::Value, resource: &str) -> Option<String> {
    if v.get("subject").and_then(|s| s.as_str()) != Some(resource) {
        return None;
    }
    v.get("links")?.as_array()?.iter().find_map(|l| {
        (l.get("rel")?.as_str()? == ISSUER_REL).then(|| l.get("href")?.as_str().map(str::to_string)).flatten()
    })
}

async fn matrix_base(f: &impl Fetcher, domain: &str) -> Option<String> {
    // Matrix client discovery on the homeserver name used by Office Unbound deployments (matrix.<domain>), then the domain.
    for base in [base_of(domain, "matrix"), Url::parse(&format!("https://{domain}/")).ok()?] {
        let u = base.join(".well-known/matrix/client").ok()?;
        if let Ok(Some(v)) = f.get_json(&u).await {
            if let Some(b) = v.pointer("/m.homeserver/base_url").and_then(|b| b.as_str()) {
                return Some(b.to_string());
            }
        }
    }
    None
}

/// Runs discovery. `Err(NotFound)` when no candidate answered with a valid document.
pub async fn discover(f: &impl Fetcher, input: &Input) -> Result<Deployment, DiscoveryError> {
    let (domain, hint, bases, resource) = match input {
        Input::Email { user, domain } => {
            let r = format!("acct:{user}@{domain}");
            (domain.clone(), Some(format!("{user}@{domain}")), vec![base_of(domain, "autodiscover"), base_of(domain, "cloud")], r)
        }
        Input::Server { url, domain } => {
            let r = url.as_str().trim_end_matches('/').to_string();
            (domain.clone(), None, vec![url.clone(), base_of(domain, "autodiscover")], r)
        }
    };
    let mut last_err = None;
    // 1. Client document.
    for b in &bases {
        let u = b.join(".well-known/office-unbound/client.json").unwrap();
        match f.get_json(&u).await {
            Ok(Some(v)) => match parse_client_doc(v).and_then(|d| finish(&domain, d, Source::ClientDocument, hint.clone())) {
                Ok(d) => return Ok(d),
                Err(e) => last_err = Some(e),
            },
            Ok(None) => {}
            Err(_) => {}
        }
    }
    // 2. OpenCloud WebFinger (files host).
    let wf_bases: Vec<Url> = match input {
        Input::Email { domain, .. } => vec![base_of(domain, "cloud")],
        Input::Server { url, .. } => vec![url.clone()],
    };
    for b in wf_bases {
        if let Ok(Some(v)) = f.get_json(&webfinger_url(&b, &resource)).await {
            if let Some(issuer) = webfinger_issuer(&v, &resource) {
                let matrix = matrix_base(f, &domain).await;
                let portal = base_of(&domain, "app").to_string();
                let doc = ClientDocument {
                    version: 1,
                    name: None,
                    issuer,
                    client_id: FALLBACK_CLIENT_ID.into(),
                    files: b.to_string(),
                    portal: Some(portal),
                    chat_web: matrix.as_ref().map(|_| base_of(&domain, "chat").to_string()),
                    matrix,
                    mail: Some(base_of(&domain, "mail").to_string()),
                };
                return finish(&domain, doc, Source::WebFinger, hint);
            }
        }
    }
    Err(last_err.unwrap_or(DiscoveryError::NotFound(domain)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake(HashMap<String, serde_json::Value>);
    impl Fetcher for Fake {
        async fn get_json(&self, url: &Url) -> Result<Option<serde_json::Value>, String> {
            Ok(self.0.get(url.as_str()).cloned())
        }
    }

    #[test]
    fn parses_inputs() {
        assert_eq!(parse_input(" Doc@Company.COM ").unwrap(), Input::Email { user: "Doc".into(), domain: "company.com".into() });
        match parse_input("cloud.company.com").unwrap() {
            Input::Server { url, domain } => {
                assert_eq!(url.as_str(), "https://cloud.company.com/");
                assert_eq!(domain, "company.com");
            }
            _ => panic!(),
        }
        assert_eq!(parse_input("http://cloud.company.com"), Err(DiscoveryError::BadInput), "plain http refused");
        assert_eq!(parse_input("https://u:p@cloud.company.com"), Err(DiscoveryError::BadInput));
        assert_eq!(parse_input("doc@localhost"), Err(DiscoveryError::BadInput));
        assert_eq!(parse_input("a b@c.com"), Err(DiscoveryError::BadInput));
        assert_eq!(parse_input("file:///etc/passwd"), Err(DiscoveryError::BadInput));
        assert_eq!(parse_input(""), Err(DiscoveryError::BadInput));
    }

    fn wf(resource: &str, issuer: &str) -> serde_json::Value {
        serde_json::json!({"subject": resource, "links": [{"rel": ISSUER_REL, "href": issuer}]})
    }

    #[tokio::test]
    async fn webfinger_path_like_officeunbound8() {
        let mut m = HashMap::new();
        m.insert(
            "https://cloud.company.com/.well-known/webfinger?resource=acct%3Adoc%40company.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer".into(),
            wf("acct:doc@company.com", "https://auth.company.com/realms/ou"),
        );
        m.insert(
            "https://matrix.company.com/.well-known/matrix/client".into(),
            serde_json::json!({"m.homeserver": {"base_url": "https://matrix.company.com"}}),
        );
        let d = discover(&Fake(m), &parse_input("doc@company.com").unwrap()).await.unwrap();
        assert_eq!(d.source, Source::WebFinger);
        assert_eq!(d.issuer, "https://auth.company.com/realms/ou");
        assert_eq!(d.client_id, FALLBACK_CLIENT_ID);
        assert_eq!(d.files_url, "https://cloud.company.com/");
        assert_eq!(d.matrix_url.as_deref(), Some("https://matrix.company.com/"));
        assert_eq!(d.login_hint.as_deref(), Some("doc@company.com"));
        assert!(d.foreign_hosts.is_empty());
    }

    #[tokio::test]
    async fn client_document_wins_and_flags_foreign_hosts() {
        let mut m = HashMap::new();
        m.insert(
            "https://autodiscover.company.com/.well-known/office-unbound/client.json".into(),
            serde_json::json!({"version": 1, "name": "Company", "issuer": "https://auth.company.com/realms/ou", "client_id": "ou-desktop",
                "files": "https://cloud.company.com", "matrix": "https://matrix.elsewhere.example"}),
        );
        let d = discover(&Fake(m), &parse_input("doc@company.com").unwrap()).await.unwrap();
        assert_eq!(d.source, Source::ClientDocument);
        assert_eq!(d.client_id, "ou-desktop");
        assert_eq!(d.name, "Company");
        assert_eq!(d.foreign_hosts, vec!["matrix.elsewhere.example".to_string()]);
    }

    #[tokio::test]
    async fn rejects_bad_documents() {
        let mut m = HashMap::new();
        m.insert(
            "https://autodiscover.company.com/.well-known/office-unbound/client.json".into(),
            serde_json::json!({"version": 1, "issuer": "http://auth.company.com/realms/ou", "client_id": "x", "files": "https://cloud.company.com"}),
        );
        assert!(matches!(discover(&Fake(m), &parse_input("doc@company.com").unwrap()).await, Err(DiscoveryError::Invalid(_))));
        // WebFinger answer for another subject is ignored.
        let mut m = HashMap::new();
        m.insert(
            "https://cloud.company.com/.well-known/webfinger?resource=acct%3Adoc%40company.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer".into(),
            wf("acct:someone@else.com", "https://auth.evil.example/"),
        );
        assert_eq!(discover(&Fake(m), &parse_input("doc@company.com").unwrap()).await, Err(DiscoveryError::NotFound("company.com".into())));
        assert_eq!(discover(&Fake(HashMap::new()), &parse_input("doc@company.com").unwrap()).await, Err(DiscoveryError::NotFound("company.com".into())));
    }

    #[tokio::test]
    async fn server_url_input() {
        let mut m = HashMap::new();
        m.insert(
            "https://cloud.company.com/.well-known/webfinger?resource=https%3A%2F%2Fcloud.company.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer".into(),
            wf("https://cloud.company.com", "https://auth.company.com/realms/ou"),
        );
        let d = discover(&Fake(m), &parse_input("https://cloud.company.com/apps/files").unwrap()).await.unwrap();
        assert_eq!(d.files_url, "https://cloud.company.com/");
        assert_eq!(d.login_hint, None);
    }
}
