//! External-URL and token-audience policy.
//!
//! * `open_external`: the GUI may ask the agent to open a URL in the system browser only if it is https and belongs to one of the
//!   account's deployment origins (or the IdP authorization endpoint during sign-in). No file://, no custom schemes, no
//!   arbitrary sites from chat messages without the user's click being routed through this check.
//! * `may_send_token`: a bearer token is attached only to requests for the origins discovered for that account, so a token of
//!   tenant A is never sent to tenant B or to a third party (tenant isolation, brief section 12).

use url::Url;

/// Exact scheme+host+port origins (no wildcard subdomains).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OriginSet(Vec<String>);

pub fn origin_of(u: &Url) -> Option<String> {
    match u.origin() {
        url::Origin::Tuple(s, h, p) => Some(format!("{s}://{h}:{p}")),
        url::Origin::Opaque(_) => None,
    }
}

impl OriginSet {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, u: &Url) {
        if let Some(o) = origin_of(u) {
            if !self.0.contains(&o) {
                self.0.push(o);
            }
        }
    }

    pub fn contains(&self, u: &Url) -> bool {
        origin_of(u).map(|o| self.0.contains(&o)).unwrap_or(false)
    }

    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum UrlPolicyError {
    #[error("not a valid URL")]
    Invalid,
    #[error("only https links can be opened")]
    Scheme,
    #[error("link is not part of this Office Unbound deployment")]
    Foreign,
    #[error("link contains credentials")]
    Userinfo,
}

/// Validates a URL the user wants to open in the system browser.
pub fn open_external(raw: &str, allowed: &OriginSet) -> Result<Url, UrlPolicyError> {
    if raw.len() > 4096 || raw.chars().any(|c| c.is_control()) {
        return Err(UrlPolicyError::Invalid);
    }
    let u = Url::parse(raw).map_err(|_| UrlPolicyError::Invalid)?;
    if u.scheme() != "https" {
        return Err(UrlPolicyError::Scheme);
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(UrlPolicyError::Userinfo);
    }
    if !allowed.contains(&u) {
        return Err(UrlPolicyError::Foreign);
    }
    Ok(u)
}

pub fn may_send_token(target: &Url, allowed: &OriginSet) -> bool {
    crate::http::allowed_scheme(target) && allowed.contains(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> OriginSet {
        let mut s = OriginSet::new();
        s.add(&Url::parse("https://cloud.a.example/").unwrap());
        s.add(&Url::parse("https://auth.a.example/realms/ou").unwrap());
        s
    }

    #[test]
    fn opens_only_deployment_https() {
        assert!(open_external("https://cloud.a.example/f/123", &set()).is_ok());
        assert_eq!(open_external("http://cloud.a.example/", &set()), Err(UrlPolicyError::Scheme));
        assert_eq!(open_external("file:///C:/Windows/System32/cmd.exe", &set()), Err(UrlPolicyError::Scheme));
        assert_eq!(open_external("ms-settings:", &set()), Err(UrlPolicyError::Scheme));
        assert_eq!(open_external("https://cloud.a.example.evil.test/", &set()), Err(UrlPolicyError::Foreign));
        assert_eq!(open_external("https://cloud.b.example/", &set()), Err(UrlPolicyError::Foreign));
        assert_eq!(open_external("https://x@cloud.a.example/", &set()), Err(UrlPolicyError::Userinfo));
        assert_eq!(open_external("https://cloud.a.example:8443/", &set()), Err(UrlPolicyError::Foreign), "port is part of the origin");
        assert_eq!(open_external("https://cloud.a.example/\n", &set()), Err(UrlPolicyError::Invalid));
    }

    #[test]
    fn token_audience() {
        assert!(may_send_token(&Url::parse("https://cloud.a.example/remote.php/dav/").unwrap(), &set()));
        assert!(!may_send_token(&Url::parse("https://cloud.b.example/remote.php/dav/").unwrap(), &set()));
        assert!(!may_send_token(&Url::parse("http://cloud.a.example/").unwrap(), &set()));
    }
}
