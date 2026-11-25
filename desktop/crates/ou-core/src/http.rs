//! The one HTTP client constructor. TLS is always verified with the operating system's trust store (rustls-platform-verifier:
//! Windows CertGetCertificateChain, so enterprise CAs deployed by GPO work); there is no switch to disable it.
//! Plain HTTP exists only in test builds and only to loopback addresses (mock IdP / mock servers).

use std::time::Duration;

use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("only https:// URLs are allowed")]
    NotHttps,
    #[error("HTTP client could not be built: {0}")]
    Build(String),
}

fn install_crypto_provider() {
    // Idempotent: a second install returns Err, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn user_agent() -> String {
    format!("OfficeUnboundDesktop/{}", crate::VERSION)
}

/// Production client: HTTPS only, verified TLS, bounded redirects and timeouts, no cookies.
pub fn client() -> Result<reqwest::Client, HttpError> {
    install_crypto_provider();
    reqwest::Client::builder()
        .https_only(true)
        .user_agent(user_agent())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| HttpError::Build(e.to_string()))
}

/// Test client: like `client()` but also allows http:// to loopback (mock servers). Test builds only.
#[cfg(any(test, feature = "test-support"))]
pub fn test_client() -> reqwest::Client {
    install_crypto_provider();
    reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("test client")
}

/// Whether `u` may be fetched: https always; http only to loopback and only in test builds.
pub fn allowed_scheme(u: &Url) -> bool {
    match u.scheme() {
        "https" => true,
        #[cfg(any(test, feature = "test-support"))]
        "http" => is_loopback(u),
        _ => false,
    }
}

pub fn is_loopback(u: &Url) -> bool {
    match u.host() {
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

pub fn require_allowed(u: &Url) -> Result<(), HttpError> {
    if allowed_scheme(u) {
        Ok(())
    } else {
        Err(HttpError::NotHttps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_only_in_production_rules() {
        assert!(allowed_scheme(&Url::parse("https://cloud.example.com/").unwrap()));
        assert!(!allowed_scheme(&Url::parse("ftp://cloud.example.com/").unwrap()));
        assert!(!allowed_scheme(&Url::parse("http://cloud.example.com/").unwrap()), "plain http to a remote host");
        assert!(allowed_scheme(&Url::parse("http://127.0.0.1:9/").unwrap()), "loopback only in test builds");
    }

    #[test]
    fn production_client_builds() {
        client().unwrap();
    }
}
