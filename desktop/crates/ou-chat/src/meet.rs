//! Meetings (brief section 7, first step): open the deployment's Jitsi Meet in the **system browser**. Nothing is embedded; the
//! browser handles camera, microphone and screen sharing permissions. In-app meetings come only after those are verified.
//!
//! The Jitsi base URL must come from the deployment (proposed discovery field `meet`); there is no guessing of `meet.<domain>`.
//! Room names are random (not derived from the Matrix room id), so a link cannot be guessed from a room id; the token service in
//! front of Jitsi still requires a signed-in user.

use ou_core::urlpolicy::{open_external, OriginSet};
use url::Url;

use crate::{ChatClient, ChatError};

/// Jitsi room names: letters and digits only, 16..64 characters.
pub fn valid_room_name(n: &str) -> bool {
    (16..=64).contains(&n.len()) && n.chars().all(|c| c.is_ascii_alphanumeric())
}

pub fn new_room_name() -> String {
    // 18 random bytes -> 24 base64url chars; drop '-' and '_' so the name is plain alphanumeric
    let mut s: String = ou_core::oidc::random_token(18).chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    while s.len() < 20 {
        s.push_str(&ou_core::oidc::random_token(6).chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>());
    }
    format!("OU{s}")
}

/// `https://meet.company.com/<room>`; refuses a non-https base or a base with a path/query.
pub fn meeting_url(meet_base: &Url, room: &str) -> Result<Url, ChatError> {
    if meet_base.scheme() != "https" || meet_base.query().is_some() || meet_base.path() != "/" {
        return Err(ChatError::Config("meeting base must be https://host/".into()));
    }
    if !valid_room_name(room) {
        return Err(ChatError::Refused("meeting name".into()));
    }
    meet_base.join(room).map_err(|_| ChatError::Refused("meeting name".into()))
}

/// Whether a link in a chat message is a meeting of *this* deployment (shown as a "Join" button). Anything else stays an
/// ordinary link, opened only after the URL policy check.
pub fn parse_meeting_link(link: &str, meet_base: &Url) -> Option<Url> {
    let u = Url::parse(link).ok()?;
    if u.scheme() != "https" || u.origin() != meet_base.origin() || !u.username().is_empty() {
        return None;
    }
    let room = u.path().strip_prefix('/')?;
    valid_room_name(room).then_some(u)
}

/// Validates the URL against the account's origins and hands it to the shell's browser opener.
pub fn open_meeting<F>(url: &Url, allowed: &OriginSet, open_browser: F) -> Result<(), ChatError>
where
    F: FnOnce(&Url) -> Result<(), String>,
{
    let u = open_external(url.as_str(), allowed).map_err(|e| ChatError::Refused(e.to_string()))?;
    open_browser(&u).map_err(ChatError::Refused)
}

impl ChatClient {
    /// "Meet now" from a room: posts the link into the room (so others can join from chat) and opens it in the browser.
    pub async fn start_meeting<F>(&self, room_id: &str, meet_base: &Url, allowed: &OriginSet, open_browser: F) -> Result<Url, ChatError>
    where
        F: FnOnce(&Url) -> Result<(), String>,
    {
        let url = meeting_url(meet_base, &new_room_name())?;
        self.send_text(room_id, &format!("Meeting started: {url}")).await?;
        open_meeting(&url, allowed, open_browser)?;
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_urls() {
        for _ in 0..50 {
            assert!(valid_room_name(&new_room_name()));
        }
        assert_ne!(new_room_name(), new_room_name());
        let base = Url::parse("https://meet.company.com/").unwrap();
        let u = meeting_url(&base, "OUabcdefghijklmnopqr").unwrap();
        assert_eq!(u.as_str(), "https://meet.company.com/OUabcdefghijklmnopqr");
        assert!(meeting_url(&Url::parse("http://meet.company.com/").unwrap(), "OUabcdefghijklmnopqr").is_err());
        assert!(meeting_url(&base, "../admin").is_err());
        assert!(meeting_url(&base, "short").is_err());
    }

    #[test]
    fn links() {
        let base = Url::parse("https://meet.company.com/").unwrap();
        assert!(parse_meeting_link("https://meet.company.com/OUabcdefghijklmnopqr", &base).is_some());
        assert!(parse_meeting_link("https://meet.company.com.evil.test/OUabcdefghijklmnopqr", &base).is_none());
        assert!(parse_meeting_link("https://x@meet.company.com/OUabcdefghijklmnopqr", &base).is_none());
        assert!(parse_meeting_link("http://meet.company.com/OUabcdefghijklmnopqr", &base).is_none());
        assert!(parse_meeting_link("https://meet.company.com/a/b", &base).is_none());
    }

    #[test]
    fn opens_only_allowed_origins() {
        let mut allowed = OriginSet::new();
        allowed.add(&Url::parse("https://meet.company.com/").unwrap());
        let mut opened = None;
        open_meeting(&Url::parse("https://meet.company.com/OUabcdefghijklmnopqr").unwrap(), &allowed, |u| {
            opened = Some(u.clone());
            Ok(())
        })
        .unwrap();
        assert!(opened.is_some());
        assert!(open_meeting(&Url::parse("https://meet.other.example/OUabcdefghijklmnopqr").unwrap(), &allowed, |_| Ok(())).is_err());
    }
}
