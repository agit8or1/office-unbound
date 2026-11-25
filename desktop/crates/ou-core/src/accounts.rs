//! Accounts: one per (deployment issuer, user subject). Non-secret settings live in `accounts.json` under the per-user data
//! directory (`%LOCALAPPDATA%\OfficeUnbound` on Windows); secrets live in the `SecretStore` under the account's own prefix.
//! Each account has its own data directory and its own origin allowlist, so nothing (token, cache, sync journal) crosses accounts.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::discovery::Deployment;
use crate::urlpolicy::OriginSet;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("this account is already signed in")]
    Duplicate,
    #[error("unknown account")]
    Unknown,
    #[error("settings file error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Modules {
    pub files: bool,
    pub chat: bool,
}

impl Default for Modules {
    fn default() -> Self {
        Self { files: true, chat: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub id: String,
    pub deployment: Deployment,
    pub subject: String,
    pub label: String,
    pub created_at: u64,
    #[serde(default)]
    pub modules: Modules,
    /// Local sync root, once configured (Phase 2).
    #[serde(default)]
    pub sync_root: Option<PathBuf>,
}

impl Account {
    /// Origins that may receive this account's tokens and may be opened in the browser for it.
    pub fn origins(&self) -> OriginSet {
        let mut s = OriginSet::new();
        let d = &self.deployment;
        for u in [Some(&d.issuer), Some(&d.files_url), d.portal_url.as_ref(), d.matrix_url.as_ref(), d.chat_web_url.as_ref(), d.mail_web_url.as_ref(), d.meet_url.as_ref(), d.office_url.as_ref()].into_iter().flatten() {
            if let Ok(u) = url::Url::parse(u) {
                s.add(&u);
            }
        }
        s
    }

    pub fn data_dir(&self, root: &Path) -> PathBuf {
        root.join("accounts").join(&self.id)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub version: u32,
    pub accounts: Vec<Account>,
}

pub fn new_account_id() -> String {
    // 16 random bytes, hex: safe as a path component and a credential-name component.
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS random number generator");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Per-user data root: `%LOCALAPPDATA%\OfficeUnbound` on Windows; `$XDG_DATA_HOME/office-unbound-desktop` elsewhere (dev only).
pub fn default_root() -> PathBuf {
    if let Ok(p) = std::env::var("OU_DESKTOP_HOME") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(p).join("OfficeUnbound");
        }
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share"));
    base.join("office-unbound-desktop")
}

impl Registry {
    pub fn path(root: &Path) -> PathBuf {
        root.join("accounts.json")
    }

    pub fn load(root: &Path) -> Result<Self, AccountError> {
        match std::fs::read(Self::path(root)) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| AccountError::Io(format!("accounts.json is damaged ({e}); it was not changed"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self { version: 1, accounts: vec![] }),
            Err(e) => Err(AccountError::Io(e.to_string())),
        }
    }

    /// Atomic write (temp file + rename) so a crash never leaves a half-written settings file.
    pub fn save(&self, root: &Path) -> Result<(), AccountError> {
        std::fs::create_dir_all(root).map_err(|e| AccountError::Io(e.to_string()))?;
        let tmp = root.join("accounts.json.tmp");
        let data = serde_json::to_vec_pretty(self).map_err(|e| AccountError::Io(e.to_string()))?;
        std::fs::write(&tmp, data).map_err(|e| AccountError::Io(e.to_string()))?;
        std::fs::rename(&tmp, Self::path(root)).map_err(|e| AccountError::Io(e.to_string()))
    }

    pub fn add(&mut self, a: Account) -> Result<&Account, AccountError> {
        if self.accounts.iter().any(|x| x.deployment.issuer == a.deployment.issuer && x.subject == a.subject) {
            return Err(AccountError::Duplicate);
        }
        self.accounts.push(a);
        Ok(self.accounts.last().unwrap())
    }

    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.id == id)
    }

    pub fn remove(&mut self, id: &str) -> Result<Account, AccountError> {
        let i = self.accounts.iter().position(|a| a.id == id).ok_or(AccountError::Unknown)?;
        Ok(self.accounts.remove(i))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::discovery::Source;

    pub fn deployment(domain: &str) -> Deployment {
        Deployment {
            domain: domain.into(),
            name: domain.into(),
            issuer: format!("https://auth.{domain}/realms/ou"),
            client_id: "OpenCloudDesktop".into(),
            files_url: format!("https://cloud.{domain}/"),
            portal_url: Some(format!("https://app.{domain}/")),
            matrix_url: Some(format!("https://matrix.{domain}/")),
            chat_web_url: Some(format!("https://chat.{domain}/")),
            mail_web_url: Some(format!("https://mail.{domain}/")),
            meet_url: Some(format!("https://meet.{domain}/")),
            office_url: None,
            source: Source::WebFinger,
            login_hint: None,
            foreign_hosts: vec![],
        }
    }

    pub fn account(domain: &str, sub: &str) -> Account {
        Account {
            id: new_account_id(),
            deployment: deployment(domain),
            subject: sub.into(),
            label: format!("{sub}@{domain}"),
            created_at: 1,
            modules: Modules::default(),
            sync_root: None,
        }
    }

    #[test]
    fn registry_roundtrip_and_isolation() {
        let dir = std::env::temp_dir().join(format!("ou-acc-{}", new_account_id()));
        let mut r = Registry::load(&dir).unwrap();
        let a = account("a.example", "u1");
        let b = account("b.example", "u1");
        r.add(a.clone()).unwrap();
        r.add(b.clone()).unwrap();
        assert!(matches!(r.add(account("a.example", "u1")), Err(AccountError::Duplicate)));
        r.save(&dir).unwrap();
        let r2 = Registry::load(&dir).unwrap();
        assert_eq!(r2.accounts.len(), 2);
        assert_ne!(a.data_dir(&dir), b.data_dir(&dir));
        let oa = a.origins();
        assert!(oa.contains(&url::Url::parse("https://cloud.a.example/x").unwrap()));
        assert!(!oa.contains(&url::Url::parse("https://cloud.b.example/x").unwrap()), "A's token never goes to B");
        assert!(oa.contains(&url::Url::parse("https://meet.a.example/room").unwrap()), "meetings host allowed for links");
        let raw = std::fs::read_to_string(Registry::path(&dir)).unwrap();
        assert!(!raw.to_lowercase().contains("token") && !raw.to_lowercase().contains("password"), "no secrets in settings");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_file_is_reported_not_replaced() {
        let dir = std::env::temp_dir().join(format!("ou-acc-{}", new_account_id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Registry::path(&dir), b"{not json").unwrap();
        assert!(Registry::load(&dir).is_err());
        assert_eq!(std::fs::read(Registry::path(&dir)).unwrap(), b"{not json");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
