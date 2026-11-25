//! Secret storage. Only refresh tokens (and, later, Matrix device keys' pickle passphrase) are stored; passwords never are.
//!
//! * `wincred::CredentialManager` (Windows): generic credentials, `CRED_PERSIST_LOCAL_MACHINE` (this user on this computer, not
//!   roaming), protected by DPAPI under the user's logon credentials.
//! * `MemoryStore`: tests and the Linux development build. There is deliberately no plaintext file backend.
//!
//! Keys are namespaced `OfficeUnbound/<account-id>/<name>`; an account can only reach its own entries through `AccountSecrets`.

use std::collections::HashMap;
use std::sync::Mutex;

/// Windows limit for a generic credential blob (CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512).
pub const MAX_SECRET_BYTES: usize = 2560;
pub const TARGET_PREFIX: &str = "OfficeUnbound/";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SecretError {
    #[error("secret is larger than the platform limit ({0} bytes)")]
    TooLarge(usize),
    #[error("invalid secret name")]
    BadName,
    #[error("secret store error: {0}")]
    Backend(String),
}

pub trait SecretStore: Send + Sync {
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError>;
    fn delete(&self, key: &str) -> Result<(), SecretError>;
    /// Keys starting with `prefix` (used for cleanup on account removal / uninstall).
    fn list(&self, prefix: &str) -> Result<Vec<String>, SecretError>;
}

pub fn validate_key(key: &str) -> Result<(), SecretError> {
    let ok = key.starts_with(TARGET_PREFIX)
        && key.len() <= 200
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
        && !key.contains("..");
    if ok {
        Ok(())
    } else {
        Err(SecretError::BadName)
    }
}

fn check(key: &str, value: &[u8]) -> Result<(), SecretError> {
    validate_key(key)?;
    if value.len() > MAX_SECRET_BYTES {
        return Err(SecretError::TooLarge(value.len()));
    }
    Ok(())
}

#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemoryStore {
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        check(key, value)?;
        self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        validate_key(key)?;
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn delete(&self, key: &str) -> Result<(), SecretError> {
        validate_key(key)?;
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, SecretError> {
        let mut v: Vec<String> = self.0.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect();
        v.sort();
        Ok(v)
    }
}

/// An account's view of the store: it can only name keys under its own prefix.
pub struct AccountSecrets<'a> {
    store: &'a dyn SecretStore,
    prefix: String,
}

impl<'a> AccountSecrets<'a> {
    pub fn new(store: &'a dyn SecretStore, account_id: &str) -> Result<Self, SecretError> {
        if account_id.is_empty() || !account_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(SecretError::BadName);
        }
        Ok(Self { store, prefix: format!("{TARGET_PREFIX}{account_id}/") })
    }
    fn key(&self, name: &str) -> Result<String, SecretError> {
        if name.is_empty() || name.contains('/') || name.contains("..") {
            return Err(SecretError::BadName);
        }
        Ok(format!("{}{name}", self.prefix))
    }
    pub fn set(&self, name: &str, v: &[u8]) -> Result<(), SecretError> {
        self.store.set(&self.key(name)?, v)
    }
    pub fn get(&self, name: &str) -> Result<Option<Vec<u8>>, SecretError> {
        self.store.get(&self.key(name)?)
    }
    pub fn delete(&self, name: &str) -> Result<(), SecretError> {
        self.store.delete(&self.key(name)?)
    }
    /// Removes every secret of this account (sign-out / account removal).
    pub fn purge(&self) -> Result<usize, SecretError> {
        let keys = self.store.list(&self.prefix)?;
        for k in &keys {
            self.store.delete(k)?;
        }
        Ok(keys.len())
    }
}

#[cfg(windows)]
pub mod wincred {
    //! Windows Credential Manager backend (CredWriteW / CredReadW / CredDeleteW / CredEnumerateW).
    use super::*;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND, FILETIME};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn from_wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    pub struct CredentialManager;

    impl SecretStore for CredentialManager {
        fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            check(key, value)?;
            let target = wide(key);
            let user = wide("Office Unbound Desktop");
            let cred = CREDENTIALW {
                Flags: 0,
                Type: CRED_TYPE_GENERIC,
                TargetName: target.as_ptr() as *mut u16,
                Comment: std::ptr::null_mut(),
                LastWritten: FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 },
                CredentialBlobSize: value.len() as u32,
                CredentialBlob: value.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut(),
                TargetAlias: std::ptr::null_mut(),
                UserName: user.as_ptr() as *mut u16,
            };
            // SAFETY: all pointers reference live buffers for the duration of the call.
            let ok = unsafe { CredWriteW(&cred, 0) };
            if ok == 0 {
                return Err(SecretError::Backend(format!("CredWriteW failed ({})", unsafe { GetLastError() })));
            }
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
            validate_key(key)?;
            let target = wide(key);
            let mut p: *mut CREDENTIALW = std::ptr::null_mut();
            // SAFETY: CredReadW allocates `p`, released with CredFree below.
            let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) };
            if ok == 0 {
                let e = unsafe { GetLastError() };
                return if e == ERROR_NOT_FOUND { Ok(None) } else { Err(SecretError::Backend(format!("CredReadW failed ({e})"))) };
            }
            let v = unsafe {
                let c = &*p;
                let v = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec();
                CredFree(p as *const core::ffi::c_void);
                v
            };
            Ok(Some(v))
        }

        fn delete(&self, key: &str) -> Result<(), SecretError> {
            validate_key(key)?;
            let target = wide(key);
            let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
            if ok == 0 {
                let e = unsafe { GetLastError() };
                if e != ERROR_NOT_FOUND {
                    return Err(SecretError::Backend(format!("CredDeleteW failed ({e})")));
                }
            }
            Ok(())
        }

        fn list(&self, prefix: &str) -> Result<Vec<String>, SecretError> {
            if !prefix.starts_with(TARGET_PREFIX) || prefix.contains('*') {
                return Err(SecretError::BadName);
            }
            let filter = wide(&format!("{prefix}*"));
            let mut count: u32 = 0;
            let mut arr: *mut *mut CREDENTIALW = std::ptr::null_mut();
            let ok = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut arr) };
            if ok == 0 {
                let e = unsafe { GetLastError() };
                return if e == ERROR_NOT_FOUND { Ok(vec![]) } else { Err(SecretError::Backend(format!("CredEnumerateW failed ({e})"))) };
            }
            let mut out = Vec::with_capacity(count as usize);
            unsafe {
                for i in 0..count as usize {
                    out.push(from_wide((**arr.add(i)).TargetName));
                }
                CredFree(arr as *const core::ffi::c_void);
            }
            out.sort();
            Ok(out)
        }
    }
}

/// The platform default store.
pub fn platform_store() -> Box<dyn SecretStore> {
    #[cfg(windows)]
    {
        Box::new(wincred::CredentialManager)
    }
    #[cfg(not(windows))]
    {
        // Linux/macOS desktop clients are Phase 7 (Secret Service / Keychain). The dev build keeps tokens in memory only.
        Box::new(MemoryStore::new())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Shared contract test: run against every backend (MemoryStore here; CredentialManager in the Windows CI job).
    pub fn contract(store: &dyn SecretStore, run: &str) {
        let a = AccountSecrets::new(store, &format!("test-a-{run}")).unwrap();
        let b = AccountSecrets::new(store, &format!("test-b-{run}")).unwrap();
        assert_eq!(a.get("refresh").unwrap(), None);
        a.set("refresh", b"tok-a").unwrap();
        b.set("refresh", b"tok-b").unwrap();
        assert_eq!(a.get("refresh").unwrap().as_deref(), Some(&b"tok-a"[..]));
        assert_eq!(b.get("refresh").unwrap().as_deref(), Some(&b"tok-b"[..]), "accounts are isolated");
        a.set("refresh", b"tok-a2").unwrap();
        assert_eq!(a.get("refresh").unwrap().as_deref(), Some(&b"tok-a2"[..]), "overwrite");
        assert_eq!(a.set("big", &vec![b'x'; MAX_SECRET_BYTES + 1]), Err(SecretError::TooLarge(MAX_SECRET_BYTES + 1)));
        a.set("max", &vec![b'y'; MAX_SECRET_BYTES]).unwrap();
        assert_eq!(a.get("../test-b/refresh"), Err(SecretError::BadName), "no traversal into another account");
        assert_eq!(a.purge().unwrap(), 2);
        assert_eq!(a.get("refresh").unwrap(), None);
        assert_eq!(b.get("refresh").unwrap().as_deref(), Some(&b"tok-b"[..]), "purge of A leaves B");
        b.purge().unwrap();
        assert!(AccountSecrets::new(store, "bad/id").is_err());
        assert!(store.set("NotOurs/x", b"v").is_err(), "foreign namespace refused");
    }

    #[test]
    fn memory_store_contract() {
        contract(&MemoryStore::new(), "mem");
    }

    #[cfg(windows)]
    #[test]
    fn credential_manager_contract() {
        let run = format!("{}", std::process::id());
        contract(&wincred::CredentialManager, &run);
    }
}
