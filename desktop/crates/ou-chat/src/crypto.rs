//! End-to-end encryption status for the GUI: key backup and recovery (secret storage), device verification state.
//! Nothing here can turn encryption off, export keys in the clear or skip verification.

use matrix_sdk::encryption::recovery::RecoveryState;
use serde::Serialize;

use crate::{mx, ChatClient, ChatError};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Recovery {
    /// Not known yet (before the first sync).
    Unknown,
    /// Key backup + recovery set up and this device has the secrets.
    Enabled,
    /// Set up on the account but this device has not been unlocked with the recovery key (or verified by another device).
    Incomplete,
    /// No recovery on the account: losing all devices loses encrypted history.
    Disabled,
}

pub fn map(s: RecoveryState) -> Recovery {
    match s {
        RecoveryState::Enabled => Recovery::Enabled,
        RecoveryState::Incomplete => Recovery::Incomplete,
        RecoveryState::Disabled => Recovery::Disabled,
        _ => Recovery::Unknown,
    }
}

impl ChatClient {
    pub fn recovery_state(&self) -> Recovery {
        map(self.client.encryption().recovery().state())
    }

    /// Sets up key backup and recovery; returns the recovery key, which the GUI shows **once** for the user to save.
    /// It is never stored by Office Unbound.
    pub async fn enable_recovery(&self) -> Result<String, ChatError> {
        self.client.encryption().recovery().enable().await.map_err(mx)
    }

    /// Unlocks this device with the user's recovery key (downloads cross-signing secrets and the backup key).
    pub async fn recover(&self, recovery_key: &str) -> Result<(), ChatError> {
        self.client.encryption().recovery().recover(recovery_key.trim()).await.map_err(mx)
    }

    /// Whether this device is cross-signed by the user (verified).
    pub async fn device_verified(&self) -> Result<bool, ChatError> {
        let enc = self.client.encryption();
        let dev = enc.get_own_device().await.map_err(mx)?;
        Ok(dev.is_some_and(|d| d.is_cross_signed_by_owner()))
    }
}
