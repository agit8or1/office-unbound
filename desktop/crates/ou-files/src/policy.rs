//! Guard thresholds as policy (owner decision 2026-11-25: tenant admins may adjust them within hard limits).
//!
//! Layers, applied in order: built-in defaults → tenant policy (from the deployment) → user setting. Every value is clamped to
//! the hard limits **on the client**, so a misconfigured or compromised server can loosen protection only up to the hard maximum,
//! never switch it off. Users may only make the guard stricter than the tenant allows. Rules that are never configurable:
//! "hold when every synced item would be deleted", "an incomplete listing never deletes", "never run on auth/network failure or
//! a missing sync folder" (see `guard`).

use ou_core::safety::DeletePolicy;
use serde::{Deserialize, Serialize};

use crate::guard::GuardPolicy;

/// One threshold: default and the inclusive range a tenant may choose from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub default: u32,
    pub min: u32,
    pub max: u32,
}

impl Limit {
    fn clamp(&self, v: u32) -> u32 {
        v.clamp(self.min, self.max)
    }
}

/// Hold when more than N items would be deleted in one run.
pub const MAX_DELETE_ITEMS: Limit = Limit { default: 200, min: 1, max: 5_000 };
/// Hold when more than P % of the synced items would be deleted.
pub const MAX_DELETE_PERCENT: Limit = Limit { default: 30, min: 1, max: 50 };
/// The percentage rules apply from this many synced items on (below, only the item counts and the "all items" rule apply).
pub const MIN_ITEMS_FOR_PERCENT: Limit = Limit { default: 20, min: 5, max: 100 };
/// Hold when more than N already-synced files would be overwritten or replaced in one run.
pub const MAX_MODIFIED_ITEMS: Limit = Limit { default: 500, min: 1, max: 10_000 };
/// Hold when more than P % of the synced files would be overwritten or replaced.
pub const MAX_MODIFIED_PERCENT: Limit = Limit { default: 50, min: 1, max: 80 };

/// Wire form of the tenant policy (all optional; unknown fields ignored for forward compatibility).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delete_items: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delete_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items_for_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_modified_items: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_modified_percent: Option<u32>,
}

/// Where the effective value came from (shown in Settings → Files → "Protection").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Default,
    Tenant,
    /// Tenant value outside the hard limits, replaced by the nearest limit.
    TenantClamped,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Effective {
    pub max_delete_items: (u32, Origin),
    pub max_delete_percent: (u32, Origin),
    pub min_items_for_percent: (u32, Origin),
    pub max_modified_items: (u32, Origin),
    pub max_modified_percent: (u32, Origin),
}

/// For each field: "stricter" means smaller, except `min_items_for_percent`, where smaller also means stricter
/// (the percentage rule starts earlier). So the user value wins only if it is <= the tenant/default value.
fn resolve(limit: Limit, tenant: Option<u32>, user: Option<u32>) -> (u32, Origin) {
    let (base, origin) = match tenant {
        None => (limit.default, Origin::Default),
        Some(v) if limit.clamp(v) == v => (v, Origin::Tenant),
        Some(v) => (limit.clamp(v), Origin::TenantClamped),
    };
    match user.map(|u| limit.clamp(u)) {
        Some(u) if u < base => (u, Origin::User),
        _ => (base, origin),
    }
}

pub fn effective(tenant: Option<&GuardSettings>, user: Option<&GuardSettings>) -> Effective {
    let t = |f: fn(&GuardSettings) -> Option<u32>| tenant.and_then(f);
    let u = |f: fn(&GuardSettings) -> Option<u32>| user.and_then(f);
    Effective {
        max_delete_items: resolve(MAX_DELETE_ITEMS, t(|s| s.max_delete_items), u(|s| s.max_delete_items)),
        max_delete_percent: resolve(MAX_DELETE_PERCENT, t(|s| s.max_delete_percent), u(|s| s.max_delete_percent)),
        min_items_for_percent: resolve(MIN_ITEMS_FOR_PERCENT, t(|s| s.min_items_for_percent), u(|s| s.min_items_for_percent)),
        max_modified_items: resolve(MAX_MODIFIED_ITEMS, t(|s| s.max_modified_items), u(|s| s.max_modified_items)),
        max_modified_percent: resolve(MAX_MODIFIED_PERCENT, t(|s| s.max_modified_percent), u(|s| s.max_modified_percent)),
    }
}

impl Effective {
    pub fn guard_policy(&self) -> GuardPolicy {
        GuardPolicy {
            deletes: DeletePolicy {
                max_items: self.max_delete_items.0 as usize,
                max_fraction: f64::from(self.max_delete_percent.0) / 100.0,
                min_items_for_ratio: self.min_items_for_percent.0 as usize,
            },
            max_modified_items: self.max_modified_items.0 as usize,
            max_modified_fraction: f64::from(self.max_modified_percent.0) / 100.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_guard_defaults() {
        let p = effective(None, None).guard_policy();
        assert_eq!(p, GuardPolicy::default());
    }

    #[test]
    fn tenant_values_within_limits_apply() {
        let t = GuardSettings { max_delete_items: Some(1000), max_delete_percent: Some(10), ..Default::default() };
        let e = effective(Some(&t), None);
        assert_eq!(e.max_delete_items, (1000, Origin::Tenant));
        assert_eq!(e.max_delete_percent, (10, Origin::Tenant));
        assert_eq!(e.max_modified_items, (500, Origin::Default));
    }

    #[test]
    fn tenant_cannot_switch_protection_off() {
        let t = GuardSettings {
            max_delete_items: Some(u32::MAX),
            max_delete_percent: Some(100),
            min_items_for_percent: Some(1_000_000),
            max_modified_items: Some(0),
            max_modified_percent: Some(0),
        };
        let e = effective(Some(&t), None);
        assert_eq!(e.max_delete_items, (5_000, Origin::TenantClamped));
        assert_eq!(e.max_delete_percent, (50, Origin::TenantClamped));
        assert_eq!(e.min_items_for_percent, (100, Origin::TenantClamped));
        assert_eq!(e.max_modified_items, (1, Origin::TenantClamped), "0 would hold every run; clamped to 1");
        assert_eq!(e.max_modified_percent, (1, Origin::TenantClamped));
    }

    #[test]
    fn user_may_only_tighten() {
        let t = GuardSettings { max_delete_items: Some(1000), ..Default::default() };
        let stricter = GuardSettings { max_delete_items: Some(50), ..Default::default() };
        let looser = GuardSettings { max_delete_items: Some(4000), max_delete_percent: Some(45), ..Default::default() };
        assert_eq!(effective(Some(&t), Some(&stricter)).max_delete_items, (50, Origin::User));
        let e = effective(Some(&t), Some(&looser));
        assert_eq!(e.max_delete_items, (1000, Origin::Tenant));
        assert_eq!(e.max_delete_percent, (30, Origin::Default));
    }

    #[test]
    fn wire_format_is_forward_compatible() {
        let t: GuardSettings = serde_json::from_str(r#"{"max_delete_items": 300, "future_field": true}"#).unwrap();
        assert_eq!(t.max_delete_items, Some(300));
        assert_eq!(serde_json::to_string(&GuardSettings::default()).unwrap(), "{}");
    }
}
