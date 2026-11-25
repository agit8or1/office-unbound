# Guard thresholds as policy

Status: **Implementing**. The client-side model is in `desktop/crates/ou-files/src/policy.rs` (unit-tested on Linux). The server side
is not started, and ICS is not touched. Owner decision 2026-11-25: tenant admins may adjust the thresholds within hard limits.

## 1. Thresholds

| Setting (`GuardSettings` field) | Default | Hard min | Hard max | Meaning |
|---|---|---|---|---|
| `max_delete_items` | 200 | 1 | 5,000 | Hold if more items would be deleted in one run (both directions together) |
| `max_delete_percent` | 30 | 1 | 50 | Hold if more than this share of the synced items would be deleted |
| `min_items_for_percent` | 20 | 5 | 100 | The percentage rules apply from this many synced items on |
| `max_modified_items` | 500 | 1 | 10,000 | Hold if more already-synced files would be overwritten or replaced |
| `max_modified_percent` | 50 | 1 | 80 | Same, as a share of the synced items |

**Never configurable** (they are enforced in `guard::preflight`, not in the policy):

- hold when *every* synced item would be deleted;
- an incomplete local or remote listing never causes deletions;
- no engine run on an auth or network failure, or when the sync folder is missing, emptied, unmarked or foreign;
- an approval is bound to the exact plan id.

## 2. Resolution (`policy::effective`)

The layers are built-in defaults, then the tenant policy, then the user setting.

- **Clamping on the client.** Each tenant value is clamped to [min, max] *in the client*. A misconfigured or compromised server can
  loosen protection at most to the hard maximum. It can never switch the guard off. Clamped values carry `Origin::TenantClamped`, and
  Settings shows "your organisation's value X was limited to Y".
- **Users can only tighten.** A user value applies only if it is stricter (smaller) than the tenant's or the default value. A looser user
  value is ignored.
- **Display.** Settings → Files → Protection shows each effective value with its origin (default / organisation / you).

## 3. How the tenant setting would reach the client (design, not built)

1. **Source of truth.** The tenant administrator sets the values in the portal/ICS tenant settings (later work, owned by ICS). They are
   stored per tenant.
2. **Transport.** The values are published in the deployment's client document `/.well-known/office-unbound/client.json`, which ou-core
   already fetches over verified HTTPS during discovery, as an optional object
   `"policy": {"files": {"guard": { …GuardSettings… }}, "version": <int>}`. That is the same channel and trust anchor as the issuer and
   files URLs. Unknown fields are ignored (serde default). No new endpoint, and no device-management channel that could run commands
   (brief section 11: narrowly scoped).
3. **Later, per user or group.** If policies vary by group, use a read-only authenticated endpoint on the portal
   (`GET /api/client/policy`, OIDC bearer) that returns the same JSON for the signed-in user. The client merges it as the tenant layer.
4. **Caching and refresh.** The agent caches the last valid policy per account (in the account's data directory, next to the registry).
   It refreshes at startup, at sign-in, and every 12 hours. Offline, the cached policy is used. If no policy was ever received, the
   defaults apply. A policy whose `version` is lower than the cached one is ignored (no rollback).
5. **Enforcement.** The policy is applied entirely on the client, in `preflight`, before the engine starts. The server cannot request a
   deletion through this path. It can only set thresholds within the hard limits.
6. **Audit.** When the effective policy changes, the agent logs the old and new values and their origin (the values contain no secrets).

## 4. Proposed ou-core change

Add `policy: Option<serde_json::Value>` to `discovery::ClientDocument` and `Deployment`. ou-core passes it through without
interpreting it, and each feature crate parses its own subtree (`ou_files::policy::GuardSettings`). The lead owns ou-core, so this is a
proposal, not a change.
