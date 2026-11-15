# Collaboration lab results (Phase 6 spike) - 2026-11-15

Status: **Tested (lab prototype, executed)**. Chat and meetings run in two nspawn machines on the ICS host; every PASS/FAIL below is real output of `blueprints/lab/spike-collab/tests/` run from the ICS host. Scripts: `blueprints/lab/spike-collab/` (README there). Licenses: `docs/status/third-party-inventory.md` section 5a. Desk evaluation it answers: `docs/status/collaboration-eval.md`.

## 1. What was built

| Machine | Cap | Stack (pinned) |
|---|---|---|
| `ou-chat1` 192.168.186.245 | MemoryMax 1.5G | PostgreSQL 16.15; Synapse 1.165.0+noble1 (matrix.org apt repo, held); matrix-authentication-service 1.29.0 (release binary, sha256 d233fd94...e02f93 = GitHub asset digest) with Keycloak as only upstream (client `ou-matrix`, code+PKCE, JIT users, `localpart = preferred_username`, local passwords/registration off); Element Web 1.12.35 (tarball sha256 5aaff32e...bba5, `.asc` verified against Element release key 712BFBEE...A179B100); nginx 1.24. Names `chat.`, `matrix.`, `mas.ou-lab.internal`, lab-CA cert |
| `ou-meet1` 192.168.186.246 | MemoryMax 2G | Jitsi stable debs jitsi-meet 2.0.11248-1, web/config/prosody/tokens 1.0.9442-1, jicofo 1.0-1205-1, jitsi-videobridge2 2.3-318-gbf271b11f-1 (all `apt-mark hold`), Prosody 0.12.4 with `authentication="token"`, `allow_empty_token=false`, HS256 secret shared with the Office Unbound token service (FastAPI, ~100 lines, client `ou-meet` at Keycloak); nginx. Names `meet.`, `meet-auth.ou-lab.internal` |

No Docker. Synapse/Jitsi are vendor packages in the lab; production per ADR-0007 = own builds from pinned source (not done here).

## 2. Test results (final runs)

| Test | Result |
|---|---|
| C01 Matrix SSO + chat (`c01_matrix.py`) | **23 PASS / 0 FAIL** |
| C02 deprovisioning (`c02_deprovision.py`, final run with back-channel logout enabled) | 13 PASS / 1 FAIL (the FAIL is a test-design artefact, see 3) |
| C03 Jitsi JWT + 2 participants (`c03_jitsi.py`) | **18 PASS / 0 FAIL** |
| C04 Element Web UI (`c04_element_ui.py`, user carol) | **2 PASS / 0 FAIL** |
| C05 Keycloak logout -> MAS back-channel -> Matrix (`c05_backchannel.py`) | **6 PASS / 0 FAIL** (after fixing lab DNS, see 3) |

### C01 (real output, abridged)
```
PASS homeserver login flows are SSO/token only (no m.login.password) - ['m.login.sso', 'm.login.token']
PASS bob SSO login via MAS+Keycloak -> @bob:matrix.ou-lab.internal - 3.2s, access ttl 300s, refresh token True
PASS alice SSO login via MAS+Keycloak -> @alice:matrix.ou-lab.internal - 3.1s
PASS alice receives bob's message via /sync - 0.1s
PASS alice downloads file byte-exact (sha256 match) - 200 307200 bytes
PASS anonymous media download refused (authenticated media) - 401
PASS bob access token refresh via MAS - 200
PASS alice (left) does not see messages sent after she left (history up to leave only)
```
Login is a real browser flow (headless Chromium): MAS `/authorize` -> Keycloak form -> MAS -> loopback redirect -> code exchange; everything after that is the plain Client-Server API. First login of a user shows one MAS "Create Account" confirmation page (import of the claims); later logins go straight through. MAS auto-forwards to Keycloak (single upstream, no password).
C04: Element Web itself: "Sign in" -> MAS -> Keycloak -> back in 8.1 s; room created, message visible in timeline. A user who already has cross-signing keys (bob) lands on Element's "Confirm your digital identity" screen on a new browser (device verification / recovery key): this is the E2EE UX we have **not** evaluated.

### C03 (real output, abridged)
```
PASS anonymous XMPP session (no token) refused - <not-allowed/><text>token required</text>
PASS JWT signed with a wrong secret refused - <not-allowed/><text>Invalid signature</text>
PASS token service refuses unauthenticated caller (401)
PASS /join without session redirects to Keycloak
PASS bob (Keycloak login) receives a Jitsi JWT - 3.8s  | room-scoped | exp-iat = 120s | name/email from Keycloak
PASS bob's JWT (room A) does NOT admit a browser to room B - "Sorry, you're not allowed to join this call."
PASS bob / carol joined conference and see the other participant + 2 remote tracks each (P2P disabled: media via JVB)
PASS JVB /debug: a conference with 2 endpoints - conferences=1 endpoints=[2]
PASS JVB is forwarding video (allocator bitrate_bps > 0) - bitrate_bps=[362892, 362892, ...]
```
Anonymous users cannot create or join any room: with token auth Prosody offers no SASL mechanism without a valid token. Room scope is enforced at MUC join (`token_verification`), not at the XMPP auth step. Weakness in the test: "expired JWT" was signed with a wrong secret, so it proves signature checking, not `exp` handling; `exp` enforcement itself is NOT separately proven. Fake camera/mic in headless Chromium (`--use-fake-device-for-media-stream`), 2 browsers (bob, carol), JVB UDP path inside the lab zone only.

## 3. Deprovisioning (alice) - measured, and what MAS needs

Access tokens live 300 s; Synapse caches MAS token introspection (observed up to ~118 s).

| Scenario | Measured |
|---|---|
| A (run 1, no MAS integration): LDAP lock + Keycloak logout + Keycloak disable, 0.5 s | New SSO login refused immediately. **Existing Matrix session kept working**: access token ran until its own expiry (306 s), the **refresh token was still accepted (HTTP 200)** and the refreshed token worked: a locked/disabled user keeps Matrix access indefinitely. MAS owns its sessions and never polls Keycloak. (Output saved in the run, scratchpad `c02-run1-A330.out`; first part of that run.) |
| B: MAS admin API `POST /api/admin/v1/users/{id}/lock` (client-credentials client, scope `urn:mas:admin`, `policy.data.admin_clients`) | Refresh refused (400 invalid_grant) ; token rejected by Synapse after **2 s** (one earlier run: 118 s for a token whose introspection was cached); live `/sync` ended with 401. Unlock restores access |
| D: MAS `oauth2-sessions/{id}/finish` | token rejected after **1 s** |
| **C05: only a Keycloak user logout, with MAS `on_backchannel_logout: logout_all` and a Keycloak back-channel logout URL on client `ou-matrix`** | **Matrix token rejected after 1 s, refresh refused (400)** - no MAS admin call needed |

What MAS needs for deprovisioning: (1) provider setting `on_backchannel_logout: logout_all` and the Keycloak client's `backchannel.logout.url` = `https://<mas>/upstream/backchannel-logout/<provider ulid>` with session-required; Keycloak must be able to reach and resolve MAS (in the lab ou-id1, which I may not modify, cannot resolve `mas.ou-lab.internal`; Keycloak logged `UnknownHostException`, so the lab client uses the machine IP `https://192.168.186.245/...` which the nginx vhost and the cert IP SAN accept); (2) belt and braces: ICS also calls the MAS admin API (lock for suspend, `deactivate` for delete - not exercised, irreversible) with a dedicated client-credentials client; the admin API must not be internet-exposed (lab: nginx `allow 192.168.186.0/24`). Keycloak **disable** alone does not end sessions; the logout call does. Existing offline/long-lived refresh tokens at Keycloak are a separate item (identity results KI-2). C02 final run: its one FAIL is the old assertion "live /sync still running after 20 s", written for the no-back-channel case; with back-channel logout enabled the sync ends (expected).
Restoration verified: LDAP unlock + Keycloak enable + MAS unlock -> alice can sign in again.

## 4. Resources (nspawn cgroup, after all tests)

| | MemoryMax | Idle/current | Peak (incl. install, apt, page cache) | Main RSS |
|---|---|---|---|---|
| ou-chat1 | 1.5G | 0.49 GiB | 1.27 GiB | MAS 116 MB, Synapse python 107 MB, Postgres ~37 MB x procs |
| ou-meet1 | 2G | 0.94 GiB | 1.68 GiB | JVB java 472 MB (heap flag `-Xmx3072m`; my `VIDEOBRIDGE_MAX_MEMORY` sed did not take effect: the cgroup is the only cap), Jicofo 311 MB (-Xmx256m), token service ~55 MB |

Two concurrent video participants (fake media): conference stayed within the cap; no load test beyond that.

## 5. Problems found and fixed (all folded into the scripts)
Synapse requires `C` collation; MAS needs its working directory (`share/policy.wasm`) and the `adminapi` listener; MAS dynamic registration needs an https `client_uri`; jitsi-meet postinst only configures nginx when package `nginx` is installed; Ubuntu 24.04 Prosody (Lua 5.4) lacks `inspect` (symlink from 5.3) - without it every token session fails with "No available SASL mechanisms"; `jitsi-meet-tokens` leaves empty `app_id`/`app_secret` lines that override earlier settings; files written into `PrivateUsers=pick` machines from the host show up as `nobody`. Keycloak admin token (5 min) expired during a long test and left alice disabled once (restored; test now re-authenticates before cleanup).
A from-scratch rerun of both install scripts on fresh machines was **not** done; several steps were applied live and folded back (same caveat as the identity spike).

## 6. Not proven / open
- Mobile apps (Element X, Jitsi Meet app): not tested; Element X needs MAS (provided) plus Sliding Sync (native in Synapse 1.165), untested.
- E2EE: device verification, cross-signing, **key backup/recovery key** (Element showed "Confirm your digital identity"; bob needs another device or a recovery key). Server-side key backup retention, loss scenarios and the MSP admin story are open.
- Jitsi recordings (Jibri), dial-in/SIP (Jigasi), Asterisk/telephony: not installed. Element Call/LiveKit (the eval's primary meeting recommendation) not built; Jitsi only. Matrix widget/Jitsi integration from Element and Outlook invite integration not tried.
- TURN/NAT traversal for external users, UDP 10000 exposure, and any non-lab network path.
- Token service is a spike: in-memory sessions, HS256 shared secret (production: RS256/asap key, persistent sessions, role check e.g. `meet-user`, moderator mapping, rate limits), no `exp` negative test, anonymous guest join links deliberately not supported.
- Federation disabled (server name `matrix.ou-lab.internal`); no well-known/delegation design for a real domain; Synapse worker/HA and backup/restore of Postgres+media+signing key not drilled; MAS admin API hardening; load, retention, moderation, audit logs.
- Back-channel logout end-to-end only proven with the IP-based URL workaround; `deactivate` (account deletion) path not run.
- Keycloak MFA through MAS (login UX with TOTP) untested.
