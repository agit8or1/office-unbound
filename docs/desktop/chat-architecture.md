# Desktop chat and meetings: decision, design, evidence

Scope: brief section 6 (Teams-like chat) and section 7 (meetings, first step), crate `desktop/crates/ou-chat`.
Status words follow ADR-0000. Linux evidence only; nothing here is verified on Windows.

## 1. What is live (officeunbound8, read-only checks, 2026-11-25)

| Check | Result |
|---|---|
| `https://matrix.officeunbound.com/_matrix/client/versions` | 200, spec up to v1.17; `org.matrix.simplified_msc3575` (native sliding sync) true |
| `/_matrix/client/v3/login` | flows `m.login.sso` (`oauth_aware_preferred`, `delegated_oidc_compatibility`) and `m.login.token` only: no password login |
| `/_matrix/client/v1/auth_metadata` (and the MSC2965 unstable path) | 200, issuer `https://mas.officeunbound.com/`: **next-generation auth (MSC3861) is active**, Synapse delegates to MAS |
| `https://matrix.officeunbound.com/.well-known/matrix/client` | homeserver base URL + `org.matrix.msc2965.authentication` issuer/account |
| MAS `/.well-known/openid-configuration` | `registration_endpoint` present (dynamic client registration), `device_authorization_endpoint` present, PKCE `S256`, grants `authorization_code`, `refresh_token`, `device_code`, `client_credentials`; token auth `none` allowed (public clients) |
| MAS client-registration policy | the deployment's MAS config (`blueprints/catalog/templates/chat/mas.yaml`) has no `policy:` section, so MAS 1.29.0's default policy applies. Its rego (`policies/client_registration`) accepts `application_type: native` with `http://127.0.0.1/...` redirect URIs and an https `client_uri`; MAS matches loopback redirects without the port (`crates/data-model/src/oauth2/client.rs`). **No MAS or Synapse change is needed.** |
| Element Web `https://chat.officeunbound.com/` | 200, `/version` 1.12.35; `config.json`: `server_name` matrix.officeunbound.com, guests and custom servers off, `sso_redirect_options.immediate`, group calls off, no Jitsi configured |
| Jitsi | **not deployed**: catalog component `meetings` is `maturity: experimental` (planned only with `ICS_EXPERIMENTAL=meetings`); `meet.officeunbound.com` does not resolve |

Component versions from the catalog: Synapse 1.165.0, MAS 1.29.0, Element Web 1.12.35-ou2; MAS upstream is the deployment's Keycloak
(`pkce_method: always`, `skip_confirmation: true`, `on_backchannel_logout: logout_all`).

## 2. Decision: native client on matrix-rust-sdk (not embedded Element Web)

Recommended and implemented: **a native chat module on matrix-rust-sdk 0.20 (Apache-2.0)**, with the chat UI drawn by the desktop shell.

| | Embed Element Web in WebView2 | Native on matrix-rust-sdk |
|---|---|---|
| E2EE | Element's WASM build of the same Rust crypto; keys live in the WebView's IndexedDB | Same crypto (vodozemac, matrix-sdk-crypto) in-process; store encrypted with a key held in Windows Credential Manager |
| Sign-in | Element runs its own OIDC flow **inside the WebView**: the Keycloak SSO cookie of the system browser is not there, so the user signs in a second time (password + MFA), against the brief's "sign in once" and "authenticate in the system browser" | MAS auth code + PKCE in the **system browser**; Keycloak's existing session makes it silent (live run: 10 HTTP steps, about 1 s, no prompt after the first Keycloak sign-in) |
| Background | Sync and notifications only while the WebView is alive | Sync, unread badge and notifications from the agent, window closed or not |
| Feature set | Everything Element has, on day one | Built step by step (list below); the SDK already provides threads, reactions, edits, receipts, typing, presence, room directory, user directory, key backup, recovery, verification |
| Maintenance | Track Element releases inside our shell; hosting a remote web app in the shell's WebView mixes origins with the shell's IPC (needs a separate, IPC-less WebView) | One Rust dependency to update; UI is ours. SDK releases are frequent and the API moves (0.x): budget an upgrade every few months |
| Size | Element's web bundle (tens of MB, not measured here), served by the deployment or shipped | Measured on Linux x86_64: a release probe binary with the whole chat stack (`examples/chat_size_probe.rs`, LTO, stripped) is 25.7 MB; Windows size not measured. A clean release build of it took 19 min on the ICS |
| Separate ecosystem? | No | No: the same Synapse, MAS, rooms and devices as Element; users can keep Element on other machines |

Why not Element: the brief requires one sign-in in the system browser, background notifications and no separate chat ecosystem; an
embedded Element meets the last point but not the first two without patching Element. Element stays the web client
(`chat.officeunbound.com`) and the fallback ("Open in browser") for features the desktop does not have yet.

Encryption is never weakened: rooms created by the desktop are encrypted by default; there is no API to disable encryption, export
keys in the clear or skip verification; undecryptable messages are shown as such; attachments in encrypted rooms are encrypted
before upload (live-verified: the uploaded attachment came back as an encrypted-file descriptor and decrypted locally).

## 3. Sign-in design (implemented in `ou-chat::auth`)

1. The shell gets the homeserver from discovery (`Deployment.matrix_url`). matrix-sdk reads `auth_metadata` (MSC2965).
2. Dynamic registration (MSC2966): native public client, `redirect_uris: ["http://127.0.0.1/callback"]`, `client_uri` = the
   deployment's portal (https), `client_name: "Office Unbound Desktop"`, grant types `authorization_code` + `refresh_token`,
   `token_endpoint_auth_method: none`. No logo/tos/policy URIs. The client id is stored per account and reused (mock test
   `second_sign_in_reuses_the_registered_client`).
3. Authorization code + PKCE S256 in the system browser; scopes are the Matrix API scope and a device scope (MSC2967). The redirect
   arrives at a one-shot loopback listener on `127.0.0.1:<ephemeral>/callback` that checks `state` (constant time), ignores stray
   requests, caps requests at 8 KiB and answers with a no-store, no-script page.
4. MAS -> Keycloak: the same Keycloak session as the files sign-in, so no second password or MFA prompt. MAS shows its consent
   page once per client registration (live: one consent click; the test driver submits it).
5. Tokens: access + refresh token, client id and the store key are kept only in the `SecretStore` (Credential Manager on
   Windows), namespaced `OfficeUnbound/<account>/matrix-*`. matrix-sdk refreshes tokens; each rotation is persisted
   (`SessionChange::TokensRefreshed`). The mock test checks that no token appears in any file under the data directory.
6. Revocation (admin ends the session in MAS, user disabled in Keycloak with back-channel logout): the next request gets
   `M_UNKNOWN_TOKEN`, refresh fails with `invalid_grant`, ou-chat deletes the dead tokens, keeps the encrypted store (room keys)
   and calls the shell's `SignedOut` callback (mock test `revoked_session_signals_signed_out_and_keeps_the_store`).
7. Sign-out: revokes the tokens at MAS (device removed) and deletes this device's store and credentials.

Device-code login (RFC 8628) is offered by MAS but not used: the loopback flow keeps the browser SSO and needs no code typing.

## 4. What ou-chat does (Linux evidence)

| Feature | Status | Evidence |
|---|---|---|
| MAS sign-in, dynamic registration, token storage, restore, revoke handling, sign-out | Implemented, live-tested on officeunbound8 (Linux) | mock tests 4/4; live test 1/1 |
| Sync, room list (favourites, low priority, unread, highlights), badge count | Implemented, tested (mock), room list live | mock + live |
| Send/receive text in an **encrypted** room, history with decryption | Implemented, live-tested | live: own message returned encrypted and was decrypted |
| Attachments upload/download (encrypted rooms: ciphertext), server size limit, safe Windows file names, no overwrite | Implemented, live-tested | live: 26-byte file round trip |
| Notifications hook (`Notifier` trait, push rules incl. mentions/mutes, preview <= 140 chars) | Implemented, tested (mock) | mock: mention -> highlight notification |
| Search | Implemented for unencrypted rooms (server `/search`); encrypted rooms are reported in `not_searched` | live: message found |
| Redact, read receipt, favourite, create, leave, forget | Implemented; redact/leave/forget live-tested | live cleanup |
| Key backup / recovery status, enable recovery, recover with key | Implemented, **not tested** (needs a second device) | - |
| Meetings: random room name, link posted in the room, opened in the system browser through ou-core's URL policy | Implemented, unit-tested; **no Jitsi to test against** | unit |
| DMs, threads, reactions, edits UI, mentions UI, presence, typing, directory lookup, drag and drop, muting UI | Planned (SDK supports them; GUI not built) | - |

Known SDK behaviour handled: matrix-sdk 0.20 fails the next sync (`CacheStateAlreadyExists`) if a room is forgotten before its
leave was synced; `leave()` and `forget()` are separate and `leave_and_forget()` syncs in between (found in the first live run).

Not verified on Windows: everything. In particular Credential Manager with these secret sizes (session JSON is about 300 bytes,
under the 2,560-byte limit), bundled SQLite on NTFS, the loopback redirect with Windows Defender Firewall prompts (loopback is
normally exempt), WebView-free system-browser launch, toast notifications.

## 5. Live test record (officeunbound8, account `doctest`, 2026-11-25)

`OU_CHAT_LIVE=1 cargo test -p ou-chat --test live_matrix -- --ignored` with `tests/live/mas_browser.py` as the browser (MAS ->
Keycloak -> MAS consent -> loopback; TLS verified, only hosts under the test domain).

- Run 1: everything up to cleanup passed; the sync after forgetting failed (SDK behaviour above). The two `[OU-TEST]` rooms were
  already redacted, left and forgotten; the device stayed signed in and was ended with `mas_browser.py --end-sessions
  "Office Unbound Desktop"` (MAS GraphQL `endOauth2Session`, status ENDED).
- Run 2 (after the fix): pass in 4.5 s: sign-in, encrypted + plain `[OU-TEST]` rooms, send, receive/decrypt, attachment round
  trip, search, 3 events redacted, 2 rooms left and forgotten, device signed out. `--end-sessions` afterwards: 0 active sessions.
- Run 3 (adds attachment lookup by event id): pass in 4.1 s, same cleanup; `--end-sessions` afterwards: 0 active sessions.
- Left behind (cannot be removed by a user): three MAS client registrations named "Office Unbound Desktop" (one per run, each
  test run starts with an empty in-memory store), three uploaded attachments (26 bytes each; ciphertext) and the redacted event
  shells in the six forgotten rooms; Synapse removes media only through its admin API. The MAS/Keycloak browser sessions of the
  test driver expire on their own.

## 6. Owner decisions

1. **Accept the native-SDK route** (section 2) and Element Web as the browser fallback.
2. **Consent screen:** MAS shows "Allow Office Unbound Desktop access" once per installation. To skip it, the deployment could
   register Office Unbound Desktop as a static MAS client (fixed `client_id`, `client_auth_method: none`, redirect
   `http://127.0.0.1/callback`) and publish that id in the client document. That is a MAS config change, and whether MAS then
   skips the consent page is not verified. Optional; the dynamic flow works today without any change.
3. **Search in encrypted rooms:** needs a local index (matrix-sdk `experimental-search`, tantivy, larger binary; the index must
   be encrypted at rest). Decide whether that is wanted for beta.
4. **Meetings:** Jitsi (`meetings`) is experimental and not deployed on officeunbound8. Deploying it, and adding its URL to the
   client document, is the owner's call; until then the "Meet now" button stays hidden.
5. **MSRV:** matrix-sdk 0.20 needs Rust 1.96; the workspace says 1.85. `ou-chat` declares 1.96; CI (winci) must use a current
   stable toolchain.

## 7. Proposed `ou-core` API changes (lead's crate; not made here)

1. `discovery::ClientDocument` / `Deployment`: add `meet: Option<String>` (Jitsi base URL) and add it to the account's
   `OriginSet`, so `meet::open_meeting` passes the URL policy. Optionally `matrix_client_id: Option<String>` for decision 2.
2. `http`: a constructor for long-poll clients (`client_with_timeout(Duration)`), or document that per-request timeouts are set
   by callers. matrix-sdk sets its own per-request timeouts on the shared client, which override the 30 s client default; no
   change is strictly needed today.
3. `oidc`: expose the loopback listener (`Loopback::bind`, `redirect_uri()`, `wait(state)`) with a configurable path so ou-chat
   can drop its copy (`ou-chat::auth::Loopback`, same rules: state check, 8 KiB cap, no-store page).
4. `session`: the comment in `session.rs` says ou-chat builds a second `Session` for MAS. ou-chat instead lets matrix-sdk own the
   MAS tokens (it must, to refresh during sync and to handle soft logout) and stores them through `SecretStore`. Proposal: drop
   that comment, keep the `TokenProvider` for Keycloak services.
5. `ipc::Request`: add chat requests (`ChatRooms`, `ChatHistory`, `ChatSend`, `ChatSendFile`, `ChatDownload`, `ChatSearch`,
   `ChatMarkRead`, `ChatStartMeeting`) and events (`ChatNotification`, `ChatBadge`, `ChatSignedOut`); payload shapes are the
   `Serialize` types in ou-chat (`RoomSummary`, `ChatMessage`, `ChatNotification`, `SearchResult`), mirrored in
   `desktop/ui/src/chat/types.ts`. Tokens never cross IPC.
