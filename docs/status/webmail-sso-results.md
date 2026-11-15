# Webmail SSO: Keycloak -> grommunio-web (Gromox), results

Date: 2026-11-15. Lab only. Status words per ADR-0000: PASS = executed this session, output quoted. Agent S (groupware SSO).

## 1. Result
grommunio-web **already ships OIDC support** (class `WebAppKeyCloak`, upstream tag `grommunio-web-5.2`, the version pinned in `build-from-source.sh`) and Gromox 3.13 already validates the
resulting RS256 access token (`authmgr` -> `auth_login_token`, used by zcore `zs_logon_token`, i.e. the MAPI session behind the web UI). **No code patch was needed for SSO.**
It is pure configuration: a Keycloak client, `/etc/gromox/keycloak.json`, `/etc/gromox/bearer_pubkey`, lab CA in the node's trust store.
The portal's earlier finding ("grommunio-web has no OIDC login") was wrong. What upstream does NOT have is a URL for Calendar/Contacts: that needed a small patch (section 5).

The old `ou-gw1` was **not touched**. A fresh node `ou-gw-sso1` (Debian 12, built from the same pinned tags by `build-from-source.sh`, 18 min) carries the SSO set-up.

## 2. Approach and versions
| Piece | Version / value |
|---|---|
| grommunio-web | 5.2 (dd9029d9), upstream `WebAppKeyCloak` + `WebAppAuthentication::authenticateWithAccessToken` (authorization-code flow, server side, one-time `state`, validated callback URL) |
| gromox | 3.13 (8b620206), `exch/authmgr.cpp: verify_token()`: RS256 signature with `/etc/gromox/bearer_pubkey`, `exp`, user = claim `email`, then SQL `meta` lookup |
| mapi-header-php | 2.4 (`class.keycloak.php`: code exchange, refresh, introspection, logout URL) |
| Keycloak | 26.8.2 on ou-id1, realm `ou-lab`, new client `ou-webmail` (confidential, code flow only, no implicit/password grant, no service account, fullScope off, redirect URI exactly `https://sso.ou-lab.internal/web`, audience mapper) |
| Node | `ou-gw-sso1`, 192.168.186.233, zone oulab, PrivateUsers=pick, MemoryMax=3G, JOBS=3; web host `sso.ou-lab.internal`, own lab TLS CA; users via LDAP (`lab-ldap.sh`, domain `ou-lab.internal`, directory users incl. bob); no SQL users (`GW_USERS=` `GW_SHARED=`) |

Flow: browser -> `/web/` (no session: login page meta-refreshes to Keycloak) -> Keycloak login or existing SSO session -> `/web?code=..&state=..` -> PHP exchanges the code with the client secret (TLS to
Keycloak, system CA store), **introspects** the token at Keycloak, keeps the tokens only in the server-side PHP session, calls zcore `logon_token(access_token)`; zcore verifies signature/exp and takes the mailbox
identity from the token. The browser only holds the PHP session cookie (`__Secure-GROMMUNIO_WEB`, HttpOnly, Secure, SameSite=None [upstream sets None for the OAuth round trip]) and the encryption-store cookie.
Every ~280 s webmail refreshes the token (refresh token) and re-introspects; a failure sends the browser back to Keycloak.

Reproduce: `blueprints/lab/spike-groupware/lab-sso.sh` (config, LDAP, Keycloak client via `kc-webmail-client.py` run inside ou-id1 with the admin password file read there and never printed, keycloak.json, bearer key,
patch + rebuild). Client secret: `ou-id1:/root/ou-lab-secrets/kc-webmail-client-secret` (0600), node `/etc/gromox/keycloak.json` (root:gromoxcf 0640).

### Things found while doing it (all folded into the scripts)
1. **PKCE must not be required on the client.** grommunio-web's `login_url()` sends no `code_challenge`; with `pkce.code.challenge.method=S256` Keycloak answers `invalid_request: Missing parameter: code_challenge_method` and the login page loops (meta refresh every 1 s). The confidential secret protects the code exchange instead. (The portal uses PKCE because it is our code.)
2. **Audience mapper required.** Webmail introspects the access token with its own credentials; Keycloak refuses with `Client 'ou-webmail' is not in the token audience` unless an `oidc-audience-mapper` for `ou-webmail` is on the client (fullScope off means no automatic audience).
3. **`php-gd` was missing from `GW_RUN_PKGS`**: `Call to undefined function imagecreatefromstring()` (profilepicture) aborts the hierarchy load, so the UI stays on the welcome wizard. The earlier HTTP-only test GW08 could not see it. Added to `common/packages.env` (also true for ou-gw1 and ou-gw-r1: neither has php-gd, so their web UI is affected by the same defect; not changed because ou-gw1 is in use).
4. The lab CA must be in the node's system trust store (PHP curl) for the token exchange to Keycloak; no verification was disabled anywhere.
5. First login of a mailbox shows grommunio's "Welcome" wizard (Get Started) once.

## 3. Tests (executed; Playwright headless Chromium, `blueprints/lab/tests/webmail_sso_e2e.js`, bob, TLS verified against both lab CAs, password read from ou-id1 at run time and never printed). Screenshots in `docs/screenshots/webmail-sso/`
```
PASS Keycloak sign-in (the only password entry) - authenticate POSTs=1
PASS webmail opened without second password prompt - chain: auth.../account/ > sso.ou-lab.internal/web/ > sso.ou-lab.internal/web/   (authenticate POSTs still 1)
PASS mailbox loaded, bob visible - displayName="Lab Bob" smtp=bob@ou-lab.internal
PASS default store inbox resolvable - inbox ok
PASS deep link ?action=context&view=calendar opens calendar view - current context=calendar
PASS deep link ?action=context&view=contacts opens contact view - current context=contact
PASS deep link survives OIDC redirect (fresh webmail session, Keycloak SSO) - context=calendar authPosts=1
PASS Keycloak logout ends the webmail session - redirected to Keycloak login after ~279s
-- 9 PASS, 0 FAIL
```
(`no JWT in page HTML` is part of the 9; mailbox of bob is empty in this lab, only the store/hierarchy/name was proven, not message rendering.)

### Logout: what ends and when (measured, precise)
* Webmail's own **Logout** button: upstream redirects to Keycloak RP-initiated logout with `id_token_hint` + `refresh_token` in the URL, destroys the PHP session. Not separately run in the browser this session (code read only: `index.php:76`).
* **Logout at Keycloak (other app / account console / admin)** does **not** end the webmail session immediately: webmail was still usable at t+5 s and for the next ~4.5 min; it was sent to the Keycloak login at **t+279 s**
  (the 280 s refresh interval in `regenerate_access_token()`, which then fails introspection/refresh). Worst case about 280 s plus Keycloak's access-token life (5 min) is NOT additive: the check is the introspection, which fails as soon as the SSO session is gone.
  So: bounded at roughly 5 min (one refresh interval), not instant; measured once (single run). Keycloak back-channel logout is not implemented by grommunio-web. Instant kill would need a patch (backchannel endpoint that destroys the PHP session) or a shorter `280` (hard-coded upstream).
* IMAP/EWS/ActiveSync/DAV are not part of this flow (still LDAP password, 60 s credential cache, see groupware-ldap-results.md).

## 4. Security analysis
Negative test `blueprints/lab/tests/webmail_sso_negative.sh`: tokens fed straight to zcore `mapi_logon_token` (php CLI on the node):
```
valid_other_client            ACCEPTED   (real bob token of client ou-lab-test: aud=account, azp=ou-lab-test)
tampered_email                rejected   (payload email changed to alice@, signature kept)
expired_claim_resigned_badly  rejected
alg_none  empty_sig  garbage  truncated_sig   all rejected
```
* **Validation is cryptographic**, both layers: Keycloak introspection (webmail) and RS256 signature + `exp` (gromox). No header trust anywhere: nginx sets `REMOTE_USER ""` for php, gromox takes identity from the signed `email` claim, not from anything the PHP layer sends. The browser never sees a token (checked: no `eyJ...` in page HTML; session cookies HttpOnly+Secure).
* Gromox `verify_token` does **not** check `iss`, `aud`/`azp` or `alg`: any token signed by the realm key with an `email` is accepted by zcore (the row `valid_other_client`). Mitigations present: zcore is a **unix socket** `/run/gromox/zcore.sock` (mode 0666, node-local only, no TCP listener, gromox-http has no Bearer path: grep of the 3.13 source and the open-port list), and webmail only ever passes tokens it got through its own code exchange + introspection (aud-bound). Residual risk: a local process on the node holding any user's realm token can open that user's mailbox via zcore (it could equally use the token only with the user's consent anyway). A patch to `verify_token` adding aud/iss checks would close it; not made (not needed for the web path).
* **Identity = `email` claim.** If a user can change their own email in Keycloak they can become another mailbox. In this lab: LDAP federation is `READ_ONLY`, so directory users cannot edit it (config read from the admin API), **but the realm user profile still lists `email` edit = [admin, user]** for any non-federated (local) Keycloak user. Hardening required before production: set `email.permissions.edit=[admin]` in the realm user profile (not done here: shared realm, not asked). Also `bearer_pubkey` is a single static key.
* **Key rotation:** gromox reads exactly one PEM key from `/etc/gromox/bearer_pubkey`. Keycloak realm key rotation (or a new active RS256 key) makes every SSO login fail with "Token did not validate" until the file is refreshed (+ zcore reread: it is read per verification, no restart). ICS needs an action `groupware.sync_bearer_key` (fetch `/realms/<realm>` `public_key`, compare, write) and a health check. Rotate with overlap impossible (one key).
* The login page of grommunio-web, once `keycloak.json` exists, only redirects to Keycloak (no local password form). Break-glass: `define('DISABLE_KEYCLOAK', true)` in `config.php`, or remove `keycloak.json`. A broken client config makes the page loop (seen with PKCE); monitor it.
* CSRF/session: upstream sets the PHP session cookie SameSite=None when Keycloak is enabled (needed for the redirect) so webmail CSRF protection relies on grommunio's own checks (Origin enforcement on logout etc.), weaker than Lax. Back-channel logout missing (section 3). One-time `state` and a validated callback URL are implemented upstream; no PKCE, no `nonce`, no ID-token signature verification in webmail (it relies on TLS to Keycloak plus introspection for the access token).
* Secrets: client secret in `keycloak.json` (0640 root:gromoxcf; web pool user `groweb` is in `gromoxcf`, as is every gromox daemon). Per-customer client + secret needed.
* Directory/lock behaviour: LDAP-disabled users fail at Keycloak login at once; an already-logged-in webmail session ends at the next refresh (<= ~280 s) because introspection/refresh fails; reconcile (`gw-ldap-sync.py`, address_status) refuses at the zcore side immediately (`meta` lookup). Not re-measured here.

## 5. Deep links (Calendar, Contacts)
Upstream knows only `?action=mailto` and `?action=profile` (`server/includes/util.php: storeURLDataToSession`; `client/grommunio/*/URLAction.js`). No URL reaches Calendar or Contacts.
Smallest maintainable patch (kept as a patch for agent K's pipeline): `blueprints/build/grommunio-web/patches/0001-context-deep-link.patch` (apply with `patch -p1` on the 5.2 tree; dry-run + build verified): +12 lines PHP (whitelist `mail|calendar|contacts|tasks|notes` -> stored in the session) and one new 43-line JS file (`core/ContextURLAction.js`, registers a `context` URL action that calls `container.switchContext`). The value never comes from user text, only from a fixed map. The session keeps the action across the Keycloak redirect, so the link works when signed out (PASS above).
| View | URL |
|---|---|
| Mail | `https://<host>/web/` (default) or `?action=context&view=mail` |
| Calendar | `https://<host>/web/?action=context&view=calendar` |
| Contacts | `https://<host>/web/?action=context&view=contacts` |
| Tasks / Notes | `...view=tasks` / `...view=notes` |
Licence: grommunio-web is AGPL-3.0; the patch is a derivative work under the same licence (header says so); our modified copy must be offered to users (AGPL network clause) when we deploy it.

## 6. What the portal must change
1. Mail tile -> `https://<mailhost>/web/` unchanged; it is now SSO (no second prompt) once the mail node has `keycloak.json`. Calendar tile -> `https://<mailhost>/web/?action=context&view=calendar`, Contacts tile -> `...&view=contacts` (needs the patched web build).
2. Remove the "separate password" note in the Mail/Calendar/Contacts launcher text.
3. Keep the portal "Sign out" as is (RP-initiated logout ends the Keycloak SSO session; webmail follows within ~5 min, section 3). To end webmail at once the portal would first have to send the user to `https://<mailhost>/web/?logout` (not wired).
4. **Production/lab mail node `ou-gw1` has NOT been switched**: needs client redirect URI `https://gw1.ou-lab.internal/web` added to `ou-webmail` (or one client per host), lab CA in its trust store, `keycloak.json` + `bearer_pubkey`, `php-gd`, the patched web build. `lab-sso.sh` does this for a node named by `GW_MACHINE`/`GW_HOST` (it reconfigures the whole node, so for ou-gw1 only steps 4, 5, 6 apply).

## 7. Not proven / open
* Only Chromium, only user bob, empty mailbox (store/hierarchy/name loaded, no message list rendering with content). Webmail's own Logout button not run in the browser. Token refresh after the 280 s mark with a live session is covered indirectly (session survived 280 s then failed only after Keycloak logout) but not as an explicit success test.
* Real Outlook/ActiveSync/IMAP are not SSO (they use the LDAP password); OAuth for IMAP/Outlook would need `XOAUTH2` support which Gromox's imap/http do not have.
* Source-built node only; the Debian/openSUSE grommunio packages are not tested. Newer upstream tags than 5.2 were not checked (the reference clone matches 5.2).
* Key rotation, email-edit hardening, back-channel logout, ou-gw1 switch: section 4/6, not implemented.

## 8. Files
`blueprints/lab/spike-groupware/{lab-sso.sh,kc-webmail-client.py,webmail-patch-inner.sh}` (new; `lab-configure.sh`, `lab-nginx.sh`, `lab-ldap.sh` gained `GW_HOST/GW_USERS/GW_SHARED/GW_MACHINE` overrides with the old values as defaults), `blueprints/build/grommunio-web/patches/0001-context-deep-link.patch`,
`blueprints/lab/tests/{webmail_sso_e2e.js,webmail_sso_negative.sh}`, `blueprints/lab/common/packages.env` (php-gd), `docs/screenshots/webmail-sso/`.

## 9. Follow-up (agent AA, 2026-11-15)
Email/username read-only profile, bearer key follower with rotation test, gromox claim-validation patch (alg/iss/aud/exp/nbf/email), ou-gw1 switch and the portal deep links are done: see `docs/status/sso-rollout-results.md`. Sections 4 and 6.4 above describe the state before that work.
