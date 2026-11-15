# User portal (Phase 3): results

Date: 2026-11-15. Code: `portal/` (separate app from the ICS console; ADR-0002 identity/tenant/infra separation: the portal holds no infrastructure credential and talks only to the customer's Keycloak/OpenCloud with the signed-in user's own token).
Status words follow ADR-0000. PASS = executed in this session (lab only). Screenshots: `docs/screenshots/portal/` (home/devices/account x light/dark x desktop/mobile, plus the signed-out landing page).

## 1. What it is
Python 3.12 + FastAPI + Jinja2 server-rendered pages, **no JavaScript at all**, one stylesheet, system fonts, no CDN. Runs as one uvicorn process with TLS on 443 in the nspawn machine `ou-portal1`
(Ubuntu 24.04, zone `oulab`, `PrivateUsers=pick`, MemoryMax 768M, static 192.168.186.244, `portal.ou-lab.internal`; ~45 MB RSS). All Python deps are Ubuntu packages (fastapi 0.101.0, uvicorn 0.27.1, httpx 0.26, PyJWT 2.7, jinja2, cryptography): no pip, no build step.
Systemd unit is sandboxed (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, syscall filter, only `CAP_NET_BIND_SERVICE`).

### Design decisions
* **BFF, confidential client `ou-portal`.** The browser holds only an opaque `__Host-ou_portal` cookie (HttpOnly, Secure, SameSite=Lax, Path=/, no Domain). Access/refresh/ID tokens stay in server memory; refresh is done server side. Confidential rather than public because the code exchange happens server-side where a secret can be kept, so token-endpoint client authentication is added on top of PKCE (S256, also enforced on the Keycloak client). A public client would be the right choice for a SPA or desktop app.
* **Flow:** authorization code + PKCE S256, `state` bound to the browser by a second `__Host-` flow cookie (login-CSRF), `nonce`, ID token verified (JWKS signature, iss, aud, azp, exp, nonce). `next` is restricted to same-site paths. Logout = RP-initiated logout at Keycloak with `id_token_hint`.
* **CSRF:** all POSTs carry a per-session token + Origin check. **CSP** `default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self' <auth> <files>; frame-ancestors 'none'; base-uri 'none'` (no script-src at all), HSTS, nosniff, same-origin referrer/COOP/CORP, `no-store` on pages.
* **OpenCloud with the user's token: verified that OpenCloud accepts the Keycloak access token directly** (it resolves the user through the `uuid` claim; the `ou-portal` client therefore carries the same `uuid` + `roles` mappers as the OpenCloud clients). No token exchange needed. Used for: `GET /graph/v1.0/me/drive`, `REPORT /remote.php/dav/files/<user>` (OpenCloud search, KQL `mtime>=<90 days>`, newest 8 files), `POST /app/new` (create file; same call OpenCloud's own New menu makes).
  There is no Graph "recent" endpoint in OpenCloud 9.1 (`/graph/v1.0/me/drive/recent` and `/graph/v1beta1/me/drive/recent` return 404, `/graph/v1beta1/search/query` 404), so "recent" = search by modification time.
* Create-and-open: the portal creates `New <type> <timestamp>.docx|xlsx|pptx` in the user's home through `/app/new`, then redirects to `/external-collaboraonline/<space>/<name>?fileId=...` (the URL OpenCloud web navigates to itself after "New > Document", read from a real browser session). OpenCloud's own menu creates ODF files; the portal creates OOXML (configurable `doc_ext`).
* Recent-file links use OpenCloud's own resolver `/f/<fileid>`, rebuilt on the configured files host (the server-supplied link is ignored).

## 2. Lab changes (also in host-changes.md)
New machine `ou-portal1`; Keycloak client `ou-portal` created through the admin API (`portal/deploy/kc-portal-client.py`, run **inside ou-id1** by `run-kc-client.sh`; the admin password file is read there and never printed; client secret written to `ou-id1:/root/ou-lab-secrets/kc-portal-client-secret` 0600 and pushed to `ou-portal1:/etc/ou-portal/client-secret` 0640 root:ou-portal); TLS cert for `portal.ou-lab.internal` (+IP) issued by the lab CA on ou-id1 using `blueprints/lab/common/lab-ca.sh` (new optional `issue portal` line, `HOST_PORTAL`/`IP_PORTAL` in `lab.env`; the name-constrained CA accepted it). The machine trusts the lab CA **and** the separate `OU Lab CA gw1` (the mailbox host `gw1.ou-lab.internal` still has its own CA, see groupware results; `mail.ou-lab.internal` is not served by any lab machine, so the lab uses `gw1.ou-lab.internal` for mail/DAV/IMAP).
Install: `portal/deploy/install-portal.sh` (run in the machine). Rebooting the machine brought the service back (checked: active, TLS answers).

## 3. Automated test (executed): `portal/e2e/portal-e2e.js`, Playwright headless Chromium against the real lab, user `bob` (password read from ou-id1 at run time, never printed or written to artifacts)
Final run: **39 PASS / 0 FAIL** (log not stored in repo; every line below was printed PASS):
* Landing page, click Sign in, Keycloak login (URL had `code_challenge_method=S256`, `client_id=ou-portal`), back at the portal as "Hello, Bob".
* Cookie: `__Host-ou_portal` HttpOnly+Secure+Lax+Path=/ with no Domain, opaque (not a JWT), not visible to `document.cookie`, flow cookie removed, no JWT/password in the page HTML, zero `<script>`/inline `style`, no CSP violation logged.
* Launcher: Mail/Calendar/Contacts (grommunio-web `https://gw1.ou-lab.internal/web/`, HTTP 200, title "grommunio Web", TLS verified) and Files (OpenCloud files view of bob reached with **no second login**, SSO).
* Recent files: 8 shown; every one exists in bob's OpenCloud (cross-checked via Graph with an independent token), the newest in OpenCloud is first.
* A recent-file link opens the file inside OpenCloud (no re-login).
* New document / spreadsheet / presentation: file created in bob's OpenCloud (Graph confirms), editor opened with the real Collabora frame (`office.ou-lab.internal/browser/.../cool.html`), file then appears in Recent. Files deleted again by the test (WebDAV 204; Collabora holds a lock for a few seconds first, the test retries).
* Account: profile from OIDC claims, MFA status line, "This device" session row (from Keycloak's account API with the user token), password link lands on Keycloak's account console with SSO.
* Devices: `.mobileconfig` downloads (mail+CalDAV+CardDAV payloads, bob's address, password string absent), autoconfig XML served publicly without secrets, 3 sha256 checksums listed.
* No horizontal scroll at 390 px (light and dark). Sign out ends the Keycloak SSO session (`/account` then shows the Keycloak login form).
Also `pytest portal/tests`: 16 PASS with a mock IdP/OpenCloud (PKCE+Basic client auth, forged/foreign state, bad nonce/aud/iss/exp/signature, open-redirect, CSRF/Origin, refresh and refresh failure, logout, CSP, mobileconfig/autoconfig contents incl. no password keys, newest-first and folder filtering, ignoring the server-supplied link). Run with the same package versions as the machine (venv with fastapi 0.101.0/starlette 0.27/PyJWT 2.7).

## 4. Device onboarding: what is real and what is not
| Item | State |
|---|---|
| Thunderbird autoconfig XML at `/.well-known/autoconfig/mail/config-v1.1.xml` and `/mail/config-v1.1.xml` | served and structurally validated. **Not tested with a real Thunderbird.** A client only finds it if `autoconfig.<domain>` (or `https://<domain>/.well-known/...`) points to the portal: DNS/ proxy step for the customer, not done in the lab. Autoconfig has no CalDAV/CardDAV. |
| Apple `.mobileconfig` (IMAP, SMTP, CalDAV, CardDAV; no passwords; unsigned; deterministic UUIDs so reinstall replaces) | generated, parsed as a valid plist in tests, delivered by the browser test. **Not installed on a real iOS/macOS device.** `CalDAVPrincipalURL` is `/dav/` (discovery via current-user-principal; grommunio-dav answers PROPFIND there, GW04), not exercised by an Apple client. |
| Profile signing | **Production requirement, not done.** Sign with a certificate that chains to a CA the device trusts (S/MIME-style CMS signature, e.g. `openssl cms -sign` with the organisation's code/profile-signing cert) so iOS shows "Verified". For the lab CA hosts the devices must also install the lab CA (a root payload could be added; deliberately not shipped). |
| Outlook classic | text only: Autodiscover at `https://autodiscover.<domain>/autodiscover/autodiscover.xml`. Gromox answers Autodiscover POX with MAPI/HTTP (GW02), but **no real Outlook was run** and the lab has no `autodiscover.ou-lab.internal` name/cert. Page says New Outlook/mobile Outlook cannot be used. |
| OpenCloud desktop client | AppImage and macOS arm64/x86_64 pkg with the vendor-published SHA-256 (GitHub release v4.0.0, digests read from the release API; the AppImage digest equals the one verified in T07). **Windows installer: not among the v4.0.0 release assets**, the page links the release page; open item. Download links are not fetched or re-hashed by the portal. |
| Mobile apps | links: OpenCloud for iOS (App Store id 6743121005), Android (Play, F-Droid), DAVx5 (F-Droid). Play/F-Droid pages answered HTTP 200 when checked; nothing installed. |

## 5. Known limitations and pending
* **Mail SSO: not available.** grommunio-web has no OIDC login; Mail/Calendar/Contacts open its own password sign-in (same LDAP password). Therefore also **no deep links to Calendar or Contacts**: all three tiles go to `/web/` (no documented URL route was found in the source; untested guesses were not shipped). Real SSO into webmail would need a grommunio-web patch or an auth proxy (new work item).
* SMTP submission (587/465) is not configured on the lab mailbox host (groupware results): the settings shown for outgoing mail are the intended production values and are untested end to end.
* "Sign out everywhere else" and the MFA-on/off pill: covered by mock tests; against the real Keycloak only the read side (session list, credentials list) ran. Not executed live because bob's real sessions are shared with other lab test runs. MFA enrolment itself (TOTP) not exercised.
* Sessions are in process memory (restart = silent re-login). Single process; scale-out needs a shared store. Session lifetime 8 h absolute, refresh until Keycloak refuses.
* Disabled-user behaviour: not tested with the portal. By ADR-0004 findings the portal drops the session when the refresh is refused (unit-tested), but a locked user keeps a valid portal session until the access token (5 min) cannot be refreshed; OpenCloud calls fail first (~11-13 s).
* Back-channel logout from Keycloak to the portal is not implemented (client attribute is set, no endpoint).
* The portal machine is not yet enrolled in the ICS, not in the backup set, and no ICS "portal" component/health check exists.
* Accessibility: semantic landmarks, skip link, focus styles, 44 px targets, tables with captions, forced-colors/reduced-motion rules; **no axe/screen-reader run yet**.
* Browser matrix: Chromium only.
