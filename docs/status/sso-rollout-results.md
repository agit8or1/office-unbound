# SSO rollout: hardening, ou-gw1, portal, ICS lifecycle with Matrix (agent AA)

Date: 2026-11-15. Lab only. Status words per ADR-0000: PASS = executed this session, output quoted below (raw outputs of the runs were kept in the agent's scratchpad; the commands are in the files named). Builds on `webmail-sso-results.md` (agent S), `collaboration-lab-results.md` (agent R), `portal-results.md`, `user-lifecycle-results.md`.

## 1. Webmail SSO hardening

### 1.1 Realm user profile: `email` and `username` read-only for users (PASS)
Script `blueprints/lab/spike-groupware/kc-profile-harden.py` (inside ou-id1, admin password read from the local file, never printed; helper `kc_lib.py`). A throw-away LOCAL user (random password) signs in with the `admin-cli` client and calls the Account REST API (`POST /realms/ou-lab/account`, what the account console uses):
```
BEFORE  {"email": {"http": 204, "changed": true},  "username": {"http": 400, "changed": false}}   <- a user could re-point the mailbox identity
apply   {'username': ['admin'], 'email': ['admin']}
AFTER   {"email": {"http": 400, "changed": false}, "username": {"http": 400, "changed": false}}
        {"firstName_http": 204, "firstName_changed": true}                                         <- other attributes stay user-editable
```
`username` was already immutable for users in this realm (HTTP 400: realm setting "edit username" off); it is now also `edit=[admin]` in the profile. LDAP-federated users were already read-only (READ_ONLY federation). Admin edits still work. NOT covered: a realm admin can still change any email (by design); a user who can reach Keycloak's admin console (none) would bypass this.

### 1.2 Key rotation: gromox follows the realm signing key (PASS)
`blueprints/lab/spike-groupware/ou-sync-bearer-key.py` (stdlib only, installed by `lab-sso-keysync.sh` as `/usr/local/sbin/ou-sync-bearer-key` + systemd timer every 30 s). It reads the realm's active key (`public_key` of `/realms/<r>`), finds the matching JWKS entry (`use=sig`, `alg=RS256`) and takes its **kid**; the PEM written to `/etc/gromox/bearer_pubkey` (atomic, 0640 root:gromoxcf, only when changed) is built from that entry. No match or fetch error: old key stays, exit code 3/2. zcore re-reads the file per verification, no restart. Unit test `blueprints/lab/tests/test_sync_bearer_key.py`: 3 PASS (JWK->SPKI equals OpenSSL's encoding for 2048/3072/4096 bit keys; picks the active key by kid among several; refuses when the active key is absent).

End-to-end test `blueprints/lab/tests/webmail_sso_keyrotation.sh` (real bob tokens into zcore `mapi_logon_token`, same layer webmail uses), run on `ou-gw-sso1` and on `ou-gw1`; a second RS256 provider with higher priority is added to realm ou-lab (kc-rotate-key.py), then removed (rollback):
```
1 baseline                    token kid=PKaqwBE...   T0 (old key): ACCEPTED
2 rotate (add key), sync stopped   token kid=yagZE_O...   T1 (new key, before sync): rejected      <- the outage the job prevents
3 sync job                    [sync] bearer key kid=yagZE_O... UPDATED
                              T1 (new key, after sync): ACCEPTED     T0 (old key, after sync): rejected
4 rollback (remove key)       token kid=PKaqwBE...   T2 (old key again, before sync): rejected
                              [sync] ... UPDATED    T2 (old key again, after sync): ACCEPTED
```
(Same sequence on ou-gw-sso1 with kid xrpZ78w....) Limitations: gromox holds ONE key, so tokens signed by the previous key (max. access-token life 5 min) stop validating at the switch; webmail refreshes its token every 280 s and sends the browser through Keycloak again when it fails (not separately timed). The follower polls every 30 s: after a rotation SSO logins can fail for up to 30 s + (zcore reads per request: none). Not done: an ICS health check that alerts on `state.json` age / exit code 2-3 (the timer unit failing is visible to the existing `service` checks); a multi-key gromox (would need the patch below to accept a key set).

### 1.3 gromox token validation (alg / iss / aud / exp / nbf / email): patch + tests (PASS on a NEW build machine)
Patch `blueprints/build/gromox/patches/0001-authmgr-bearer-claims.patch` (apply with `patch -p1` on gromox-3.13 / 8b620206; for agent K's pipeline). Changes: JOSE `alg` must be exactly `RS256`; `exp` must be present/integral/future, `nbf` (if any) passed, `email` non-empty; new `gromox.cfg` directives **`bearer_issuer`** and **`bearer_audience`** (default empty = unchanged behaviour plus a NOTICE log). The claim logic is a header-only function `include/gromox/bearer.hpp` with a unit test `tests/bearer.cpp` registered in `make check` (Makefile.am, `doc/authmgr.4gx` documents the options). Backwards compatible; suitable as an upstream submission (AGPL like gromox).

Built and tested on **`ou-aa-gx1`**, a copy of the `ou-gw-sso1` machine (3.3 GB, `MemoryMax=3G`; host memory was fine: `free -g` 8 GB available, only `authmgr.lo` and the test were compiled, ~1 min). `ou-gw1`'s binaries were not touched.
```
make check TESTS=tests/bearer      PASS: tests/bearer  (# TOTAL: 1  PASS: 1  FAIL: 0; 27 individual checks incl. alg none/HS256/RS512/rs256, aud array/string/substring, exp==now, nbf, empty email)
integration (blueprints/lab/tests/gromox_bearer_claims_test.sh, real bob token of client ou-lab-test: aud=account), zcore mapi_logon_token:
  [no policy (legacy default)]                    real ACCEPTED   alg_none rejected  alg_hs256_header rejected  alg_rs512_header rejected
  [audience=ou-webmail (token is for account)]    real rejected   (the "valid_other_client" row of the earlier negative test is now closed)
  [audience=account + correct issuer]             real ACCEPTED
  [audience=account + wrong issuer]               real rejected
```
Production setting: `bearer_issuer=https://<kc>/realms/<realm>`, `bearer_audience=ou-webmail` (the client already carries an audience mapper for `ou-webmail`). **ou-gw1 and ou-gw-sso1 still run the unpatched gromox**: the patch is only deployed on the test machine; it becomes effective on the next gromox build from agent K's pipeline. Not tested: the patched build under the full webmail browser flow (only zcore level), real-world interaction with other token consumers.

## 2. ou-gw1 switched to webmail SSO (PASS)
`blueprints/lab/spike-groupware/lab-sso-existing.sh` = steps 4-6 of `lab-sso.sh` for an existing node, plus key follower, php-gd and a hosts entry for `auth.ou-lab.internal` on the node (`kc-webmail-client.py` now MERGES redirect URIs: `ou-webmail` serves both `sso.ou-lab.internal` and `gw1.ou-lab.internal`, one shared client secret in the lab; per-node/customer clients are still the production recommendation). gromox binaries, LDAP/auth config and mailboxes untouched. Total script time 53 s (20:12:36 -> 20:13:29); service impact is the restart of `gromox-zcore` and `php8.2-fpm` (about 1-2 s each) and the web directory swap.

Regression, monitoring checks were disabled by the owner: `blueprints/lab/tests/gw_run_all.sh` before and after (identical):
```
GW01 13/0  GW02 12/0  GW03 7/0  GW04 10/0  GW05 4/0  GW08 4/0  GW07 7/0   (PASS/FAIL) - before and after the switch
```
(IMAP/EWS/ActiveSync/DAV keep the LDAP password and are unaffected; GW08 is HTTP level and does not exercise the login page.) SSO e2e on gw1 (`webmail_sso_e2e.js`, `WEB_HOST=gw1.ou-lab.internal`, bob, TLS verified; screenshots `docs/screenshots/webmail-sso-gw1/`):
```
PASS Keycloak sign-in (the only password entry) - authenticate POSTs=1
PASS webmail opened without second password prompt
PASS mailbox loaded, bob visible - displayName="Lab Bob" smtp=bob@ou-lab.internal
PASS default store inbox resolvable   PASS no JWT in page HTML
PASS deep link ?action=context&view=calendar opens calendar view   PASS deep link ...view=contacts opens contact view
PASS deep link survives OIDC redirect (fresh webmail session, Keycloak SSO)
PASS Keycloak logout ends the webmail session - redirected to Keycloak login after ~279s      -- 9 PASS, 0 FAIL
```
The key-rotation test above was also run on gw1 (the job keeps gw1 working through a rotation). Test-script bug found and fixed: `text=Get Started` matched the wizard's subtitle, not the button (new mailboxes show the Welcome wizard once); now `text="Get Started"`.
Break-glass: `mv /etc/gromox/keycloak.json{,.off}; systemctl restart php8.2-fpm` brings the password login form back (and back again by renaming). ou-gw1 now needs Keycloak up for webmail logins.

## 3. Portal (PASS)
`portal/app/config.py: Settings.mail_view_url()` (fixed set mail/calendar/contacts), `templates/home.html`: Calendar tile -> `https://gw1.ou-lab.internal/web/?action=context&view=calendar`, Contacts -> `...view=contacts`, Mail unchanged. The "separate password" statement existed only in `portal-results.md` section 5 (superseded here; the templates never carried a note). `pytest portal/tests`: 17 passed (new test: tile hrefs, no "separate/own/same password" wording, view whitelist). Deployed to `ou-portal1` (install-portal.sh; env backup `/root/portal.env.bak-aa`). `portal/e2e/portal-e2e.js` section 7 now requires, for each of Mail/Calendar/Contacts: webmail reached, no password form, 0 Keycloak authenticate POSTs, and the right context. Real run (bob): **39 PASS / 0 FAIL** (a first run had one FAIL, "new document: editor opened (Collabora frame)", the same step passed for spreadsheet/presentation and on the rerun; not related to the mail tiles, cause not investigated):
```
PASS mail tile opens the real webmail without a password prompt, in the mail view (HTTP 200, TLS verified) - .../web/ | context=mail | auth POSTs=0
PASS calendar tile ... in the calendar view ... context=calendar | auth POSTs=0
PASS contacts tile ... in the contact view ... context=contact | auth POSTs=0
SUMMARY: 39 PASS, 0 FAIL
```

## 4. ICS identity lifecycle with Matrix
### 4.1 Code (`ics/ics/identity.py`, `ics/tests/test_identity.py`: 31 passed in `test_identity.py`)
Matrix (MAS) is an optional downstream of a stack: `mas_url`, `mas_client_id`, `mas_client_secret` (all three or none; the secret is held in the vault like the LDAP/Keycloak ones and redacted everywhere). `class Mas` calls only: client-credentials token, `GET /users/by-username`, `POST /users/{id}/lock|unlock|deactivate`, list + `POST .../finish` for `oauth2-sessions` and `compat-sessions`.
* **disable**: after the Keycloak revoke (whose logout also triggers the back-channel logout, 4.3): `matrix.lock` (refresh + new logins refused at once) and end of all active sessions; VERIFY adds path `matrix_access` (polled, refused when locked and no live session) and state `matrix` (`locked`, `active_sessions == 0`); a user MAS never saw is fine (`user_present: false`).
* **enable**: `matrix.unlock`; a deactivated account is an error (irreversible). **delete**: sessions ended + `deactivate` (rooms/history stay on the homeserver). **reconcile**: new critical kinds `matrix_not_locked`, `matrix_sessions_remain`, `matrix_active` (deleted but not deactivated), warning `matrix_locked`; report only, nothing repaired.
* Tests with fakes: parameter coupling, full disable/enable/delete flow, user without Matrix, a session that cannot be ended makes VERIFY FAIL loudly, classify table, reconcile drift, the real `Mas` class against a mock transport (exact endpoints only, client-credentials with `urn:mas:admin`). Full `ics/tests` run: 423 passed, 1 error (`test_m2_heartbeat_stays_fresh_while_both_loops_progress`: a PostgreSQL deadlock in the TRUNCATE fixture, the lab ICS instance on the same test database had only just been stopped; the test passes when run alone).
* **Credential scope, honestly**: MAS has ONE admin scope (`urn:mas:admin`); it cannot be limited to lock/unlock. The narrowing is: a client of its own (`01K9C0SN6N04SKT44QR73EBH7Q`, created by `blueprints/lab/spike-collab/mas-ics-client.py`, separately revocable, not agent R's test client), its secret only in the ICS vault, the code calling only the endpoints above, and (production requirement, lab already `allow 192.168.186.0/24`) the admin API reachable only from the ICS.

### 4.2 Real lab run (PASS): `ics/scripts/lab_user_lifecycle.py matrix`
The production `ics` service was not touched and still runs the previous code, so the run used a **second ICS instance of this branch** (`ics/scripts/lab_ics_instance.py`: own DB `ics_test_aa`, own throw-away keys, 127.0.0.1:8099, the real approval/vault/audit/worker code paths) against the real lab LDAP, Keycloak, MAS and Synapse. It has no mail/files nodes (their agents trust the production ICS key), so mail/files probes are not part of this run. A fresh user is created with the one-time enrollment token, signs in to Matrix with a real browser (MAS -> Keycloak), and its OWN Matrix tokens are polled once a second while the ICS disables it:
```
plan idm.user.disable risk=normal approvals=1 -> job succeeded
ICS steps: ldap.lock 2ms (+0.0s); keycloak.revoke 104ms (+0.1s); matrix.lock 27ms (+0.1s)
ICS VERIFY overall=PASS matrix state={"locked": true, "deactivated": false, "user_present": true, "active_sessions": 0} matrix_access={"status": "refused", "seconds": "0.2"}
after the lock: access token refused after 0.6 s, refresh token refused after 2.6 s (target 60 s); new SSO login possible: False
enable steps: ldap.unlock+credential_reset 10ms; keycloak.enable 68ms; matrix.unlock 25ms
after enable + re-enrolment: Matrix SSO login possible again: True
INJECTED DRIFT: unlocked the Matrix account out of band (ICS says 'disabled')
reconcile after drift: [('matrix_not_locked', 'critical')]
delete steps: keycloak.delete 80ms; matrix.deactivate 28ms; ldap.delete 2ms; MAS account deactivated=True
audit + job result scan for passwords / the MAS client secret: leaks=none
RESULT PASS: Matrix access refused within 60 s of the lock; total run 59 s
```
(Earlier lab finding unchanged: without any MAS integration the same user keeps Matrix access indefinitely, `collaboration-lab-results.md` section 3.) One run; the 118 s Synapse introspection-cache case seen by agent R is bounded by the explicit session end and was not reproduced. The stack-less-node setup means the extended `lifecycle` mode (mail/files, production ICS) does not include Matrix yet: register a stack with the `mas_*` fields on the production ICS after the next ICS deployment, then run `matrix` or add it to the stack used by `lifecycle`.

### 4.3 Back-channel logout Keycloak -> MAS (PASS)
Keycloak could not resolve `mas.ou-lab.internal`; added `192.168.186.245 mas.ou-lab.internal` to `/etc/hosts` of ou-id1 ONLY for that name (host-changes.md). Client `ou-matrix` now has `backchannel.logout.url = https://mas.ou-lab.internal/upstream/backchannel-logout/01HQW90Z35CMXFJWQPHC3BGZGQ` (was the IP workaround; `kc-collab-clients.py` updated). `c05_backchannel.py` rerun:
```
PASS Keycloak admin logout of alice - 204
PASS Matrix access token rejected after ONLY a Keycloak logout (no MAS admin call) - after 1s
PASS refresh token refused after back-channel logout - HTTP 400
== C05 ...: 6 PASS / 0 FAIL
```
Keycloak's own TLS trust accepted the lab-CA certificate of MAS (no truststore change needed).

## 5. Not done / open
* The patched gromox is not on ou-gw1/ou-gw-sso1 (agent K's build + a controlled switch); until then `valid_other_client` style tokens remain accepted there (mitigation unchanged: zcore is a node-local unix socket).
* Key follower: one key only (overlap impossible); no ICS monitor check on its state file.
* gw1 shares the `ou-webmail` client secret with the lab SSO node; webmail Logout button and non-Chromium browsers still untested; mailbox of bob has no content (hierarchy/store only).
* ICS production service not redeployed with the Matrix code; the production stack `lab-acme` has no MAS fields; MAS admin API IP allow-list is lab-wide (/24), not ICS-only.
* ActiveSync/IMAP/Outlook still use the LDAP password (no SSO), so a locked user is refused there via the LDAP lock path only.
