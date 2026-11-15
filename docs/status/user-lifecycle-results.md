# User lifecycle through the ICS: provision -> change -> deprovision, with measured effective access removal

Date: 2026-11-15. Lab only (`ou-id1` OpenLDAP + Keycloak 26.8.2, `ou-files1` OpenCloud 9.1.0, `ou-gw1` Gromox 3.13; ICS on this host).
Status words follow ADR-0000: everything marked PASS below was executed in this session and the output is quoted. Acceptance item 19 (effective access removal) is
**PASS in the lab for every path we can probe, with three documented gaps** (section 6).

## 1. What was built
One lifecycle as typed ICS actions (`idm.*`, ics/README.md "Identity lifecycle"): `stack.register` (high), `user.create` (normal), `user.update_groups` (normal; high for privileged groups),
`user.disable` (normal, includes the VERIFY step), `user.enable` (normal), `user.delete` (high), `reconcile` (low, read only; also periodic). All go through plan -> approval bound to the plan hash ->
single-use job -> hash-chained audit; the existing property tests still pass. New plan risk tier `normal` = exactly one approver who is not the requester.

Service identities (none is a broad credential):
| system | identity | what it can do | proof |
|---|---|---|---|
| OpenLDAP | `cn=svc-ics,ou=system` (`ldap-ics-bind.sh`) | add/modify/delete entries under `ou=people`; write (never read) `userPassword`; manage `pwdAccountLockedTime`; add/remove `member` of EXISTING groups; nothing else | ACL test: cannot add groups, cannot change `description` of a group, cannot touch `ou=system`/`svc-bind`/`svc-gromox`, cannot read `userPassword`. The first ACL draft was too wide (my own test reset `svc-bind`'s password; restored and fixed, host-changes.md) |
| Keycloak | client `ou-ics`, client-credentials only (`kc-ics-client.py`) | realm-management `manage-users`, `view-users`, `query-clients` | with its token: users/sessions/consents/clients = 200; `GET /roles`, `/components`, `/events`, client-secret, `PUT realm` = 403 |
| Gromox | node agent runbooks `gromox.sync_user`, `gromox.kick_user`, `gromox.user_state` | params exactly `{user: <lowercase uid>}`; `systemctl start --wait ou-rb-<name>@<uid>.service` (template units -> root helper `ou-gw-user`, validates again); polkit rule generated from the root-owned `agent.json` allows exactly those `start` verbs; a bad uid / other unit -> "Access denied" (executed on the node) | pytest + manual `setpriv --reuid=ou-agent systemctl start ...` |
| OpenCloud | node agent runbook `opencloud.check_user` on the new agent on `ou-files1` | runs `opencloud auth-app create --user-name <uid> --expiration 1s` as user `opencloud` and DISCARDS the token: a real "can OpenCloud resolve this user" probe (its own LDAP filter) | executed: alice -> resolved, nonexistent -> "user not found" |
TLS everywhere is verified (LDAPS with CA **and** hostname: wrong CA and `ldaps://<ip>` both refused, executed). Agents were installed only on `ou-files1` (new) and `ou-gw1` (upgraded); `ou-id1` needs none because LDAP and Keycloak are reached over the network with the narrow identities above.

Initial password: none exists. `create` (and `enable`) issue a one-time enrollment token; only the plan's requester can reveal it (once); the user sets their own password via `POST identity/enroll`.
Verified in the run below: an approver gets 404 on reveal, second reveal 404, second redemption 403, and the audit log / job results contain neither the passwords, the token, nor the app token (automated scan).

## 2. The run (verbatim output of `ics/scripts/lab_user_lifecycle.py lifecycle`, 2026-11-15)
```
18:09:11.251Z  == lifecycle of lce4ac45 in stack lab-acme
18:09:14.397Z  plan idm.user.create          risk=normal approvals=1 -> job succeeded
18:09:14.397Z  create steps: ldap.add 177ms; ldap.groups 15ms; enrollment.issued 7ms; gromox.sync 803ms; opencloud.visible 470ms
18:09:14.397Z  stable id (idm user id) f33072e5-0f25-46a5-830c-f518910922ad  entryUUID 67dd60d8-756b-1041-8e87-2b123d2e0c1d  opencloud_visible=True
18:09:14.411Z  approver cannot reveal the enrollment token (404): OK
18:09:14.654Z  user set their own password via the one-time token; second use of the token -> HTTP 403; second reveal -> 404
18:09:15.939Z  logins with the user's own password/tokens: {"Keycloak login": true, "Keycloak offline login": true, "OpenCloud Graph /me (bearer)": true, "OpenCloud WebDAV (bearer)": true, "IMAP login": true, "IMAP session open": true, "EWS GetFolder": true, "ActiveSync OPTIONS": true, "OpenCloud WebDAV (app token)": true}
18:09:17.525Z  plan idm.user.update_groups   risk=normal approvals=1 -> job succeeded
18:09:17.525Z  groups now: ["mail-users", "opencloudGuest", "opencloudUser"]
18:09:18.596Z  plan idm.user.update_groups   risk=normal approvals=1 -> job succeeded
18:09:18.616Z  privileged group change -> risk=high approvals_required=2 (high = 2 approvers)
18:09:19.371Z  all paths accepted before the disable: {"keycloak password login": true, "keycloak SSO refresh token": true, "keycloak offline refresh token": true, "opencloud Graph (access token)": true, "opencloud WebDAV (access token)": true, "opencloud WebDAV (app token)": true, "imap fresh login": true, "imap session opened BEFORE": true, "ews GetFolder": true, "activesync OPTIONS": true}
18:09:19.399Z  disable plan risk=normal approvals_required=1; requester cannot approve own plan: 403
18:09:19.421Z  approved by 1 approver -> approved; polling every 1 s
18:09:26.466Z  disable job succeeded
18:09:26.467Z     step ldap.lock                         2 ms  (at +0.0 s after lock)
18:09:26.467Z     step keycloak.revoke                 254 ms  (at +0.3 s after lock)
18:09:26.467Z     step gromox.suspend                  675 ms  (at +0.9 s after lock)
18:09:26.467Z     step gromox.quarantine_mailbox       307 ms  (at +1.2 s after lock)

A. independent measurement (user's REAL credentials/tokens issued before the disable; clock starts when the ICS locks the account)
credential path                  result    refused after   note
keycloak password login          PASS              0.1 s
keycloak SSO refresh token       PASS              2.0 s
keycloak offline refresh token   PASS              2.0 s
opencloud Graph (access token)   PASS              5.1 s
opencloud WebDAV (access token)  PASS              5.1 s
opencloud WebDAV (app token)     PASS              4.1 s
imap fresh login                 PASS              2.0 s
imap session opened BEFORE       PASS              2.0 s
ews GetFolder                    PASS              2.0 s
activesync OPTIONS               PASS              2.0 s
18:09:26.467Z  ICS VERIFY (state_only mode, rotate_credentials=false): overall=PASS state={"ldap": {"locked": true}, "gromox": {"maildir_mode": "0000", "address_status": 1}, "keycloak": {"enabled": false, "online_sessions": 0, "offline_sessions": 0}} paths={"oc_user_resolution": ["refused", "3.6"]}
18:09:28.554Z  plan idm.user.enable          risk=normal approvals=1 -> job succeeded
18:09:28.554Z  enable steps: ldap.unlock+credential_reset 6ms; keycloak.enable 91ms; gromox.reactivate 719ms; opencloud.visible 367ms
18:09:28.658Z  old password after enable (must be refused): imap=True kc=False
18:09:29.013Z  re-enrolled with a new password: kc=True imap=True ews=True
18:09:29.076Z  FINDING: OpenCloud app token minted BEFORE the first disable, after enable -> ACCEPTED AGAIN (token resurrected)
18:09:41.893Z  plan idm.user.disable         risk=normal approvals=1 -> job succeeded

B. the ICS's own VERIFY step (mode canary_probe: valid canary credential accepted before, probed every second after)
credential path                  result    refused after   note
kc_login                         PASS              2.2 s
ldap_bind                        PASS              2.2 s
imap_login                       PASS              2.2 s
ews_getfolder                    PASS              2.2 s
kc_sso_refresh                   PASS              2.2 s
oc_bearer_graph                  PASS             10.2 s
oc_bearer_webdav                 PASS             10.2 s
imap_open_session                PASS              2.2 s
activesync_options               PASS              2.2 s
kc_offline_refresh               PASS              2.2 s
oc_user_resolution               PASS              8.5 s
18:09:41.893Z     baseline accepted before revocation: {"ldap": {"locked": true}, "gromox": {"maildir_mode": "0000", "address_status": 1}, "keycloak": {"enabled": false, "online_sessions": 0, "offline_sessions": 0}} ; overall PASS
18:09:45.499Z  plan idm.reconcile            risk=low    approvals=0 -> job succeeded
18:09:45.499Z  reconcile (clean): critical=0 findings=[]
18:09:45.593Z  INJECTED DRIFT: unlocked the directory entry out-of-band (ICS says 'disabled')
18:09:48.711Z  plan idm.reconcile            risk=low    approvals=0 -> job succeeded
18:09:48.711Z  reconcile after drift: [('ldap_not_locked', 'critical', 'ldap'), ('opencloud_resolves', 'critical', 'opencloud')]
18:09:48.787Z  reconcile did NOT auto-fix: Keycloak password login now (user disabled in KC, unlocked in LDAP) -> False
18:09:48.890Z  delete plan risk=high approvals_required=2
18:09:50.981Z  delete job succeeded: {"uid": "lce4ac45", "note": "mailbox data is retained on the groupware node (suspended, locked); there is no purge action", "state": "deleted", "entry_uuid": "67dd60d8-756b-1041-8e87-2b123d2e0c1d", "mailbox_retained": true}
18:09:51.117Z  LDAP entries left for lce4ac45: 0; gromox state: 1 (1 = suspended, mailbox data retained)
18:09:51.220Z  audit scan (500 newest entries) for the user's passwords / enrollment token / app token: leaks=none
18:09:51.250Z  job results scan: leaks=none
18:09:51.339Z  audit chain: {"ok": true, "checked": 638, "head": "a5fe1f95167d8548aab4817f3ab0993e7a10e8d9a5ec2b4271f8ffa5b7069062", "legacy_unauthenticated": 1, "mac_checked": true, "prob

SUMMARY {"independent_fail": 0, "independent": {"keycloak password login": 0.1, "keycloak SSO refresh token": 2.0, "keycloak offline refresh token": 2.0, "opencloud Graph (access token)": 5.1, "opencloud WebDAV (access token)": 5.1, "opencloud WebDAV (app token)": 4.1, "imap fresh login": 2.0, "imap session opened BEFORE": 2.0, "ews GetFolder": 2.0, "activesync OPTIONS": 2.0}, "app_token_resurrected_after_enable": true, "ics_verify": {"kc_login": "2.2", "ldap_bind": "2.2", "imap_login": "2.2", "ews_getfolder": "2.2", "kc_sso_refresh": "2.2", "oc_bearer_graph": "10.2", "oc_bearer_webdav": "10.2", "imap_open_session": "2.2", "activesync_options": "2.2", "kc_offline_refresh": "2.2", "oc_user_resolution": "8.5"}, "ics_verify_fail": 0, "drift_detected": true, "audit_leaks": []}
RESULT PASS: 0 credential path(s) not refused within 60 s; total run 40 s
```
Table A is the independent measurement: the user's REAL password/tokens (issued before the disable, `rotate_credentials=false`) are probed once per second by the script,
clock = the moment the ICS applied the LDAP lock (reported by the job). Table B is the ICS's own VERIFY on a second disable (a canary credential is installed, accepted before, refused after).
Timings include the ICS's own sequential steps (lock +0.0 s, Keycloak +0.3 s, Gromox suspend +0.9 s, mailbox quarantine +1.2 s) and the 1 s poll granularity.

## 3. Per-path result (measured, target <= 60 s)
| credential path | refused after (A, real credentials) | refused after (B, ICS VERIFY canary) | what ends it |
|---|---|---|---|
| Keycloak password login | 0.1 s | 2.2 s | LDAP lock (bind) + Keycloak user disabled |
| Keycloak SSO refresh token | 2.0 s | 2.2 s | Keycloak disable + logout |
| Keycloak OFFLINE refresh token | 2.0 s | 2.2 s | consent/offline revoke + disable (an LDAP lock alone does NOT: t06/KI-2) |
| OpenCloud access token (Graph /me, WebDAV) issued before | 5.1 s | 10.2 s | OpenCloud re-resolves the user in LDAP (lock excludes it), cache ~5-10 s; the JWT itself would live 300 s |
| OpenCloud app token (opencloudcmd style, WebDAV Basic) | 4.1 s | n/a (lab script only) | same user resolution; **the token is NOT revoked**, see section 6 |
| IMAPS fresh login | 2.0 s | 2.2 s | `address_status=1` (reconcile) is checked before Gromox's 60 s credential cache |
| IMAP session opened BEFORE the disable | 2.0 s | 2.2 s | **only** the mailbox quarantine (section 5); the TCP connection stays open |
| EWS GetFolder | 2.0 s | 2.2 s | suspend |
| ActiveSync OPTIONS | 2.0 s | 2.2 s | suspend |
| LDAP bind with the user's credential | - | 2.2 s | ppolicy lock |
| OpenCloud user resolution (`opencloud.check_user`) | - | 8.5 s (state-only run: 3.6 s) | LDAP lock |
Worst case measured: 10.2 s. Directory state after the job (VERIFY state checks): locked, Keycloak user disabled with 0 online and 0 offline sessions, Gromox `address_status=1`, maildir mode 0000.

## 4. Other lifecycle evidence from the same run
* create: LDAP add 0.18 s, groups, enrollment, Gromox sync 0.8 s (`externid == entryUUID` verified by the ICS), OpenCloud visibility 0.5 s; stable id = idm user id + immutable `entryUUID`.
* update_groups: adding `opencloudGuest` (normal); a change touching the privileged group `opencloudAdmin` was planned as **high, 2 approvals** (then rejected, not executed).
* disable plan: normal, 1 approval; the requester's own approval attempt -> 403.
* enable: password replaced by a random one and a NEW enrollment issued; Keycloak/Gromox restored; the old password is refused by Keycloak at once, but **Gromox IMAP still accepted the old password right after enable** (its 60 s credential cache, same as groupware-ldap-results.md section 8; irrelevant after 60 s).
* reconcile: clean after a verified disable; after an injected out-of-band LDAP unlock it reported `ldap_not_locked` and `opencloud_resolves` as **critical**, and did not repair anything (Keycloak still refused the login because the Keycloak user stayed disabled). The periodic job runs every `reconcile_interval_seconds` (120 s in the lab; 7+ runs recorded in `idm_reconcile_runs`, including one that caught a leftover drift from a failed earlier run).
* delete (high, 2 approvals): LDAP entry and Keycloak shadow user removed, Gromox mailbox **retained** (suspended, mode 0000), no purge action exists; the uid/mail stay reserved (plan-time 409 on reuse).
* audit chain verified after the run (`ok: true`, MAC-checked); no secret in audit/jobs.

## 5. Investigation: killing already-open sessions (Gromox / OpenCloud)
**Gromox has no per-user session termination.** Source read on `ou-gw1` (`/usr/src/ou/gromox/mra/imap`): the only timeouts are global (`imap_autologout_time`, default 30 min); there is no admin command, signal or midb verb that drops one user's IMAP context. Restarting `gromox-imap` would end it but hits every user and another operator uses that unit, so it is **not** used as a per-user action.
Measured (the session stays authenticated after the account is suspended; `gromox-mbop freeze` and midb `X-UNLD` alone are not enough either because the IMAP process reads message files itself):
```
before suspend:
   NOOP       OK
   SEARCH     OK
   FETCH body ('OK', b'secret body')
   STATUS     ('OK', [b'"INBOX" (MESSAGES 1)'])
   LIST       OK
   SELECT     OK
   APPEND     OK
   CREATE     OK
suspend (locked) kicktest2@ou-lab.internal          locked
after LDAP lock + gromox suspend (no quarantine):
   NOOP       OK
   SEARCH     OK
   FETCH body ('OK', b'secret body')
   STATUS     ('OK', [b'"INBOX" (MESSAGES 2)'])
   LIST       OK
   SELECT     OK
   APPEND     OK
   CREATE     OK
{"uid": "kicktest2", "mail": "kicktest2@ou-lab.internal", "cmd": "quarantine", "ts": 1794766217, "state": {"exists": true, "externid": "8b7a826e-756b-1041-8e88-2b123d2e0c1d", "address_status": 1}, "frozen": true, "midb_unloaded": true, "maildir_mode": "0000"}
after quarantine (freeze + midb unload + chmod 000):
   NOOP       OK
   SEARCH     NO
   FETCH body ('NO', [b'server internal error, Unable to read midb.sqlite, see midb logs'])
   STATUS     ('NO', [b'server internal error, Unable to read midb.sqlite, see midb logs'])
   LIST       NO
   SELECT     NO
   APPEND     NO
   CREATE     NO
```
`gromox.kick_user` therefore implements a **mailbox quarantine** for an already-suspended user: `gromox-mbop freeze --no-wait` (exmdb rejects the store), midb `X-UNLD`, `chmod 000` on the maildir; `gromox.sync_user` (enable) releases it (chmod 770 + `thaw`). The connection itself stays open (NOOP answers) but every data operation fails. This is a workaround on files, not a protocol-level logout: it protects the mailbox content, not the socket.
**OpenCloud**: `opencloud auth-app` has only `create` (no list/delete); app tokens live in the jsoncs3 appauth store (`.../oncs3-appauth-data/.../<entryUUID>.json`) and there is no admin API to delete one without the user's own session. `opencloud.revoke_app_tokens` was therefore NOT implemented (editing the store behind a running OpenCloud would race its cache). What happens instead: while the user is locked/removed OpenCloud cannot resolve the user and refuses the token (4-5 s).

## 6. NOT revoked / gaps (be explicit)
**Update (agent AC, `lifecycle-gaps-results.md`): items 1 (app tokens), 3 (socket: IMAP sessions are now closed by a Gromox event patch) and the ActiveSync wipe part of 2 are addressed and proven in the lab; the residual risks are listed there.**
1. **OpenCloud app tokens are not revoked, only unusable while the user is locked.** Measured in the run: a token minted before the first disable was **ACCEPTED AGAIN after `idm.user.enable`**. Mitigations until a revoke path exists: mint app tokens with short expirations; treat "disable then enable" as re-admitting old app tokens; deletion makes them dead (entryUUID is gone). A real fix needs an OpenCloud-side delete API/CLI or a reviewed store edit.
2. **ActiveSync device wipe / EAS Ping, MAPI sessions, EWS streaming connections**: not probed beyond fresh requests; remote wipe needs admin-api (not built) and must be requested before the account is suspended. Not implemented.
3. **Gromox socket**: an open IMAP connection is not closed, only emptied (quarantine). A client that never sends another command stays connected until `imap_autologout_time`.
4. Keycloak access tokens already issued remain cryptographically valid up to 300 s for any resource server that validates the JWT offline without a directory lookup; OpenCloud refuses them in 5-10 s only because it re-resolves the user. Other consumers are not covered.
5. No mailbox purge/export action (policy: retain; address reserved). Gromox password cache: up to 60 s of old-password acceptance after a credential change (not after suspend).
6. Probes need `probe_client_id` (a public Keycloak client with direct grants; the lab's `ou-lab-test`). Without it the VERIFY step degrades to state checks plus the OpenCloud resolution probe (`mode: state_only`).
7. Not run: clean-room re-install, real Outlook/phone clients, the GUI desktop client, MFA on the user, LDAP/Keycloak outage behaviour during a disable (a failed step fails the job; nothing is retried automatically).

## 7. Tests and how to rerun
* `cd ics && .venv/bin/pytest` -> see the status line at the end of this file. `tests/test_identity.py` (25 tests): parameter validation, risk tiers/approvals (normal needs one other approver, privileged groups/delete/register need two), plan-time policy (unknown stack/domain/group/duplicate, delete only after disable, reuse of a deleted uid refused), create/disable/enable/delete flow on in-memory LDAP/Keycloak/agent fakes through the real worker/vault/audit, one-time enrollment (requester-only reveal, once, 5 failures burn, expiry, malformed ids), VERIFY pass and loud failure (stuck IMAP session; Gromox that stays active), canary mode, secrets/AAD binding, reconcile classification + report-only + periodic, probe measurement semantics (errors never count as refused), real agent with stub systemctl (fixed argv, uid regex, not-enabled runbooks rejected, stale result files ignored), ICS->agent interop, polkit rule rendering.
* Lab: `/opt/office-unbound/ics/.venv/bin/python ics/scripts/lab_user_lifecycle.py all` (`setup` is idempotent; `cleanup` deletes leftover `lc*` users). Needs passwordless sudo to the lab machines and the lab accounts from `lab_monitoring_demo.py`.
* Files: `ics/ics/{identity,idprobe}.py`, migrations 0004/0005, `ics/agent/ou_agent/runbooks.py`, `ics/agent/deploy/{runbooks/*,agent*.json,render_polkit.py,install-agent.sh}`, `blueprints/lab/spike-identity-files/kc/{ldap-ics-bind.sh,kc-ics-client.py}`, `blueprints/lab/spike-groupware/gw-ldap-sync.py` (`--user` for a vanished address now suspends it).

## 8. Test status line
`cd ics && .venv/bin/pytest -q` (2026-11-15, final code): **181 passed** in 192.9 s (152 at the start of this task; 25 new tests are in `tests/test_identity.py`, the remaining 4 came from other files changed in the tree meanwhile, e.g. by the concurrent security review; `conftest.py` gained `extra=` runbooks for the fake agent and the new tables in the TRUNCATE list).
