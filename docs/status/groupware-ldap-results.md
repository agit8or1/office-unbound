# Groupware on the single directory: Gromox <- OpenLDAP (lab results)

Date: 2026-11-15. Lab only (`ou-gw1` Gromox 3.13 source build, `ou-id1` OpenLDAP 2.6.10 + Keycloak 26.8.2, OpenCloud on `ou-files1` used read-only as a consumer).
Status words follow ADR-0000: PASS = executed in this session, output quoted. Anything not quoted is stated as unproven (section 8).

## 1. Result in one paragraph
OpenLDAP on `ou-id1` is now the only place where users and passwords are created for Keycloak, OpenCloud **and** Gromox. A user created
with `ldap-user.sh add` becomes a Gromox mailbox after one reconcile call (`gw-ldap-sync.py`, 0.4 s) and logs into Keycloak, OpenCloud,
IMAPS, EWS, ActiveSync and MAPI/HTTP with the same password and receives mail. Deprovisioning by LDAP lock is refused on every
Gromox path within **60 s** (credential caches), or immediately (0 s measured) when the reconcile call is added. Not killed by either: an IMAP session
that was already open (section 5).

## 2. How Gromox uses LDAP (from docs + source, then verified)
* `ldap_adaptor` (4gx): SQL (`users` table) stays the lookup table; LDAP only verifies the password: search `mail=<login>` with the bind account, then a
  simple BIND as the found DN. `authmgr` (default `auth_backend_selection=ldap`) uses LDAP for users whose SQL `externid` is **not NULL**, the SQL
  `password` column for `externid IS NULL`. The `externid` value is ignored by Gromox itself; we store the LDAP `entryUUID`, which is what makes a
  user "directory-managed" and gives a stable identity (rename/mail change safe) for the sync.
* Mapping used: `mail` -> login + `users.username`; `entryUUID` -> `users.externid`; `displayName` (fallback `cn`) -> PR_DISPLAY_NAME;
  `memberOf cn=mail-users` -> entitlement (mailbox allowed); `pwdAccountLockedTime` -> locked. Groups beyond the entitlement group (e.g. OpenCloud roles) are not used by Gromox.
* Public Gromox has **no** LDAP importer. Only grommunio-admin-api has one (`services/ldap.py importUser/downsyncUser`, `Users.create`). We did not
  build admin-api: it drags in Flask/SQLAlchemy/its own config, systemd units, a licence module (5-user cap, see groupware-source-eval.md) and its
  own LDAP config schema, and the end state is that ICS drives provisioning with typed actions. Instead we wrote a ~200-line reconcile script that does what
  `Users.create` + `UserSetup` do for a user (users row incl. externid, PR_DISPLAY_TYPE_EX/PR_DISPLAY_NAME, mailbox dirs, `gromox-mkprivate`, `gromox-mkmidb`).
  No admin-api code was copied (AGPL; behaviour cross-read only). Because admin-api is not built, **no cap patch exists** (nothing under `blueprints/build/grommunio-admin-api/`).
  The script reads the same `/etc/gromox/ldap_adaptor.cfg` keys as admin-api (`ldap_object_id`, `ldap_user_filter`, `ldap_user_displayname`) plus one OU key `ou_entitlement_group`.
  This is the shape of the ICS action `groupware.sync_users(customer, [mail])` (idempotent, `--dry-run`, `--json`, per-user or full, exit codes 0/1/2).

## 3. What was configured (host changes are also in host-changes.md)
* `ou-id1`: account `cn=svc-gromox,ou=system,dc=ou-lab,dc=internal` (`kc/ldap-gromox-bind.sh`). ACL: only `ou=people`, only attrs
  `entry,objectClass,uid,mail,cn,sn,givenName,displayName,entryUUID,memberOf` (+ `pwdAccountLockedTime`); no `userPassword`, no groups, no write.
  svc-bind (Keycloak/OpenCloud) unchanged.
* `ou-gw1`: `/etc/gromox/ldap_adaptor.cfg` (0640 root:gromoxcf, `ldaps://ldap.ou-lab.internal`), lab CA in `/etc/ou-lab-ldap/ca.crt`, `/etc/ldap/ldap.conf`
  `TLS_REQCERT demand`, `/etc/hosts` entry for ldap.ou-lab.internal, `gw-ldap-sync.py` in `/usr/local/sbin`, apt `ldap-utils python3-ldap3 python3-pymysql`,
  postfix `virtual_mailbox_domains += ou-lab.internal` (reload only), gromox domain `ou-lab.internal` (+ public store). `gromox-http/zcore/imap` restarted once at 17:09
  after checking `gromox-imap` was active. Repro: `blueprints/lab/spike-groupware/lab-ldap.sh`.
* Mail domain of directory users is `ou-lab.internal` (what ldap-user.sh puts in `mail`). The 8 SQL users live in the separate legacy domain `gw1.ou-lab.internal`.

## 4. Provisioning (gw_ldap_01, executed)
```
PASS LDAPS certificate verification enforced - sync with wrong CA refused (rc=2, CERTIFICATE_VERIFY_FAILED)
PASS svc-gromox is read-only and limited - cannot read userPassword, cannot see ou=groups, cannot write (Insufficient access)
PASS ldap-user.sh add gwl31b14e - added to OpenLDAP (mail-users + opencloudUser)
PASS pre-sync: gromox does not know the user - no SQL row, IMAP login refused before sync
PASS sync refuses to adopt local user - conflict reported, rc=1, row untouched
PASS sync creates user - created in 0.4s: created  gwl31b14e@ou-lab.internal  externid=4dbcdc9a-7563-1041-8e72-2b123d2e0c1d
PASS sync idempotent - second run: unchanged
PASS Keycloak password grant - HTTP 200 (LDAP federation, user imported on first login)
PASS OpenCloud accepts the token (same LDAP) - graph /me 200 mail=gwl31b14e@ou-lab.internal
PASS IMAPS login / wrong password refused / EWS GetFolder inbox / EWS wrong password -> 401 / ActiveSync OPTIONS
PASS MAPI/HTTP Connect - X-ResponseCode=0 status/err=(0, 0)
PASS SMTP :25 accepts new recipient ; PASS mail received (IMAP) - token found in INBOX
PASS legacy user still works (SQL password) - alice@gw1 SQL login ok ; PASS legacy user cannot use LDAP password
PASS cleanup: LDAP delete -> sync suspends - address_status=1 (mailbox data kept)
-- GW-LDAP-01: 25 PASS, 0 FAIL, 0 SKIP
```
`gw_ldap_03` (5 seeded users alice..erin@ou-lab.internal): IMAP+EWS+Keycloak all accepted with the directory passwords, full reconcile "nothing pending": 12 PASS.
Regression: gw_01 13 PASS, gw_02 12 PASS, gw_03 7 PASS after the change (legacy SQL users unaffected).

### Existing SQL users: migrated or separated?
**Separated, not migrated.** The 7 users + shared mailbox in `gw1.ou-lab.internal` keep `externid NULL` + SQL password (they are lab fixtures for gw_01..08).
They are never touched by the sync (the script refuses to adopt a local row; `--adopt` exists but was not used). Single-store rule for production: every
customer user has `externid` set; local SQL passwords are allowed only for service/shared mailboxes. Mailbox content migration from a SQL user to its directory
twin (`alice@gw1` -> `alice@ou-lab`) would be `gromox-exm2mt` / `gromox-import` (exercised in GW07 for backup/restore, **not** run for this migration). The 8 legacy rows should be dropped when the fixtures are rebuilt on the directory domain.

## 5. Deprovisioning (gw_ldap_02, executed; defaults: `auth_cred_caching=1min`, `http_basic_auth_cred_caching=1min`)
Times = seconds after the LDAP lock (A) or lock+reconcile (B,C) command returned, polling every 1 s, caches warmed and one IMAP session held open.
```
A lock only      : keycloak login 0.0 | IMAPS login 60.1 | EWS new conn 60.1 | EWS keep-alive 60.1 | ActiveSync OPTIONS 60.1 | MAPI/HTTP auth 60.1
B lock+reconcile : all six paths 0.0   (reconcile = address_status=1; took 0.5 s incl. lock)
C lock+SIGHUP    : all six paths 0.0   (SIGHUP of gromox-http/zcore/imap drops the credential cache; units stayed active)
D unlock+reconcile: IMAP+EWS restored after 2 s
Keycloak refresh token after LDAP lock: HTTP 200; after admin logout: HTTP 400   (confirms t06)
```
* **Max delay with LDAP lock alone: 60 s** (cache lifetime; the observed refusal is exactly at the 60 s expiry, i.e. worst case = cache lifetime).
  Both caches are 1 min; the earlier (HTTP basic) and the authmgr cache expire together in our single probe pattern, so we cannot say which one alone would give 120 s worst case:
  theoretical worst case with two stacked caches is up to ~2 min (not observed). Tunables: `auth_cred_caching`, `http_basic_auth_cred_caching` (0 disables).
* With the explicit reconcile step the delay is ~0 s for new logins because authmgr reads `address_status` from SQL before any cache. **Deprovision action = LDAP lock/disable + `gw-ldap-sync.py --user` (+ Keycloak revoke).**
* Not ended by any of the above: a **pre-existing IMAP session** (`pre-existing IMAP session still usable after refusal: True` in A, B and C). It ends at disconnect, `imap_autologout_time`
  (default 30 min idle) or `gromox-imap` restart; a client that keeps polling/IDLEs stays logged in. If the policy needs hard kill, ICS must restart gromox-imap (affects all users: deliberate action, not done here since another operator uses that unit).
  The same question for open EAS Ping / MAPI sessions was **not measured** (only fresh requests and a keep-alive EWS connection, which were refused).
* Keycloak: LDAP lock blocks **new** logins at once (0.0 s) but refresh/offline tokens survive (t06; re-confirmed above); the ICS step must call the Keycloak admin API (logout + consent revoke + disable).
* ActiveSync device wipe/block: in the public source, remote wipe is requested through admin-api (`ADMIN_API_WIPE_ENDPOINT`, `POST .../sync/<device>/wipe`) and delivered at the **next authenticated** provisioning request of the device.
  An account that is already suspended cannot authenticate, so the wipe must be requested **before** disabling the account (or the account re-enabled briefly). With admin-api absent this path does not exist: **unproven, needs our own endpoint** (grommunio-sync reads wipe state from that URL). Lab has `PROVISIONING=true` in sync config but no device was provisioned.
* Not covered: app passwords (Gromox has none; OpenCloud app tokens are a files-side item), OpenCloud's ~11-13 s (t06).

## 6. Findings that change the design
1. LDAP is only a password check for Gromox; without the reconcile step the user cannot exist, and a lock does not suspend the mailbox (delivery continues; auth fails). Reconcile must run on every directory change (event/timer) and as an explicit step in provision/deprovision.
2. Gromox has no LDAP filter for "entitled" users: search is by mail only. A user outside `mail-users` but with a `mail` attribute who is already a Gromox user can still bind until reconcile suspends them (the sync handles this: "not in cn=mail-users" -> suspended).
3. Deleting a user in LDAP never deletes mailbox data (sync only suspends: `no longer in LDAP`). Purge is a separate, explicit, audited action (not implemented).
4. `ldap-user.sh` already produces everything Gromox needs (`mail`, `displayName`, `mail-users`). No directory schema change.
5. The mail domain of directory users (`ou-lab.internal`) differs from the gw1 test domain; production needs one domain per customer = LDAP `mail` domain, created via `--create-domain`.

## 7. Files
`blueprints/lab/spike-groupware/{gw-ldap-sync.py,lab-ldap.sh}`, `blueprints/lab/spike-identity-files/kc/ldap-gromox-bind.sh`,
`blueprints/lab/tests/{gw_ldap_lib.py,gw_ldap_01_provision.py,gw_ldap_02_deprovision.py,gw_ldap_03_directory_users.py}` (`gw_lab.py` now also honours `OU_STRICT_SKIP=1`, exit 77).
Run: `OU_CA_FILE=<id CA> OU_KC_ADMIN_PASSWORD=... python3 gw_ldap_01_provision.py` (needs passwordless sudo to `systemd-run -M ou-id1/ou-gw1`; missing prerequisites SKIP; with `OU_STRICT_SKIP=1` a SKIP exits 77, verified: 5 SKIP -> rc=77).

## 8. Unproven / not done
* Real Outlook/phone clients, real EAS provisioning and remote wipe, shared/group mailboxes and distribution lists from LDAP groups, aliases (`mailAlternativeAddress`).
* LDAP outage behaviour (slapd was deliberately not stopped: shared with Keycloak/OpenCloud); StartTLS path (only LDAPS tested).
* Whether the two caches stack to ~120 s in the worst phase alignment; longer-lived open sessions (EAS Ping, MAPI sessions, web UI sessions).
* Password change in LDAP while cached (old password accepted up to 60 s per the docs; not separately measured). Large user counts (5 users + test users only), reconcile load.
* Leftover test objects: suspended `gwl*/gwd*` rows and mailboxes in Gromox, shadow users `gwl*/gwd*` in Keycloak (the throw-away LDAP entries are deleted).
* The sync script has had one lab run set and no unit tests; admin-api's richer behaviour (templates, quotas, aliases, group sync, `max_user`) is not replicated.
* Clean-room re-run of `lab-ldap.sh` was not done (steps were run interactively, then folded into the script).
