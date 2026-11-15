# Identity + files + document-editing lab results

Date: 2026-11-15. Executed in systemd-nspawn machines (zone `oulab`, internet egress only; no Proxmox, no Docker).
Status values follow ADR-0000: everything below marked PASS was executed, with the output excerpt quoted. Lab only: the
numbers say nothing about production sizing, and the Collabora packages are the vendor CODE build (lab functional testing
only; production = our own source build, ADR-0007).

## 1. Topology and versions

| Machine | Role | MemoryMax | Peak RSS observed | IP (static) |
|---|---|---|---|---|
| `ou-id1` | OpenLDAP 2.6.10, PostgreSQL 16.15, Keycloak 26.8.2 (OpenJDK 21.0.13), lab CA | 2G | Keycloak java ~0.65-0.87 GB; machine total 0.87 GB idle | 192.168.186.241 (`auth.`, `ldap.ou-lab.internal`) |
| `ou-files1` | OpenCloud 9.1.0 (`opencloud server` + separate `opencloud-collaboration`), nginx | 2G | 0.23 GB idle, 0.57 GB peak | .242 (`cloud.`) |
| `ou-office1` | Collabora CODE `coolwsd 26.04.6.1-1` + `code-brand 26.04.6-1` (`collaboraoffice 26.04.6-1`), nginx | 3G | 0.29 GB idle, 1.7 GB peak (document load + conversion) | .243 (`office.`) |

Total MemoryMax 7G (limit met). Base OS Ubuntu 24.04 (noble) minbase (`/var/lib/machines/ou-base-noble`); the Debian 12 base was not used because Keycloak 26 needs JDK 21 and the blueprint targets noble (PG 16 / JDK 21 in the archive).

| Artifact | Pin | Verification (executed) |
|---|---|---|
| Keycloak 26.8.2 tar.gz | `KC_URL` in versions.env | `kc.tgz: OK` against published sha1 `7918de2786c7db466152128bea350becbd40a58f`; sha256 computed by us: `dd124787283918bc597628887168333465ee2a811a389e0003569e52be7e487f` (re-verified inside the machine by `install-kc.sh` `verify_sha1`) |
| OpenCloud 9.1.0 linux-amd64 | `OC_URL` | `opencloud: OK` sha256 `183d95c3a77ccb520dabaa106e08d1037afcaa8af6403c22eb6ac9a565de777e` (published value); `opencloud version` -> `Version: 9.1.0 Edition: rolling` |
| Collabora CODE `coolwsd` | vendor apt repo `https://www.collaboraoffice.com/repos/CollaboraOnline/CODE-deb` (older `CODE-ubuntu2404` path in docs is 404), key `.../downloads/gpg/collaboraonline-release-keyring.gpg` | apt signature check via `signed-by`; `coolwsd_26.04.6.1-1_amd64.deb` sha256 (from the signed index) `08a470c6435677e69f40a5d12aa89cb17163bb7376f9cdaa8b59dc9fb416a0aa`; packages put on `apt-mark hold`. Keyring fingerprint NOT checked out of band (trust on first use) |
| slapd | Ubuntu archive `2.6.10+dfsg-0ubuntu0.24.04.1` | apt |
| PostgreSQL | `16.15-0ubuntu0.24.04.1` | apt |
| Test deps | requests 2.34.2, python-docx 1.2.0, openpyxl 3.1.5, python-pptx 1.0.2, websocket-client 1.9.2 | pip, in a venv outside the repo |

Lab TLS: `common/lab-ca.sh` worked unchanged apart from making the mail cert optional (IP of the groupware VM is outside
the name-constrained subnet). The name-constrained CA (permitted DNS `ou-lab.internal`, IP /24) was accepted by Go
(OpenCloud, Collabora/OpenSSL), Java (Keycloak -> LDAPS) and Python (requests); no client rejected it.

## 2. Directory decision (ADR-0004): OpenLDAP

Requirements: authoritative per-customer directory; consumed by Keycloak (federation), Gromox `ldap_adaptor` (mail attribute,
stable object id, group membership), OpenCloud (user backend), written by ICS only; no duplicate user stores.

| | lldap 0.6.3 | OpenLDAP 2.6 (chosen) | 389-DS |
|---|---|---|---|
| Keycloak federation | works (docs), simplified schema, no `entryUUID` attribute only `uid`; role mapper untested | **tested here**: user mapper + `role-ldap-mapper` over `groupOfNames`, `uuidLDAPAttribute=entryUUID`, READ_ONLY, import users; roles claim correct for all 5 users | works (standard), heavier admin |
| Gromox `ldap_adaptor` | needs `entryUUID`/mail/DN attributes; lldap exposes a subset; unverified | standard `inetOrgPerson` + operational `entryUUID` + `memberOf`: all returned to the read-only bind user (verified by ldapsearch; **gromox itself not run**) | standard, `nsUniqueId` instead of entryUUID by default |
| OpenCloud | documented shared-LDAP pattern (`example_configs/opencloud.md`), but "no documented way to give an LDAP user admin rights" (not an issue with OIDC role claims) | **tested here**: OpenCloud reads the same LDAP read-only (`OC_LDAP_SERVER_WRITE_ENABLED=false`, `entryUUID`), roles come from the Keycloak claim; this is the upstream `idm/ldap-keycloak.yml` pattern (which uses OpenLDAP) | would work; no upstream pattern |
| Writable LDAP needed by OpenCloud? | no, with the pattern above | **No.** Autoprovisioning (needs writable LDAP, i.e. OpenCloud's own idm shadow store) is not used. One user store only. | same |
| Account disable | no native lock attribute (ldap bind/`pwdAccountLockedTime` absent) | ppolicy overlay: `pwdAccountLockedTime=000001010000Z` blocks bind (so Keycloak password checks fail) and is filterable (`(!(pwdAccountLockedTime=*))` hides the user from OpenCloud). Verified by t06 | `nsAccountLock` (native) |
| Ops | single static binary + sqlite, web UI, young project | mature, in the Ubuntu archive (patched by distro), ACLs, overlays (memberOf, refint, ppolicy), replication, `cn=config` is clunky (scripted in `install-openldap.sh`) | heavier (dsctl/dsconf, more RAM) |

Decision: **OpenLDAP**, deployed. It is the only candidate where every claim above was exercised in this lab; lldap remains a
valid lighter option but would need the Gromox/entryUUID and disable-user questions solved first. Not tested: 389-DS (comparison
is from documentation knowledge, not execution). Licence note in `third-party-inventory.md` (OpenLDAP Public License text still to be re-read by counsel).

Deployed shape: base `dc=ou-lab,dc=internal`; `ou=people` (`inetOrgPerson`), `ou=groups` (`groupOfNames`: opencloudAdmin,
opencloudSpaceAdmin, opencloudUser, opencloudGuest, mail-users), `ou=system` bind user `cn=svc-bind` (read, including
operational attrs), `ou=policies`. LDAPS :636 with the lab cert (TLS >= 1.2); ldap:// only on 127.0.0.1. Overlays memberof, refint, ppolicy.
Only `cn=admin` (ICS) can write; `userPassword` readable by nobody but bind. 5 test users: alice (admin), bob (user), carol (spaceadmin), dave (guest), erin (no role).

## 3. Test results (all executed 2026-11-15)

Final run, after a full reboot of all three machines (`machinectl reboot`; every service came back by itself, no manual step):

| Test | Result | Excerpt |
|---|---|---|
| t01_oidc | **36 PASS / 0 FAIL** | `PASS client OpenCloudDesktop registered - login page served for redirect http://127.0.0.1` ... `PASS dave OpenCloud role id - role opencloudGuest assigned` ... `PASS erin rejected by OpenCloud - HTTP 403 (login fails cleanly without role claim)` |
| t02_files_webdav | **11 PASS / 0 FAIL** | `PASS GET big.bin identical - sha256 27a10d0a7bc1` ... `PASS data after opencloud restart - big.bin identical after restart` (opencloud unit restarted via `systemctl -M`) |
| t03_office_roundtrip | **28 PASS / 0 FAIL** | `PASS test.xlsx content (after restart) - formulas=('=SUM(A1:A3)', ...)`; opencloud + coolwsd restarted between phases. Collabora editor save: `PASS test.xlsx content after Collabora save - formulas=('=SUM(A1:A3)', '=AVERAGE(A1:A3)', '=Data!B1*2', 'OU-...') cached=(60, 20, 120) D5='EDITED-OU-...'`, `PASS test.docx content after Collabora save - heads=['EDITED-Heading OU-...'] cells=['a','b','c','OU-...']`, `PASS test.pptx content after Collabora save - slides=2 ... notes='notes OU-...' pics=1` |
| t04_wopi | **13 PASS / 0 FAIL** | `PASS CheckFileInfo without proof-key refused - HTTP 500`, `PASS Collabora loads document via WOPI`, `PASS Collabora save (PutFile) - .uno:Save success=true`, `PASS stored DOCX contains Collabora edit - paragraphs=['EDITEDBYCOLLABORAWOPI check ...'] (bytes changed 36595 -> 20537)`, `PASS Collabora save created a version - version listed after save` |
| t05_versions | **9 PASS / 0 FAIL** | `PASS list versions - 2 old versions listed (3 writes => 2 old)`, `PASS restored equals first version - hash equals version-1`, `PASS restore is versioned - pre-restore content (v3) kept as a version ...` |
| t06_disable_user (new) | **12 PASS / 2 FAIL (expected, see below)** for the full 420 s run; a second quick run with the extra "fresh token" probe: 14 PASS / 2 FAIL | see section 3.3 |
| MANUAL (desktop sync, offline/conflict, mobile, MFA, browser UX, co-editing, CODE limits) | **NOT RUN** | section 6 |

### 3.1 What exactly was proven for Collabora / WOPI

Proven (executed, headless, no browser): (a) OpenCloud's collaboration service registered `CollaboraOnline` in the app registry
(`/app/list`); (b) `/app/open` returns a Collabora URL + WOPI token; (c) the same protocol the browser iframe uses
(websocket `wss://office/cool/<WOPISrc?access_token>/ws`, `load`) makes **Collabora call OpenCloud's CheckFileInfo and
GetFile** (Collabora -> OpenCloud over lab-CA TLS, WOPI proof keys verified by OpenCloud, WOPI host allow-listed in
`coolwsd.xml`) and load the document in the LibreOffice kit (`perm: edit`, `status:` frame, `commandresult load success true`);
(d) typing text (`textinput`) and `save` makes **Collabora PutFile** the changed document into OpenCloud: the DOCX read back through WebDAV contains
the typed text, the xlsx contains the typed cell plus LibreOffice-written cached values (60/20/120) and still carries the formulas
including the cross-sheet one, the pptx survived a re-save with slides/notes/picture; (e) each save appears as a version.
Also proven: a WOPI token alone cannot read a file (without Collabora's proof headers CheckFileInfo returns 500; tampered token 401).
Not proven: rendering/tiles correctness, browser UI (CSP/iframe/`frame-ancestors`), multi-user co-editing, MS-authored
fidelity (only generator files used), pptx slide-text editing (needs object selection, manual), CODE document/connection limits
and nag banners (>20 docs not opened), `convert-to` endpoint (only listed in capabilities).

### 3.2 Behaviour learned vs the prepared blueprint

See section 5 (deviations). Notable: WebDAV path `/remote.php/dav/files/<user>` works; Graph `/graph/v1.0/me` works;
OpenCloud built-in role ids are oCIS-like except guest = `38071a68-456a-4553-846a-fa67bf5596cc`.

### 3.3 Disable user: how long do existing sessions/tokens keep working (t06)

Access-token lifespan 300 s, SSO idle 10 h, offline idle 30 d (realm defaults in `realm-ou-lab.json`). Poll interval 5 s. Output excerpt:

```
A directory-lock only (LDAP ppolicy lock, nothing else)
PASS new password login - denied after 0s
FAIL SSO refresh token - STILL WORKING after 420s (horizon)
FAIL offline refresh token - STILL WORKING after 420s (horizon)
PASS old access token -> OpenCloud /me - denied after 11s
PASS old access token -> OpenCloud WebDAV - denied after 11s
PASS FRESH access token (from refresh) -> OpenCloud /me - denied after 13s   (quick re-run)
B lock + Keycloak revoke (consent revoke + admin logout + user disabled)
PASS new password login - denied after 0s | SSO refresh - denied after 0s | offline refresh - denied after 0s
PASS old access token -> OpenCloud /me - denied after 11s (13s in re-run) | WebDAV same
```

Findings (lab, single run each; the ~11-13 s is OpenCloud's per-request user/userinfo cache, not tuned or investigated further):
1. Locking the account in the directory blocks **new** Keycloak logins immediately (LDAP bind fails).
2. OpenCloud stops accepting even an **already issued** access token about 11-13 s after the lock, because it re-resolves the user in LDAP (filter excludes locked accounts) - this is much better than the 5-min JWT lifetime. This depends on the OpenCloud LDAP filter; if the user is only disabled in Keycloak, OpenCloud would honour the JWT until expiry (not tested).
3. **Keycloak keeps honouring refresh tokens** (SSO and offline) after a directory-only lock for the whole horizon: Keycloak does not re-check LDAP on refresh. Other consumers of Keycloak tokens (anything that trusts the JWT without a directory lookup) would keep working indefinitely. FAIL against the ADR-0004 target for scenario A is therefore real and by design of the test.
4. Full deprovision (B) = directory lock + Keycloak admin API (revoke consents -> kills offline tokens, user logout, disable user): refresh tokens died in <1 s; effective end-to-end access ended with OpenCloud's ~11-13 s lag. **ICS deprovisioning must do both steps**; the target of 5 min is met (worst measured ~13 s) for the OpenCloud path. Gromox, ActiveSync devices and app passwords are not covered (groupware not part of this lab).
5. Not measured: desktop client behaviour (it holds an offline token), back-channel logout delivery to OpenCloud, MFA.

## 4. Verified configuration facts (for ADR-0004/0005 updates)

- Keycloak: `KC_HTTPS_*` with lab cert, `KC_TRUSTSTORE_PATHS` lab CA, Postgres localhost, `--import-realm` from `data/import` (realm `ou-lab` imported in ~25 s startup). LDAP federation (`openldap`, READ_ONLY, import on) imported users on first login; `role-ldap-mapper` (`groupOfNames`, `member`) turns LDAP groups into realm roles; a user-attribute mapper `entryUUID -> uuid` plus a declared `uuid` user-profile attribute (Keycloak 26 drops undeclared attributes) plus a `uuid` claim mapper on all clients. Access token carries `roles` and `uuid`.
- OpenCloud env (see `opencloud.env.tmpl`): external OIDC via `OC_OIDC_ISSUER`, `OC_EXCLUDE_RUN_SERVICES=idm,idp`, `PROXY_USER_OIDC_CLAIM=uuid`, `PROXY_USER_CS3_CLAIM=userid`, `OC_LDAP_USER_SCHEMA_ID=entryUUID`, `GRAPH_LDAP_SERVER_UUID=true`, `OC_LDAP_SERVER_WRITE_ENABLED=false`, `PROXY_AUTOPROVISION_ACCOUNTS=false`, `PROXY_ROLE_ASSIGNMENT_DRIVER=oidc`. All accepted by 9.1.0 (no "unknown variable" warnings seen; the log was only skimmed for errors).
- The collaboration service is a separate process (`opencloud collaboration server`, own unit) and must start after the main server's NATS (:9233); started too early it exits (`Failed to connect to NATS`) and systemd restarted it within ~5 s; the unit now waits for NATS. After an `opencloud` restart the collaboration unit follows (`Requires=`).
- WOPI traffic (`/wopi/...`) reaches the collaboration service through OpenCloud's proxy on :9200 (nginx needed no extra route).
- posix storage driver needs `inotify-tools` (without it the server panics: `inotifywait is not installed`). ext4 with user xattrs inside the nspawn worked.
- Collabora (vendor deb) settings that worked: `ssl.enable=false`, `ssl.termination=true`, `ssl.ca_file_path` = lab CA, `ssl.ssl_verification=true`, `net.listen=loopback` (binds `[::1]:9980` only: nginx must proxy to `[::1]`), `storage.wopi.alias_groups` mode `groups` with host `https://cloud.ou-lab.internal:443`. The websocket `Origin` must be the Collabora host.

## 5. Deviations from the blueprints (all applied to the scripts/tests)

| Item | Blueprint | Reality / change |
|---|---|---|
| Substrate | 3 cloud-init VMs | nspawn machines; static IPs; no ufw (isolation = host nft); `lab.env` IPs changed to 192.168.186.241-243 |
| Directory | lldap | OpenLDAP (`install-openldap.sh`, `ldap-user.sh`); `provision-lldap.sh` removed; `LLDAP_*` removed from versions.env; realm component renamed `openldap`, `role-ldap-mapper` uses `groupOfNames`; `uuid` mapper/user-profile added |
| OpenCloud users | autoprovision into internal idm | shared read-only LDAP, no autoprovisioning (answers the ADR-0004 open question: a writable LDAP is **not** required) |
| Collabora | Docker `collabora/code` image + docker.io | vendor `.deb` (`coolwsd` 26.04.6.1-1) in an nspawn machine; no Docker anywhere. `COLLABORA_DEB_REPO/KEY_URL/COOLWSD_VERSION` added to versions.env |
| Collabora jails | image default (SYS_ADMIN) | In an unprivileged nspawn `unshare(CLONE_NEWNS)`/coolmount fail (EPERM) and Landlock is unavailable (`ENOENT`): coolwsd runs with `security.capabilities=false`, `mount_jail_tree=false`, **no chroot jail** (coolwsd logs "running without chroot jails is insecure"). Lab only; a production build must run with jails (needs a VM or a privileged container with CAP_SYS_ADMIN - not tried) |
| nginx | `http2 on;` | noble ships nginx 1.24 (directive unknown): removed; nginx-light |
| OpenCloud units | single unit with `OC_ADD_RUN_SERVICES=collaboration` | two units; `opencloud init --config-path /etc/opencloud` run as root; bind password via root-only `opencloud.secrets.env`; `inotify-tools` added |
| `lib.sh` | `gen_secret` via `tr|head` | died with SIGPIPE under `set -o pipefail`: now `openssl rand -hex 16` (no trailing newline: a newline in a secret file broke `ldap -y`) |
| `install-kc.sh` | - | `/opt/keycloak/data` was created root-owned (truststore write EACCES): `chown -R` added; `/etc/hosts` needs a `127.0.1.1 <hostname>` line (sudo warnings) |
| t01 | oCIS role ids | guest id differs (38071a68-...) |
| t03 | unit `collabora`, ssh restart only | unit `coolwsd`; restart hooks via `OU_RESTART_CMD`/`OU_MACHINE_*`; new Collabora edit-fidelity phase |
| t04 | direct CheckFileInfo/GetFile with the WOPI token | impossible by design (proof keys): rewritten to drive a real Collabora session (edit + save) |
| t05 | meta listing counted incl. the collection; restore count | listing fixed (first href is the collection; oldest by padded timestamp); restore consumes the restored version and keeps the replaced one as a version |
| t06 | - | new |

Blueprint scripts were edited live and in the repo; **a from-scratch rerun of `install-kc.sh`/`install-files.sh`/`install-office.sh` as written was NOT done** (the machines were built stepwise with the same commands, then fixes were folded back into the files). `install-openldap.sh` was run from scratch (purge + reinstall) successfully. Treat the scripts as "fixed, last full run partial".

## 6. Unverified items and manual tests still needed

Unverified: gromox `ldap_adaptor` against this directory (only the LDAP attributes it needs were verified: `mail`, `entryUUID`, `memberOf`, DN-based group membership); Keycloak MFA (TOTP/WebAuthn) and brute-force lockout behaviour; Keycloak back-channel logout to OpenCloud; Organizations feature; version retention/quota accounting; OpenCloud full-text search/Tika/thumbnails (not deployed); backup/restore of the data tree and `opencloud.yaml` (not drilled; keep the config dir in the backup set); behaviour at scale (25 users) and under load; CODE document/connection caps and nag banner (not exercised beyond a handful of sessions); co-editing; the 10 s OpenCloud user-cache TTL (not found in docs/not tuned); licence texts (OpenLDAP, OpenCloud, Collabora MPL parts) not re-read; vendor repo key not fingerprint-verified.

Manual tests (see `blueprints/lab/tests/MANUAL-CHECKLIST.md`, sections A and C): desktop client (Linux/Windows/macOS) initial sync, offline edit + reconnect, same-file conflict on two clients (naming, data loss), TUS resume, token refresh after offline > SSO idle, VFS; mobile (Android/iOS) login via WebFinger + offline_access; browser login incl. MFA and logout/SSO termination; Collabora UI editing and rendering, pptx slide text, two simultaneous editors, MS-authored files with tracked changes/charts; disable-user timing from the real desktop/mobile clients (offline token path) and role-claim removal; admin password/app-password flows. Quota/versions UI check.

## 7. How to rerun

Machines: `ou-id1`, `ou-files1`, `ou-office1` (`machinectl list`); tests from the ICS host with the env described in `blueprints/lab/tests/lab-test.env.example` ("nspawn lab variant") and a venv built from `requirements.txt`. The host resolves the lab names through a marked block in `/etc/hosts` (recorded in host-changes.md). Test-user passwords live only in `/root/ou-lab-secrets/test-users.env` inside `ou-id1`.

## Lead verification re-run (2026-11-15, from ICS host, full `run_all.sh files` with restart + directory hooks)
- T01 36/0, T02 11/0 (incl. restart persistence), T04 13/0, T05 9/0 — confirmed.
- T03 in full sequence: 19 PASS / **3 FAIL** — `app/open HTTP 500` for docx/xlsx/pptx edit phase immediately after T02 restarted OpenCloud. T03 alone: 28/0. → **Known issue KI-1:** after an OpenCloud restart there is a window where the app-provider/collaboration registration is not ready and document open fails (storage-users logs "record not found in cache"). Needs: readiness wait in tests, an ICS service-level "document open" check, and root-cause investigation (registry/app-provider re-registration timing).
- T06 scenario A: 6 PASS / 2 FAIL (Keycloak SSO + offline refresh tokens survive an LDAP-only lock > 420 s) — confirms the finding: ICS deprovisioning MUST also revoke in Keycloak. Scenario B not re-run by lead (needs Keycloak admin credential in env).
- Note: SKIP exits 0 in these scripts; evidence must be read from PASS/FAIL counts, not exit codes. Use OU_STRICT_SKIP=1 in CI.

### KI-1 diagnosis (lead, 2026-11-15)
Probe (restart `opencloud` on ou-files1, poll `POST /app/open` every 1 s): 502 (nginx, proxy down) at t+0.1 s → 500 `"Error contacting the requested application"` at t+2.5 s → 200 at t+4.8 s. Restarting `coolwsd` alone: app/open 200 immediately. Unauthenticated `GET /app/list` lists `CollaboraOnline` at t+4.6 s — an accurate readiness signal, whereas `/.well-known/openid-configuration` (what T03 waited on) answers ~2 s earlier.
Cause: readiness ordering — the collaboration app registers with OpenCloud's app registry a few seconds after the proxy is up. No data loss.
Fix: `ou_lab.wait_app_ready()` (polls /app/list) used in T03 after restarts. Full sequence T01–T05 now 97 PASS / 0 FAIL.
ICS follow-up: the files service health check must use `/app/list` contains the editor + a canary `app/open`, not just HTTP 200 on the proxy.

## T07 Desktop sync (lead, 2026-11-15) — 11 PASS / 0 FAIL
Client: OpenCloud Desktop v4.0.0 Linux AppImage (sha256 22c5fac4453ce2bf…1d2c matches published .sha256), `opencloudcmd` 4.0.0.3642 = the desktop client's sync engine (libsync), run headless in lab machine `ou-desk1`; trusts the lab CA via system store (no `--trust`).
Auth: opencloudcmd sends Basic user:app-token → enabled OpenCloud app tokens (`OC_ADD_RUN_SERVICES=auth-app`, `PROXY_ENABLE_APP_AUTH=true`); test mints a 15-min token per run via `opencloud auth-app create`. Global Basic auth stays disabled. GUI client uses OIDC (client `OpenCloudDesktop`) — not exercised.
Proven: upload; download; offline period with edits on both sides → reconcile on reconnect (new local file, local edit, remote file); conflict (same file edited both sides) → server keeps SERVER-VERSION, local edit preserved as `down (conflicted copy <ts>).txt`; local delete → server 404.
Not proven: GUI client/OIDC login flow, virtual files (on-demand), Windows/macOS clients, notifications, large files/bandwidth, mobile apps.
Deprovisioning note: app tokens are an additional credential type that the ICS user-disable flow must revoke (add to KI-2 scope).
