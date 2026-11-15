# Files + Identity Stack Evaluation (OpenCloud / Collabora / Keycloak / Seafile)

Date: 2026-11-15. Method: web search/fetch of primary docs and GitHub only; nothing installed or run.
Rule: anything not confirmed in a fetched primary source is marked UNVERIFIED.
Note: WebFetch summarises pages with a small model, so exact values (env var names, versions) should be re-checked against the docs before use in automation.

## 1. OpenCloud

### Facts
- Latest stable server: **9.1.0** (2026-11-11); 9.1.1-rc.1/rc.2 pre-releases 2026-11-13. Rolling release model with multiple maintained lines (7.2.5, 4.0.9 maintenance releases same day). 9.0.0 (2026-10-27) had breaking changes (push-based thumbnailer, new auth-guest service); read upgrade notes first. https://github.com/opencloud-eu/opencloud/releases
- License: **Apache 2.0** (server). https://github.com/opencloud-eu/opencloud
- Architecture: single Go binary (`opencloud init`, `opencloud server`); no database, all data on filesystem. Services run inside the one process, except the collaboration (WOPI) service which is started separately (`opencloud collaboration server`). Built-in IdP (LibreGraph Connect / lico) and built-in LDAP (idm) for small setups, OR external OIDC IdP.
  - https://github.com/opencloud-eu/opencloud ; https://docs.opencloud.eu/docs/dev/server/services/collaboration/information
- Storage backends: `posix` (default since 2.0.0 per docs), `decomposed`, `decomposeds3` (S3/MinIO). posix/decomposed need a fully POSIX FS (ext4, XFS, ZFS; CephFS, GPFS, NFS >= 4.2 with `noac`) and xattrs. https://docs.opencloud.eu/docs/admin/getting-started/requirements ; https://docs.opencloud.eu/docs/admin/configuration/storage/storage-posix
  - posix: no migration path from decomposed to posix (copy data into a new install). Everything under `storage/users` must be on one filesystem. Non-collaborative mode: do not modify the tree externally while running. `STORAGE_USERS_POSIX_WATCH_FS=true` for live change detection on local FS.
- Backup/restore guidance (posix docs): snapshot the whole OpenCloud filesystem tree regularly (FS-dependent; e.g. ZFS/LVM/XFS snapshot) and restore it. Config dir must be backed up as well (UNVERIFIED that docs say so; sensible because it holds secrets/JWT).
- Versioning: user docs describe restore/download of earlier versions from the file Details sidebar. https://docs.opencloud.eu/docs/user/files-and-folders/versions/  Retention policy and quota accounting of versions: UNVERIFIED (not found).
- Sharing / spaces / quotas: OpenCloud is spaces-based (inherited from oCIS); per-space/user quotas exist. UNVERIFIED in this session (no page fetched). Guest access by email added in 9.0.0 (release notes).
- Desktop client: repo opencloud-eu/desktop, latest **4.0.0 (2026-09-03)**. Windows VFS since 3.0.0; Windows/macOS/Linux builds implied (Qt 6.11, dropped macOS 12). 4.0.0 sync fixes: per-file retries on transient errors, TUS upload resume after 409, token refresh handling. No conflict-handling-specific fix noted. https://github.com/opencloud-eu/desktop/releases  Conflict file naming/behaviour: UNVERIFIED (ownCloud-client lineage likely makes "conflicted copy" files; test).
- Mobile: Android app in Play Store/F-Droid (F-Droid 1.2.3, 2026-05-23, Android 8+); iOS app on App Store (iOS 15.4+). https://opencloud.eu/en/news/opencloud-now-also-available-android-app ; https://f-droid.org/en/packages/eu.opencloud.android ; https://apps.apple.com/app/id6743121005
- Deployment: official `opencloud-compose` (Docker Compose v2 only; modular files). Modules: traefik, idm/ldap-keycloak, weboffice/collabora, weboffice/euro-office, external-proxy, search (Tika), thumbnails/imagor, monitoring, radicale (CalDAV/CardDAV). Data/config dirs must be UID/GID 1000. https://github.com/opencloud-eu/opencloud-compose  Binary deployment also supported (Linux production).
- Minimum resources (docs): up to 10 users 1 GHz/512 MB RAM; up to 1,000 users 2 GHz dual core/8 GB RAM; disk sized to data, unrestricted IOPS. Docs numbers are optimistic once search/Tika/thumbnails/Collabora are added; budget more (see section 5).
- Offline sync: desktop client syncs local folder; offline editing then upload on reconnect. Conflict handling details UNVERIFIED.

### External Keycloak: wiring (docs: https://docs.opencloud.eu/docs/admin/configuration/authentication-and-user-management/external-idp)
- Set `OC_OIDC_ISSUER` to the Keycloak realm URL. Disable the embedded IdP (compose `idm/ldap-keycloak.yml` module shows the supported pattern; it ships Keycloak + shared LDAP with clients `web`, `OpenCloudDesktop`, `OpenCloudAndroid`, `OpenCloudIOS`).
- Client IDs: web = `web` (scopes `openid profile email`); desktop `OpenCloudDesktop`, Android `OpenCloudAndroid`, iOS `OpenCloudIOS` (scopes `openid profile email offline_access`). Desktop WebFinger discovery needs desktop >= 4.0. So the Keycloak realm needs those four public clients (PKCE) with correct redirect URIs and `offline_access` allowed.
- User matching: `PROXY_USER_OIDC_CLAIM` vs `PROXY_USER_CS3_CLAIM`; username claim default `preferred_username` (can use `sub` for stability).
- Role mapping: `PROXY_ROLE_ASSIGNMENT_DRIVER=oidc`, claim name via `PROXY_ROLE_ASSIGNMENT_OIDC_CLAIM` (default `roles`); mapping in `proxy.yaml` `oidc_role_mapper`: admin->`opencloudAdmin`, spaceadmin->`opencloudSpaceAdmin`, user->`opencloudUser`, user-light->`opencloudGuest`. One role per user, first match wins; no match = login fails. Recommended `GRAPH_ASSIGN_DEFAULT_USER_ROLE=false` with oidc driver. Claim must be in access token or userinfo -> in Keycloak add a mapper (realm roles or group -> token claim, add to access token + userinfo).
- Auto-provisioning: `PROXY_AUTOPROVISION_ACCOUNTS=true` creates the user on first OIDC login but **requires a writable LDAP server** (built-in idm LDAP is fine for small setups); claims for username/email/display name set via `PROXY_AUTOPROVISION_CLAIM_*`. With false, users must pre-exist. Implication: with external Keycloak you still run OpenCloud's internal idm LDAP (it is just a user shadow store) unless users are provisioned otherwise. How cleanly this works with stock opencloud-compose Keycloak: UNVERIFIED, test.
- Logout/session behaviour (back-channel logout, disabled user): not covered in OpenCloud docs fetched; UNVERIFIED.

### WOPI / Collabora
- Built-in collaboration service speaks WOPI to Collabora, ONLYOFFICE or MS Office Online. Not started by `opencloud server`; needs gateway + app-registry and the document server up first. Env: `COLLABORATION_APP_PRODUCT=Collabora`, `COLLABORATION_APP_ADDR` (Collabora URL), `COLLABORATION_WOPI_SRC` (public WOPI URL), `OC_URL`, `OC_JWT_SECRET`, `OC_REVA_GATEWAY`; store default nats-js-kv. https://docs.opencloud.eu/docs/dev/server/services/collaboration/information
- opencloud-compose: WOPI is served on the main domain under `/wopi` and `/collaboration` (no separate WOPI subdomain); Collabora needs its own subdomain; Collabora and "Euro Office" (OnlyOffice-based alternative, JWT secret required) are mutually exclusive. README does not mention ONLYOFFICE by name. https://github.com/opencloud-eu/opencloud-compose
- How WOPI saves map to versions: UNVERIFIED (test: each Collabora save should create a new version).

## 2. Collabora Online and ONLYOFFICE

### Collabora
- Source repo: https://github.com/CollaboraOnline/online. Collabora Online is open source (MPL 2.0 is the commonly stated license; the README fetched only pointed to COPYING) -> license text UNVERIFIED here. Development has moved to Gerrit; GitHub for issues/releases.
- CODE (Collabora Online Development Edition): rolling build, roughly monthly; Collabora says it is for "testing, home use, small teams", **"not recommended for production environments"**; the OpenCloud/Nextcloud/Seafile quick-starts are "for testing purposes only". https://www.collaboraonline.com/code/
- Limits/nag: older community reports of 10 documents / 20 connections cap and an "unsupported development version" message in the Nextcloud integration; newer forum posts say limits were removed. No official statement found -> **limits/nags UNVERIFIED; test the current CODE image** (e.g. open 25 docs / 30 connections). https://help.nextcloud.com/t/collabora-document-limitation-by-purpose-10docs-20connections/4425 ; https://forum.collaboraonline.com/t/what-are-the-limitations-of-the-collabora-server/2180
- Production options: (a) commercial Collabora Online subscription via Collabora or a partner (stable, tested updates, security fixes, SLA) - pricing not retrieved; (b) self-build from source (open source, no support; heavy, and CODE branding/stable cadence issues); (c) ONLYOFFICE as an alternative editor. MSP implication: budget a Collabora partner/commercial subscription for paying customers; use CODE in lab only.

### ONLYOFFICE Docs Community
- License: AGPL v3 (Community); Enterprise/Developer commercial. https://github.com/ONLYOFFICE/DocumentServer
- Connection limit: historically **20 simultaneous connections** (each open tab counts). Reported removed in **9.4** (May 2026) with license text updated for attribution/modified-version labeling (still AGPLv3). Evidence is secondary (linuxiac 2026-05-20), official release notes not found -> UNVERIFIED. https://linuxiac.com/onlyoffice-docs-9-4-removes-community-connection-limit/
- Community edition lacks clustering, DR, multi-tenancy, admin panel, mobile web editors, SLA support. Format fidelity for OOXML is generally strong (UNVERIFIED here).
- OpenCloud officially wires Collabora (and Euro Office) in compose; ONLYOFFICE is supported by the collaboration service (`COLLABORATION_APP_PRODUCT=OnlyOffice`) but without a compose module.

## 3. Keycloak
- Latest: **26.8.2** (2026-11-05, security release); 26.8.0 2026-10-01; cadence about monthly minors. https://github.com/keycloak/keycloak/releases
- Production deploy: container image built with `kc.sh build` then `start --optimized` (HTTPS only, health/metrics on :9000); never `start-dev`; set container memory limit; bootstrap admin via `KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD`. External PostgreSQL (supported/recommended DB; standard). https://www.keycloak.org/server/containers
- Resources (official sizing for HA clusters, use as upper reference): ~1250 MB RAM request/1360 MB limit per pod base, 2 GB suggested for small prod; 1 vCPU per 15 password logins/s. For an MSP lab/small prod: 2 vCPU, 2-4 GB RAM, Postgres on same or separate small VM. https://www.keycloak.org/high-availability/single-cluster/concepts-memory-and-cpu-sizing
- Isolation model for MSP:
  - Realm-per-customer: hard isolation (users, clients, IdPs, policies, admins). Costs: more admin overhead, realm count affects startup/cluster ops; no official hard cap; old advice < ~100 realms/node, a 2026 vendor test claims thousands work (vendor, UNVERIFIED). https://skycloak.io/?p=3568
  - Organizations (26.x): many customers in one realm; vendor sources say GA since 26.0; 26.7 added org fine-grained admin permissions (UNVERIFIED, vendor claim). Recent security fixes touching Organizations identity-first login/invitations (26.8.1, 26.8.2) show the feature is still maturing. Weaker isolation (shared realm policies, shared admin plane, per-org role differences limited).
  - Recommendation for per-customer self-hosted stacks (this project's model): **one Keycloak per customer, one realm** (or a shared MSP Keycloak with realm-per-customer if cost forces consolidation). Reserve Organizations for MSP staff federation. Decide after pilot.
- MFA: built-in OTP (TOTP) and WebAuthn/passkeys via authentication flows and required actions (standard feature; not re-fetched, UNVERIFIED in this session).
- Revocation on user disable: disabling a user stops new logins and refresh; already-issued access tokens stay valid until expiry (keep short, 5 min); logout does not revoke access tokens; offline tokens (needed by desktop/mobile clients, `offline_access`) outlive SSO sessions and must be revoked explicitly (admin console, or not-before policy) ; behaviour varied across versions per forum reports. Treat as **must-test** (test 6 below). Sources: https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.4/html/server_administration_guide/managing-user-sessions ; https://forum.keycloak.org/t/confused-about-offline-token-behavior/24714
- LDAP federation: Keycloak can *consume* an LDAP/AD server (user federation, import or read-through). Keycloak is **not** an LDAP server.
- Gromox/grommunio: `ldap_adaptor` binds to a real LDAP server (config `/etc/gromox/ldap_adaptor.cfg`: ldap_host, ldap_bind_user, ldap_search_base, ldap_mail_attr; supports OpenLDAP and AD attribute conventions; per-org LDAP creds since Gromox 1.33). https://docs.grommunio.com/man/ldap_adaptor.4gx.html  So Gromox cannot read Keycloak directly; it needs OpenLDAP / 389DS / lldap / AD. Whether Gromox/grommunio-web supports OIDC login: UNVERIFIED (not checked).
- Design consequence: put a small LDAP directory as the **source of truth** per customer (lldap is lightest; 389DS/OpenLDAP if schema needs) and have Keycloak federate it (Keycloak -> LDAP) for SSO to OpenCloud, while Gromox binds the same LDAP directly for mailbox auth. OpenCloud's own idm LDAP can stay as an internal shadow store for autoprovisioning. Alternative: use the same LDAP as OpenCloud's user backend (fetch of that config UNVERIFIED).

## 4. Seafile fallback (brief)
- Latest: 13.0 (early 2026; Docker-only deployment per forum). https://linuxiac.com/seafile-13-0-file-sync-server-launches-with-ai-search-advanced-metadata/
- License: CE server is open source (AGPLv3 per most sources; some say GPLv2 - UNVERIFIED). Pro is proprietary: free for 3 users, about USD 100/yr for 9 users (vendor pricing page; one forum thread says 3-user free mode behaved differently after 12->13 upgrade, UNVERIFIED). https://seafile.com/en/pricing ; https://forum.seafile.com/t/upgrade-from-pro-12-to-pro-13-shows-community-edition-3-user-free-mode-gone/24824
- Office: CE documented to work with Collabora (own WOPI host in Seafile; needs HTTPS; `OFFICE_SERVER_TYPE='CollaboraOffice'`) and OnlyOffice. https://manual.seafile.com/13.0/extension/collabora_online/  Some collaborative features/SAML/cluster/MS Office Online are Pro only.
- SSO: OAuth/OIDC-style supported in CE (OIDC specifically UNVERIFIED); SAML Pro only.
- Sync: block-level deduplicating sync, mature; SeaDrive virtual drive client (also Pro-adjacent features unverified). Sync reliability is its historic strength; fits as fallback if OpenCloud desktop conflicts/offline tests fail.

## 5. Recommendation: per-customer lab topology

### Topology (lab, one customer, ~25 users)
Three VMs (or one VM with compose for the lab; split for realism):
| VM | Contents | Size |
|---|---|---|
| kc | Keycloak 26.8.x (optimized container) + PostgreSQL 16 + (optional) lldap | 2 vCPU, 4 GB RAM, 20 GB |
| oc | opencloud-compose: OpenCloud 9.1.x, Traefik (or external reverse proxy), Tika/search, collaboration service | 4 vCPU, 8 GB RAM, 40 GB OS + data disk on XFS/ext4 (ZFS if snapshots) |
| office | Collabora (CODE for lab; commercial for prod) | 4 vCPU, 4-8 GB RAM, 20 GB |
Sizing is a starting point (docs minimums are lower; UNVERIFIED for real load). Document-editing RAM scales with open docs (~tens-hundreds MB per doc on Collabora, UNVERIFIED).
DNS/TLS: `cloud.lab`, `auth.lab`, `office.lab` with real or lab-CA certs trusted by all (Collabora->WOPI and OpenCloud->Collabora calls validate certs unless `COLLABORATION_APP_INSECURE`). Collabora must allow the WOPI host (`aliasgroup`/`server_name` config; needs the OpenCloud host allowed).

### SSO wiring
1. Keycloak realm `cust1`; clients `web`, `OpenCloudDesktop`, `OpenCloudAndroid`, `OpenCloudIOS` (public, PKCE, redirects per OpenCloud docs; `offline_access` allowed).
2. Mapper: realm role/group -> claim `roles` (or custom claim name set in `PROXY_ROLE_ASSIGNMENT_OIDC_CLAIM`) in access token + userinfo; roles `opencloudAdmin`, `opencloudSpaceAdmin`, `opencloudUser`, `opencloudGuest`.
3. OpenCloud: `OC_OIDC_ISSUER=https://auth.lab/realms/cust1`, role driver `oidc`, autoprovision on with internal idm LDAP (or external LDAP), `GRAPH_ASSIGN_DEFAULT_USER_ROLE=false`.
4. Collabora does not do SSO; it trusts WOPI access tokens minted by OpenCloud. No Keycloak client needed for it.
5. Access-token lifespan 5-10 min; SSO idle 8-12 h; MFA (TOTP/WebAuthn) required for admin role at minimum.
6. Later: lldap behind Keycloak federation, Gromox binds same lldap.

### Test plan (record pass/fail, versions, screenshots)
1. OIDC login: web login via Keycloak for each role (admin/spaceadmin/user/guest); first-login autoprovision creates user; user without role claim is rejected cleanly; MFA prompt works; logout from OpenCloud ends Keycloak SSO session (and vice versa); desktop + Android + iOS login via WebFinger/OIDC.
2. Office round-trip (scripted content verification): create new DOCX, XLSX, PPTX from OpenCloud web UI in Collabora; enter known content (heading, table, 3 formulas incl. cross-sheet ref, 2 slides with image and notes); save/close; download via WebDAV/API; verify with python-docx / openpyxl (formulas + cached values) / python-pptx; reopen in Collabora and compare. Also upload a Microsoft-authored DOCX/XLSX/PPTX (tables, tracked changes, charts, macros-free) and diff after edit. Two simultaneous editors on one DOCX; confirm saves merge and no data loss. Check CODE limits/nag: open > 20 docs/connections; note any banner.
3. Versions: edit same file 3 times; list versions; restore version 1; confirm content hash equals original; confirm restore itself is versioned; check quota effect and any retention setting.
4. Restart persistence: `docker compose restart` and full VM reboot of oc, kc, office; confirm sessions/re-login, files/versions/shares intact, collaboration service reconnects (start order issue), in-progress edit recovered or clean error; also test restore from FS snapshot to a second VM (backup test), including config dir and xattrs.
5. Desktop sync: initial sync of 5k small + 5 large files; offline edit then reconnect; same file edited offline on two clients (expect conflict copy; check no data loss and naming); rename/move/delete while offline; large file resume (TUS); token refresh after Keycloak access-token expiry while offline > SSO idle; Windows VFS if relevant; Linux client behaviour.
6. Disable-user: disable user in Keycloak while desktop+web are connected; measure time until access stops (web, desktop offline token, mobile). Also remove role claim and confirm behaviour. Revoke offline tokens and recheck.
7. Resource baseline: idle and loaded RAM/CPU per container; Keycloak realm startup time.
8. Fallback gate: if tests 2, 5 or 6 fail materially, repeat 2 and 5 on Seafile CE 13 + Collabora.

### Open items
- Collabora CODE limits and commercial pricing/partner terms (UNVERIFIED).
- OpenCloud quotas, version retention, conflict behaviour, back-channel logout (UNVERIFIED).
- Gromox OIDC support (UNVERIFIED).
- Keycloak MFA specifics and Organizations maturity (verify on 26.8 docs).
