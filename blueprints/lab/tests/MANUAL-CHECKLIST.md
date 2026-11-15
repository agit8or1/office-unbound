# Manual checklist: things automation cannot prove

Status: PREPARED, NOT EXECUTED. Record for every row: date, tester, client + exact build, server package versions
(`dpkg -l | grep -E 'gromox|grommunio'`, `opencloud version`, Keycloak/Collabora versions), PASS/FAIL, evidence (screenshot, trace).
Source test plans: `docs/status/files-identity-eval.md` (Test plan 1-8), `docs/status/groupware-eval.md` section 6.3 (items 3-10).
Rows marked **REAL OUTLOOK** need a licensed Microsoft Outlook build on a client that trusts the lab CA (import `ca.crt` into the OS trust store of that client only, and add the lab names to its hosts file).
Test accounts: alice@ou-lab.internal (admin), bob (user), carol (space admin), dave (guest), erin (no role); passwords in `kc:/root/ou-lab-secrets/test-users.env`.

## A. Files / Office (OpenCloud + Collabora)

| # | Test | Result |
|---|---|---|
| A1 | Browser login at https://cloud.ou-lab.internal via Keycloak for alice/bob/carol/dave; erin gets a clean refusal (no role) | |
| A2 | In OpenCloud web create new DOCX, XLSX, PPTX in Collabora; enter heading + table; 3 formulas incl. cross-sheet ref; 2 slides with image + notes; save, close; download; open with python-docx/openpyxl/python-pptx (reuse T03 `check_*` functions); reopen in Collabora and compare | |
| A3 | Upload MS-Office-authored DOCX/XLSX/PPTX (tables, tracked changes, charts, no macros); edit in Collabora; diff before/after in MS Office | |
| A4 | Two simultaneous editors on one DOCX (bob + carol with a share); no lost edits | |
| A5 | CODE limits/nag: open > 20 documents / 30 connections; record any banner or refusal | |
| A6 | Each Collabora save creates a new file version (UI Details > Versions); restore v1; restore itself is versioned; note retention + quota effect | |
| A7 | MFA (TOTP + WebAuthn) enforced for alice only; prompt works in web; erin/bob unaffected | |
| A8 | Logout in OpenCloud ends Keycloak SSO session and vice versa; back-channel logout from Keycloak admin console | |
| A9 | Desktop client (OpenCloud desktop 4.0.0, record build) login via WebFinger/OIDC; initial sync 5k small + 5 large files; offline edit then reconnect; same file edited offline on two clients (expect conflict copy: record naming, no data loss); rename/move/delete offline; large-file resume | |
| A10 | Android + iOS apps login via OIDC (OpenCloudAndroid / OpenCloudIOS), upload + download | |
| A11 | Disable-user timing: disable alice in the identity source while web + desktop + mobile are connected; measure time until each loses access (target <= 5 min per ADR-0004); then revoke offline tokens (Keycloak admin: Sessions > Offline) and recheck; remove role from lldap group and re-test | |
| A12 | Full VM reboot of files, kc, office in turn: sessions, files, versions, shares intact; collaboration service re-registers with Collabora; in-progress edit recovered or clean error | |
| A13 | Backup test: filesystem snapshot of /var/lib/opencloud + /etc/opencloud restored to a second VM; xattrs and versions intact | |
| A14 | Resource baseline: idle + loaded RAM/CPU per service (`systemd-cgtop`, `docker stats`); Keycloak realm start time | |

## B. Groupware client matrix (grommunio) - **REAL OUTLOOK** unless noted

| # | Client | What to test | Expectation (groupware-eval.md 6.1) | Result |
|---|---|---|---|---|
| B1 | **REAL OUTLOOK**: classic Outlook for Windows (M365 Apps current channel; also Outlook 2024) | Autodiscover profile creation for alice@ou-lab.internal; cached-mode sync of mail/calendar/contacts/tasks; free/busy; shared mailbox; delegation; send-on-behalf; server rules; OOF; public folders; 25 MB attachment; offline/online reconnect; capture MAPI/HTTP trace (Fiddler/Outlook ETL) | Expected, lab-verify | |
| B2 | **REAL OUTLOOK**: new Outlook for Windows | Add as Exchange (record error) and as IMAP/SMTP; what works (mail only?) | Partial: IMAP/SMTP only | |
| B3 | **REAL OUTLOOK**: Outlook for Mac current + legacy | Add Exchange account (Autodiscover + EWS); mail, calendar, invites, reply/forward drafts, free/busy, shared folders | Partial/unverified | |
| B4 | **REAL OUTLOOK**: Outlook iOS/Android | Add as IMAP; try manual Exchange/EAS; record autodetect behaviour; with a proxy log check whether data routes via Microsoft cloud | IMAP only; EAS unsupported | |
| B5 | Apple Mail / Calendar / Contacts (macOS/iOS) | EWS vs IMAP+CalDAV+CardDAV account; event + contact round-trip | Expected | |
| B6 | Native iOS Mail / Android (EAS) | mail/calendar/contacts/OOF over ActiveSync with provisioning; push | Expected | |
| B7 | Thunderbird, DAVx5 | IMAP/SMTP, CalDAV/CardDAV | Expected | |
| B8 | grommunio-web (browser) | login (LDAP password), mail send/receive, calendar, contacts | Expected | |
| B9 | grommunio-admin-web | login, domain/user view; OIDC/Keycloak SSO not wired in this spike | n/a | |

## C. Groupware operations (manual)

| # | Test | Result |
|---|---|---|
| C1 | Licensing: create 6+ users in community mode; record whether anything blocks (5-user cap is a legal question, ADR-0003 gate) | |
| C2 | App passwords / lockout behaviour for Outlook/EAS/DAV; password change in lldap propagates immediately (bind-based auth) | |
| C3 | Mail flow: DKIM/SPF/DMARC are NOT testable here (no public DNS by design); test only local relay, TLS, rate limits | |
| C4 | Backup/restore of one mailbox (gromox data dir + MariaDB dump); upgrade to next grommunio bundle; failure/recovery | |
| C5 | Load: 50 mailboxes MAPI + EAS soak, RAM/CPU vs 4 vCPU / 6 GB minimum | |
| C6 | Prove isolation: `postqueue -p` empty of external mail; `ss -tn state established '( dport = :25 )'` shows no external SMTP; tcpdump on the VM uplink shows no port 25/465/587 egress | |
