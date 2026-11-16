# Manual checklist: things automation cannot prove

Status: PREPARED, NOT EXECUTED (exception: section B rows B7 and B7b were executed by automation on 2026-11-15, see docs/status/client-compat-results.md). Record for every row: date, tester, client + exact build, server package versions
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
| A11 | Disable-user timing: disable alice in the identity source while web + desktop + mobile are connected; measure time until each loses access (target <= 5 min per ADR-0004); then revoke offline tokens (Keycloak admin: Sessions > Offline) and recheck; remove role from the LDAP group and re-test (automated part: t06_disable_user.py) | |
| A12 | Full VM reboot of files, kc, office in turn: sessions, files, versions, shares intact; collaboration service re-registers with Collabora; in-progress edit recovered or clean error | |
| A13 | Backup test: filesystem snapshot of /var/lib/opencloud + /etc/opencloud restored to a second VM; xattrs and versions intact | |
| A14 | Resource baseline: idle + loaded RAM/CPU per service (`systemd-cgtop`, `docker stats`); Keycloak realm start time | |

## B. Groupware client matrix (grommunio) - **REAL OUTLOOK** unless noted

| # | Client | What to test | Expectation (groupware-eval.md 6.1) | Result |
|---|---|---|---|---|
| B1 | **REAL OUTLOOK**: classic Outlook for Windows (M365 Apps current channel; also Outlook 2024) | Autodiscover profile creation for alice@ou-lab.internal; cached-mode sync of mail/calendar/contacts/tasks; free/busy; shared mailbox; delegation; send-on-behalf; server rules; OOF; public folders; 25 MB attachment; offline/online reconnect; capture MAPI/HTTP trace (Fiddler/Outlook ETL) | Expected, lab-verify | **not tested** - requires a licensed Microsoft Outlook (M365 Apps current channel or Outlook 2024) on Windows. Owner provides: a Windows VM/PC, the Office licence, the lab CA + hosts entries (gw1/autodiscover.gw1 -> 192.168.186.218). Server-side MAPI/HTTP + Autodiscover are covered by gw_02/t16 only |
| B2 | **REAL OUTLOOK**: new Outlook for Windows | Add as Exchange (record error) and as IMAP/SMTP; what works (mail only?) | Partial: IMAP/SMTP only | **not tested** - requires the vendor client (new Outlook for Windows) and a Microsoft account. Owner provides: Windows device + Microsoft account. (Thunderbird's IMAP result in B7 shows the IMAP server side works; it says nothing about this client) |
| B3 | **REAL OUTLOOK**: Outlook for Mac current + legacy | Add Exchange account (Autodiscover + EWS); mail, calendar, invites, reply/forward drafts, free/busy, shared folders | Partial/unverified | **not tested** - requires Outlook for Mac + licence on macOS hardware. Owner provides: a Mac and the licence. (Evolution-EWS, B7b, is the closest EWS evidence) |
| B4 | **REAL OUTLOOK**: Outlook iOS/Android | Add as IMAP; try manual Exchange/EAS; record autodetect behaviour; with a proxy log check whether data routes via Microsoft cloud | IMAP only; EAS unsupported | **not tested** - requires iOS/Android devices with Outlook mobile (Microsoft account for app set-up). Owner provides: devices + a proxy/capture set-up |
| B5 | Apple Mail / Calendar / Contacts (macOS/iOS) | EWS vs IMAP+CalDAV+CardDAV account; event + contact round-trip | Expected | **not tested** - requires Apple hardware (macOS/iOS). Owner provides: a Mac/iPhone and the lab CA profile. The portal's .mobileconfig is unsigned and was never installed on a device |
| B6 | Native iOS Mail / Android (EAS) | mail/calendar/contacts/OOF over ActiveSync with provisioning; push | Expected | **not tested** - requires an iOS or Android device with the native EAS client. Owner provides: device(s) with the lab CA installed. Server-side EAS is covered by gw_03/t14 only |
| B7 | Thunderbird, DAVx5 | IMAP/SMTP, CalDAV/CardDAV | Expected | Thunderbird ESR 153.7.0 (Mozilla tarball, signature-verified): IMAP/SMTP/CalDAV/CardDAV executed, see docs/status/client-compat-results.md (mail 12 PASS + 1 FAIL: the autoconfig-advertised SMTP :587 does not exist on the lab MTA; CalDAV/CardDAV 12 PASS). DAVx5: **not tested** (needs an Android device) |
| B7b | GNOME Evolution 3.52 + evolution-ews 3.52 (EWS to Gromox) | account via EWS; calendar/contacts/mail; meeting invitation/accept; free/busy | Not in the vendor matrix | executed 2026-11-15/16 (automated via EDS API + Camel; GUI not clicked), see docs/status/client-compat-results.md: calendar, contacts, free/busy PASS; EWS send/invitation/AcceptItem PASS only after Gromox `outgoing_smtp_url` fix (E-3117 before); star flag not mapped; Camel mail ops partly inconclusive |
| B8 | grommunio-web (browser) | login (LDAP password), mail send/receive, calendar, contacts | Expected | |
| B9 | grommunio-admin-web | login, domain/user view; OIDC/Keycloak SSO not wired in this spike | n/a | |

## C. Groupware operations (manual)

| # | Test | Result |
|---|---|---|
| C1 | Licensing: create 6+ users in community mode; record whether anything blocks (5-user cap is a legal question, ADR-0003 gate) | |
| C2 | App passwords / lockout behaviour for Outlook/EAS/DAV; password change in the directory (OpenLDAP) propagates immediately (bind-based auth) | |
| C3 | Mail flow: DKIM/SPF/DMARC are NOT testable here (no public DNS by design); test only local relay, TLS, rate limits | |
| C4 | Backup/restore of one mailbox (gromox data dir + MariaDB dump); upgrade to next grommunio bundle; failure/recovery | |
| C5 | Load: 50 mailboxes MAPI + EAS soak, RAM/CPU vs 4 vCPU / 6 GB minimum | |
| C6 | Prove isolation: `postqueue -p` empty of external mail; `ss -tn state established '( dport = :25 )'` shows no external SMTP; tcpdump on the VM uplink shows no port 25/465/587 egress | |
