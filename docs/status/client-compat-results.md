# Client compatibility results (open-source desktop clients)

Date: 2026-11-15/16. Lab only. Server under test: `ou-gw1` (Gromox 3.13-ou2 source build, grommunio-dav 1.9-ou1, Postfix, Debian 12), directory = OpenLDAP on `ou-id1`, autoconfig document served by the portal on `ou-portal1`. Status words (ADR-0000 style): PASS / FAIL / PARTIAL / NOT SUPPORTED, each backed by output printed in this session.
Machine: `ou-desk2` (clone of `ou-base-noble`, Ubuntu 24.04, zone `oulab`, `PrivateUsers=pick`, `MemoryMax=2G`, Xvfb :99). Code: `blueprints/lab/spike-desk/` (provisioning + README) and `blueprints/lab/tests/cc_*.py` (tests).

## 1. Summary

| Client | Version | Protocols used | Result |
|---|---|---|---|
| Mozilla Thunderbird ESR (MPL-2.0) | 153.7.0esr, official tarball, SHA256SUMS signature + sha256 verified | autoconfig (HTTP) -> IMAPS 993, SMTP (STARTTLS), CalDAV, CardDAV (grommunio-dav) | mail 12 PASS / 1 FAIL; CalDAV + CardDAV 12 PASS / 1 NOT SUPPORTED (scheduling not exercised) |
| GNOME Evolution (GPL) + evolution-ews (LGPL) | Evolution/EDS 3.52.3, evolution-ews 3.52.0 (Ubuntu 24.04) | EWS (SOAP over HTTPS, Basic) to Gromox; Autodiscover checked server-side | calendar, contacts, free/busy PASS; EWS mail send, meeting invitation and AcceptItem FAIL until a server config fix (outgoing SMTP URL) landed in the lab at 23:52 UTC, PASS after; Evolution mail layer partly inconclusive (see 4.4) |
| Classic Outlook, new Outlook, Outlook for Mac, Outlook iOS/Android | - | - | **not tested** - requires vendor client/licence or device (section 6) |
| Apple Mail/Calendar/Contacts, native iOS/Android EAS, DAVx5 | - | - | **not tested** - requires Apple hardware / phones (section 6) |
| Webmail SSO | - | - | already proven elsewhere (webmail-sso-results.md), skipped |

## 2. What was driven through the client, what was verified server-side

* **Thunderbird**: real `thunderbird` process (Xvfb, throw-away profile, user `tester`), driven over **Marionette** (`-marionette -remote-allow-system-access`) by `blueprints/lab/spike-desk/marionette.py`. Chrome-privileged JavaScript calls the *client's own modules*: `FindConfig.parallelAutoDiscovery` (the code the account hub runs), `CreateInBackend.createAccountInBackend`, `nsIMsgCompose.sendMsg`, IMAP folder/flag/search/copy services, `cal.provider.detection` + `calICalendar` (caldav provider), `CardDAVUtils.detectAddressBooks` + CardDAV directory. **The GUI was not clicked**; no xdotool input. One screenshot of the real UI (Xvfb) was taken while debugging.
* **Evolution**: real Evolution Data Server session per test user (D-Bus session + gnome-keyring, `evolution-source-registry`, `evolution-calendar-factory`, `evolution-addressbook-factory`) with the real **evolution-ews** backends, driven through the EDS client API (`ECalClient`, `EBookClient`, `ESourceRegistry`) and through Camel (`CamelEwsStore`, `CamelEwsTransport`, `CamelFolder`; the mail layer of Evolution). The Evolution GUI (`evolution` binary) was **not** started.
* **Verified server-side** with independent clients: `imaplib` (IMAPS), raw CalDAV/CardDAV (`REPORT`/`GET`/`PUT`), raw EWS (`FindItem`, `CreateItem/AcceptItem`), `smtplib` (to inject mail on :25). In the reverse direction a server-side change is made and the client is asked to show it.
* Test users (created with `ldap-user.sh add` + `gw-ldap-sync.py --user`, deleted again at the end): `cctb1`, `cctb2` (Thunderbird), `ccev1`, `ccev2` (Evolution), `@ou-lab.internal`. Passwords never printed.
* Hosts: `/etc/hosts` entries only inside `ou-desk2` (gw1/autodiscover.gw1 -> .218, auth/ldap -> .241, portal -> .244, `autoconfig.ou-lab.internal` -> 127.0.0.1). Lab CA + `OU Lab CA gw1` public certs in the system store; for Thunderbird also imported into its own NSS store (`nsIX509CertDB.addCertFromBase64`). TLS verification was never disabled.

## 3. Thunderbird ESR 153.7.0

Install: Mozilla `ftp.mozilla.org/pub/thunderbird/releases/153.7.0esr/linux-x86_64/en-US/thunderbird-153.7.0esr.tar.xz`; `SHA256SUMS` verified with `SHA256SUMS.asc` ("Good signature from Mozilla Software Releases", primary fingerprint pinned `14F2 6682 D091 6CDD 81E3 7B6D 61B7 B526 D98F 0353`), tarball sha256 `dbdda16e00f09c5a61ddad607517014b9e3364bef3499a1a2f64f0a3e575bcb6` matched. Script: `install-desk2.sh`.

### 3.1 Mail (`cc_tb_mail.py`, clean profile, run `2e4b38`: 12 PASS, 1 FAIL)

| Feature | Result | Driven via client | Verified server-side | Protocol |
|---|---|---|---|---|
| Autoconfig for cctb1 and cctb2 | PASS | `FindConfig.parallelAutoDiscovery` fetched `http://autoconfig.ou-lab.internal/mail/config-v1.1.xml?emailaddress=...` (shim log shows `User-Agent: ... Thunderbird/153.7.0`); got IMAP gw1.ou-lab.internal:993 SSL, SMTP :587 STARTTLS | - | HTTP autoconfig (via desk2-only shim, see 3.3) |
| Account creation from the discovered config | PASS | `CreateInBackend.createAccountInBackend` | IMAP login worked | - |
| Autoconfig-advertised SMTP `gw1.ou-lab.internal:587 STARTTLS` reachable | **FAIL** | - | TCP connect refused: no submission service on the lab MTA (only :25, no AUTH, `mynetworks`); the portal document advertises a service that does not exist (known: portal-results.md) | TCP |
| Send cctb1 -> cctb2 | PASS (after pointing SMTP to :25 STARTTLS, no AUTH, by hand) | `nsIMsgCompose.sendMsg(Now)` | message in cctb2 INBOX (IMAP SEARCH); Fcc copy in cctb1 `Sent` | SMTP :25 |
| Sent copy | PARTIAL | Thunderbird created its own `Sent` (and `Trash`) because the server's folders are `Sent Items`/`Deleted Items` and Gromox advertises no SPECIAL-USE; the server now has both `Sent` and `Sent Items` | IMAP LIST | IMAP |
| Receive + read body (UTF-8) | PASS | `getNewMessages`, `MsgHdrToMimeMessage` | - | IMAPS |
| Flags read+flagged, client -> server | PASS | `markMessagesRead/Flagged` | FLAGS `\Flagged \Seen` | IMAPS |
| Flag change server -> client | PASS | `updateFolder` shows unflagged, still read | `STORE -FLAGS \Flagged` | IMAPS |
| Message injected server-side appears in client | PASS | `getNewMessages` | IMAP APPEND | IMAPS |
| Create folder | PASS | `createSubfolder` | IMAP LIST shows it | IMAPS |
| Copy message into the folder | PASS | `MailServices.copy.copyMessages` | message in the new folder (IMAP SEARCH) | IMAPS |
| Search | PASS | `nsIMsgSearchSession` with online scope (server-side SEARCH), 11 hits for `tb-` | - | IMAPS |

### 3.2 CalDAV + CardDAV (`cc_tb_dav.py`, run `e3f55c`: 12 PASS, 1 NOT SUPPORTED)

| Feature | Result | Driven via client | Verified server-side |
|---|---|---|---|
| CalDAV discovery on `https://gw1.ou-lab.internal/dav/` | PASS | `cal.provider.detection.detect` found Calendar, Notes, Tasks collections (plus one bogus "ics" entry for `/dav/` itself) | - |
| Create event | PASS | `calICalendar.addItem` | CalDAV GET shows SUMMARY/LOCATION; EWS FindItem lists it |
| Edit (title, location, time) | PASS | `modifyItem` | CalDAV GET shows new values |
| Server-created event appears | PASS (needs `calendar.refresh()`; not seen until refreshed) | `refresh` + `getItemsAsArray` | CalDAV PUT 201 |
| Delete | PASS | `deleteItem` | CalDAV GET 404 |
| Invitations / iTIP scheduling | NOT SUPPORTED here (not exercised in Thunderbird; covered with Evolution/EWS, section 4) | - | - |
| CardDAV discovery | PASS | `CardDAVUtils.detectAddressBooks` found `Contacts` | - |
| Create / edit / delete contact | PASS x3 | `addCard`, `modifyCard` (vCardProperties), `deleteCards` | CardDAV REPORT shows vCard, edited e-mail, then gone |
| Server-created contact synced in | PASS | `CardDAVDirectory.syncWithServer` | CardDAV PUT 201 |

Client quirk found: Thunderbird's calendar auth deletes a saved login that it hands out twice within 60 s; a freshly registered caldav calendar fires parallel requests and the first PUT then went out with empty credentials (401). The test registers the calendar, waits 10 s, re-checks the login, then works sequentially. This is a Thunderbird behaviour, not a Gromox defect, but real users with a password saved at the same moment could see a prompt.

### 3.3 Autoconfig honesty note
The portal serves the XML on `portal.ou-lab.internal`; the lab certificate does not cover `autoconfig.<domain>`. A tiny forwarder (`autoconfig-shim.py`, desk2 only, 127.0.0.1:80) stands in for the customer's `autoconfig.<domain>` DNS/proxy step and fetches the document from the portal over verified TLS. So this proves the document is **parseable and complete enough for Thunderbird**; it does not prove customer DNS. No CalDAV/CardDAV in autoconfig (format limitation); Thunderbird found DAV only because the test pointed it at `/dav/`.

## 4. Evolution 3.52.3 + evolution-ews 3.52.0 against Gromox EWS

Server-side Autodiscover (what Evolution consumes): POX `POST https://autodiscover.gw1.ou-lab.internal/autodiscover/autodiscover.xml` as ccev1 returned `EwsUrl=https://gw1.ou-lab.internal/EWS/Exchange.asmx`, `OABUrl=https://gw1.ou-lab.internal/OAB/`, AuthPackage basic (PASS). **Evolution's own Autodiscover lookup was not exercised** (PARTIAL): it derives `autodiscover.<mail-domain>` = `autodiscover.ou-lab.internal`, which neither DNS nor the certificate (gw1.* names only) covers in the lab. The EWS source was configured with the URLs from the Autodiscover answer. Evolution also has no EWS mail account created by the backend: the three sources (mail account, identity, transport) that the account assistant writes were written by the test.

### 4.1 Account / folder discovery
PASS for both users: after the collection source (`[Authentication] Method=NTLM`, password in the keyring) was loaded, evolution-ews authenticated with Basic over TLS (lab CA) and created sources `Calendar`, `Contacts`, `Notes`, `Tasks`, `Global Address List` (SyncFolderHierarchy). Note: the first start of a fresh EDS profile often returned only the GAL source; a second setup pass produced the folders.

### 4.2 Calendar, contacts, free/busy (`cc_evo.py`, run `9377fe`, after the server fix)

| Feature | Result | Driven via client | Verified server-side |
|---|---|---|---|
| Create event | PASS | `ECalClient.create_object_sync` | CalDAV REPORT lists it; EWS FindItem lists it |
| Edit title/location | PASS | `modify_object_sync` | CalDAV shows `EDITED`, `LOCATION:Room 9` |
| Delete | PASS | `remove_object_sync` | gone in CalDAV |
| Server-created event (CalDAV PUT) appears in client | **FAIL / unreliable** | `get_object_list_sync` after `refresh_sync`, polled 260 s (backend `StoreChangesInterval=3` min) | PUT 201. Seen within 90 s in one early run, not seen within 260 s in three later runs and not within 400 s in a dedicated probe. Not root-caused |
| Create contact | PASS | `EBookClient.add_contact_sync` | CardDAV REPORT shows the vCard (same store) |
| Edit contact | PASS | `modify_contact_sync` | CardDAV shows edited e-mail |
| Server-created contact appears | PASS | `get_contacts_sync` | CardDAV PUT 201 |
| Delete contact | PASS | `remove_contact_sync` | gone in CardDAV |
| Free/busy of another user | PASS | `ECalClient.get_free_busy_sync` -> `FREEBUSY;FBTYPE=BUSY:20261209T100000Z/20261209T110000Z` for ccev2 (busy slot made in ccev2's Evolution; an event without `TRANSP` is reported FREE: Evolution maps a missing TRANSP to free) | raw EWS `GetUserAvailability` agrees |

### 4.3 Meetings (organizer ccev1, attendee ccev2)

| Step | Before server fix (runs `62a8aa`, `f2dbef`, ~23:00-23:50 UTC) | After fix (run `9377fe`, 00:0x UTC) |
|---|---|---|
| Organizer creates event with attendee (EWS CreateItem + SendMeetingInvitations) | **FAIL** HTTP 500; gromox-http: `E-3117: failed to send mail (The desired service is unavailable)` | PASS; invitation mail in ccev2 INBOX (IMAP) |
| Delivered iTIP mail becomes an EWS `IPM.Schedule.Meeting.Request` | PASS | PASS (no automatic calendar entry before the attendee acts: PASS) |
| Attendee accepts **through Evolution's calendar API** (`receive_objects_sync`) | PARTIAL: refused by evolution-ews itself ("Cannot create meetings organized by other users in an Exchange Web Services calendar"); Evolution accepts from the mail view (EWS AcceptItem on the message), which needs the GUI and was **not driven** | same |
| Accept at protocol level (raw EWS `CreateItem/AcceptItem`, not Evolution) | calendar entry created, but HTTP 500 (response mail to organizer cannot be sent, E-3117) | calendar entry created, HTTP 200 NoError |

Root cause of E-3117 (found by reading, not changed by this agent): `/etc/gromox/gromox.cfg` had no `outgoing_smtp_url`; Gromox's default target `localhost` resolves to `::1` first while Postfix on ou-gw1 listens on IPv4 only (`::1:25` refused, `127.0.0.1:25` open, `inet_protocols = ipv4`). Another agent added `outgoing_smtp_url=smtp://127.0.0.1:25` and restarted gromox-http at 23:52 UTC; from then on EWS send/invite/accept work. Anyone rebuilding the groupware node must carry that line (it is not in the repo's lab scripts at the time of writing).

### 4.4 Mail through Evolution's mail layer (Camel EWS)
Results come from three different runs; the harness (Python/pygobject over Camel) turned out to be fragile and is the weakest part of this report.

| Feature | Result | Evidence |
|---|---|---|
| Receive + read (mail injected via SMTP :25, listed and opened, UTF-8 body) | PASS | all runs |
| Send via EWS (`CamelEwsTransport.send_to_sync`) | FAIL before the fix (HTTP 500, E-3117), PASS after (arrives in ccev2 INBOX) | runs `f2dbef` / `9377fe` |
| Create folder in client | PASS | server IMAP LIST shows `INBOX/CC-<run>` |
| Read + answered flags client -> server | PASS in runs `62a8aa`, `f2dbef` (server FLAGS `\Seen \Answered`); inconclusive in later runs | see below |
| Star (follow-up flag) client -> server | **FAIL** (3 runs): client marks FLAGGED, server FLAGS stay `\Seen \Answered`; Gromox does not map the EWS flag set to `\Flagged` | imaplib FETCH FLAGS |
| Search in client | PASS in runs `62a8aa`, `f2dbef` and interactively; inconclusive later | `search_by_expression` |
| Move to the new folder | PASS interactively (moved 1, listed in destination); the orchestrated runs failed on a pygobject decode error | - |
| Server-side `\Seen` shows in client | PASS in `f2dbef`, FAIL in `62a8aa` (60 s wait) | - |
| Delete in client | not conclusive | - |

Harness defect: after the first runs the Camel calls returned garbage uid strings (`UnicodeDecodeError`), the worker aborted once (SIGABRT) and in the last attempt (clean profile, run `e0a96b`) segfaulted on its first Camel call (core dumped, journal of `evo1srv`), so the final mail-only re-run produced no result lines; I could not prove whether this is pygobject ownership handling of Camel uid arrays or an evolution-ews issue. Rows marked "inconclusive" must not be read as product failures. Treat Evolution mail (other than receive, send, folder create) as **PARTIAL** until re-run through the real GUI.

## 5. Findings for the product / lab

1. **Portal autoconfig advertises SMTP 587 STARTTLS, the lab MTA only has :25 (no AUTH).** Thunderbird accepts the document and then cannot send. Production needs a real submission service (587/465 with SASL) or the autoconfig must advertise what exists.
2. **Gromox needs `outgoing_smtp_url=smtp://127.0.0.1:25` (or a dual-stack MTA).** Without it every EWS send, meeting invitation and AcceptItem fails with 500/E-3117 although Gromox itself and Postfix are healthy. Add it to `blueprints/lab/spike-groupware/*` (not done by this agent: read-only on main checkout).
3. Gromox does not auto-create a calendar entry for an incoming meeting request; the attendee's client must act (EWS: `AcceptItem`). With `outgoing_smtp_url` set, `AcceptItem` works at protocol level.
4. Star/flag from Evolution-EWS is not reflected as IMAP `\Flagged` (Gromox gap or mapping difference).
5. No SPECIAL-USE on IMAP: Thunderbird created duplicate `Sent`/`Trash` folders next to `Sent Items`/`Deleted Items`.
6. Evolution-EWS server->client change propagation for calendar items is slow or absent in a running session (see 4.2).
7. Thunderbird calendar auth quirk (3.2) and Thunderbird 153's built-in Exchange/EWS account type were **not** exercised.

## 6. Not tested (owner must provide)

| Client | Status | What an owner needs to provide |
|---|---|---|
| Classic Outlook for Windows (M365 Apps, Outlook 2024) | not tested | Windows VM/PC, Microsoft Office licence, lab CA + hosts entries; capture MAPI/HTTP |
| New Outlook for Windows | not tested | Windows device + Microsoft account |
| Outlook for Mac | not tested | Mac + licence |
| Outlook iOS/Android | not tested | iPhone/Android device + Microsoft account; proxy for traffic capture |
| Apple Mail/Calendar/Contacts, iOS Mail | not tested | Mac/iPhone, the lab CA profile (portal `.mobileconfig` is unsigned and untested) |
| Android native EAS / DAVx5 | not tested | Android device, lab CA |
| Thunderbird native Exchange (EWS) account type | not tested (available in 153, not driven) | - |

## 7. Reproduce
See `blueprints/lab/spike-desk/README.md`. In short: `install-desk2.sh` in a clone of `ou-base-noble`, create the four users (documented paths), run `cc_tb_mail.py`/`cc_tb_dav.py` against a fresh Thunderbird profile and `evo-servers.sh start` + `cc_evo.py` (`CC_EVO_SECTIONS=mail` for the mail part only).

## 8. Limits
GUI not driven for either client; Evolution mail layer partly inconclusive (4.4); results are for one server build (Gromox 3.13-ou2) and one client build each; the autoconfig path used a desk-local shim; interop with other server products was not tested; one agent's lab server was changed by someone else mid-test (fix at 23:52 UTC), which is why meeting/send results are reported before and after.
