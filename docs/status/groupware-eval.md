# Groupware backend evaluation: grommunio/Gromox vs mailcow/SOGo

Date: 2026-11-15. Method: public docs and public GitHub API/raw files only; nothing installed.
Confidence legend: items marked UNVERIFIED could not be confirmed from a primary source in this pass.

## 1. grommunio / Gromox ecosystem

### 1.1 Versions

Latest *bundle*: grommunio 2026.06.2 (30 Sep 2026): gromox 3.11, Web 5.1, Sync 2.6, DAV 1.8,
Antispam 4.1.5, Keycloak 26.7.4; admin API/web versions not stated.
Source: https://docs.grommunio.com/admin/release_notes/

Newer upstream git tags (GitHub API, queried 2026-11-15) are ahead of that bundle:

| Component | Latest git tag | Source |
|---|---|---|
| gromox | gromox-3.13 (release 2026-10-29) | https://github.com/grommunio/gromox/releases |
| grommunio-sync | 2.7 | https://github.com/grommunio/grommunio-sync/tags |
| grommunio-dav | 1.9 | https://github.com/grommunio/grommunio-dav/tags |
| admin-api | 1.21 | https://github.com/grommunio/admin-api/tags |
| admin-web | 5.0.0 | https://github.com/grommunio/admin-web/tags |
| grommunio-web | v4.5.1 | https://github.com/grommunio/grommunio-web/tags |

Discrepancy: the release notes say Web 5.1 but the repo's newest tag is v4.5.1. Not resolved; treat the
Web version as UNVERIFIED. Repos are named `admin-api` / `admin-web` (the `grommunio-` prefixed URLs
301-redirect). No public repo named `grommunio-antispam` or `antispam` was found under the org
(https://github.com/grommunio), so the antispam source and license are UNVERIFIED.
Code is also mirrored on Codeberg (per search summary of https://ng.grommunio.com/pricing/, not
independently confirmed).

### 1.2 License per component

| Component | License | Evidence |
|---|---|---|
| gromox | AGPL-3.0 (GitHub shows NOASSERTION; LICENSE.txt is the AGPLv3 text; README badge says AGPL-3.0) | https://github.com/grommunio/gromox/blob/master/LICENSE.txt , https://github.com/grommunio/gromox |
| grommunio-web | AGPL-3.0-or-later with mixed bundled third-party licenses (MIT, Apache-2.0, MPL-2.0, GPL/LGPL, OFL etc. in LICENSES/); code derived from Kopano/Zarafa | https://github.com/grommunio/grommunio-web/blob/master/LICENSE.txt , https://github.com/grommunio/grommunio-web/tree/master/LICENSES |
| grommunio-sync | AGPL-3.0 | https://github.com/grommunio/grommunio-sync |
| grommunio-dav | AGPL-3.0 | https://github.com/grommunio/grommunio-dav |
| admin-api | AGPL-3.0 | https://github.com/grommunio/admin-api |
| admin-web | AGPL-3.0 | https://github.com/grommunio/admin-web |
| grommunio-antispam | UNVERIFIED (no public repo located) | n/a |
| grommunio-setup (+ -deb) | setup: NOASSERTION; setup-deb: AGPL-3.0 per GitHub metadata (file-level check not done) | https://github.com/grommunio/grommunio-setup |
| Documentation | CC BY-SA 4.0 or later | https://docs.grommunio.com/admin/installation/ |

### 1.3 Community vs commercial

Pricing page (https://ng.grommunio.com/pricing/): Community is free, up to 5 users, no manufacturer
support; paid tiers Basic EUR 1.99, Plus 2.99, Business 4.49 per user/month (from 6 / 6 / 50 users),
Enterprise custom (from 1,000). The page states all software features are in every plan; plans differ by
user count and support. Commercial licenses are sold only through certified partners. The page does not
say which enterprise add-ons (Archive, MDM) are in which tier.

Repositories: setup offers a community repo ("best effort, not supported") or a supported
(subscription) repo (https://docs.grommunio.com/admin/installation/ ,
https://docs.grommunio.com/admin/quickstart/). Community packages:
https://download.grommunio.com/community/packages/ (per search result listing).

Licence counting: only active (non-disabled) accounts count (2025.01.2); limits are checked on user
reactivation (2026.06.2). Source: release notes URL above. UNVERIFIED: whether the 5-user cap is enforced
technically in community builds or by terms only. The GTC (https://grommunio.com/gtc/) says the community
version may be downloaded free and operated under the open source licenses (per search summary; not read
in full). Implication for an MSP: more than 5 mailboxes in a community deployment sits in a grey area
until the terms are read by counsel; there is no Outlook-specific user limit documented, the cap is
per-user across all protocols.

Trademark: https://docs.grommunio.com/legal_notice.html states grommunio, the grommunio logo and gromox
are registered trademarks of grommunio GmbH (per search summary). No dedicated trademark/brand-usage or
white-label policy was found. UNVERIFIED whether rebranding web UI/admin is permitted. AGPL covers code,
not marks; assume the name and logo must be removed from a white-labeled product and ask grommunio
GmbH in writing. Web carries Kopano/Zarafa copyright notices that must be preserved (LICENSE.txt above).
AGPL section 13 requires offering source to network users of modified versions.

## 2. Protocol support per component

| Capability | Component | Status | Source |
|---|---|---|---|
| MAPI/HTTP | gromox-http | Supported; Outlook desktop without plugin | https://github.com/grommunio/gromox , https://ng.grommunio.com/features/ |
| RPC/HTTP (Outlook Anywhere) | gromox-http | Supported | gromox README |
| EWS | gromox (ews plugin) | Left beta 2023.11.3, default on; 2026.06.1 "greatly expanded": tasks, calendar occurrences with timezones, delegate mgmt, full meeting workflow; 2026.06.2: Outlook for Mac reply/forward drafts, MoveItem/CopyItem/FindFolder/FindItem fixes. Completeness vs Exchange is UNVERIFIED (no operation coverage matrix found) | https://docs.grommunio.com/admin/release_notes/ |
| Autodiscover | nginx + gromox php | Supported (Autodiscover and Autoconfig); DNS record for it strongly recommended | https://docs.grommunio.com/admin/architecture/ , https://docs.grommunio.com/admin/quickstart/ |
| ActiveSync | grommunio-sync at /Microsoft-Server-ActiveSync | Supported; protocol version UNVERIFIED (docs give none) | architecture page |
| CalDAV / CardDAV | grommunio-dav (via php-mapi/zcore) | Supported incl. tasks | architecture page |
| IMAP / POP3 / SMTP | gromox-imap, gromox-pop3, postfix + gromox-delivery | Supported; ports 25/110/143/587/993/995 | quickstart page |
| Free/busy | web, MAPI, EWS | Free/busy and time suggestions in calendar; EWS GetUserAvailability coverage UNVERIFIED | features page |
| Shared mailboxes, public folders, GAL | gromox | Supported | features page |
| Delegation | gromox, EWS | Shared calendar delegation; EWS delegate mgmt since 2026.06.1 | features + release notes |
| Rules (server-side) | gromox | UNVERIFIED (features page silent; MAPI rule tables are part of gromox's OXCMAIL/OXORULE implementation but not confirmed here) | n/a |
| OOF | gromox | UNVERIFIED (not on features page; EWS OOF settings coverage unconfirmed) | n/a |

## 3. Install targets, resources, dependencies, auth

Supported platforms per release notes (https://docs.grommunio.com/admin/release_notes/):
- 2025.01.1: RHEL 9/EPEL 9, openSUSE/SLES 15.5+, Debian 12, Ubuntu 24.04 listed as supported; appliance on openSUSE 15.6.
- 2025.01.2: `grommunio-setup` semi-automatic setup for Debian/Ubuntu (DEB); PHP 7 dropped.
- 2026.06.1: appliance base openSUSE Leap 16.0/SLES 16; Debian 13 and Ubuntu 26.04 LTS; native .deb packages for the stack.
- 2026.06.2: Ubuntu 26.04 builds, Files packaged for Debian.
So Ubuntu 24.04 and Debian 12 are listed as supported package targets (since 2025.01.1). Whether the
2026.06.x repos still carry 24.04/12 builds is UNVERIFIED; check the repo index before the lab.
The primary documented path is the appliance ISO/OVA/container (installer overwrites the whole disk):
https://docs.grommunio.com/admin/installation/ . Source build docs: https://github.com/grommunio/gromox/blob/master/doc/install.rst

Minimum resources (quickstart): 4 cores, 6 GB RAM, 32 GB system disk plus mailbox storage; IPv6
must be active (::1 sufficient); at least two DNS names (mail, autodiscover); port 80 for Let's
Encrypt; RPC/HTTP, MAPI/HTTP, EWS, EAS all on 443. https://docs.grommunio.com/admin/quickstart/

Dependencies (architecture + install pages):
- MariaDB/MySQL central DB (SQLite per-user store); nginx; php-fpm; Redis cache; Postfix MTA handing to
  "grommunio Antispam" via milter (Rspamd not named in docs; UNVERIFIED that it is rspamd-based).
  https://docs.grommunio.com/admin/architecture/
- gromox-zcore is required by anything using php-mapi (web, sync, dav): gromox install.rst above.
- Optional: Keycloak (grommunio Auth), Chat, Files, Meet, Archive.

Authentication: LDAP/Active Directory via gromox-ldap (architecture page; configurable in Admin UI per
features page). OIDC/Keycloak: OIDC login in Web since 2023.11.1, passkeys 2023.11.3, Admin SSO button
and auto-provisioned Keycloak clients in 2026.06.2 (release notes). Whether Outlook/EAS/DAV clients can
authenticate with OIDC tokens rather than passwords is UNVERIFIED; assume password (or app password)
for non-web protocols.

## 4. Microsoft client reality (Microsoft sources only)

Microsoft does not document any non-Exchange server for these clients; everything about third-party
servers below is therefore inference marked as such.

**Classic Outlook for Windows.** Microsoft publishes MAPI over HTTP as the Exchange transport
(https://techcommunity.microsoft.com/blog/exchange/outlook-connectivity-with-mapi-over-http/586590 , found by
search, not read in full). No Microsoft page found that states classic Outlook connects to non-Microsoft
MAPI/HTTP servers; UNVERIFIED from Microsoft. Classic Outlook is still available: Outlook 2024 is supported
until 10/10/2029 (https://learn.microsoft.com/en-us/lifecycle/products/outlook-2024). Microsoft 365 Apps
classic Outlook end date: UNVERIFIED (third-party article claims 2029). Classic Outlook "Available" for
Exchange on-prem:
https://support.microsoft.com/en-us/office/feature-comparison-between-new-outlook-and-classic-outlook-de453583-1e76-48bf-975a-2e9cd2ee16dd
grommunio's own claim of native Outlook desktop support: https://ng.grommunio.com/features/ (vendor claim).

**New Outlook for Windows.** Learn page "Supported accounts in new Outlook for Windows" (ms.date
2025-10-29): supported are M365 work/school (Exchange Online), Outlook.com, Gmail, Yahoo, iCloud, and IMAP/POP;
"On-premises Exchange accounts aren't supported" (error "We couldn't reach the email server").
https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/get-started/supported-account-types
The feature comparison page (link above) lists Exchange on-prem as "Partially available" in new Outlook,
via IMAP only, with functionality limited by protocol. The two pages are inconsistent; both exclude
MAPI/EWS-based on-prem. Conclusion: new Outlook = IMAP/SMTP only against grommunio, no calendar/contacts sync.

**Outlook for Mac.** Support article https://support.microsoft.com/en-us/outlook/end-of-support-for-legacy-outlook-for-mac :
legacy client keeps working with Exchange on-premises until 9 Oct 2029 (security updates only), stops working
with Exchange Online in Oct 2026; the current Outlook for Mac is "Supported" for Exchange SE on-prem
accounts (business/enterprise plans). The article says legacy uses EWS with Exchange Online and EWS
retires 1 Oct 2026 (Online); the protocol for on-prem is not named. Setup requirements (Exchange 2016+,
Basic/NTLM only, no Kerberos, not Mac App Store build) come from search summaries of Q&A pages: weak sources,
UNVERIFIED. Whether current Outlook for Mac accepts a non-Exchange EWS server is UNVERIFIED from Microsoft;
grommunio's 2026.06.2 notes explicitly target Outlook for Mac (release notes URL above), a vendor signal only.

**Outlook for iOS/Android.** Microsoft: it is a "cloud-backed application"; for on-prem Exchange it uses
hybrid Modern Authentication. Data is synchronized by Exchange Online over EAS into a cloud cache, and
requires full Exchange hybrid, Entra Connect, Intune/EMS licensing, publicly reachable Autodiscover/EAS not
behind pre-authentication, and an Exchange-licensed on-prem. Basic-auth EAS is used only for Exchange 2010 or
when no hybrid is configured. https://learn.microsoft.com/en-us/exchange/clients/outlook-for-ios-and-android/use-hybrid-modern-auth ,
https://learn.microsoft.com/en-us/exchange/clients/outlook-for-ios-and-android/outlook-for-ios-and-android
Microsoft states "If you only have an Exchange on-premises license, you aren't licensed to use the app" (same
HMA page) and that unsupported on-prem features include shared/delegate calendars and mailboxes and drafts.
All Microsoft docs are written for Exchange Server 2013-SE; a non-Exchange ActiveSync server is not
documented. Microsoft's mobile support pages list IMAP/POP as supported generic accounts but state
IMAP syncs mail only, with calendar/contacts needing an Exchange ActiveSync provider
(https://support.microsoft.com/en-us/outlook/what-email-services-does-your-app-support , from search
summary). Expectation: IMAP mail works; EAS to grommunio-sync via manual basic-auth setup is UNVERIFIED and is not a
documented/supported Microsoft scenario; Microsoft Cloud-proxied sync (cloud cache) would also put mailbox
data in Microsoft's cloud, which defeats the self-hosting aim.

## 5. mailcow / SOGo (comparison)

- mailcow-dockerized: GPL-3.0; latest release tag 2026-11 (2026-11-05). https://github.com/mailcow/mailcow-dockerized
  ("Any part of mailcow itself is released under GPLv3"; bundled components have own licenses, README.)
- Stack: Dovecot, Postfix, Rspamd, SOGo, nginx, Redis, ClamAV optional; shared mailboxes/calendars;
  login via Keycloak/LDAP/AD/OIDC. https://docs.mailcow.email/
- SOGo: GPL-2.0 per GitHub metadata, COPYING.GPL and COPYING.LGPL in repo; latest tag SOGo-5.12.13.
  https://github.com/Alinto/sogo ; site says "GPL or LGPL version 2 or newer" https://www.sogo.nu/
- SOGo protocols: ActiveSync (native), CalDAV, CardDAV, GroupDAV, IMAP. Outlook is not native; needs the
  third-party Outlook CalDav Synchronizer plugin. No MAPI or EWS mentioned. https://www.sogo.nu/
- Consequence: no MAPI/HTTP, no EWS, so classic Outlook has only IMAP + plugin; no Autodiscover for
  Exchange-protocol Outlook profiles (UNVERIFIED for mailcow's autodiscover mapping to EAS; typically
  returns IMAP/SMTP and ActiveSync profile).
- Strong points: simpler Docker deploy, widely used, no user cap, permissive for MSP resale (GPL, no
  user-based licence). Not verified here: install OS list and min RAM (docs page not fetched).

## 6. Conclusion

### 6.1 Expected client compatibility with grommunio (Gromox) backend

| Client | Expectation | Reason |
|---|---|---|
| Classic Outlook for Windows (M365 Apps / 2021 / 2024) | Expected (lab-verify) - **not tested**: requires a licensed Outlook on Windows (owner provides VM/licence) | MAPI/HTTP + Autodiscover served by gromox (vendor-documented); not a Microsoft-documented scenario |
| New Outlook for Windows | Partial (IMAP/SMTP only) - **not tested**: requires the vendor client + Microsoft account | MS: on-prem Exchange unsupported / IMAP only; no MAPI/EWS |
| Outlook for Mac (current) | Partial/unverified - **not tested**: requires a Mac + licence | EWS on gromox improving (2026.06.2) but MS support scope is Exchange; test |
| Outlook iOS/Android | Partial (IMAP mail only); EAS unsupported - **not tested**: requires devices | MS design requires hybrid/cloud sync; EAS manual path undocumented |
| Native iOS/Android mail (ActiveSync) | Expected - **not tested** on a device (server-side EAS only: gw_03/t14) | grommunio-sync EAS (version UNVERIFIED) |
| Apple Mail/Calendar/Contacts | Expected - **not tested**: requires Apple hardware | EWS/IMAP/CalDAV/CardDAV per features page |
| Thunderbird | **Lab-verified 2026-11-15** (ESR 153.7.0): IMAP, folders, flags, search, CalDAV, CardDAV PASS; autoconfig PASS but advertises SMTP :587 which the lab MTA lacks (send needed :25 set by hand). See client-compat-results.md | IMAP/SMTP, CalDAV/CardDAV |
| GNOME Evolution + evolution-ews (EWS) | **Lab-verified 2026-11-15/16** (3.52): account/folder discovery, calendar, contacts, free/busy PASS; EWS send + meeting invitation PASS only after Gromox `outgoing_smtp_url` was set (E-3117 before); star flag not mapped to IMAP `\Flagged`; server->client calendar change sync unreliable; Camel mail ops partly inconclusive. See client-compat-results.md | EWS (Gromox) |
| Webmail | Expected (SSO proven: webmail-sso-results.md) | grommunio-web |

For SOGo/mailcow: classic Outlook partial (IMAP + plugin), new Outlook partial (IMAP), mobile native EAS expected,
Outlook mobile same limits as above.

### 6.2 Recommendation

Use grommunio/Gromox as the primary groupware backend candidate: it is the only open stack here that
speaks MAPI/HTTP and EWS, which is the requirement for full Outlook desktop fidelity. Risks to settle
before commitment: (a) 5-user community cap and unknown white-label/trademark terms (needs written answer
from grommunio GmbH, or a partner agreement); (b) Microsoft does not support or document third-party servers
for Outlook; compatibility is vendor-asserted and can regress on Outlook updates; (c) new Outlook and Outlook
mobile will not give a full experience, so the product must steer Windows users to classic Outlook (a
shrinking window; Outlook 2024 to 10 Oct 2029) or webmail; (d) AGPL obligations on forks; (e) version/distro
discrepancies above. Keep mailcow/SOGo as fallback for small tenants wanting a simple
IMAP + EAS + DAV service with no Outlook-native requirement.

### 6.3 Lab test plan

Environment: 2 VMs (Ubuntu 24.04 and Debian 12; plus the openSUSE appliance as control), 4 vCPU/6 GB, IPv6
on, public-style DNS + ACME, 2 domains, LDAP source and a Keycloak instance.
1. Packaging: check repo index for 24.04/12 builds of 2026.06.2 or later; install via grommunio-setup(-deb) from
   the community repo; record package versions of gromox, web, sync, dav, admin-api/web, antispam; record real
   license files from installed packages (closes antispam/web gaps).
2. Licensing: create 6+ users in community mode; record whether anything blocks; get written grommunio
   answer on user cap, repo use, rebranding.
3. Outlook classic (M365 Apps current channel + Outlook 2024): Autodiscover profile creation,
   cached mode sync of mail/calendar/contacts/tasks, free/busy, shared mailbox, delegation, send-on-behalf,
   server rules, OOF, public folders, large attachments, offline/online reconnect, MFA absent. Capture MAPI/HTTP
   traces.
4. New Outlook Windows: attempt add as IMAP and as Exchange; record errors and what works.
5. Outlook for Mac current + legacy: Exchange account add (Autodiscover, EWS), mail, calendar, meeting
   invites, reply/forward drafts, free/busy, shared folders.
6. Outlook iOS/Android: add IMAP; try manual Exchange/EAS; record Autodetect behavior and whether data
   routes via Microsoft cloud (observe with proxy logs). Native iOS Mail and Android EAS: mail/calendar/contacts/OOF.
7. Apple Mail/Calendar (EWS vs IMAP+CalDAV), Thunderbird, DAVx5.
8. Auth: LDAP bind, Keycloak SSO for web/admin, app passwords for Outlook/EAS/DAV, lockout behavior.
9. Mail flow: Postfix + antispam, DKIM/SPF/DMARC, TLS, rate limits; backup/restore of a mailbox; upgrade
   2026.06.x to next bundle; failure/recovery.
10. Load: 50 mailboxes MAPI + EAS soak, record RAM/CPU against the 4c/6 GB minimum.
Exit criteria: classic Outlook and native mobile pass every item in 3 and 6 without errors; documented list
of EWS/EAS gaps; legal answer in writing.
