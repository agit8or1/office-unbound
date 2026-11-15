# Groupware lab results: Gromox source build on `ou-gw1`

Date: 2026-11-15. Status vocabulary (ADR-0000): items below are **VERIFIED-IN-LAB** only where a test in
`blueprints/lab/tests/gw_*.py` ran and printed PASS in this session; everything else is stated as unproven.

## 1. What was built and where

Machine `ou-gw1` (systemd-nspawn, cloned from `ou-base-bookworm`, Debian 12.x, `Boot=yes PrivateUsers=pick`, zone `oulab`,
`MemoryMax=6G`, no extra capabilities needed). IP 192.168.186.218 (DHCP; stayed the same across two machine restarts).
Mail domain/host: `gw1.ou-lab.internal` (`/etc/hosts` entry on the ICS; no public DNS/MX). Everything compiled **inside** the machine.

| Component | Pinned tag | Commit SHA | Build |
|---|---|---|---|
| libHX | `v4.28` | 37aba2e4c56fc1253623797a6e72259ef7ecc79b | autotools (`autoreconf -fi`, needed: Debian 12 ships 4.17) |
| wmime | `wmime-1.2.0` | 9c8e38c79158c53c31ac08f8bf329472f8bcf657 | CMake (not autotools despite `README.autotools`) |
| gromox | `gromox-3.13` | 8b620206f91b4766c48537b54575fe65e131abab | autotools, `--prefix=/usr --sysconfdir=/etc --localstatedir=/var`; includes php-mapi ext |
| mapi-header-php | `2.4` | 99cf86a3a05dd52f5fffa74db347fac0a1969986 | `make install` -> /usr/share/php-mapi |
| grommunio-sync | `2.7` | d493c82431dc8ab5282bb0aeb6bf8b8bd3b872ad | PHP + `composer install --no-dev -a` |
| grommunio-dav | `1.9` | 5220793d117b50e6638e5428909379122b48edbd | PHP + composer |
| grommunio-web | `grommunio-web-5.2` | dd9029d93cecec1ba868ed0d8d976bb3f185a328 | `npm ci` + `make` (needs Node >= 20: Debian node 18 failed, used official Node 22.23.5 tarball with sha256 check) |

Runtime from Debian 12: MariaDB 10.11.18, nginx 1.22.1, PHP 8.2.32-fpm, postfix 3.7.11, redis. Admin-api NOT installed.
Tag SHAs are the checked-out commits (`git rev-parse HEAD` after `clone --depth 1 --branch <tag>`). Tags were chosen as the
newest public release tag on 2026-11-15 (gromox 3.13 matches `configure.ac` of the reference clone).

Reproduction: `blueprints/lab/spike-groupware/build-from-source.sh` (build stages: deps libhx wmime gromox mapihdr sync dav web),
then `lab-configure.sh` (DB, TLS, users, postfix, gromox cfg), `lab-nginx.sh`, `lab-apps.sh` (sync/dav/web wiring).
The scripts are the commands actually run, with the fixes found below folded in; the *combined* scripts were not re-run
from a pristine machine end-to-end (stages were run incrementally and patched). **Update:** the clean-room re-run was done on `ou-gw-r1` (all 8 stages OK in 18.5 min, see restore-drill-results.md, groupware tier); it needed one fix, the missing package list (`GW_PKGS` in `common/packages.env`).

## 2. How it was configured (no admin-api)
- MariaDB db `email` (utf8mb4), schema created by `gromox-dbop -C`; db user `gromox`@localhost and @127.0.0.1 (postfix is chrooted).
- Domain `gw1.ou-lab.internal` and users inserted with plain SQL (`orgs`, `domains`, `users`, `user_properties`): 7 users
  alice..grace (privilege_bits=15, address_status=0) + shared mailbox `support` (address_status=4). Password hashes: `openssl passwd -6`.
  `user_properties` needs PR_DISPLAY_TYPE_EX (0x39050003)=0 and PR_DISPLAY_NAME (0x3001001F), else zcore logs "users with no
  PR_DISPLAY_TYPE_EX ... existence undefined" (admin-api would write these).
- Mailboxes: `gromox-mkprivate`, **`gromox-mkmidb`** (without it IMAP SELECT fails), `gromox-mkpublic` for the domain.
- `max_user=0` on the domain: no limit enforced by gromox: 8 accounts exist, 7 log in (6th and 7th user prove no 5-user cap in the server).
  The 5-user cap lives only in admin-api (see groupware-source-eval.md); this build has none because it never had admin-api.
- Listen binds are read from `gromox.cfg` (not per-daemon cfg): http 127.0.0.1:10080 (plain, nginx terminates TLS),
  delivery-queue LMTP/SMTP 127.0.0.1:24, IMAP 143/993 with the lab cert. nginx 443 proxies /mapi /EWS /OAB /autodiscover to
  gromox-http; /Microsoft-Server-ActiveSync -> php-fpm(grommunio-sync), /dav -> php-fpm(grommunio-dav), /web -> grommunio-web.
- postfix: virtual domain, recipient check via SQL (`users`), `virtual_transport=lmtp:[127.0.0.1]:24`, `default_transport=error:` (no outbound relay).
  No SMTP submission service (587/SASL) was configured: tests submit on :25 from the lab zone.
- Lab-only TLS: self-signed CA "OU Lab CA gw1 (lab only)" + server cert (SAN hostname, autodiscover. name, IP) in `/etc/ou-lab-tls/`
  inside the machine. All tests verify against that CA (copy at `/etc/office-unbound/lab/gw1-ca.crt`). No TLS verification is disabled anywhere.
- Test passwords: random, `/root/lab-creds.env` in the machine (0600) and `/etc/office-unbound/lab/gw1-users.env` on the ICS (root:administrator 0640).
- Shared-mailbox ACL: rows inserted directly into the support store's sqlite `permissions` table (rightsAll=1531 for alice, bob).
  This is a lab shortcut; real deployments set it via MAPI/EWS/admin tooling.
- Services not run: `gromox-istore` (needs `istore_standalone`), pop3, snapshot, cleaner timer. Not needed for the tests.

## 3. Test results (all executed from the ICS host against https://gw1.ou-lab.internal unless noted)
Run `blueprints/lab/tests/gw_run_all.sh` (final run after restart, 2026-11-15 ~16:39):

| Test | Result | Key evidence |
|---|---|---|
| GW01 SMTP :25 -> IMAPS fetch, 2 pairs; IMAP login 7 users; external recipient | 13 PASS | `PASS IMAPS fetch bob - token in bob INBOX`; `PASS user count >5 - 7 users logged in via IMAP`; `refused: ... 550 5.1.1 Recipient address rejected: lab` |
| GW02 EWS GetFolder/FindItem/CreateItem(calendar)/FindItem, isolation; Autodiscover POX; MAPI/HTTP | 12 PASS | see excerpts below |
| GW03 ActiveSync OPTIONS, FolderSync, Sync(inbox) | 7 PASS | versions `12.0,12.1,14.0,14.1,16.0,16.1`; 14 folders; token found in Sync |
| GW04 CalDAV + CardDAV PUT/GET/REPORT, wrong-password 401, isolation, EWS cross-check | 10 PASS | `EWS sees DAV-created event`, erin gets 404 for dave's event |
| GW05 shared mailbox support@ | 4 PASS | delivered; alice reads via EWS; carol `ErrorAccessDenied`; direct login refused |
| GW06 persistence across `machinectl poweroff` + `start` | 3 PASS | seed before, verify after: IMAP alice+bob token, DAV event intact |
| GW07 backup/restore (gromox-exm2mt -> delete -> wipe -> gromox-import) | 7 PASS | tokens back exactly once each (see 4) |
| GW08 grommunio-web login | 4 PASS | 303 after login, `"fullname":"Alice (lab)"` in page |

Excerpts (verbatim):
```
PASS EWS unauthenticated -> 401 - 401 WWW-Authenticate=Basic realm="msrpc realm", charset="utf-8"
PASS EWS GetFolder inbox - Success; ['Inbox', '9']
PASS EWS FindItem inbox has token - subject with OU-EWS-1c8e33c558 returned
PASS EWS CreateItem calendar - created OU-EVT-1c8e33c558
PASS Autodiscover POX - MAPI/HTTP + EWS URLs present   (Protocol Type="mapiHttp" MailStore .../mapi/emsmdb/?MailboxId=616c6963-...@gw1.ou-lab.internal ; EwsUrl .../EWS/Exchange.asmx ; also EXHTTP, EXCH, EXPR sections)
PASS MAPI/HTTP Connect headers - HTTP 200 X-RequestType=Connect X-ResponseCode=0 X-ServerApplication=Exchange/15.00.0847.4040 Content-Type=application/mapi-http X-PendingPeriod=30000
PASS MAPI/HTTP Connect Status/ErrorCode=0 - StatusCode=0 ErrorCode=0 (session cookie: set)
PASS MAPI/HTTP Disconnect - X-ResponseCode=0
PASS EAS Sync inbox contains token ... ; PASS CalDAV PUT event - HTTP 201 ; PASS CardDAV PUT vcard - HTTP 201
```
**What the MAPI/HTTP test proves and does not.** It sends a real MS-OXCMAPIHTTP `Connect` (binary body: the user's LegacyDN from
Autodiscover + flags/codepage/LCIDs) to the exact URL Autodiscover advertises, with Basic auth, and gets a well-formed
`application/mapi-http` response: `X-ResponseCode: 0`, meta tags `PROCESSING/DONE`, body StatusCode=0/ErrorCode=0, a session
cookie, then a clean `Disconnect`. So the emsmdb endpoint, auth and session handling work. It does **not** prove an actual
Outlook profile can be created, that NSPI (address book) queries work (only that `/mapi/nspi/` answers 401), that ROP
(Execute) streams such as sync/FX transfer work, cached mode, free/busy, or Outlook's NTLM/Negotiate auth (only Basic is
configured; Outlook for Microsoft 365 against a Basic-auth Exchange-like server must be tried manually).
Two test-writing mistakes surfaced (not product defects): Autodiscover needs the `.../autodiscover/outlook/responseschema/2006a`
namespace and an Outlook User-Agent to emit the `mapiHttp` section; MAPI URIs require `?MailboxId=` (else 404).

## 4. Backup/restore (GW07)
`gromox-exm2mt -u grace@... -ars IPM_SUBTREE > grace.mt` (GXMT, ~145 KB for ~10 messages) -> IMAP delete+expunge one message ->
`gromox-mbop -u ... emptyfld -a inbox` (wiped INBOX; "deleted 7 message(s)") -> `gromox-import -u ... -x -c < grace.mt` (rc=0) ->
IMAP shows each of the 4 tokens exactly once again. Findings:
- Export `-ar /` (root container) did NOT restore: import failed "create_folder ... Root Container ... already exists", and a
  default import places folder trees under **Drafts** (`-B DRAFTS`). Working recipe: export with `-s` (splice markers) of `IPM_SUBTREE`, import with `-x`.
- No dedupe on import (docs): restore into a non-empty mailbox duplicates. ACLs are not exported. This is a logical export; the
  production plan still needs filesystem/MariaDB snapshots (`gromox-snapshot` or LVM/ZFS) + `mariadb-dump`: **not exercised**.

## 5. Problems encountered (and fixes)
1. `make -j48` OOM-killed wmime inside the 6G cap (cgroup peak hit 6.0 GB). Fixed: `JOBS=6`.
2. wmime cmake demanded a sendmail path: `-DVMIME_HAVE_MESSAGING_PROTO_SENDMAIL=OFF`.
3. Kernel hostname `ou-lab` did not resolve: gromox-http/zcore exit "getaddrinfo ou-lab". Fix: set hostname + /etc/hosts.
4. Missing dirs for delivery: `/var/lib/gromox/queue/{mess,save,cache}`.
5. Listen directives (`http_listen`, `lda_listen`, `imap_listen`) must be in `gromox.cfg`; putting them in `http.cfg` was ignored (bound :80, clash with nginx).
6. `umask 077` leaked from the creds subshell and made the TLS certs unreadable to the gromox user (IMAP failed).
7. postfix is chrooted: MySQL lookups via `localhost` socket fail ("Temporary lookup failure"); use 127.0.0.1 + TCP grant.
8. `gromox-mkmidb` required for IMAP; `user_properties` rows required (see 2).
9. After a reboot `php8.2-fpm` failed: sockets in `/run/php-fpm` (tmpfs) and the dir was not recreated -> added tmpfiles.d entry. Found only because of the restart test (first restart FAILED php-fpm, second PASSED).
10. `grommunio-web-5.2` build: Debian nodejs 18 fails (EBADENGINE / ESM); Node 22 tarball works.
11. A first nginx request right after reload to /web/ returned 404 once (race); not reproducible.
12. Note: `gromox/AGENTS.md` exists in the tag checkout; treated as data, ignored.

## 6. Resource usage
- Build time (48-core host, JOBS=6, in 6G-capped container): deps apt ~1 min; libHX ~1 min; wmime 2.5 min; gromox 5.3 min (27 CPU-min);
  sync+dav seconds; grommunio-web ~1 min (npm ci 4 s, make + precompress). Total about 11 min wall.
- Idle RAM of whole stack (container cgroup after tests): ~1.3 GB incl. page cache; big RSS: gromox-imap 123 MB, mariadb 112 MB, gromox-http 85 MB,
  delivery-queue 43 MB, php-fpm workers ~35 MB each. (gromox daemons size contexts for large fd limits; no tuning done.)
- Disk: machine image 3.5 GB (base 354 MB); `/usr/src/ou` (sources + objects) 1.2 GB (deletable), grommunio-web deploy 105 MB, MariaDB 128 MB, mailstores 26 MB for 8 mailboxes.
- Recorded cgroup MemoryPeak 6.0 GB was the OOM build (item 1), not steady state.

## 7. Still unproven / manual tests required
- Real Outlook (classic/new) profile creation via Autodiscover over MAPI/HTTP incl. address book, cached-mode sync, calendar sharing, OOF, free/busy.
- Real phone EAS clients (iOS/Android) incl. provisioning (disabled here; needs admin-api policy endpoint or patch), push/Ping over time.
- CalDAV/CardDAV with Apple/Thunderbird/DAVx5; iTIP scheduling invitations between users.
- SMTP submission with AUTH on 587/465 (not configured), inbound from a foreign MTA, DKIM/SPF/DMARC, rspamd/ClamAV, outbound relay.
- Browser behaviour of grommunio-web (only HTTP login + page content checked, no JS execution).
- Snapshot-based backup, restore of ACLs/rules, upgrade path between gromox versions, concurrency/load, multi-server.
- Production-grade user admin: this lab used raw SQL. The replacement for admin-api (our ICS driving typed actions) must create
  users/domains/properties exactly like section 2 and set ACLs.
- Clean-room end-to-end run of the three scripts on a fresh clone (stages were run incrementally).
- Licence/legal re-check of any patches (none were made: this build is unmodified upstream source).

## 8. Files
`blueprints/lab/spike-groupware/{build-from-source.sh,lab-configure.sh,lab-nginx.sh,lab-apps.sh}`,
`blueprints/lab/tests/{gw_lab.py,gw_01..gw_08*.py,gw_run_all.sh}`.
