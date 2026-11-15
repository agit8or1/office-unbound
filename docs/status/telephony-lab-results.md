# Telephony lab results (Phase 6 spike) - 2026-11-15

Status: **Tested (lab prototype, executed)**. One nspawn machine on the ICS host; every PASS/FAIL below is real output of `blueprints/lab/spike-pbx/tests/` (final run `run_all.sh`: P01 13/0, P02 11/0, P03 10/0, P05 14/0, P04 17/0). Scripts: `blueprints/lab/spike-pbx/` (README there). Desk evaluation: `docs/status/collaboration-eval.md` section 3. Licenses: `docs/status/third-party-inventory.md` section 5b. Lab only; proves nothing about production.

**EMERGENCY CALLING WARNING.** This PBX has no outside line and therefore cannot place a 911/112/999 call. The dialplan traps 112, 911, 999, 110, 933 and answers "not in service" (`Log(WARNING, ...)`), and the web softphone shows a permanent banner. The optional SIP trunk (`pbx/templates/pjsip_trunk.conf.DISABLED`, `extensions_pstn.conf.DISABLED`) is not included by any config and its header repeats the obligations flagged in collaboration-eval 3.3 (Kari's Law / RAY BAUM'S Act, EU 112 and location rules). Legal review is required before any trunk or any "replaces your phone line" claim. No legal conclusion is drawn here.

## 1. What was built

| | |
|---|---|
| Machine | `ou-pbx1` 192.168.186.247, clone of `ou-base-noble` (Ubuntu 24.04), zone oulab, PrivateUsers=pick, **MemoryMax 768M**. **Deviation from the brief (Debian 12):** `asterisk` is not in the Debian 12 or 13 archives (checked `dists/bookworm|trixie` Packages: absent; only sid has 22.10.1), so the packaged option is Ubuntu 24.04 universe. |
| Asterisk | 20.6.0~dfsg+~cs6.13.40431414-2build5 (apt, pinned, `apt-mark hold`), PJSIP only; `chan_sip`, IAX, skinny, unistim, mgcp, dahdi, voicemail imap/odbc not loaded; AMI and ARI disabled; plain HTTP bound to 127.0.0.1 only. Ports: 5061/tcp SIP-TLS 1.2, 8089/tcp WSS (`/ws`), RTP 10000-10200/udp; no UDP/TCP SIP. Certificate from the lab CA (SAN pbx./phone.ou-lab.internal + IP 192.168.186.247), signed with the CA key read from ou-id1's filesystem (ou-id1 not modified) |
| Clients | WebRTC: JsSIP 3.13.9 (npm tarball sha512 verified, bundled with esbuild 0.25.4 into one file, `phone/bundle-src/` has the lockfile), DTLS-SRTP, WSS. Native/desk class: TLS + mandatory SDES-SRTP (tested with baresip 1.0.0) |
| Provisioning | `ou-pbx sync` reads the authoritative OpenLDAP as `svc-bind` (read-only), people with `telephoneNumber` (4-digit extension) and no `pwdAccountLockedTime`; writes `/etc/asterisk/ou/{pjsip,extensions,voicemail}_ou.conf` and reloads only on change. Runs from `ou-pbx-sync.timer` every 15 s and on demand. LDAP failure = fail-static (config untouched). `ldap-user.sh` has no attribute support, so `ldap-phone.py` (svc-ics) sets `telephoneNumber`; test extensions **bob 1002, carol 1003** (LDAP, persist) |
| Credentials | per device (`<uid>.web`, `<uid>.native`, `<uid>.desk`), 128-bit random, only `md5_cred = MD5(user:realm:password)` stored on the PBX (`auth_type=md5`), clear password returned once to the caller (CLI JSON, or the authenticated `/api/credential` response, `Cache-Control: no-store`) |
| Softphone | `https://phone.ou-lab.internal` (nginx -> FastAPI). Keycloak client **`ou-phone`** (confidential, code + PKCE S256, registered via admin API with `kc-phone-client.py`). Session re-validated against Keycloak userinfo and LDAP at each credential issue; CSRF header; strict CSP (`script-src 'self'`, `connect-src 'self' wss://pbx.ou-lab.internal:8089/ws`, no inline); cookie HttpOnly/Secure/SameSite=Strict |
| Dialplan | `ou-internal` only: extension calls (rings all of the user's devices 20 s, then voicemail), 600 echo test, `*97` voicemail main, emergency trap. No outbound pattern exists |
| Voicemail | `app_voicemail` file storage, PIN generated per mailbox (stored in `voicemail_ou.conf`, 0660 `ou-pbx:asterisk`), `mailcmd=/usr/local/sbin/ou-pbx-mail` -> gw1 SMTP :25 with STARTTLS verified against the gw1 lab CA, recipient = LDAP `mail` |
| CDR | `cdr_csv` (`/var/log/asterisk/cdr-csv/Master.csv`) |

## 2. Test results (final run, real output abridged)

### P01 WebRTC call, two headless Chromium (bob, carol): 13 PASS / 0 FAIL
```
PASS bob softphone registered over WSS (own credential from /api/credential) - status='registered' ext=1002
PASS carol softphone registered over WSS ... ext=1003
PASS login + provisioning + register for both users took - 2.3s
PASS carol's phone rings (Answer button visible) - carol callstate=ringing-in peer='Lab Bob 1002'
PASS call answered: both sides 'connected'
PASS two PJSIP channels Up and bridged on the PBX - PJSIP/carol.web-00000001!ou-internal!!1!Up!AppDial!... | PJSIP/bob.web-00000000!ou-internal!1003!2!Up!Dial!PJSIP/carol.web,20,Tt!1002...
 f5acc937 bob.web-00000000   00:00:04 ulaw  207  0 0 0.000   207  0 0 0.000      (pjsip show channelstats, sample 1)
 f5acc937 carol.web-00000001 00:00:04 ulaw  207  0 0 0.000   207  0 0 0.000
 f5acc937 bob.web-00000000   00:00:07 ulaw  361  0 0 0.000   361  0 0 0.000      (sample 2, +3 s)
 f5acc937 carol.web-00000001 00:00:07 ulaw  361  0 0 0.000   361  0 0 0.000
PASS RTP flows both directions on both legs - sample1=[(207, 207), (207, 207)] sample2=[(361, 361), (361, 361)]
PASS web endpoint media encryption is mandatory DTLS-SRTP - media_encryption : dtls
PASS CDR row written (1002 -> 1003, ANSWERED, billsec>0) - "1002","1003","ou-internal",..."PJSIP/bob.web-00000000","PJSIP/carol.web-00000001","Dial",...,8,7,"ANSWERED"
```
Chromium: `--use-fake-device-for-media-stream --use-fake-ui-for-media-stream --disable-features=WebRtcHideLocalIpsWithMdns`; ICE host candidates inside the lab zone only (no STUN/TURN).
Limit of the evidence: packet counters prove RTP flows and is accepted/decrypted by Asterisk (0 lost); the audio content itself (the fake microphone beep) was not analysed on the far end.

### P02 native client (baresip over TLS + SRTP): 11 PASS / 0 FAIL
```
PASS clear SIP password appears in no file on the PBX (only the MD5 digest is stored) - 0 files
BARESIP: carol.native@pbx.ou-lab.internal: {0/TLS/v4} 200 OK (OU-PBX) [1 binding]
BARESIP: srtp: audio: SRTP is Enabled (cryptosuite=AES_CM_128_HMAC_SHA1_80)
BARESIP: carol.native@pbx.ou-lab.internal: Call established: sip:600@pbx.ou-lab.internal;transport=tls
PJSIP/carol.native-00000002!ou-internal!600!3!Up!Echo!!1003...
 carol.native-00000 00:00:05 ulaw  248 0 0 0.000  248 0 0 0.001 / 00:00:06 ulaw 299 0 0 0.001  299 0 0 0.001
PASS CDR row written (1003 -> 600, ANSWERED)
PASS wrong password: registration refused - reg: ...: 401 Unauthorized (OU-PBX)
```
baresip ran inside `ou-pbx1` (Debian/Ubuntu package, `sip_verify_server yes` against the lab CA; pointed at the PBX IP because libre ignores /etc/hosts; a 440 Hz tone file as microphone). It is the same machine as the server, so the network path is loopback-like inside the lab zone; it is a protocol test, not a NAT/WAN test. Echo return audio was not analysed (`aufile` output file was empty; the proof is the PBX packet counters, which count RTP received from the client and the echoed transmit).

### P03 voicemail -> e-mail: 10 PASS / 0 FAIL
```
PASS carol's phone rings and she does NOT answer
PASS after the ring timeout bob's call is in VoiceMail() - 21s after dialling
PASS voice message stored on the PBX - msg0000.WAV 15400 | msg0000.gsm 15576 | msg0000.txt 303
PASS e-mail delivered to carol@ou-lab.internal (IMAPS on the lab groupware) - 1 new
   | From: "Office Unbound PBX" <voicemail@pbx.ou-lab.internal> | To: "Lab Carol" <carol@ou-lab.internal> | Subject: [Voicemail] New message from 1002
PASS audio attachment present with data - [('msg0000.WAV', 15400)]
PASS body mentions caller name from LDAP (Lab Bob) - Hello Lab Carol, you have a new voicemail from Lab Bob <1002> (0:09, ...)
```
Verified by an IMAPS login to gw1 as `carol@ou-lab.internal` (LDAP password; directory mailbox). The message is ~9 s of Chromium's fake microphone beep; intelligibility not checked. Delivery used SMTP :25 inside the lab; no external relay.

### P05 softphone credential endpoint: 14 PASS / 0 FAIL
Anonymous `/api/me` and `POST /api/credential` 401; `/` redirects to `/login` -> Keycloak code+PKCE S256 with client `ou-phone`; alice (no `telephoneNumber`) gets no extension and 403 from the credential endpoint; request without the CSRF header 403; `?user=carol` ignored (always the session's own uid); cookie HttpOnly/Secure/Strict; CSP as above with no inline script/style/handlers; the issued web password appears in no file, log or journal on the PBX (grep over /var/log, /var/lib/ou-pbx, /etc/asterisk, /var/spool, journal: 0). Not tested: the `Origin` check in `credential()` (code present, the test for it was dropped because the browser always sends the right origin).

### P04 deprovisioning (carol locked in LDAP with `ldap-user.sh lock`, i.e. `pwdAccountLockedTime`): 17 PASS / 0 FAIL
```
   | sync output: {"changed": [true, true, true], "endpoints": ["bob.native", "bob.web"], "removed": ["carol.native", "carol.web"]}
   | MEASURED A (explicit re-run, live call in progress): LDAP lock 0.1s | LDAP lock -> sync finished 0.6s | LDAP lock -> first refused REGISTER 0.6s
PASS live call of carol hung up by the PBX - no channels
PASS carol's registered contacts (web + native) deleted on the PBX
PASS bob (control user) still registers
PASS after unlock the OLD credential still does not work (purged, not resurrected)
   | MEASURED B (timer only, 15 s period): LDAP lock -> first refused REGISTER 3.6s (status 401)
```
Another run of B gave 8.1 s; by construction the worst case is the 15 s timer period plus ~0.6 s of sync. Refusal is HTTP-401 (the endpoint no longer exists, so the PBX challenges and never accepts), not 403. The PBX derives "disabled" from `pwdAccountLockedTime`, readable by `svc-bind`; a user deleted from LDAP or whose `telephoneNumber` is removed takes the same path (not separately tested). Existing registrations are deleted and live channels hung up at sync time; a device that is mid-call when the next sync runs is dropped within one period.

## 3. Resources

`ou-pbx1` cgroup MemoryMax 768M (applied: `MemoryMax=805306368`). Idle after all tests 0.21-0.29 GiB (cgroup incl. page cache); RSS: asterisk 78 MB, python (softphone service) 65 MB, nginx 6 MB. Peak 768M during `apt` install (page cache; not an RSS figure). Two simultaneous WebRTC calls and one native call ran inside the cap. No load test (concurrent calls, transcoding: all legs were G.711 ulaw).

## 4. Licenses (details in third-party-inventory.md 5b)

Asterisk GPL-2.0 (Debian copyright: GPL-2-Asterisk / GPL-2+ / LGPL / Expat mix; includes bundled pjproject); baresip BSD-3-Clause (some GPL files in debian copyright, flagged); JsSIP MIT (+ debug, ms, events, sdp-transform MIT, bundled); nginx BSD-2; FastAPI/uvicorn/httpx/ldap3 per Ubuntu packages (MIT/BSD, LGPL for ldap3: flag). No per-seat, user or call limits found in the source we run. Obligations: GPL source offer for any modified Asterisk we ship (none modified here).

## 5. Problems found and fixed (all folded into the scripts)
`chan_sip` (Ubuntu build) stole the WSS endpoint (every WebRTC REGISTER got `realm="asterisk"` -> "Wrong password"); three competing voicemail modules made the `VoiceMail` application disappear; libre/baresip ignores /etc/hosts; baresip module order for SRTP; Chromium mDNS ICE candidates; voicemail greeting takes ~13 s before recording; `Group=` of the softphone unit must be `ou-pbx` (bind password readable) with `SupplementaryGroups=asterisk`. A from-scratch rerun of the install scripts on a fresh machine was NOT done (several steps were applied live and folded back).

## 6. Not proven / open
- **PSTN / SIP trunk**: not built or tested (template only); **emergency calling / E911 / location / on-site notification**: not implemented, legal review pending; dialplan only refuses.
- **Desk phones** (Yealink etc., auto-provisioning templates, TLS/SRTP interoperability with real hardware): not tested; the baresip run is the only non-WebRTC client. Linphone and mobile clients untested.
- **Mobile push** (FCM/APNs wake-up for incoming calls on iOS/Android) and mobile softphone apps: not tested; ADR-0007 external-dependency question stays open.
- NAT/WAN: no STUN/TURN, no external users, no SBC/fail2ban/rate limiting, no SIP flood or brute-force protection; RTP port range exposure and `strictrtp` behaviour behind NAT untested.
- No transcoding/Opus (Ubuntu build has no `codec_opus` module in use; ulaw/alaw only), no video, no conferencing, no call recording, no presence/BLF, no call transfer/forward/hold tests, no paging/queues/IVR.
- Concurrency and capacity (calls, registrations at 250 users), HA, backup/restore of voicemail spool and `/var/lib/ou-pbx` (devices.json holds MD5 credentials + voicemail PINs, 0600), voicemail PIN delivery to users (generated, never shown), voicemail-to-email privacy (audio attached in plain e-mail; SMTP is opportunistic-STARTTLS verified inside the lab only).
- Provisioner uses the shared `svc-bind` read account; production needs a dedicated read-only `svc-pbx` bind with access to `telephoneNumber` and `pwdAccountLockedTime` only. MD5 digest auth is what SIP/Asterisk offer; SHA-256 digest is not enabled. TLS cipher list restricted to two ECDHE-RSA GCM suites (TLS 1.2); TLS 1.3 not offered on the SIP transport.
- Web softphone: one `web` device per user (re-login rotates the credential and kicks the previous browser); no logout back-channel from Keycloak (a disabled user is stopped by the LDAP sync, not by a Keycloak event); the softphone does not re-register after credential rotation elsewhere; no ringtone/UI polish; audio device selection absent; in-memory OIDC sessions.
- Production per ADR-0007/0008: Asterisk 22 LTS from pinned source (Debian sid source package 22.10.1 or upstream tarball), not the Ubuntu 20.6.0 package (universe: no Canonical security maintenance; 20.6.0 is a 2024 snapshot and certainly behind upstream security fixes).
- Backup, ICS node-agent integration (enrol `ou-pbx1`, typed actions `pbx.sync`, `pbx.issue_credential`), monitoring checks: not done.
