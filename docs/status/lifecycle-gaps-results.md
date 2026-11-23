# Identity lifecycle gaps: app-token revocation, per-user IMAP session kill, ActiveSync remote wipe

Date: 2026-11-15. Lab only (`ou-files1` OpenCloud 9.1.0, `ou-gw1` Gromox 3.13 + grommunio-sync, `ou-id1` OpenLDAP/Keycloak). Closes the open items of
`user-lifecycle-results.md` section 6 (1), (2) and (3). Status words follow ADR-0000: PASS = executed in this session, output quoted.

**How it was proven.** Changes were run through the real ICS code path (plan -> approvals -> worker -> signed agent runbooks) on a *development* ICS instance
of this worktree (database `ics_test_ac`, port 8120) talking to *sidecar* agents on the two nodes (`ics/scripts/lab_agent_sidecar.sh`: same code, own keys/trust,
port 8444), so the production ICS and its agent trust were not touched. Driver: `ics/scripts/lab_user_lifecycle.py gaps` (and `lifecycle` as regression, PASS).
Test suite: `pytest` 16 new tests in `ics/tests/test_identity_gaps.py` plus the existing identity tests (status line at the end).

## 1. OpenCloud app tokens are now revoked on disable (PASS)
**Mechanism (source: opencloud v9.1.0 `services/auth-app`).** The CLI only has `create`, but the service exposes `GET/DELETE /auth-app/tokens` for the *authenticated
user's own* tokens (GET lists ids, DELETE takes the id; the list never contains a secret). The CLI itself impersonates a user with the machine-auth key
(`Authenticate{Type: machine, ClientId: username:<uid>}`), so the helper uses the same supported path:
`opencloud auth-app create --user-name <uid> --expiration 300s` -> temporary token -> `GET /auth-app/tokens` on the loopback proxy -> `DELETE` every id except the temporary one
-> list again (only the temporary one may remain) -> delete the temporary one and require HTTP 401. Runbook `opencloud.revoke_app_tokens` (params exactly `{user}`), template unit
`ou-rb-opencloud-revoke@<uid>.service` (runs as user `opencloud`), helper `ics/agent/deploy/runbooks/ou-oc-revoke` (argv only, uid regex `\Z`-anchored, loopback only, no token is ever
written down or reported; the error text never includes CLI stdout). In `idm.user.disable` the step runs **before the LDAP lock** (a locked user cannot be resolved by OpenCloud;
then the runbook reports `resolved:false`) and the VERIFY verdict fails (`not_revoked: oc_app_tokens`) when a resolvable user's tokens were not all deleted. The lock is never skipped.

**Evidence** (`gaps` run, 2026-11-15 20:43):
```
3 app tokens minted, accepted by WebDAV: [True, True, True]
step {"step": "opencloud.revoke_app_tokens", "ms": 1075, "ok": true, "listed": 5, "revoked": 4, "resolved": true, "remaining": 0}
oc app token 1/2/3   PASS   2.0 s   (seconds from plan approval; the revoke step itself finished ~1 s after approval)
AFTER ENABLE: pre-disable app tokens accepted? [False, False, False] (all must be False); a NEW token works: True
```
Direct helper run (before/after on one token): HTTP 200 -> 401 within the same second. Regression `lifecycle` run: "app token minted BEFORE the first disable, after enable -> still refused"
(the finding of the previous report, `resurrected`, is gone: `app_token_resurrected_after_enable: false`).
**Residual risk.** (a) A user who is *already locked* (e.g. disabled out-of-band) cannot be resolved, so nothing can be revoked until they are enabled again; run the disable while the user is
active, or revoke at re-enable (not implemented). (b) Tokens minted between the revoke and the lock (about 1 s window) are dead as soon as the lock lands, but would survive a later re-enable; the
lifecycle always disables through this action, and a second disable removes them. (c) Needs `AUTH_APP` enabled and the proxy reachable on loopback (PROXY_HTTP_ADDR; here 127.0.0.1:9200).

## 2. Per-user termination of open IMAP sessions (PASS for IMAP; POP3/EWS/MAPI/EAS see residual risk)
**Search result (source gromox 3.13).** No supported per-user session control exists: `gromox-mbop` has no such command, midb has only `X-UNLD`, zcore/exmdb have no session-close RPC, imap
has only the global `imap_autologout_time`. The only inter-process channel that reaches every `gromox-imap` process is the **event bus** (`gromox-event`, `unix:/run/gromox/event.sock`), but it routes events
only to hosts that have `user:folder` selected. Hence an upstream-quality patch (`blueprints/build/gromox/patches/0002-imap-event-user-kick.patch`, documented in the
README next to it, for agent K's pipeline): `gromox-event` delivers a new verb `USER-KICK <user> *` to every listener; `gromox-imap` remembers `kicked[user]=now`, remembers when each session authenticated,
and ends sessions authenticated *before* the kick with `* BYE [UNAVAILABLE] Session terminated by administrator` (idle connections found by the sleeping-list scanner within ~100 ms, others at the next
command). Sessions authenticated after the kick are unaffected (re-enable works; no ban list). Runbook `gromox.kill_sessions` (helper `ou-gw-user kill <uid>` speaks the event protocol: `OK`, `ID`, `USER-KICK`).
In `idm.user.disable` it runs after the Gromox suspension and *before* the quarantine, which stays as the fallback (mailbox content protected even if the kick is not delivered; an unpatched
gromox-event accepts the line and ignores it, so the VERIFY probe `imap_open_session` is what would catch that).

**Evidence.** Built on `ou-gw1` (copy of the 3.13 tree at `/usr/src/ou/gromox-ac`, patch applied with `patch -p1`, only `imap` and `event` rebuilt; originals saved in `/root/ac-orig/`).
Kill primitive alone, user still active (so the quarantine cannot be the cause):
```
USER-KICK for lg0a9905 (helper rc=0): {"cmd": "kill", "kick_sent": true}
sessions closed after the kick (s): {'selected session': 0.0, 'authenticated session (mailbox closed)': 0.0}; bystander lh0fa4ea session still alive: True; fresh login of lg0a9905 still works: True
```
Within the disable: step `gromox.kill_sessions` at +0.9..1.2 s after the lock, `imap session (opened before disable)` refused 2.0..4.0 s after approval (1.9 s after lock in `lifecycle`; the old
1.9 s came from the quarantine, so the number is not better, but the connection is now really closed instead of emptied).
**Residual risk.** (a) POP3 (`gromox-pop3`, not deployed in the lab) and the HTTP-based protocols are not covered by the patch: EWS, MAPI/HTTP, EAS and webmail authenticate **per HTTP request** (Gromox credential cache <= 60 s),
so they end with the suspension; what stays open are *already running* long requests (EWS `GetStreamingEvents`, EAS `Ping`/long `Sync`, MAPI notification waits) until they time out. This was read from source
(`exch/mh/emsmdb.cpp` checks the session cookie against the authenticated user per request) but **not probed** with a live EWS-streaming/MAPI client; the mailbox quarantine makes any data operation of those fail. (b) A kick
that arrives in the few milliseconds between a login and the end of its first processing pass misses that session. (c) We now run a patched `imap`/`event` binary on `ou-gw1`; it has to go through K's pipeline
before it exists in any customer build (README of the patch). (d) Event bus trust = same as for every event producer (local socket / `event_hosts_allow`).

## 3. ActiveSync remote wipe (PASS in the lab with a scripted EAS client; no real device tested)
**Mechanism (source grommunio-sync + admin-api).** grommunio-sync decides on every command (`index.php`: provisioning required when the device's policy key does not match the cached one; the cache entry
`grommunio-sync:provisioningcache[<device>|-|<user>]` is deleted by the admin) and answers `Provision` with `RemoteWipe` when `GET ADMIN_API_WIPE_ENDPOINT/<user>?devices=<id>` reports a status >= 2; the device's
progress is POSTed back (REQUESTED=4 when the instruction was sent, WIPED=8 when the device acknowledges). The state lives in the Gromox tables `user_devices` / `user_device_history` (schema n93, already
present in `email`). `grommunio-admin-api` is not installed in the lab, so `ou-wipe-api` (`ics/agent/deploy/runbooks/ou-wipe-api`, python stdlib + pymysql, user `ou-wipe`, [::1]:8080) implements exactly the
contract sync already points at: `GET wipe/<user>`, `GET syncPolicy/<user>` (empty policy), `POST wipe/<user>` **only** for device acknowledgements (4/8/32/64 for a device whose wipe was requested) and the
"policy deployed" status 1; a wipe *request* can not be created over HTTP, only the root helper writes it. Config needs `PROVISIONING=true` (+ `LOOSE_PROVISIONING=true` so clients that send no policy key, e.g. the load tools, keep working; they would also never get a wipe).
Runbooks (all `{user}` only): `gromox.wipe_devices` (every device grommunio-sync knows from redis `userdevices`: `user_devices.status=2` + history row `ou-ics` + `HDEL provisioningcache`),
`gromox.devices` (read only: device, last sync, status, last 6 history rows). ICS: `idm.user.disable` gets `wipe_devices` (plan risk **high**, 2 approvers; destructive) and `wipe_wait_seconds` (0..300); the wipe is
requested **first** (before the canary credential replaces the password and before any lock: the first run of this task failed exactly because the device then presented a stale password and the failed attempts locked the
account); with a wait the job polls `gromox.devices` every 5 s until all devices reached >= `wipe_delivered`, then records `delivered / undelivered_devices` in the verdict and continues regardless (an offline phone
never blocks a leaver's lock). New read-only action `idm.user.devices` (risk low) shows the devices and the acknowledgement history.

**Evidence** (scripted EAS client `ics/ics/easprobe.py`: WBXML Provision phase 1/2, FolderSync, wipe acknowledgement; AS 16.1; it keeps polling FolderSync like a device and provisions when it gets status 142):
```
EAS device oulabwipe0a9905: provisioned=True policy_key_len=9; FolderSync -> (200, 1)
disable with wipe_devices -> risk=high approvals_required=2
step gromox.wipe_devices {"requested": 1, "delivered": 1, "undelivered_devices": [], "waited_s": 5.7, devices: [{"status": "wiped_acknowledged"}]}
device simulator events: foldersync (200,1) -> foldersync (200, 142) -> provision remote_wipe=True status=1 -> ack http 200
device oulabwipe0a9905: status=wiped_acknowledged history=[wiped_acknowledged 192.168.186.1, wipe_delivered 192.168.186.1, wipe_pending ou-ics]
seconds_request_to_delivery: 2.2
```
The delivery is visible in the Provision response itself (`RemoteWipe` element = status delivered), the device list per user is `idm.user.devices` / `gromox.devices`, and the acknowledgement is recorded with time and the device's IP in `user_device_history`.

**What this does and does not prove (added 2026-11-23, M365 parity roadmap revision).** This is existing, lab-tested functionality: the ICS can
request an ActiveSync remote wipe, deliver it in the `Provision` response and record the device's acknowledgement. It is **not** complete mobile
device management and must not be described as "remote wipe" capability: no real phone has been validated; an EAS wipe acknowledgement is the
client's statement, not proof that data was erased; a device that stays offline, or a client that ignores or does not implement EAS remote wipe,
never executes it; and it covers only the ActiveSync mail account path. Revocation, selective corporate-data wipe and full-device wipe are planned
as separate actions in [mobile-remote-wipe-security.md](../requirements/mobile-remote-wipe-security.md) (WIPE-) and
[intune-and-mobile-mdm.md](../requirements/intune-and-mobile-mdm.md) (MDM-).
An earlier run with the 90 s wait and an unreachable device (wrong password) reported `delivered: 0, undelivered_devices: [...]` and the disable still succeeded and locked the account: PASS for the "report, do not hide" requirement.
**Residual risk.** (a) A real phone/Outlook was **not** tested; only the protocol response is proven. A device that is offline, uses `LOOSE` clients without a policy key, or never calls Provision never wipes. (b) Delivery
needs the device to authenticate once more before the account is suspended, so a disable with `wipe_wait_seconds: 0` normally leaves the wipe `wipe_pending` (reported as undelivered). Observed grommunio-sync behaviour:
after suspension `Provision` still answered HTTP 200 for a device with a pending wipe (sync does not authenticate a Provision while a wipe is due), but a device that is refused with 401 on its normal commands does not know to call it. (c) The
wipe acknowledgement is reported by the device and **unauthenticated** by design of the protocol (anyone who can reach Provision with the device id can acknowledge); treat `wiped_acknowledged` as "device said so". (d) `PROVISIONING=true` changes
behaviour for every provisioning-capable client of that gateway (first connection needs the two-phase provisioning with an empty policy). (e) `ou-wipe-api` is a *subset* of the admin-api; install the real admin-api
when it is part of the stack and drop the shim (same tables). (f) No EAS sessions other than the request/response commands were probed (EAS `Ping` hanging requests end with their heartbeat timeout).

## 4. Files
`ics/ics/identity.py` (steps, `wipe_devices`, `idm.user.devices`), `ics/ics/easprobe.py`, `ics/agent/ou_agent/runbooks.py` (+4 runbooks, uid regex `\Z`), `ics/agent/deploy/runbooks/{ou-oc-revoke,ou-wipe-api,ou-gw-user,*.service}`,
`ics/agent/deploy/{agent.json,agent-files.json,render_polkit.py,install-agent.sh}`, `blueprints/build/gromox/patches/{0001-*.patch,README.md}`, `ics/scripts/{lab_user_lifecycle.py (gaps), lab_agent_sidecar.sh, lab_monitoring_demo.py}`,
`ics/tests/test_identity_gaps.py`. One incidental fix: the agent's uid pattern used `$` (accepts a trailing newline); it is now `\Z`.
Rerun: `OU_DEMO_BASE=... OU_DEMO_ICS_ENV=... OU_LAB_SIDECAR=1 python ics/scripts/lab_user_lifecycle.py {setup|gaps|lifecycle}` (development ICS) or without those variables against the production ICS after it was upgraded.

## 5. Test status line
`ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-a.env pytest -q` (2026-11-15, final code): **434 passed** in 445 s (16 new in `tests/test_identity_gaps.py`).
