# Gromox patches carried by Office Unbound (for the build pipeline)

Ordered queue, applied by the pipeline (`gromox/recipe.yaml`, package version 3.13-ou2) or by hand with `patch -p1` from the Gromox source root (3.13), in this order.
Patches are intended to be upstreamable as they are.

## 0001-authmgr-bearer-claims.patch

Validates `alg` (RS256 only), `exp`/`nbf`, non-empty `email` and, with the new `gromox.cfg` directives `bearer_issuer` and `bearer_audience`, `iss` and `aud` of OIDC
bearer tokens (agent AA; unit test `tests/bearer.cpp`, behaviour test `blueprints/lab/upgrade/gw_behaviour_tests.py`). Adds `include/gromox/bearer.hpp`, `tests/bearer.cpp`
and Makefile.am entries (so unlike 0002 it touches the build system).


## 0002-imap-event-user-kick.patch

**Problem.** Gromox has no way to end the open IMAP sessions of ONE user. The only timers are global (`imap_autologout_time`) and restarting
`gromox-imap` hits every user. Suspending a user (`address_status`) only stops *new* logins; a session that is already authenticated keeps reading the
mailbox (measured in `docs/status/user-lifecycle-results.md` section 5).

**Change** (3 files, about 90 lines):
* `tools/event.cpp` (`gromox-event`): a new verb `USER-KICK <user> <any>` is delivered to *every* listener except the sender. All other verbs keep their
  routing (to the hosts that have `user:folder` selected); a session that selected nothing would otherwise be unreachable.
* `mra/imap/parser.cpp`, `imap.hpp` (`gromox-imap`): on `USER-KICK` the process records `kicked[lowercase user] = now` (mutex protected, entries older
  than 24 h are pruned). Every context remembers when it became authenticated (`auth_time`, set when the first processing pass after the login ends). A
  session whose user was kicked after it authenticated gets `* BYE [UNAVAILABLE] Session terminated by administrator` and is closed through the
  normal end-of-processing path. Idle/IDLE connections are found by the existing sleeping-list scanner (~100 ms), connections that send a command are
  checked at the start of `imap_parser_process`. A session authenticated *after* the kick is not affected (re-enable works, no ban list).
* **Which sessions are kicked (security review 4, M2).** The match is on the session's AUTHENTICATED identity (`ctx.authenticated_actor`; the
  login name before `!` on a delegated `actor!target` login), not on the mailbox it is attached to (`ctx.username`). Kicking bob therefore ends
  `bob`, `bob!carol` and `bob!shared`, and does NOT end `carol!bob` (carol's delegate session on bob's mailbox). The kick table is bounded
  (10 000 entries, oldest evicted; pruned only when it has grown) so it cannot be inflated through the event socket (L3).
  Test: `blueprints/lab/tests/gromox_user_kick_delegate_test.py` (build machine only): the pre-fix code closes A=bob and D=carol!bob but leaves
  B=bob!carol alive (FAIL), the fixed code closes A and B and leaves C and D alone (PASS).
* Sender: any process that can connect to the event socket (`unix:/run/gromox/event.sock`, same trust as every event producer) sends
  `ID <name>` then `USER-KICK <user> *`. The ICS agent helper `ou-gw-user kill <uid>` does exactly this.

**Not covered / follow-up for upstream:** `gromox-pop3` and the HTTP/EWS/MAPI/EAS processes do not listen for this event (POP3 is not deployed in the
lab; see docs/status/lifecycle-gaps-results.md for what remains). A `gromox-mbop -u <user> kick` front end would be the natural CLI. The window between
a login and the end of its first processing pass (a few ms) is not covered by `auth_time`.

**Evidence:** built on `ou-gw1` (`/usr/src/ou/gromox-ac`, only `imap` and `event` rebuilt), installed over `/usr/libexec/gromox/{imap,event}` (originals in
`/root/ac-orig/`), selected and authenticated-only sessions closed in <1 s, a bystander user's session and a fresh login of the kicked user unaffected
(`ics/scripts/lab_user_lifecycle.py gaps`).

## 0001-authmgr-bearer-claims.patch (L1, security review 4)
Signature first: the token is parsed as JSON only after the RS256 signature verified, `exp`/`nbf` must satisfy `isInt64()` (jsoncpp 1.9.5 throws
`Json::LogicError` for values above INT64_MAX), and `login_token()` catches `std::exception`. `blueprints/lab/tests/gromox_bearer_claims_test.sh` now
sends forged tokens with `exp`/`nbf` = 18446744073709551615 and 1e19 and checks that zcore stays up (`NRestarts=0`).


## 0003-outgoing-smtp-default.patch (client compatibility, agent BJ)
`outgoing_smtp_url` defaulted to `sendmail://localhost` in six places (ruleproc, exmdb, emsmdb, zcore, ews, delivery). Our mail library (wmime) is built with
the sendmail transport OFF, so a node without that line failed every EWS/MAPI send, meeting invitation and AcceptItem with `E-3117 ... No factory available`
(first seen in `docs/status/client-compat-results.md`). The default is now the explicit IPv4 URL `smtp://127.0.0.1:25` (Postfix on the node listens there;
a host NAME such as `localhost` may resolve to `::1` first), and `doc/gromox.cfg.5` says so. `gw-mta.sh` additionally writes the line into `gromox.cfg`.

## 0004-ews-sendas-sendonbehalf.patch (send-as / send-on-behalf over EWS, agent BJ)
Finding (3.13 source + lab measurements, `docs/status/gw-client-fixes-results.md`): EWS CreateItem/SendItem authorised `From:` only through
`get_mbox_perm()` bits: store owner, a folder-ACL row with bit 0x4 (`frightsGromoxSendAs`) or a `config/delegates.txt` entry (which `get_mbox_perm`
turns into the same bit). `config/sendas.txt` (what admin-api and our `gromox.shared_access` runbook write for send-as) was only read by zcore/emsmdb, so an
EWS client of a user on sendas.txt got `ErrorAccessDenied`, and a delegates.txt user could impersonate the mailbox with NO `Sender:` header.
Change (2 files): `validate_sendas_perms` also accepts membership of `sendas.txt` (user or mailing list); new `is_send_on_behalf()` marks a message whose
identity is foreign and which the caller may use only through the delegate bit, and `send()` then sets `PR_SENDER_*` to the caller, so the mail carries
`From: <mailbox>` + `Sender: <caller>` (same as the MAPI path); send-as (store owner, sendas.txt) keeps `From` only. Denied without any grant (unchanged).
Note for clients: the EWS `From` mailbox needs `RoutingType=SMTP`; without it the exporter drops the From header.
Test: `blueprints/lab/tests/gw_sendas_test.py` (five grant combinations, delivered headers).
