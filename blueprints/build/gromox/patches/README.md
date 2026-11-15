# Gromox patches carried by Office Unbound (for the build pipeline)

Apply with `patch -p1` from the Gromox source root (3.13, tree `/usr/src/ou/gromox`). Patches are intended to be upstreamable as they are; each is
self-contained and has no build-system change.

## 0001-imap-event-USER-KICK-terminate-sessions-of-one-user.patch

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
* Sender: any process that can connect to the event socket (`unix:/run/gromox/event.sock`, same trust as every event producer) sends
  `ID <name>` then `USER-KICK <user> *`. The ICS agent helper `ou-gw-user kill <uid>` does exactly this.

**Not covered / follow-up for upstream:** `gromox-pop3` and the HTTP/EWS/MAPI/EAS processes do not listen for this event (POP3 is not deployed in the
lab; see docs/status/lifecycle-gaps-results.md for what remains). A `gromox-mbop -u <user> kick` front end would be the natural CLI. The window between
a login and the end of its first processing pass (a few ms) is not covered by `auth_time`.

**Evidence:** built on `ou-gw1` (`/usr/src/ou/gromox-ac`, only `imap` and `event` rebuilt), installed over `/usr/libexec/gromox/{imap,event}` (originals in
`/root/ac-orig/`), selected and authenticated-only sessions closed in <1 s, a bystander user's session and a fresh login of the kicked user unaffected
(`ics/scripts/lab_user_lifecycle.py gaps`).
