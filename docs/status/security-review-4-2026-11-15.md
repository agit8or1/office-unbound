# Security review 4: gromox patches, lifecycle gaps, webmail SSO / key follower, MAS, telephony, migration engine, package pipeline, Collabora (2026-11-15)

Independent review. The reviewer did not write this code. No project file other than this report was changed. Lab machines were read only (`systemd-run -M ... cat/stat/ss/grep`, a read-only `SHOW GRANTS`, and no secret values were printed). Proxmox was not contacted.

Scope:
- main: `blueprints/build/gromox/patches/0001-authmgr-bearer-claims.patch`, `blueprints/lab/spike-groupware/{lab-sso.sh,ou-sync-bearer-key.py,lab-sso-keysync.sh,kc-profile-harden.py}`, `ics/ics/identity.py` (MAS), `blueprints/lab/spike-pbx/**`, `blueprints/build/collabora/**`
- branch `worktree-agent-a834d474c4aaf0f85` (lifecycle gaps): the USER-KICK patch, `ou-wipe-api`, `ou-gw-user`, `ou-oc-revoke`, `identity.py` wipe/kill steps
- branch `worktree-agent-a6de2857a1ff7b35a`: the migration engine (not on main)
- branch `worktree-agent-aea816ba99d247f04`: the signed package pipeline, plus the live `/var/lib/office-unbound/pkgbuild` and `/etc/office-unbound/release`

Earlier reviews (`security-review-*.md`) cover none of these areas, and nothing below repeats one of their items.

Branch paths below are relative to the worktree, `.claude/worktrees/agent-<id>/`.

## Summary

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| H1 | High | pipeline | A builder-planted symlink makes the host copy any file `administrator` can read into the published, signed apt pool | CONFIRMED (mechanism reproduced) |
| H2 | High | pipeline | The release key has no passphrase, and `administrator` has `NOPASSWD: ALL` sudo while running untrusted-tree tooling, so anything running as that user can sign any channel | CONFIRMED |
| M1 | Medium | gromox | `zcore.sock` is mode 0666 and offers `logon_np` (logon with no password): any local uid on the groupware node can open any mailbox. The bearer-token hardening only adds depth on top of this | CONFIRMED (live perms + code) |
| M2 | Medium | gromox | USER-KICK matches `ctx.username`, which is the *target* mailbox. Delegated sessions (`actor!target`) of the kicked user survive, while delegates of a kicked mailbox owner are thrown out | CONFIRMED (by code) |
| M3 | Medium | pipeline / gromox | Neither gromox patch is in the pipeline recipe (`patches: []`), so pipeline-built gromox ships unpatched. ICS records `kick_sent=true` even when no listener understands the event | CONFIRMED |
| M4 | Medium | Keycloak | The user-profile hardening (users cannot edit `email`, which is the mailbox identity) was applied live by hand only. The realm export still grants `edit: [admin, user]`, and no install script runs `kc-profile-harden.py` | CONFIRMED |
| M5 | Medium | migration | A source folder name with CRLF injects IMAP commands into the read-only source connection, past the verb guard (`STORE \Deleted`, `EXPUNGE`) | CONFIRMED (loopback probe) |
| M6 | Medium | migration | The source can exceed `max_message_bytes` and memory without limit (the literal is read fully; a size mismatch only warns) | CONFIRMED (by code) |
| M7 | Medium | pipeline | The promotion gate is advisory: `index` signs whatever lies in `pool/<suite>`, `record-test` accepts any log, records are writable by `administrator`, and `.dsc`/tarballs are not gated | CONFIRMED |
| M8 | Medium | pipeline | No `Valid-Until`, one key for all suites, and the repo is served over HTTP from the builder that runs untrusted code: freeze, replay and suite substitution | CONFIRMED (missing field) / PLAUSIBLE (attack) |
| M9 | Medium | pipeline | The builder is long-lived, not a fresh clone. Prefetch runs as root with network, and `npm ci` runs without `--ignore-scripts` | CONFIRMED |
| M10 | Medium | telephony | The web SIP credential has no expiry and is not tied to the Keycloak session. Rotation does not kick live registrations | CONFIRMED (by code) |
| M11 | Medium | telephony | The web-facing `ou-phone` process holds the asterisk group (control socket, `default_perm=permit`) and write access to `/etc/asterisk/ou` | CONFIRMED (config) / PLAUSIBLE (impact) |
| L1 | Low | gromox | Pre-signature JSON crash: `exp`/`nbf` above INT64_MAX pass `isIntegral()`, `asInt64()` throws `Json::LogicError`, and `login_token` catches only `bad_alloc`, so zcore aborts | CONFIRMED (throw reproduced with the shipped jsoncpp 1.9.5) / PLAUSIBLE (abort, not run live) |
| L2 | Low | wipe shim | Unauthenticated local wipe API: any local uid can turn a full wipe into account-only (or the reverse), fake a "delivered" status for ICS, or stall the single-threaded server (negative `Content-Length`) | CONFIRMED (by code) |
| L3 | Low | gromox | USER-KICK table: unbounded entries for 24 h, and an O(n) prune under the lock that every IMAP command also takes | CONFIRMED (by code) |
| L4 | Low | key follower | Trusts the whole system CA bundle, no minimum key size, unbounded response read | CONFIRMED (by code) |
| L5 | Low | MAS | `urn:mas:admin` is full Matrix impersonation power (known). Only the first 100 sessions are listed and ended | CONFIRMED (documented) |
| L6 | Low | migration | INTERNALDATE crash loop; unvalidated date sent to the target APPEND; `BINARY[` missing from the FETCH guard; state files opened without `O_NOFOLLOW`; `fetch_body` does not match the UID | CONFIRMED / PLAUSIBLE |
| L7 | Low | telephony | Identity keyed on `preferred_username`; LDAP display name unescaped in Asterisk config; unbounded `PENDING`/`SESSIONS`; reload per page load; HA1 is password-equivalent; secrets left in `/root/stage`; unused modules autoloaded; latent trunk SDES-over-UDP and `ldap-phone.py` notes | mixed |
| L8 | Low | pipeline | The tag "signature" is not cryptographically verified (the SHA-1 commit pin is the control); reproducibility holds only within one mutable builder; `ou-admin-api.sudoers` allows postconf as root; pkgtest checks only the first key's fingerprint; the Collabora build runs as root with network | CONFIRMED |
| L9 | Low | lifecycle | Lab drift: hand-built `imap`/`event` binaries installed over the packaged ones on ou-gw1 (outside the signed pipeline); `ou_wipe` lacks the INSERT grant the code needs for new devices | CONFIRMED |

There are no Critical findings.

---

## High

### H1. The builder can make the host publish any host file (symlink in artifacts)
**Where:** `blueprints/build/build.sh:84` (branch aea816) runs `inb "tar -C /build/out/$c -c ." | tar -C "$STATE/out/$c/artifacts" -x` on the host as `administrator`. Then `blueprints/build/repo/repo.sh:62-68`: `pkgfiles` uses `ls *.deb *.dsc *.tar.*`, and `publish` copies with `cp -p "$f"`, which follows symlinks.

**Failure scenario:** the builder runs upstream code as root, for example an npm lifecycle script during the grommunio-web prefetch. That code creates `/build/out/<c>/x.deb -> /home/administrator/.ssh/id_ed25519`, or a link to any other file `administrator` can read. GNU tar restores the symlink, `publish` copies the target's content into `pool/dev`, and `serve` pushes the pool back to ou-pkg1 and the oulab zone. The file is then listed in a *signed* `Packages`.

**Fix:**
- Extract with `--no-same-owner --no-overwrite-dir`.
- Abort if `find artifacts ! -type f ! -type d` finds anything.
- Copy with `cp -P`.
- Require `dpkg-deb -I` / `dpkg-source` parsing of every file before `publish`.

### H2. The signing key is protected only by "administrator has sudo"
**Where:** `repo.sh:22` (`sg() { sudo gpg ... }`), `repo.sh:28,55-56` (`--passphrase ''`). Live state: the key file is unprotected (`(private-key`, not `protected-private-key`) at root 0600 under `/etc/office-unbound/release/gnupg`. `sudo -l` for `administrator` shows `NOPASSWD: ALL`. The revocation certificate sits in the same `openpgp-revocs.d`.

**Failure scenario:** syft, osv-scanner, licensecheck and `build.sh` run as `administrator` over untrusted upstream trees and builder output. Any code execution there, or anything else running as `administrator`, can sign a `Release` for `stable`. Every consumer trusts that key through `signed-by`. A host compromise also loses the revocation cert. The results doc lists the passphrase-less key as an open point, but `NOPASSWD: ALL` makes it worse than stated: the key gives no separation at all.

**Fix:**
- Use a dedicated signing account or host (passphrase or HSM/YubiKey).
- Limit sudoers to one wrapper that signs only `dists/<suite>/Release` after checking the promotion record (see M7).
- Move the revocation cert offline.

## Medium

### M1. zcore offers password-less mailbox logon to every local uid (context for the bearer patch)
**Where:**
- `exch/zcore/main.cpp:196` (`chmod(sockpath, FMODE_PUBLIC)`)
- `exch/zcore/zserver.cpp:652` (`zs_logon_np`: `mysql_adaptor_meta` only, no credential), RPC id `logon_np` 0x5d (`include/gromox/zcore_allcalls.hpp:102`)
- Live on ou-gw1: `srw-rw-rw- gromox:gromox /run/gromox/zcore.sock`

This is upstream design, but the SSO work relies on it. `sso-rollout-results.md` section 5 names "zcore is a node-local unix socket" as the mitigation for the still-unpatched token validation. In fact the socket is world-writable, and it answers a logon with no password at all.

**Failure scenario:** code execution as any uid on the groupware node can open every mailbox through `logon_np`. That covers `www-data`/nginx, `grosync`, `grodav`, `groweb`, `redis`, `ou-wipe`, `ou-agent` and `postfix`. The same uids can reach `auth_login_token`, so the audience/issuer patch and L1 apply to them too.

**Fix:** set the socket to mode 0660 with a dedicated group (for example `gromox-zcore`) that holds only the php-fpm pool users that need MAPI (`groweb`, `grosync`, `grodav`). Better, also restrict `logon_np` to peers whose `SO_PEERCRED` uid is on an allowlist (upstream patch candidate). Document that the node's local boundary is the real trust boundary.

### M2. USER-KICK does not end delegated sessions of the kicked user
**Where:** branch a834 `blueprints/build/gromox/patches/0001-imap-event-USER-KICK-...patch`, `imap_parser_user_kicked()` (`std::string user = ctx.username;`, patch line 110). On a delegated login `user!target`, `mra/imap/cmd.cpp:1688-1691` sets `ctx.username = target mailbox` and `ctx.authenticated_actor = user`.

**Failure scenario:** ICS disables bob. `ou-gw-user kill bob` sends `USER-KICK bob@dom *`. Bob's sessions on `bob!shared@dom` or `bob!alice@dom` have `username=shared@dom`, so they are not kicked and keep reading the delegated mailbox. The quarantine step freezes and `chmod 000`s only bob's own maildir, so the target stays readable. The reverse also happens: kicking a mailbox owner throws out every delegate's session. ICS VERIFY probes only the canary's own non-delegated session, so it reports PASS.

**Fix:** match `authenticated_actor` as well as `username`, and kick when either equals the kicked user. Add a delegated-session case to `lab_user_lifecycle.py gaps`.

### M3. The gromox security patches are not built by the pipeline, and ICS cannot tell
**Where:**
- Branch aea816 `blueprints/build/gromox/recipe.yaml:31`: `patches: []        # no functional patches`.
- Main's `0001-authmgr-bearer-claims.patch` and a834's `0001-imap-event-USER-KICK...patch` share the number `0001`. a834's `README.md` lists only USER-KICK.
- `ics/ics/identity.py:970-971` (branch a834) records `kick_sent` from `ou-gw-user kill`. `event_kick()` only checks that gromox-event answered `TRUE`, and gromox-event broadcasts to every listener whether or not the listener knows the verb.

**Failure scenario:**
- The docs say both patches "become effective on the next gromox build from the pipeline". They do not: every pipeline-built `ou-gromox` is unpatched, so tokens issued to any client of the realm are accepted, and the kill step is a silent no-op.
- On ou-gw-sso1, or any node rebuilt from the pipeline, the disable job shows `gromox.kill_sessions kick_sent=true` while no session is closed. Only the later quarantine step limits the damage.

**Fix:**
- Number the patches uniquely and list both in `recipe.yaml` `patches:`.
- Render `bearer_issuer`/`bearer_audience` into `gromox.cfg` from the stack config.
- Have `ou-gw-user kill` verify the effect: read back the imap log line `USER-KICK received`, or count the user's sessions before and after with `ss` or the imap status. Report `kick_effective` rather than `kick_sent`.

### M4. Email-claim hardening is not reproducible
**Where:**
- `blueprints/lab/spike-identity-files/kc/realm-ou-lab.json` (component `declarative-user-profile`): `email` permissions `edit: ["admin","user"]`.
- `kc-profile-harden.py` is invoked by no script (grep finds only its own docstring).
- `sso-rollout-results.md` 1.1 shows the BEFORE state: `email changed: true` (HTTP 204).

**Failure scenario:** gromox maps the session to a mailbox *only* by the token's `email` claim (`ex_user = root["email"]`), with no `email_verified` check. A realm built from the blueprint, re-imported, or set up for a new customer has users able to edit their own email in the account console. A Keycloak-local user then sets the email of a mailbox that has no Keycloak account (a shared mailbox, an admin, a not-yet-federated user), and webmail opens that mailbox. `duplicateEmailsAllowed=false` protects only addresses that already exist in Keycloak. LDAP-federated users are READ_ONLY and therefore not affected.

**Fix:** put `edit: ["admin"]` for `email`/`username` into the realm export and call `kc-profile-harden.py apply` from the realm provisioning. Optionally have the gromox claims patch also require `email_verified == true`.

### M5. Migration: IMAP command injection into the source through folder names
**Where:** branch a6de `migration/ou_migration/engine/imapx.py:344-345` (`quote()` escapes only `\` and `"`), used at `imapx.py:309` (EXAMINE) and `:321` (STATUS). The names come from `engine/mailbox.py:110-112` (`parse_list`, literal branch). `_Guard` checks only the command verb, and Python 3.12 `imaplib` does not reject CR/LF in arguments.

**Failure scenario:** a fake server returned a LIST literal containing `x"\r\nZ2 UID STORE 1:* +FLAGS (\Deleted)\r\nZ3 EXPUNGE`, and the source received those as separate commands (probe in the reviewer's scratchpad). On a permissive source, another user shares a folder with a CRLF name to the migrated mailbox, and the engine then deletes the user's source mail. That breaks the engine's core guarantee that the source is read-only.

**Fix:** reject names containing bytes below 0x20, 0x7f or NUL (skip them as `skipped:unsafe-name`), or always send names as literals. Add a regression test.

### M6. Migration: no real size or memory cap on source literals
**Where:** `engine/migrate.py:212-214` (a size mismatch against `RFC822.SIZE` only warns, and the body is appended anyway), `engine/mailbox.py:182-190`. `imaplib` reads `{N}` literals fully into memory, and the header batches of 100 are unbounded too.

**Failure scenario:** a message advertises 1 KB and sends a multi-GB literal. The result is an OOM kill, or an oversized message on Gromox.

**Fix:** check `{N}` against `max_message_bytes` before reading (override `_get_response`/`read`, or use a partial `BODY.PEEK[]<0.max+1>` fetch), and refuse when `len(body) > max`.

### M7. The promotion gate is advisory only
**Where:** `repo.sh:72-86` (`record-test X install-smoke pass /dev/null` is accepted; `records/` is 0775 and owned by `administrator`; `--approved-by` is free text), `repo.sh:40-60` (`index <suite>` signs whatever is in `pool/<suite>`), `repo.sh:95` (only `*.deb` is gated), `repo.sh:102` (`cp -p "$src"/*` also copies `.dsc`/tarballs unchecked).

**Failure scenario:** `cp foo.deb pool/stable/x/ && repo.sh index stable` ships an untested package under a valid signature. Between the hash check at line 96 and the copy at line 102 the pool can also change (TOCTOU), because the copy does not re-hash.

**Fix:**
- Make signing (the H2 wrapper) verify every `pool/<suite>` file against a promotion record that is itself signed, or at least stored outside `administrator`'s write reach.
- Copy the exact hashed files.
- Have pkgtest write its own test record.

### M8. Release metadata allows freeze, replay and suite substitution
**Where:** `repo.sh:47-52` sets no `APT::FTPArchive::Release::ValidUntil`. Live `dists/stable/Release` has only `Date`. One key signs `dev`, `staging` and `stable`. `serve` (`repo.sh:107-114`) serves plain HTTP from ou-pkg1, the machine that runs the build code.

**Failure scenario:** a compromised builder or mirror serves an old signed stable indefinitely, which withholds fixes. On a first install it can also serve dev's InRelease at the stable path, and apt only warns "Conflicting distribution".

**Fix:**
- Set `Valid-Until` to about 7 days and re-sign on a schedule.
- Serve from a host that is not the builder.
- Consider one key per channel, or `Signed-By` plus a `Suite` check in consumers.

### M9. The builder is not clean, and the network is only partly off
**Where:** `build.sh:19-26` clones ou-pkg1 only if it is missing, although the results doc says "fresh clone". `builder-inner.sh:144` adds a persistent `[trusted=yes]` local repo. `builder-inner.sh:176-178`: PREFETCH runs as root with full zone network, and `npm ci` has no `--ignore-scripts`, unlike composer's `--no-scripts`. `unshare -n` (line 180) does isolate `dpkg-buildpackage` itself.

**Failure scenario:** a malicious npm dependency runs at prefetch time with network as builder root. It persists into every later component build and the local repo, and it is the entry point for H1.

**Fix:**
- Use an ephemeral clone or overlay per component.
- Run `npm ci --ignore-scripts` and run the needed scripts explicitly.
- Route prefetch through an egress proxy limited to the registries.

### M10. Web SIP credentials outlive the Keycloak session
**Where:** `blueprints/lab/spike-pbx/phone/phone_app.py:137-150`, `pbx/ou_pbx.py:376-386, 410-427`.

**Failure scenario:** the `web` password never expires. It is removed only by a re-issue, `revoke`, an LDAP lock or removal, or losing `telephoneNumber`. A Keycloak logout, "sign out all sessions", or the new Keycloak-side session kill (branch a834) leaves it working. A credential taken from page memory (an extension, devtools, a shared machine) keeps REGISTERing and calling. On rotation, `sync()` calls `kick()` only for removed endpoints, so the old contact stays up to 600 s.

**Fix:**
- Give the credential an expiry equal to the session TTL and drop it in `sync()`.
- Call `kick(ep)` on rotation.
- Add a PBX `revoke` step to the ICS disable/session-kill flow.

### M11. The web-facing PBX app holds full Asterisk control
**Where:** `spike-pbx/20-install-pbx.sh:40, 128-139`, `ou_pbx.py:359`. The `ou-phone` uvicorn process runs as `ou-pbx` with `SupplementaryGroups=asterisk`. The control socket is 0660 group asterisk, `cli_permissions.conf` has `default_perm=permit`, and `ReadWritePaths` includes `/etc/asterisk/ou`.

**Failure scenario:** any code execution in the app or a dependency can:
- add an unauthenticated endpoint and reload;
- run `channel originate ... application System` (command execution as asterisk);
- read `pbx.key` and every HA1.

Today the dialplan has no outbound route, so toll fraud would need such a change first.

**Fix:** keep the web app unprivileged. Move issue/revoke into a small socket-activated helper that alone holds the asterisk group and config write access, and accepts only `issue <session-uid> web`.

## Low

### L1. A forged token crashes zcore before the signature check
**Where:** patch `include/gromox/bearer.hpp` (`claims["exp"].isIntegral() || now >= claims["exp"].asInt64()`, and the same for `nbf`), called in `verify_token` *before* `verify_sig`. `login_token` (`exch/authmgr.cpp:263-279`) and the zcore RPC thread (`exch/zcore/rpc_parser.cpp:135-143, 271`) catch only `std::bad_alloc`.

**Evidence:** the patched header compiled against ou-aa-gx1's jsoncpp 1.9.5:
```
{"exp":18446744073709551615,...} -> THROW LargestUInt out of Int64 range
{"exp":1e19,...}                 -> THROW double out of Int64 range
{"exp":9999999999,"nbf":18446744073709551615,...} -> THROW
```
An uncaught `Json::LogicError` in a worker thread calls `std::terminate`, so zcore aborts. All webmail MAPI sessions live in zcore memory and are lost. This was not executed against a running zcore.

Upstream already had the same class of bug (`asInt64()` on a string `exp`, `asString()` on a non-string `email`). The patch narrows it but does not remove it. The attacker needs access to the zcore socket (see M1), which any local uid has.

**Fix:** use `isInt64()` instead of `isIntegral()` for `exp`/`nbf`. Wrap `verify_token` in `catch (const std::exception &)` and return false. Add these cases to `tests/bearer.cpp`. Optionally verify the signature *before* parsing the claims.

Also noted: there is no clock-skew leeway (a stricter choice, fine), and `kid`/`typ` are ignored. That is fine with a single pinned key, and Keycloak's HMAC-signed refresh and action tokens are refused by the `alg` check.

### L2. The wipe API is unauthenticated for every local uid
**Where:** branch a834 `ics/agent/deploy/runbooks/ou-wipe-api:25, 93, 99, 136`. It listens on `[::1]:8080` (plain `HTTPServer`, single-threaded, no timeout), and the unit has `IPAddressAllow=localhost`.

**Failure scenarios:**
- (a) **Wipe-type swap.** grommunio-sync treats status 2-8 as a full wipe and status 16 or higher as account-only (`provisioningmanager.php:190-200`). Any local process, or an SSRF in a local web app, can POST 32/64 on a device with status 2, which turns a full-device wipe into an account-only wipe. The reverse also works: POST 8 on an account-only (16) device turns it into a factory reset. ICS writes only status 2 today.
- (b) **False ICS report.** A forged 4/8 makes `_wipe_devices` (`identity.py:877-899`, `WIPE_DELIVERED = 4`) report the device as `delivered` although it never fetched the instruction. sync keeps the wipe pending, so the device is still wiped later.
- (c) **Stall.** `Content-Length: -1` gives `rfile.read(-1)`, which waits for EOF, and a slow client has the same effect. The one-thread server then blocks, sync's `file_get_contents` fails, the status falls back to NA, and normal provisioning continues while the account is still active.
- (d) `GET` lists every user's devices and wipe history to any local uid.

What is good: the DB account is narrow (live `SHOW GRANTS`: SELECT/UPDATE `user_devices`, SELECT/INSERT `user_device_history`, column SELECT on `users`). A wipe request cannot be created over HTTP, and the ACK path cannot clear a wipe (sync re-reads status 2 or higher as pending).

**Fix:**
- Move the shim to a unix socket readable only by the `grosync` group, or check `SO_PEERCRED`/a shared header secret in sync's `config.php`.
- Accept an ACK only as the next state of the requested type (2→4→8, 16→32→64).
- Clamp `Content-Length` to 0..4096 and set `timeout`.
- Use `ThreadingHTTPServer`.

### L3. The USER-KICK table is unbounded and pruned in O(n) under a hot lock
**Where:** patch `parser.cpp` `imap_parser_event_proc` (patch lines 130-135). Each kick for a new name adds an entry for 24 h. Each kick scans the whole map under `g_kick_lock`, and `imap_parser_user_kicked` takes that lock on every IMAP command and every scanner pass.

**Who can trigger it:** event producers only. `event.sock` is 0770 `gromox:gromox` (live), so this is the same trust as all other event producers. It is a robustness item, not an authorization item.

**Fix:** cap the map (for example 10k entries), prune on a timer, and ignore names that `mysql_adaptor` does not know.

The broadcast change in `tools/event.cpp` keeps the existing bounds checks: `temp_string[256]` with the name ≤127 and the folder ≤63. No memory-safety problem was found in the patch.

### L4. Key follower: TLS trust and input checks
**Where:** `blueprints/lab/spike-groupware/ou-sync-bearer-key.py:99` (`cafile=/etc/ssl/certs/ca-certificates.crt`, the full public bundle plus the lab CA), `choose()` at line 59 (no minimum RSA size), `fetch()` (unbounded `json.load`).

**Failure scenario:** in production with a public hostname, any publicly trusted CA mis-issuance, or DNS control together with a public certificate, lets an attacker push their own key into `/etc/gromox/bearer_pubkey` within 30 s. That means webmail login as anyone. A realm admin adding a 1024-bit key would also be followed.

**Fix:** pin `--ca` to the deployment CA or pin the realm certificate, require `n` of at least 2048 bits and `e` = 65537, and cap the response size.

The write path itself is sound: `mkstemp` in root-owned `/etc/gromox` (`drwxr-x--- root:gromoxcf`), chmod/chown before `os.replace` (atomic), and zcore reads the file per verification, so it never sees a partial key. There is no TOCTOU. The "active key" is matched by SPKI equality, not by position.

Cosmetic: the installed script shows as `nobody:nogroup` inside the container. The host installs it as host uid 0, which is unmapped in the userns. It is not writable by anything in the container, but a container-root rename can still replace it. Install it from inside the machine (`systemd-run -M ... install -o root`).

### L5. MAS admin credential scope
`ics/ics/identity.py:473-555`. `urn:mas:admin` cannot be narrowed. A leak of the ICS-held secret gives full control of Matrix accounts: lock/unlock, deactivate, set passwords and issue sessions. The admin API allowlist is the lab /24, not the ICS only. Both points are documented in `sso-rollout-results.md` 4.1 and 5 and are restated here as accepted risk.

Small item: `active_sessions` reads only `page[first]=100`. A user with more than 100 sessions makes `end_sessions` incomplete, but VERIFY then fails loudly (it does not stay silent).

Sound:
- the secret is held in the vault and redacted;
- TLS is pinned to `identity_ca_pem` (TLS 1.2 or later), with `follow_redirects=False` and `trust_env=False`;
- MAS has passwords, registration and email change disabled, and its localpart comes from the immutable `preferred_username`, so a lookup by uid cannot hit a different account.

### L6. Migration engine, minor items (branch a6de)
- `engine/mailbox.py:35-42`: a bad month name raises `KeyError` and an impossible date raises `ValueError`. Neither is caught (`cli.py:135`), and the job crashes again on every resume.
- `mailbox.py:56/217`: the source date string is copied into the target APPEND. A trailing `\` breaks the quoting. CRLF cannot get in, so the effect is limited to malformed or failed APPENDs.
- `imapx.py:33`: `BINARY[` (RFC 3516, sets \Seen) is missing from the FETCH guard. The engine never sends it.
- `state.py:35-38`, `cli.py:77-79`: files are opened without `O_NOFOLLOW`/`O_EXCL`, and `chmod` follows symlinks. The files contain no credentials.
- `mailbox.py:187-189`: the first literal is taken without matching its UID.

### L7. Telephony, minor items (`blueprints/lab/spike-pbx`)
- `phone_app.py:98`: the extension is keyed on `preferred_username`, not `entryUUID`.
- `ou_pbx.py:322, 337`: the LDAP display name goes unescaped into `voicemail.conf`. `,` `;` `|` shift fields or comment out the rest of the line. Users cannot write displayName.
- `phone_app.py:73-79`: unbounded `PENDING`/`SESSIONS`, so an unauthenticated `/login` flood leads to an OOM restart.
- `phone_app.py:145`, `ou_pbx.py:399`: every page load rotates the credential and runs `module reload res_pjsip.so`, with no rate limit.
- `ou_pbx.py:12-14`: HA1 (`md5_cred`) is password-equivalent for digest auth. The docstring reads as if storing it were safe.
- `/root/stage/secrets/*` is left behind after the install.
- `autoload=yes` loads unused modules (`pbx_lua`/`pbx_ael` with sample contexts, `res_xmpp`, `chan_motif`, ...).
- Latent: `pjsip_trunk.conf.DISABLED` uses SDES without a TLS transport. `ldap-phone.py:12,15` puts the uid unescaped into the DN and checks with an `assert`.

### L8. Pipeline and Collabora, minor items
- `build.sh:48-51`: the PGP tag check accepts a key-id match without cryptographic verification. Integrity rests on the commit pin (open item 4).
- Reproducibility was shown only for repeat builds in one mutable builder. Build-deps are not snapshot-pinned, and for gromox only the ELF files were bit-identical, not the `.deb`. The doc admits this.
- `ou-admin-api.sudoers`: `grommunio ALL=NOPASSWD: /usr/sbin/postconf, /usr/sbin/postsuper` lets the service user rewrite `main.cf` as root (inherited from upstream).
- `pkgtest-guest.sh:16` checks the first `fpr` in the `.asc` but dearmors the whole file.
- Collabora `recipe.sh` builds as root with network in ou-build1. LibreOffice's `download.lst` sha256 checks are the control. It is not yet an ADR-0008 recipe.

### L9. Lifecycle lab drift
- ou-gw1 runs `/usr/libexec/gromox/{imap,event}` built by hand (`/root/ac-orig/` holds the originals), outside the signed pipeline. dpkg verification will flag them, and an `apt upgrade` will silently remove USER-KICK (see M3).
- `ou-wipe-api:114` runs `INSERT INTO user_devices` for a policy ACK of a new device, but `ou_wipe` has no INSERT on `user_devices`. That raises an uncaught pymysql error, and the connection is dropped without a response.

---

## Verified sound

**Bearer-claims patch (logic)**
- `alg` must equal `RS256` exactly (`none`, `HS*` and case variants are refused, and the key file is RSA only).
- `exp` is required and checked strictly, `nbf` is honoured, and `email` must be a non-empty string.
- The audience check is an exact match against a string or array, with no substring match. The issuer must match exactly.
- `signed_msg` stays the verbatim base64url text.
- The webmail token reaches zcore only from the server-side code flow (`class.webappauthentication.php`); the browser never supplies it.

**USER-KICK**
- Only processes with gromox user or group can send events (`event.sock` is 0770 `gromox:gromox`, `/run/gromox` is 0775 gromox). Non-root local users outside that group cannot kick or spoof events.
- A session authenticated after the kick is not affected.
- The kick takes the normal end-of-processing path, with no new memory handling. It follows the existing sleeping-list pattern.

**`ou-gw-user` / `ou-oc-revoke`**
- uid regex enforced at both ends, fixed template units, argv-only subprocesses, a loopback-only token API.
- The temporary token is never written or reported.
- An app token created during the revocation run shows up as `remaining` and sets `ok=false`.

**Key follower**
- Atomic write with correct mode and owner, selection by SPKI equality, and the old key kept on fetch error or an inconsistent answer.

**Keycloak**
- Live profile: `email`/`username` admin-edit only; `editUsernameAllowed=false`, `registrationAllowed=false`, `duplicateEmailsAllowed=false`, `sslRequired=all`, brute-force protection on, no identity providers, LDAP federation READ_ONLY. M4 covers only reproducibility.

**MAS client**
- See L5.

**Telephony**
- No toll-fraud path: `ou-internal` reaches only own extensions, 600, `*97` and trapped emergency numbers, and the trunk/outbound templates are not included.
- No anonymous endpoint and no `identify` sections. chan_sip, iax2 and skinny are noloaded, and AMI and ARI are off.
- `trust_id_inbound=no`.
- Only TLS 5061 and WSS 8089 are exposed (HTTP/WS on loopback). Web endpoints use DTLS-SRTP, native ones SDES over TLS with no optimistic fallback. `strictrtp` and `direct_media=no` are set.
- Credential endpoint: PKCE S256, one-time state, an HttpOnly/Secure/SameSite=Strict cookie, a CSRF header token, userinfo `sub` re-checked, and the uid always taken from the session.
- LDAPS with `CERT_REQUIRED`, and static filters.

**Migration**
- EXAMINE plus `BODY.PEEK` only, and a verb guard on the source.
- Mandatory TLS verification (TLS 1.2 or later) with no STARTTLS downgrade.
- Secrets come from env or files (symlink and permission checks) and are wrapped in `Redacted`.
- Target folder names are sanitised, and only an allowlist of flags is written.
- State is bound to the source/destination tuple, with parameterised SQL and no filesystem paths derived from folder names.

**Pipeline**
- The builder never sees the key, and `unshare -n` cuts the compile step off the network.
- Consumers pin `signed-by` with a fingerprint check.
- pkgtest rejects all 8 tamper cases.
- InRelease and Release.gpg are both present, signed with Ed25519.
- pip uses `--require-hashes`, and the NodeSource key is fingerprint-pinned.

**Collabora**
- 0001 is branding only, and the distro configs keep `--enable-hardening-flags`. 0002 changes only `brandProductURL` and `allow_update_popup=false`.
- ssl, the admin console, WOPI host allowlists and alias groups are untouched.
- No outbound calls: `INFOBAR_URL` is empty, so `processFetchUpdate` returns early (`COOLWSD.cpp:4447`).
- The relaxed settings in `tests/run_coolwsd.sh` are labelled test-only.
