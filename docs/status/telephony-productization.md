# Telephony productization (agent AH) - 2026-11-15

Status: **Tested (lab, executed)**. Every number below is real output of this session; logs are in `docs/status/telephony-productization-evidence/` (suite runs, ICS lab run) and `docs/status/package-pipeline-evidence/asterisk/` (SBOM, licence report, vulnerability summary, lintian, checksums). Builds on `telephony-lab-results.md` (lab spike, Asterisk 20.6 from Ubuntu universe) and the ADR-0008 pipeline of agent K (`package-pipeline-results.md`). Lab only; proves nothing about production. **The emergency-calling warning of the spike stands unchanged**: this PBX has no outside line, 112/911/999/110/933 are trapped and answered "not in service"; no trunk, no legal conclusion.

## 1. Result in one table

| Task | Result |
|---|---|
| Asterisk 22 LTS from pinned source, signature verified | 22.12.0 release tarball (sha256 pinned, equals upstream's published `.sha256`), **OpenPGP signature verified** (GOODSIG + VALIDSIG on the primary key `F2FC93DB7587BD1FB49E045A5D984BE337191CE7`, "Asterisk Development Team"). The public key comes from Debian's `asterisk` source package (`debian/upstream/signing-key.asc`, deb.debian.org); its fingerprint is pinned in the recipe, so a swapped key file fails the build |
| Minimal module set | 88 modules built (pjsip family, `res_srtp`, `res_http_websocket`, `res_rtp_asterisk`, `app_voicemail` file storage, `cdr_csv`, ulaw/alaw/gsm, builtin dialplan); `chan_sip`, IAX2, MGCP, Skinny, unistim, DAHDI, ARI, AMI users, FAX, ODBC, LDAP resources, MOH sound files are **not built** (list: `/usr/share/doc/ou-asterisk/modules-built.txt`, source: `blueprints/build/asterisk/debian/menuselect-enable.txt`). `BUILD_NATIVE` off (portable binary) |
| Debian 12 `.deb` via the pipeline | `ou-asterisk_22.12.0-ou1_amd64.deb` (3.0 MB, 12.4 MB installed) + `.dsc` + `orig.tar.xz` + `debian.tar.gz` (the GPL source offer), built in `ou-pkg2` (fresh clone of `ou-base-bookworm`, MemoryMax 3G, JOBS=3, ~5.5 min), compile step **in an empty network namespace**; network only in the prefetch step (pjproject tarball, sha256-pinned) |
| SBOM / licence / vulnerabilities | SPDX 2.3 (17 packages incl. bundled pjproject 2.17 as `STATIC_LINK`), syft cross-check, licence check PASS (5565 files + the unpacked pjproject tree; no id outside the policy), osv-scanner 2.7.1: 9 advisories, all Debian `libxml2 2.9.14+dfsg-1.3~deb12u6` (same libxml2 as the groupware packages; Debian status not triaged). **Not covered**: OSV has no package record for Asterisk or pjproject as generic sources, so upstream Asterisk/pjproject advisories are NOT checked by this scan |
| Signed repo dev channel | published with the pipeline's signer (`ou-release-sign`, see 2.3); `apt` on the PBX verified the signed `InRelease`; the installed `.deb` hash equals the artifact hash (`0fc668ea...d052`) |
| New machine `ou-pbx2` (Debian 12, MemoryMax 768M), installed from the repo only | done; Asterisk 22.12.0 running as the unprivileged user `asterisk` under `ou-asterisk.service` (hardened unit) |
| P01-P05 re-run against it | **P01 13/0, P02 11/0, P03 10/0, P05 14/0, P04 17/0** (final run); a first run found two real defects in the package (2.4) |
| ICS integration | typed actions, agent runbooks, one-time SIP credential, VERIFY probe; **ICS pytest 438 passed / 0 failed** (14 new telephony tests); lab run through a dev ICS on 127.0.0.1:8121 against `ics_test_aa`: **21 PASS / 0 FAIL** |
| Measured disable -> access gone | **REGISTER with the previously valid credential refused 0.58 s** after the LDAP lock the ICS applied (HTTP-401), **live call dropped on the PBX 0.78 s**, ICS-side VERIFY (`pbx_access`) 1.3 s (two runs: 0.79 s / 0.73 s and 0.58 s / 0.78 s) |

## 2. Build and release

### 2.1 Pipeline extension (blueprints/build)
`build.sh` gained source kind `tarball`: download, sha256 pin, `gpg --verify` of the detached signature against the key file shipped in the tree, and the signing **primary key fingerprint must equal the pinned one** (`VALIDSIG`); `SOURCE_DATE_EPOCH` = signature time; the extracted tree is the licence-scan input; `orig.tar.xz` is a deterministic recompression of the upstream tarball (identical sha256 `6d8ca389...` in all five builds). `bundled_sources` in the recipe (pjproject 2.17) are downloaded, sha256-verified, unpacked into the scan tree and listed in the SBOM; the licence report now lists every licence/copying file in the tree (`licence_files`). `OU_BUILDER` overrides the builder machine name. The pipeline files themselves were imported unchanged from branch `release-ag` (agent K; not on main yet).

pjproject: Asterisk fetches its bundled pjproject from `raw.githubusercontent.com/asterisk/third-party` and checks only an MD5 shipped in the tree. The recipe additionally pins the sha256 (`04b2eb1f...`), which was taken from the first download: **trust on first use**, no upstream signature exists for it. Third-party licence texts inside pjproject: libsrtp, speex, webrtc, yuv (BSD-style), resample (LGPL), absl (Apache); `gsm/COPYRIGHT`, ooura and spl_sqrt_floor texts are permissive but were only recognised by hand (the report lists them as "unrecognized text: manual review"). GPL-2.0 for Asterisk itself (LICENSE adds the OpenSSL linking exception); the package is unmodified upstream source.

### 2.2 Package
`ou-asterisk` conflicts with/replaces the Debian/Ubuntu names; conffiles under `/etc/asterisk` are generic (no transports, `http` off, `manager` off); **site configuration goes to `/etc/asterisk/ou/`** (`#tryinclude` from the package conffiles), so package upgrades never prompt. Service user/group `asterisk` created from a sysusers snippet, control socket group-accessible (`0660 asterisk:asterisk`) for the provisioner user `ou-pbx`. The unit is not enabled by the package.

### 2.3 Release key and signer
While this was running, agent "a654..." moved the lab release key behind a dedicated signer (`ou-release-sign` as user `ou-release`, security review 4); the old `repo.sh` signing path no longer works. The Asterisk publish therefore used that branch's `repo.sh` unmodified (run from a scratch copy that contains the Asterisk recipe, because the signer-side artifact check reads the recipe). Key fingerprint is unchanged. Not touched by this work.

### 2.4 Defects found by running it (both fixed, evidence in the repo)
1. **`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` in the unit broke WebRTC media**: Asterisk's ICE code enumerates local addresses through netlink (`ICE Error obtaining list of local addresses: Address family not supported by protocol`); signalling worked, the call connected, but **0 RTP packets** flowed and voicemail recordings were empty. With `AF_NETLINK` added: P01 13/0, P03 10/0. First-run log: `pbx2-suite-run1-before-netlink-fix.log` (P01 12/1, P03 5/2).
2. Agent secret directory: the SIP credential result file lived in a root-owned directory and the agent (user `ou-agent`) could not unlink it: **the plaintext password stayed on the PBX's tmpfs**. Found by the lab run's own grep ("PBX stores only digests"), fixed (directory owned by `ou-agent`, mode 0700, stale files pruned), rerun clean. Log: `ics-lab-telephony-run-before-secret-dir-fix.log`.
Also found: the generated polkit regex had a doubled backslash and matched nothing (`Access denied` from `systemctl start`), which the unit tests had not exercised; the test now evaluates the generated regular expression.

### 2.5 Not proven / open (build)
- Binaries are **not bit-reproducible**: Asterisk embeds its build date/host (`built by root @ ou-lab on ... UTC`). Source tarball and packaging inputs are deterministic; a second-builder rebuild was not done.
- Debian build dependencies are the current bookworm versions (recorded in `build-env.txt`), not snapshot-pinned.
- `stasis.conf`: Asterisk 22.12 logs `Could not find option 'minimum_size' with type 'threadpool' in module 'stasis'` at start even with the sample file; harmless in the tests, not investigated further.
- Lintian: 0 errors; warnings only (library symlink placement, missing man pages for `astcanary/astversion/rasterisk`, `chown -R` in postinst).
- Asterisk 22 LTS is supported upstream until 2029-10 (upstream policy, not verified here); there is no upgrade/rollback test and no security-update tracking job yet (ADR-0008 step 10).

## 3. The PBX on Debian 12 (`ou-pbx2`)

`blueprints/telephony/`: `00-create-pbx2.sh` (clone of `ou-base-bookworm`, MemoryMax 768M, static address), `05-own-identity.sh` (certificate + Keycloak client + host name, see below), `10-deploy-pbx2.sh` + `20-install-from-repo.sh` (adds ONLY the signed Office Unbound repo with the fingerprint-checked key, `apt install ou-asterisk`, provisioner, softphone, nginx), `30-install-agent.sh` (node agent with the `pbx.*` runbooks), `tests/` (P01-P05, parametrised by `PBX_MACHINE`, `PBX_HOST`, `PBX_IP`, `PHONE_HOST`), `pbx/ou_pbx.py` (provisioner: new `kick`, `state`, `report` commands).

**Deviation (name and address).** The plan was to reuse ou-pbx1's address and names. Another lab agent started a clone of ou-pbx1 (`ou-al-pbx1`) with the same `192.168.186.247` while ou-pbx2 was being tested; two machines with one address gave misleading failures. ou-pbx2 therefore has **its own identity: 192.168.186.248, `pbx2.` / `phone2.ou-lab.internal`**, own server certificate (SANs for those names + IP, signed with the lab CA key read from ou-id1's filesystem, ou-id1 not modified), own Keycloak client `ou-phone2` (confidential, code + PKCE, created through the admin API), one added line in the host's `/etc/hosts`. The reference ou-pbx1 stays powered off and untouched. LDAP (extensions of bob 1002 / carol 1003) is shared with the other machine: P04 locks carol in the directory while it runs.

Differences from the spike worth knowing: Debian 12 instead of Ubuntu 24.04; Asterisk 22.12.0 instead of 20.6.0 (and no `chan_sip` to disable); site config in `/etc/asterisk/ou/*_site.conf`; service name `ou-asterisk`; `sudo` installed only because the lab test suites call `sudo -u ou-pbx`.

### P01-P05 against ou-pbx2 (final run, real output, `pbx2-suite-run2-final.log`)
| Suite | Result | Notes |
|---|---|---|
| P01 WebRTC call, two headless Chromium (WSS, DTLS-SRTP) | 13 PASS / 0 FAIL | RTP counters both directions on both legs, DTLS mandatory, CDR row |
| P02 baresip over TLS 1.2 + SDES-SRTP, echo test | 11 PASS / 0 FAIL | wrong password refused (401), password in no file |
| P03 voicemail to e-mail (SMTP to gw1, IMAPS check) | 10 PASS / 0 FAIL | |
| P05 credential endpoint (Keycloak OIDC gate) | 14 PASS / 0 FAIL | CSP names `pbx2` WSS |
| P04 deprovisioning (LDAP lock) | 17 PASS / 0 FAIL | explicit sync: lock -> first refused REGISTER 0.5 s; timer only: 1.0 s (period 15 s, so up to ~15.6 s by construction) |

Resources: cgroup MemoryMax 768M held; current 206 MiB idle after the suites; peak = the cap (page cache during `apt` install and the agent install, as in the spike; not an RSS figure). No load test, no concurrent-call capacity test.

## 4. ICS integration

Design rule: the **directory is the only input** (as in the spike); the ICS writes exactly one new attribute (`telephoneNumber`) with the existing narrow `svc-ics` identity and drives the PBX only through fixed agent runbooks. PBX credentials never exist at the ICS in a reusable form.

| Piece | What |
|---|---|
| Stack config | `pbx_node_id` (enrolled agent node) + `pbx_domain` (shown with the credential); both or none. Stacks without it behave exactly as before (test: `test_stack_without_pbx_is_unchanged`) |
| `idm.user.create` | optional `extension` (`^[1-9][0-9]{3}$`): plan-time uniqueness per stack (409), needs a PBX node (422); LDAP `telephoneNumber` set at creation, `pbx.sync_extensions`, step `pbx.sync` must report `known_to_pbx` |
| `idm.user.set_extension` (new) | change/remove; change or removal runs `pbx.kick_user` (old registrations and calls end, credentials purged because the PBX derives everything from the directory) |
| `idm.user.issue_sip_credential` (new) | device `web|native|desk`; runbook `pbx.issue_credential {user, device}`; the clear password travels only agent -> ICS, is stored **encrypted by the vault bound to the row id** for at most 15 minutes, shown **once** to the plan's requester (`POST /api/v1/identity/sip-credentials/{plan_id}/reveal`, `Cache-Control: no-store`, ciphertext wiped in the same transaction, audit `identity.sip_credential_revealed`); never in job result, audit, logs (the secret is registered with the redactor). The PBX stores only `md5_cred = MD5(user:realm:password)` (Asterisk `auth_type=md5`); re-issuing rotates that device |
| `idm.user.disable` | after the LDAP lock and Keycloak revoke: **`pbx.kick_user`** (sync from the locked directory -> endpoint + credentials purged; every registered contact deleted; every live channel hung up), then VERIFY polls `pbx.user_state` until endpoint/contacts/channels are all gone; final state check `pbx` in the verdict; failure is loud (`VERIFY FAILED ... pbx_access`) |
| `enable` / `delete` | enable: `pbx.sync_extensions` (extension returns, **old credentials do not**: a new one-time credential is needed); delete: `pbx.kick_user` |
| Agent runbooks | `pbx.sync_extensions`, `pbx.kick_user`, `pbx.user_state` (params exactly `{user}`), `pbx.issue_credential` (exactly `{user, device}`); fixed template units `ou-rb-pbx-{sync,kick,state,issue}@.service` started by polkit only for these names, root helper `ou-pbx-user` revalidates and drops to the user `ou-pbx` (`setpriv`) to run `ou-pbx report|kick|state|issue`; non-secret results in `/run/ou-rb`, the credential result in `/run/ou-rb-secret` (0700, owned by `ou-agent`, file 0600, unlinked by the agent after reading); `agent-pbx.json` allowlist |
| Migration 0008 | `idm_users.extension` (unique per stack among non-deleted users) and `idm_sip_credentials` |

**Tests (pytest with fakes)**: `ics/tests/test_telephony.py` 14 tests (parameter validation; create with extension and PBX sync; no PBX node; extension change/remove ends registrations; credential revealed once to the requester only, absent from job result and audit, ciphertext at rest, expiry; disable kicks and VERIFY passes; disable **fails loud** when the PBX keeps a registration; enable does not resurrect credentials; delete; stack without PBX unchanged; real agent with stub `systemctl`: exact argv, parameter validation, the secret file is unlinked and a foreign result is ignored; polkit regex evaluated; the PBX provisioner itself: password in no file, disabled user loses endpoint/contacts/calls, unlock does not resurrect). **Full ICS suite on the final code: 438 passed, 0 failed** (7 min 21 s, `ics_test_ah`; an earlier full run found the polkit rule test failing after the unit-name length change, fixed by widening the limit only when `pbx.issue_credential` is enabled).

**Lab run** (`ics/scripts/lab_telephony.py`, dev ICS instance of this code on 127.0.0.1:8121, database `ics_test_aa`, creds in `~/.cache/ou-ics-inst-ah`; production `ics` service and database untouched): enrol the ou-pbx2 agent (`node.enroll`, 2 approvers), register stack `lab-tel` (real LDAP/Keycloak of the lab, no mailbox/files nodes), then one user: create with extension 1030 -> two device credentials issued and revealed once (second reveal 404) -> native device registers over TLS+SRTP (baresip) and holds an echo-test call while the desk credential is probed with REGISTER -> `idm.user.disable` -> measured, enable, rotation, disable, delete. 21 PASS / 0 FAIL (`ics-lab-telephony-run-final.log`):

| Measured from the LDAP lock applied by the ICS | Run A | Run B (final) |
|---|---|---|
| first REGISTER refused for the previously valid credential (401) | 0.79 s | 0.58 s |
| live call torn down on the PBX | 0.73 s | 0.78 s |
| ICS-side VERIFY `pbx_access` refused | 1.3 s | 1.3 s |
| `pbx.kick_user` runbook | 0.71 s (1 registration removed, 1 channel hung up) | same |

Also verified in the run: the issued passwords are in no file, log or journal on the PBX; the old credential does not come back after enable; a newly issued one works; re-issuing a device credential stops the previous one; after delete the PBX knows nothing of the user.

Not proven for the ICS side: the web softphone path through the ICS (the softphone still fetches its own web credential through Keycloak as in the spike, bypassing the ICS reveal); reconcile (`idm.reconcile`) does not check the PBX yet; high-risk policy for extension changes is "normal" (one approver); issuing for users of stacks with many devices, rate limits; the ICS never shows or stores the voicemail PIN.

## 5. Security notes and open points
- Provisioner still binds as the shared `svc-bind`; production needs a dedicated read-only `svc-pbx` (only `telephoneNumber`, `pwdAccountLockedTime`, `uid`, `mail`, `displayName`). Unchanged from the spike; the ICS side uses `svc-ics` only for `telephoneNumber` writes (its ACL already allowed it).
- SIP digest is MD5 (what SIP/Asterisk offer); TLS 1.2 only on the SIP transport; no SBC, fail2ban, rate limiting or flood protection; no NAT/STUN/TURN; unchanged from the spike's open list.
- Agent: the PBX agent runs with `ou-agent` having a 0700 directory in `/run` that holds a plaintext credential for the few milliseconds between helper and agent; anyone who is root on the PBX can read it (as they can the md5 state). The credential travels agent -> ICS over the pinned-TLS agent channel.
- Telephony data in the ICS DB: only the extension and ciphertext-until-revealed; no digest, no password history.
- Voicemail PIN delivery, backup/restore of the voicemail spool and `/var/lib/ou-pbx`, monitoring checks, desk phones, mobile push, PSTN/E911 remain as listed in `telephony-lab-results.md` section 6.

## 6. How to reproduce
```
cd blueprints/build && OU_BUILDER=ou-pkg2 ./build.sh prepare && OU_BUILDER=ou-pkg2 ./build.sh asterisk     # fetch+verify, licence, build, SBOM, vuln scan
<signer-enabled repo.sh> publish asterisk && <signer-enabled repo.sh> serve                              # dev channel, see 2.3
cd ../telephony && ./00-create-pbx2.sh && ./05-own-identity.sh && REPO_URL=http://<ou-repo1>:8077 ./10-deploy-pbx2.sh && ./30-install-agent.sh
cd tests && PBX_MACHINE=ou-pbx2 PBX_HOST=pbx2.ou-lab.internal PBX_IP=192.168.186.248 PHONE_HOST=phone2.ou-lab.internal PY=<venv with playwright,ldap3,requests> bash run_all.sh
cd ics && OU_INST_DIR=~/.cache/ou-ics-inst-ah OU_INST_SUFFIX=aa OU_INST_PORT=8121 ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-aa.env .venv/bin/python scripts/lab_ics_instance.py init|serve
OU_ICS_BASE=http://127.0.0.1:8121/api/v1 OU_DEMO_CREDS=~/.cache/ou-ics-inst-ah/creds.json PBX_MACHINE=ou-pbx2 .venv/bin/python scripts/lab_telephony.py setup && ... run
```
