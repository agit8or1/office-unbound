# Telephony spike (Phase 6): Asterisk PBX + WebRTC softphone

Lab only. Results: `docs/status/telephony-lab-results.md`. Licenses: `docs/status/third-party-inventory.md` section 5b.
Evaluation it answers: `docs/status/collaboration-eval.md` section 3.

**EMERGENCY CALLING: this PBX has no outside line. 112/911/999/110 are trapped and answered with "not in service" (logged as WARNING); nothing is dialled out. The SIP trunk template (`pbx/templates/*.DISABLED`) is not included anywhere and carries the legal-review warning. No legal conclusion is drawn here.**

| Part | What |
|---|---|
| `ou-pbx1` 192.168.186.247, MemoryMax 768M | Ubuntu 24.04 clone of `ou-base-noble` (asterisk is not in Debian 12/13, only sid; the Ubuntu universe package 20.6.0 is the packaged option), Asterisk 20.6.0 (pinned + held), nginx-light, `ou-pbx` provisioner, `ou-phone` softphone service, baresip (test client). Names `pbx.` / `phone.ou-lab.internal` |
| `pbx/ou_pbx.py` | LDAP (`telephoneNumber` = extension, `pwdAccountLockedTime` = disabled) -> PJSIP endpoints/auth/aors, dialplan, voicemail; one-time credentials; fail-static; `sync`, `issue`, `revoke`, `list` (ICS can call these as typed actions) |
| `phone/` | FastAPI app (Keycloak client `ou-phone`, code+PKCE) + static softphone (JsSIP 3.13.9 bundled, strict CSP) |
| `ldap-phone.py` | set/clear `telephoneNumber` (svc-ics); `ldap-user.sh` has no attribute support. Locking uses the documented `ldap-user.sh lock` |

## Order
1. `./00-host-create-machine.sh` (clones, static IP, cap, lab-CA trust; signs `pbx` cert with the lab CA key READ from ou-id1, nothing written to ou-id1). Host `/etc/hosts`: `192.168.186.247 pbx.ou-lab.internal phone.ou-lab.internal`.
2. `kc-phone-client.py` (Keycloak admin API; env `KC_URL KC_CA KC_ADMIN_PASSWORD_FILE SECRET_DIR`) registers client `ou-phone`.
3. `SECRET_DIR=<dir> ./10-host-deploy.sh` (pushes files + secrets into the machine, runs `20-install-pbx.sh`).
4. `ldap-phone.py set bob 1002; set carol 1003` (env `LDAP_CA`, `LDAP_ICS_PW_FILE`).
5. `tests/run_all.sh` from the ICS host (venv with playwright, ldap3, requests; `PY=<venv>/bin/python`). Paths in `tests/pbx_lib.py` default to this lab's scratchpad.

## Lessons encoded in the scripts
- The Ubuntu Asterisk build ships legacy `chan_sip`, which grabs the `/ws` WebSocket and answers REGISTER with its own `realm="asterisk"`: `noload => chan_sip.so` (otherwise "Wrong password" for every WebRTC client).
- Three voicemail modules exist (`app_voicemail`, `_imap`, `_odbc`); loading all makes the `VoiceMail` application vanish: `noload` the imap/odbc ones.
- `libre`/baresip does not use `/etc/hosts`: the native test points `outbound=` at the IP (cert has an IP SAN). Module order in baresip: `srtp.so` before `account.so`; `menu.so` for `/dial`.
- Chromium needs `--disable-features=WebRtcHideLocalIpsWithMdns` (mDNS ICE candidates are not resolvable by Asterisk).
- Voicemail greeting is ~13 s before the recording starts; a test hanging up earlier gets no message.
