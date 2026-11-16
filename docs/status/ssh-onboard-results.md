# SSH onboarding ("Connect with SSH"): results and owner test checklist (agent BT)

Branch `ssh-onboard` (from `fixes-r5`). Design: [ADR-0014](../adr/0014-ssh-onboarding.md). Admin guide: [connecting-proxmox.md section 12](../admin/connecting-proxmox.md). Status values per ADR-0000.

**Status: implemented, tested against a REAL OpenSSH server with faithful `pvesh`/`pveum` fakes driven by the PVE simulator; NOT run against a real Proxmox node.** The owner runs the real test (checklist below); nothing here touched pve06 or any Proxmox.

## What was built
* Backend `ics/ics/sshonboard/`: `templates.py` (the closed command set, strict validators), `client.py` (paramiko 3.5.1, pinned host key, exec only), `admin.py` (SSH twin of `ProxmoxAdminClient` so the **existing** permission-plan generator, `apply_plan`, `rollback_created`, `verify_token` are reused; dry-run twin for the approvers' command list; node identity; helper client), `ou_pve_helper.py` (the forced-command helper), `session.py` (30-minute vault-bound admin session), `trust.py` (API TLS trust decision), `actions.py` (typed actions), `api.py` (session endpoints). Migration `0011_ssh_onboard`. New typed actions: `provider.ssh.discover` (low), `provider.ssh.preview` (low), `provider.ssh_onboard` (**normal**: one approver who is not the requester, owner decision 2026-11-16; high if it widens an existing scope or is elevated), `provider.ssh_offboard` (**high**, two approvers), `provider.ssh.helper` (low), `provider.ssh.narrow` (normal).
* Frontend: `Infrastructure > Providers > Proxmox > Connect with SSH` (`SshOnboard.vue`, route `/infrastructure/providers/proxmox/connect-ssh`; links from the provider list, the connect wizard's first step, and the Permissions page: **Change with SSH**, **Remove SSH-created access**). The built console (`ics/ics/static`) is committed, so it deploys with the normal procedure. Screenshots (light and dark, from the real built UI with the API mocked): `docs/screenshots/ssh-onboard/`.
* Dependency: paramiko 3.5.1 (LGPL-2.1), bcrypt 4.2.1, PyNaCl 1.5.0, hashed in `ics/requirements.lock`.

## Evidence (executed)
Test DB `ics_test_f` only. Commands and counts are in the final section of this file (filled in at the end of the run).
* `tests/test_ssh_onboard.py`: host-key fingerprint equals `ssh-keygen -lf`, nothing runs before confirmation, pinned-key mismatch sends nothing (sshd log has no authentication), host-key change after confirmation stops the job, wrong API certificate stops discovery, discovery runs only `pvesh get` / `cat`, full onboarding (Proxmox user/roles/ACLs/tokens exact; node account, `restrict,command=` key, helper, config, sudoers; only template tools executed; secrets absent from every table), injection in every template field and every policy/session field, forced-command escape attempts (about 45 strings: shell, `;`, `$()`, backticks, newline, traversal, `sudo`, `pveum`, `acl-add`, ...; pty and port forwarding refused), helper token rotation and narrowing limited to its own identity, verification failure (extra privilege) rolls everything back, failed install rolls back, credential wiped after success / failure / cancel / expiry, session TTL 30 min, customer-bound envelope, idempotent re-run with token rotation, offboarding removes everything (pool only if empty), plan binding (a cluster change after preview refuses and changes nothing), single-node scope blocked when connected to another node, sudo path.
* `tests/test_ssh_trust.py` (real certificate chains and TLS handshakes): public CA by host name pins the root and not the leaf (a renewed leaf keeps the same pin), host-name validation is part of trust (valid chain for another name earns nothing), cluster-CA mode, self-signed fingerprint mode, reverse proxy with a public chain needs explicit confirmation of its fingerprint, a different certificate without a valid chain stops and shows both fingerprints, SSH address != API address verified as the same node (and refused with rollback when the API reaches another node), `pveproxy-ssl.pem` is read before `pve-ssl.pem`.
* Frontend: `ssh.test.ts` (model, validation, params carry no credentials), typecheck, build.

## Known limits (not hidden)
* Password authentication is not exercised against sshd (the test sshd runs as an unprivileged user without PAM); key authentication with and without passphrase is. The password path is the same `auth_password` call.
* The fakes are faithful to documented `pvesh`/`pveum` behaviour and PVE 9 JSON shapes, not to a real node. Unconfirmed on a real node: exact `pveum` option spelling on PVE 9.2 (`user token add ... --output-format json`, `acl modify ... --delete 1`, `pool add`), whether `sudo` is installed (the plan fails early with a clear message if not: `apt install sudo`), `usermod --password '*'` + key login under the node's `sshd` policy, `/cluster/status` readability for the inventory token (identity check falls back to the certificate), `get_verified_chain` private accessor on Python 3.12.
* `/etc/pve/priv/known_hosts` is not used: for whole-cluster scope the SSH identity is installed on the connected node only (documented trade-off).
* Real e2e (`ics/e2e`) not run: port 8108 was in use by another run.

## Owner test checklist (real node pve06, reached as pve.agit8or.net)
Do this on a quiet moment; nothing here touches guests. **Approvals: onboarding is normal risk (owner decision 2026-11-16): you need ONE additional console account with the approver role (not the account that requests it). Offboarding is high risk: two approvers.**

**0. Before (on pve06, as root)** snapshot the things we expect to change and the things that must not:
```
mkdir -p /root/ou-before && cp /etc/pve/user.cfg /root/ou-before/user.cfg && getent passwd > /root/ou-before/passwd
ls -l /etc/sudoers.d > /root/ou-before/sudoers.d.txt; pveum acl list > /root/ou-before/acl.txt; pveum role list > /root/ou-before/roles.txt
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub      # note this SHA256 value
dpkg -s sudo | head -2                                 # must be installed (apt install sudo if not)
```
**1. Connect.** Console > Infrastructure > Proxmox > **Connect with SSH**. Enter: host = the address you can SSH to (internal address or `pve.agit8or.net`; if SSH is not forwarded use the internal one), port 22, user `root` (or a sudo user), password or key. If the API is reached by name, put `https://pve.agit8or.net:8006` under *Optional settings > API address*; optionally the ICS address `192.168.22.167` as the `from=` restriction. Click *Store and fetch the host key*. You should see: "Stored", then step 2 showing a `SHA256:...` fingerprint.

**2. Host key.** The fingerprint on screen must equal the one you noted in step 0. Type it into the box and press *pin it*. A wrong value must be refused.

**3. Discover.** Press *Discover*. Expect cluster name, the six nodes, `PVE06-Storage`, `vmbr0`, pools, template 131 and guest counts (126, 131, 136, ...), and one of these certificate results:
* *Publicly trusted certificate: the issuing CA and the host name are pinned* (expected for `pve.agit8or.net`, Let's Encrypt); the page shows the leaf fingerprint for information only;
* *Something sits in front of the API*: shows two fingerprints; continue only if you know a reverse proxy terminates TLS; type the second (proxy) fingerprint to confirm;
* a red mismatch: stop and tell the lead (do not continue).

**4. Choose.** One node: pve06 (recommended). Rights: *Deploy into this pool*, pool `officeunbound` (new), storage `PVE06-Storage`, network `vmbr0`, template 131. (*See inventory only* is a valid smaller first test.)

**5. Review.** You must see: the permission plan (pool, role `OfficeUnboundDeploy`, user `officeunbound@pve`, tokens, ACL paths only under `/nodes/pve06`, `/pool/officeunbound`, `/storage/PVE06-Storage`, `/vms/131`, `/sdn/zones/localnetwork/vmbr0`; nothing on `/`), the node account `ou-ics` with the key fingerprint and helper hash, the sudoers text (`ou-ics ALL=(root) NOPASSWD: /usr/local/sbin/ou-pve-helper ""`), the exact command list, "Normal risk: needs 1 approver other than you", and the pinned host key / API trust line.

**6. Apply.** Press *Submit for approval and apply*; approve with the second account (Approvals page). Expect the job to finish with: permissions verified, the helper verification (8 refused probes), `node_check` "api and ssh agree: pve06" (or "same certificate on both paths") and "admin credential wiped".

**7. Verify on pve06 that only the expected things were created:**
```
pveum user list | grep officeunbound; pveum user token list officeunbound@pve
pveum role list | grep OfficeUnbound; pveum acl list | grep -i officeunbound     # only the paths above
pveum pool list | grep officeunbound
getent passwd ou-ics; ls -l /usr/local/sbin/ou-pve-helper /etc/office-unbound/ou-pve-helper.json /etc/sudoers.d/ou-ics
cat /var/lib/ou-ics/.ssh/authorized_keys          # one line: restrict,command="sudo -n /usr/local/sbin/ou-pve-helper" ssh-ed25519 ...
sha256sum /usr/local/sbin/ou-pve-helper           # equals the helper hash shown in the Review step
diff /root/ou-before/user.cfg /etc/pve/user.cfg   # only additions for officeunbound@pve, OfficeUnbound* roles, its ACLs, the pool
diff <(getent passwd) /root/ou-before/passwd      # only ou-ics
grep -E "ou-pve-helper|ou-ics" /var/log/auth.log | tail   # the ICS's later helper calls, if any
```
No guest changed (`qm list`), no other ACL changed (`diff /root/ou-before/acl.txt <(pveum acl list)`).
In the console: the cluster appears under Proxmox clusters; **Permissions > Run validation** is green; the Credentials page shows the `officeunbound@pve` tokens (no SSH password anywhere) and an `ssh_key` credential `ICS SSH identity ou-ics@pve06`.

**8. Try to break it (from any machine you control, optional):** the ICS key is in the vault and cannot be used by hand; instead confirm on pve06 that `ou-ics` cannot log in with a password (`passwd -S ou-ics` shows no usable password) and that `su - ou-ics -s /bin/sh -c id` as root works only because root can (it is not a login path).

**9. Undo.** Preferred: Permissions page > **Remove SSH-created access**, type the integration name, tick *Also delete the pool if it is empty*, enter your SSH login again, approve with two other accounts (offboarding is high risk). Then repeat the step 7 checks: everything with `officeunbound`/`OfficeUnbound`/`ou-ics` is gone and `diff` against `/root/ou-before` is empty. Manual fallback on pve06 if the console is unavailable:
```
for t in $(pveum user token list officeunbound@pve --output-format json | python3 -c 'import sys,json;[print(x["tokenid"]) for x in json.load(sys.stdin)]'); do pveum user token remove officeunbound@pve $t; done
pveum acl list --output-format json | python3 -c 'import sys,json
for a in json.load(sys.stdin):
  if a["ugid"].startswith("officeunbound@pve"): print(a["path"],a["roleid"],a["ugid"],a["type"])'   # delete each with: pveum acl delete <path> --roles <role> --users|--tokens <ugid>
pveum user delete officeunbound@pve; pveum role delete OfficeUnboundDeploy   # and every other OfficeUnbound* role
pveum pool delete officeunbound                                              # only if empty
rm -f /etc/sudoers.d/ou-ics /usr/local/sbin/ou-pve-helper /etc/office-unbound/ou-pve-helper.json; userdel -r ou-ics
```

## Run record
(see the end of the file)
