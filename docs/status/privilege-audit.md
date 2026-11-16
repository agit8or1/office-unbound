# Privilege audit and least-privilege configuration (Priority 0-E)

Date 2026-11-16, ICS host (192.168.22.167, Ubuntu 24.04), agent BW, branch `privsep` (from `integration-7`). Owner requirement: remove unnecessary
`NOPASSWD: ALL`; review every service account, build user, release signer, test runner and administrator; strict least privilege; no build process
with unrestricted access to signing keys, production infrastructure or unrelated services.

Status values per ADR-0000: the inventory is **verified** (read-only commands on the live host, 2026-11-16 01:00-01:20 UTC). The configuration below is
**implemented and tested in a scratch machine** (`ou-priv1`); it is **NOT applied** to this host. Applying it is an owner action (section 7).
No file under `/etc/sudoers*`, no account and no unit of this host was changed by this work.

## 1. Inventory of the ICS host (read-only)

### 1.1 Accounts and groups

| Account | uid | login | Notes |
|---|---|---|---|
| root | 0 | locked (`passwd -S` L) | `PermitRootLogin yes` in sshd but no password and `/root/.ssh` empty: not exploitable today, one `passwd root` away from being so |
| administrator | 1000 | password set, ssh key (1) | groups sudo, admin, users; the only human/agent/build account (cloud-init created) |
| ics | 999 | nologin, locked | service user of `ics.service`; group `ics` owns the vault/audit/signing key files |
| postgres | 109 | bash, no password | cluster owner; also in `ssl-cert` |
| ou-release | 997 | nologin, locked | release signer (GnuPG home, passphrase) |
| ou-imgsign | 995 | nologin, locked | golden-image manifest signer |
| ou-testrunner | 994 | nologin, locked | test runner (own Ed25519 key) |
| ou-agent | not on the host | | the node agent runs on guests (user `ou-agent`) and as the transient root unit `ou-agent-bkplab` on this host (finding F6) |
| cloud-init users | | | only `administrator`; cloud-init wrote `/etc/sudoers.d/90-cloud-init-users` (first boot only) |
| other | | | `nobody`, system users; no docker/lxd members (`lxd` group empty) |

### 1.2 sudoers and polkit (live `sudo -n -l` and file read)

| File | Content | Verdict |
|---|---|---|
| `/etc/sudoers` | `root ALL`, `%admin ALL=(ALL) ALL`, `%sudo ALL=(ALL:ALL) ALL`, `@includedir /etc/sudoers.d`; defaults `env_reset, use_pty, secure_path` | password-protected group rules: KEEP (the owner's interactive path; administrator has a password) |
| `90-cloud-init-users` | `administrator ALL=(ALL) NOPASSWD:ALL` | REMOVE |
| `90-claude-administrator` | `administrator ALL=(ALL:ALL) NOPASSWD: ALL` | REMOVE |
| `ou-release` | `(ou-release) ou-release-sign` (any args), `(ou-testrunner) ou-test-attest run *` (fixes-r7 install-signer.sh) | replace by exact subcommands and exact attestor arguments |
| `ou-image-sign` | `(ou-imgsign) ou-image-sign *` | replace (wildcard) |
| polkit | `/etc/polkit-1/rules.d` empty; Ubuntu defaults (`49-ubuntu-admin.rules`: groups sudo/admin are polkit admins, password needed) | add deny rule for service accounts |

Net effect today: `administrator` is root. Everything below the table is bypassable by any process of that account (read `/var/lib/ou-release/passphrase`,
replace `/usr/local/sbin/ou-release-sign`, edit `trust/*.pub`, read the ICS vault/audit/signing keys, restart or edit `ics.service`, read the DB owner URL).

### 1.3 Services (systemd)

| Unit | User | Sandbox today |
|---|---|---|
| ics.service | ics | NoNewPrivileges, ProtectSystem=strict (no ReadWritePaths), ProtectHome, PrivateTmp/Devices, empty capability set, seccomp `@system-service ~@privileged @resources`, AF_INET/INET6/UNIX, ReadOnlyPaths, InaccessiblePaths for migrate/test envs, MemoryDenyWriteExecute: `systemd-analyze security` 1.2 |
| ics-bootstrap.service | ics | same (unit shipped, not installed on this host) |
| ics-migrate.service | root (reads root-only DB-owner URL) | NoNewPrivileges, ProtectSystem=strict, empty caps, 3 address families; no seccomp/kernel protections: 1.6 after drop-in |
| ics-admin-fw.service, ou-lab-fw.service | root (nft) | none |
| ou-rb-backup@.service | root | NoNewPrivileges, PrivateTmp, ProtectHome only (more options break `runuser`, shown below) |
| ou-agent-bkplab (transient) | **root** | none: `python3 -m ou_agent serve` started by `systemd-run`, PYTHONPATH `/opt/ou-agent-bkplab`, config `/etc/ou-agent-bkplab/agent.json` |
| nginx, postgresql@16-main | root master / www-data, postgres | distribution defaults |
| ou-repo-resign.service (shipped, not installed) | administrator | none |
| systemd-nspawn@ou-*.service (11 running) | root, machines `PrivateUsers=pick` (uid-shifted), no `Bind=` in any `.nspawn` file (checked all 49) | container root is not host root |

### 1.4 Keys and secrets (owner:group mode; contents never read)

| Path | Mode | Readers today (besides root) | Purpose |
|---|---|---|---|
| `/etc/office-unbound/vault.key` | root:ics 0640 | ics | ICS credential vault master key |
| `/etc/office-unbound/audit.key` | root:ics 0640 | ics | audit hash-chain HMAC key |
| `/etc/office-unbound/ics-signing.key` | root:ics 0640 | ics | ICS Ed25519 key (job/promotion manifests) |
| `/etc/office-unbound/ics.env` | root:ics 0640 | ics | app DB URL (role `ics_app`, no DDL) |
| `/etc/office-unbound/ics-migrate.env` | root 0600 | nobody | DB owner URL |
| `/etc/office-unbound/tls/{ca,ics}.key` | root 0600 (dir 0750) | nobody | private CA / server key |
| `/etc/office-unbound/backup-lab/*` | root 0600 | nobody | restic/rest-server passwords, TLS key |
| `/etc/office-unbound/bootstrap/pve06-ics.token` | root 0600 | nobody | Proxmox API token |
| `/var/lib/ou-release/{passphrase,gnupg}` | ou-release 0400 / 0700 | ou-release | release + channel signing keys |
| `/var/lib/ou-release/trust/*.pub` | root 0644 | all (public) | trust anchors the signer verifies against |
| `/var/lib/ou-imgsign/{key.pem,passphrase}` | ou-imgsign 0600 / 0400 | ou-imgsign | golden-image signing key |
| `/var/lib/ou-testrunner/key` | ou-testrunner 0400 | ou-testrunner | attestation key |
| `/root/ou-release-revocation-*.asc` | root 0600 | nobody | revocation certificate (owner: offline copy) |
| `/etc/office-unbound/ics-test-*.env`, `lab/gw1-users.env` | root:administrator 0640 | **administrator** | TEST database credentials and lab user passwords only (by design: pytest runs as administrator) |

File permissions were already correct for an unprivileged build user. **The whole exposure is the sudoers rules**; there is no key file with a wrong mode.

### 1.5 Lab machines (running ones, via `systemd-run -M`, read-only)

No machine has a sudoers rule. Login users: `obuild` (ou-pkg1, ou-bj-pkg1), `imgbuild` (ou-build1). Service users: opencloud/ou-agent (files1), gromox, mysql, redis, ou-agent, ou-wipe
(gw1), keycloak (id1), ou-portal, ou-pkgrepo (DynamicUser, read-only repo), docker-registry/imgbuild (build1). Everything else runs as root inside the container (systemd, journald). ou-hard1 and
ou-mig-src1 were not answering on the bus at inventory time.

### 1.6 Deploy flow and CI

* `ics/deploy/install.sh` and `bootstrap.sh` run as root from a checkout: they execute repository code as root. Deploying production is therefore a root operation by nature; after the change it needs a password (owner, `sudo -i`) or a root session. No narrow sudo rule can express "run this repo's installer".
* Backups: `/usr/local/sbin/ou-backup` via `ou-rb-backup@.service` (root, spool request validated against root-owned `/etc/ou-backup/*.json`), ICS tier hook uses `runuser postgres pg_dump`.
* CI (`.github/workflows`, 5 files): GitHub-hosted runners, explicit `permissions:`, no self-hosted runner, no deploy step, no host access.
* Signer installers (`install-signer.sh`, `install-image-signer.sh`) write `/etc/sudoers.d/ou-release` / `ou-image-sign`; re-running them re-creates the broader legacy rules (see section 6.3).

## 2. Findings: account, today, needs, gap, fix

| # | Account | What it can do today | What it needs | Gap | Fix (this branch) |
|---|---|---|---|---|---|
| F1 | administrator (human, agents, build user, test runner caller) | root on the host (two `NOPASSWD: ALL` files): reads every key, rewrites signer/trust, restarts/edits ICS, reaches Proxmox token and DB owner | build in containers, ask the signer, run tests, start/stop lab machines | unrestricted | `ou-priv-signers`, `ou-priv-lab` drop-ins; both ALL files removed (apply-privsep.sh) |
| F2 | administrator -> ou-release | `ou-release-sign` with any arguments | `sign <suite>`, `admit dev`, `seed-meta`, `pubkey`, `fingerprint`, `status`, `record-test`, `promote dev staging`, `promote staging stable` | arguments unrestricted at the sudo layer | exact subcommands (no wildcard); `record-test`/`promote` stay reachable only because the signer verifies a signature the build user cannot create (runner attestation, ICS-signed manifest) |
| F3 | administrator -> ou-imgsign | `ou-image-sign *` | `sign`, `record-test`, `pubkey` (the program refuses extra arguments) | wildcard | exact three commands |
| F4 | administrator -> ou-testrunner | `ou-test-attest` any args | `^run deb-install-smoke [0-9a-f]{64}$` and `^run image-first-boot /var/lib/ou-imgbuild/out/<name>$` (sudoers regular expressions, sudo >= 1.9.10) | none after integration-8 | no wildcard; `keygen` is not granted (install-time, root); the program still takes only an admitted sha256 or an image path below the output directory and cannot be handed a result (review 7 H-3) |
| F5 | ou-testrunner | no sudo rule on the host today | root helper `/usr/local/lib/ou-testrunner/nspawn-smoke` (fixes-r7) | rule would be added by the new installer | `ou-priv-testrunner`: exactly that one path |
| F6 | ou-agent-bkplab (root, transient, unsandboxed) | whole root filesystem; reachable from lab backup runbooks | machinectl/systemd-run -M, backup spool | runs as root with no sandbox | NOT changed (it is a lab runner owned by the backup tier). Recommended: install as `ou-agent.service` (user ou-agent + generated polkit rule) as on guests, or at least add `ProtectSystem=strict ReadWritePaths=/var/lib/ou-agent-bkplab /var/lib/ou-backup NoNewPrivileges=true` after the backup owner tests it |
| F7 | ics | key files for vault, audit, signing in one group | all three | one identity holds three keys | accepted: one process uses all three. Not separable without splitting the service. polkit: all denied |
| F8 | postgres | normal | normal | `bash` shell, no password: only reachable as root | none needed; polkit denies it |
| F9 | root over ssh | locked password, `PermitRootLogin yes` | no ssh root login | latent | `--with-ssh` drop-in `PermitRootLogin no` (validated with `sshd -t`, not reloaded) |
| F10 | ics-migrate (root) | sandbox lacked seccomp/kernel protections | DB owner URL, DB socket | reduced | drop-in, score 1.6 |
| F11 | ics-admin-fw / ou-lab-fw (root) | unsandboxed nft oneshots | CAP_NET_ADMIN, netlink | | drop-ins, tested |
| F12 | nginx, postgresql | distribution defaults | | | drop-ins (NoNewPrivileges, ProtectSystem=full, ProtectHome, ProtectKernel*, caps); postgresql 6.9 -> still MEDIUM (it is a database server), tested |
| F13 | ou-rb-backup@ (root) | partial sandbox | setuid to postgres | **every** seccomp/caps-trimming option breaks `runuser` together with NoNewPrivileges (bisected: ProtectClock, ProtectHostname, ProtectKernelLogs, RestrictRealtime, SystemCallArchitectures, RestrictAddressFamilies each fail with `cannot set user id`) | only `LimitCORE=0`, `KeyringMode=private`; real fix needs the pg_dump step as its own `User=postgres` unit (backup tier owner) |
| F14 | administrator, test credentials | reads `ics-test-*.env`, `lab/gw1-users.env` | pytest | test-only secrets | accepted, documented |
| F15 | signer installers | re-create `/etc/sudoers.d/ou-release` and `ou-image-sign` with the older, broader lines | | undo this change silently | re-run `apply-privsep.sh --apply` after every installer run (idempotent, removes them again); agents BU/BA should drop the sudoers heredocs from the installers when this lands (follow-up) |
| F16 | administrator, lab hand-edits | `sudo tee`/`cat`/`install` into `/var/lib/machines/<m>/...` and `/etc/hosts`, `nft`, `apt` | rarely | cannot be expressed without root | need the owner password (or `systemd-run -M <m> --pipe sh -c 'cat > file'` into a running machine, which the lab shim allows) |

## 3. The final configuration (all under `ics/deploy/privsep/`)

| File | Installed as | Content |
|---|---|---|
| `sudoers/ou-priv-signers` | `/etc/sudoers.d/ou-priv-signers` | `Cmnd_Alias` lists with absolute paths and exact arguments for the three signer identities, `Defaults!<alias> env_reset, !setenv, !env_editor`; `(ou-release)`, `(ou-imgsign)`, `(ou-testrunner)` only, never root, never ALL |
| `sudoers/ou-priv-lab` | `/etc/sudoers.d/ou-priv-lab` | `(root) NOPASSWD:` five shim paths under `/usr/local/lib/ou-priv/bin`; `Defaults:<operator> secure_path` puts that directory first so the existing `sudo machinectl ...` calls reach the shims |
| `sudoers/ou-priv-testrunner` | `/etc/sudoers.d/ou-priv-testrunner` | `ou-testrunner` may run `/usr/local/lib/ou-testrunner/nspawn-smoke` as root (the helper validates its own path argument) |
| `lib/ou-lab-policy`, `lib/shim` | `/usr/local/lib/ou-priv/` | argument policy (machine names `ou-[a-z0-9-]+`, `ou-base-*` protected, no `-M .host`, no second `-M`, command placed after a literal `--`, `.nspawn` file only with the fixed template, `set-property ... MemoryMax=` only, `test -d/-e /var/lib/machines/ou-*` only). The shim enforces only when `SUDO_COMMAND` names the shim, so `sudo -i`/password sudo is unrestricted for the owner |
| `polkit/50-ou-privsep.rules` | `/etc/polkit-1/rules.d/` | `ics`, `postgres`, `www-data`, `ou-release`, `ou-imgsign`, `ou-testrunner`, `ou-agent`: always NO |
| `sshd/60-ou-privsep.conf` | `/etc/ssh/sshd_config.d/` (optional) | `PermitRootLogin no` |
| `systemd/<unit>.d/10-privsep.conf` | `/etc/systemd/system/<unit>.d/` | hardening drop-ins for ics, ics-bootstrap, ics-migrate, ics-admin-fw, ou-lab-fw, ou-rb-backup@, ou-repo-resign, nginx, postgresql@ (each only when the unit exists); `ReadWritePaths` is empty for ics (it writes nothing; ProtectSystem=strict), `/var/lib/office-unbound/pkgbuild` for repo-resign |
| `apply-privsep.sh`, `revert-privsep.sh` | run from the checkout | section 7 |
| `tests/` | | `in-machine-test.sh` (scratch machine end-to-end), `key-separation.sh` + `keys.manifest` (also usable on the host as a periodic check) |

Not wildcards: sudo matches the five shim paths and the exact signer lines; every argument of the lab commands is validated in Python (`ou-lab-policy`,
36 unit tests in `ics/tests/test_privsep_policy.py`, no database needed). The only sudoers entry without an argument pattern that needs one is
`ou-test-attest` (F4, argument validation inside the program).

## 4. How the lead and agents keep working (nothing gets ALL)

| Task | Command (unchanged where possible) | Rule |
|---|---|---|
| list/start/stop/clone/remove a lab machine | `sudo machinectl list|show|status|start|poweroff|terminate|reboot|remove <ou-name>`, `sudo machinectl clone <ou-src> <ou-dst>` | `ou-priv-lab`: names `ou-[a-z0-9-]+`; `ou-base-*` cannot be a clone destination, removed, stopped or used as an exec target |
| run a command inside a machine | `sudo systemd-run -M <ou-name> --wait -P -q /bin/bash -c '...'` (flags: `--wait --pipe -P --pty -t -q --collect --no-block -p -u -E --uid --gid --slice --working-directory --description`) | root **inside the container** only; `-M .host`, `--host`, `--user`, a second `-M`, a missing `-M` are refused |
| MemoryMax of a machine | `sudo systemctl set-property systemd-nspawn@<ou-name>.service MemoryMax=2G` | nothing else is allowed with systemctl |
| create the machine's `.nspawn` file | `printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' \| sudo tee /etc/systemd/nspawn/<ou-name>.nspawn` | only that template (no `Bind=`, no capabilities) |
| does the image exist | `sudo test -d /var/lib/machines/<ou-name>` | |
| sign / admit / publish | `repo.sh ...` as today (`sudo -n -u ou-release /usr/local/sbin/ou-release-sign sign dev` etc.) | exact subcommands, section 3 |
| ask for a test attestation | `sudo -n -u ou-testrunner /usr/local/sbin/ou-test-attest run deb-install-smoke <sha256>` | runs the tests itself; cannot be told a result |
| image sign / record | `sudo -n -u ou-imgsign /usr/local/sbin/ou-image-sign sign|record-test|pubkey` | |
| pytest, git, builds on the host, files under `/var/lib/office-unbound/pkgbuild` | as `administrator`, no sudo | already unprivileged |

Needs the owner's password (`sudo -i`, root console), by design: production deploys (`install.sh`, `bootstrap.sh`), `systemctl` on any real unit, editing `/etc`
(including `/etc/hosts`), `nft`, `apt`, creating DBs/roles in PostgreSQL, running `ou-backup`, reading any key, writing into `/var/lib/machines/<m>/` from the host
(use `systemd-run -M <m> --pipe sh -c 'cat > path'` instead), `install-signer.sh`/`install-image-signer.sh`. An agent that finds itself needing one of these stops and asks the owner.

Residual risks the owner must accept: (1) root in a lab container can attack anything the container can reach (the network zone `oulab` is firewalled by `ou_lab`, containers are uid-shifted and hold no signing key; they are not a hard boundary against kernel bugs). (2) The password-protected `%sudo`/`%admin` rules remain: an attacker who captures the `administrator` password has root. (3) `record-test` and `promote` are reachable by the build user; they are safe only while the signature checks inside the signer hold (agent BU, review 7). (4) Production signing should move to a separate host/HSM.

## 5. Key separation (tested)

`tests/key-separation.sh` checks, for each key in `keys.manifest`, which of {build user, ics, ou-release, ou-imgsign, ou-testrunner, nobody} can read it, and 25 sudo behaviours of the build user.

| Key | Allowed readers | Build user can read |
|---|---|---|
| ICS vault key, audit HMAC key, ICS signing key, `ics.env` | ics | no |
| ICS-migrate env, TLS CA/server keys, backup passwords, Proxmox token | root | no |
| release signing keys + passphrase (all channels) | ou-release | no |
| image signing key + passphrase | ou-imgsign | no |
| test-runner key | ou-testrunner | no |
| revocation certificate, ssh host key, shadow | root | no |

Evidence (scratch machine `ou-priv1`, Ubuntu 24.04, ICS installed with `bootstrap.sh`, account and signer users created with the production modes):
baseline before apply: NOPASSWD ALL present, key-separation FAILS (sudo section); after apply: key files 13 PASS (5 SKIP: files absent in the scratch machine), sudo section 25 PASS, total
`pass=38 fail=0 skip=5`. The files were never readable by an unprivileged build user; what changed is that `sudo` can no longer be used to become anyone else.

## 6. Test evidence (scratch machine `ou-priv1`, clone of `ou-base-noble`, MemoryMax 1G, host free memory checked first)

`bash ics/deploy/privsep/tests/in-machine-test.sh` inside the machine: **39 PASS, 0 FAIL** (2026-11-16 01:30 UTC). Covered:

1. Baseline reproduces the problem (NOPASSWD ALL, key-separation fails).
2. `apply-privsep.sh` default is a dry run and leaves every file byte-identical; refuses when the operator's password is locked.
3. `--apply`: backup dir created, three new rules validated with `visudo -cf` before moving, the four legacy files removed after `visudo -c`, `sudo -l -U administrator` lists no `NOPASSWD: ALL`, the `%sudo` password rule still listed.
4. Lab shims reached through plain `sudo machinectl ...`; `ou-base-noble` refused; `-M .host`, second `-M`, `--host`, host paths, other units refused.
5. Every sandboxed unit restarts and is active with its drop-in: postgresql@16-main, ics-migrate, ics, ics-bootstrap (shipped unit, installed for the test), nginx, ics-admin-fw, ou-lab-fw (stand-in with an nft file); the console answers through nginx; ics and callback listen on loopback. `systemd-analyze security`: ics 1.2, ics-migrate 1.6, nginx 4.6, postgresql 6.9.
6. `ou-rb-backup@` with a stand-in helper that calls `runuser postgres`: runs with the final drop-in; the bisect showing which options break it is in F13. **ou-repo-resign.service was neither installed nor started** in the machine (its drop-in is skipped when the unit is absent, as on this host): that drop-in is untested.
7. Idempotent second apply; `revert-privsep.sh` dry run changes nothing; `--apply` restores the original sudoers (NOPASSWD ALL back), removes shims/drop-ins, `ics.service` restarts fine.
8. `shellcheck -x -S style` clean on `apply-privsep.sh`, `revert-privsep.sh`, `lib/shim`, `tests/*.sh`. `python -m pytest ics/tests/test_privsep_policy.py`: 36 passed (no database; ICS_TEST_ENV_FILE not used).

Not tested: the real signer programs with the new sudo lines (the scratch machine has stubs; the exact subcommands were taken from the code on `fixes-r7`: `sign`, `admit`, `seed-meta`, `pubkey`, `fingerprint`, `status`, `record-test`, `promote`, and `repo.sh` call sites); `ou-repo-resign` (see 6); the production host itself (never touched).
Reconciled in integration-8 with `fixes-r7`: `repo.sh` calls `$ATTEST run deb-install-smoke <sha256> | $SIGN record-test` (the only attestor call sites besides the image recipe `run image-first-boot <path>`); `sign`, `admit dev`, `promote dev staging|staging stable`, `record-test` are the only signer subcommands used by `repo.sh`; `seed-meta`, `pubkey`, `fingerprint`, `status` stay for `install-signer.sh`/operator checks. The sudoers drop-in now pins the attestor arguments exactly. Checked with `visudo -cf` only; never applied.

## 7. Owner procedure

```
# from the console or a root shell that does not depend on administrator's sudo; keep a second root shell open
cd /home/administrator/office-unbound            # a checkout containing branch privsep (merge it first, or use a worktree of it)
sudo ics/deploy/privsep/apply-privsep.sh         # DRY RUN: validates and prints everything, changes nothing
sudo ics/deploy/privsep/apply-privsep.sh --apply # applies; backup in /root/sudoers-backup-<UTC timestamp>/; restarts nothing
# then, in a SECOND shell as administrator:  sudo -n true   (must fail);  sudo -l  (no NOPASSWD ALL)
# when convenient, restart production units to load the new sandboxes (brief console/DB interruption), one by one:
#   systemctl restart ics-migrate ics ; systemctl restart nginx ; systemctl restart postgresql@16-main
# undo at any time:   sudo ics/deploy/privsep/revert-privsep.sh --apply
```
Optional: `--with-ssh` (root login off; then `systemctl reload ssh`), `--restart-services` (asks you to type `restart production`), `--operator NAME`.
The script aborts before changing anything if the operator has no password or is in neither `sudo` nor `admin` (lockout protection), and rolls back automatically if
`visudo -c` or the final `sudo -l` check fails. Remember F15: after any signer installer run, run `apply-privsep.sh --apply` again.

## 8. Not done / follow-ups

* F6 (root `ou-agent-bkplab`), F13 (backup helper sandbox) need their owners.
* Installers `install-signer.sh`/`install-image-signer.sh` should stop writing sudoers once this is adopted (not edited here: agent BU is changing them).
* Production signing on a separate host or HSM, a separate `ou-build` account, and a second human for stable promotions remain the long-term answer.
