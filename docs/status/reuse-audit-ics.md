# Reuse audit for the Office Unbound ICS

Scope: static read of four MIT-licensed repos under `/home/administrator/office-unbound/reference/` (shallow clones, unmodified). No Proxmox host was contacted. No secrets were printed. Paths below are relative to `reference/<repo>/`.

## Verdict table

| Component | Verdict | Reason |
|---|---|---|
| Depl0y (whole app) | reference only | The app is broad and over-privileged, and it exposes shell, SSH and exec paths. ICS needs a narrow, typed, audited surface. |
| Depl0y `services/proxmox.py` read methods | adapt | A clean proxmoxer inventory wrapper. Strip the write methods and the password path. |
| Depl0y `services/tls_trust.py` | adapt | A real TOFU/pin/strict TLS layer. The global monkeypatch is the part to leave out. |
| Depl0y cloud-image / cloud-init code | adapt (later phase) | Useful for the deploy phase only. It enables root and password SSH, so rewrite those parts. |
| Depl0y credential storage | reject | Fernet in-DB with a local key file. Acceptable only as a fallback; see section 1. |
| St0r `backend/src/services/drills/proxmox.ts` | adapt | A small, dependency-light PVE client with token auth and fingerprint pinning. |
| rem0te approved-action / signing design | reference only | Sound design, but it targets a Windows RMM with Go agents and a passkey signer. Take the concepts, not the code. |
| rem0te audit hash chain | reuse (port the algorithm) | About 100 lines of pure crypto logic. `apps/api/src/audit/chain.ts` has no framework dependency. |
| clientst0r org/RBAC | reference only | Django multi-tenant MSP model. ICS is single-tenant, so only the ideas apply. |
| clientst0r `audit/models.py` | reference only | A who/what/when/where table. Weaker than the rem0te chain. |
| clientst0r WOPI/Collabora | reference only | Not needed for ICS. Kept in case Office Unbound hosts documents. |
| St0r recovery drills | reference only | Concepts for later restore verification. |

## 1. Depl0y

**Stack.** Python, FastAPI 0.141, SQLAlchemy 2, Alembic, PyMySQL and SQLite (`backend/requirements.txt`, `backend/app/main.py`). It uses `proxmoxer==2.3.0` and `requests`. Auth is PyJWT, passlib/bcrypt and pyotp. Credential encryption uses `cryptography`. The frontend is Vue (Vite). `paramiko` is also a dependency. About 49k lines in `backend/app`.

**How it talks to Proxmox.**
- `backend/app/services/proxmox.py` `ProxmoxService.__init__` builds `ProxmoxAPI(host, user, token_name, token_value, port, verify_ssl=host.verify_ssl, timeout=30)`.
- It uses API-token auth when a token is set, and falls back to a stored password.
- The ISO upload (L249 onward) and cloud-image import (L669) use raw `requests` with a `PVEAPIToken` auth class.

**TLS behaviour.**
- `verify_ssl` is a per-host column that **defaults to False** (`models/database.py` L94 and L512). Every Proxmox host added with defaults runs with `verify=False`.
- This is mitigated by `services/tls_trust.py`, installed from `main.py` L11 via `tls_trust.install()`. It monkeypatches `requests.Session.__init__` to mount a `PinningAdapter` whenever `verify=False`.
- Host modes are `ca` or `pin` (SHA-256 of the DER certificate). Unknown hosts follow `tls_cert_policy`: `tofu` (the default, which trusts the first certificate) or `strict` (an admin approves first).
- A changed certificate is refused and held as pending. CA-issued renewals move the pin automatically.
- The same file also provides a websocket SSL context, and `api/console.py` L71-86 uses it.
- Other `verify_ssl: bool = False` defaults exist in `api/pbs.py` L43 and `api/vm_import.py` L35 and L43, for PBS and VMware.

**Token and role instructions.**
- `PROXMOX_API_TOKENS.md` tells operators to use `root@pam!depl0y` with **privilege separation UNCHECKED**, so the token carries full root rights. It says nothing about least privilege.
- `docs/QUICKSTART.md` section 4 admits a reduced-privilege role "has not been validated" and that several features effectively need `root@pam`.
- There is no `Administrator` role grant in the installers. The only narrow roles are in `docs/NODE_MAINTENANCE.md` L183-184. `Depl0yMaintPreview` is `Sys.Audit VM.Audit Datastore.Audit Mapping.Audit`, a useful starting read-only privilege set for ICS.

**Credentials at rest.**
- `core/security.py` uses Fernet with `ENCRYPTION_KEY`. `core/config.py` generates a key into a 0600 file under `/var/lib/depl0y` if the environment variable is unset.
- Token secrets, passwords and iDRAC passwords are Fernet ciphertext in DB columns (`models/database.py` L91-93, L111, L492, L509-511).
- `ProxmoxService.__init__` has `except Exception: token_secret = host.api_token_secret`. If decryption fails it silently uses the raw column as the secret, so legacy plaintext rows still work. Copy the Fernet idea but not that fallback.
- The key sits on the same host as the database. This is encryption only against a DB-only leak.

**Arbitrary command execution: yes, several paths.**
- `services/proxmox.py` L873 `execute_qemu_agent_command(command)` posts to `agent/exec` with a free-form string. Nothing in `api/` calls it right now.
- `api/node.py` L1204 `node_termproxy` gives a node root shell via termproxy, behind `require_admin`.
- SSH and sshpass to hypervisors, with sudoers entries for `ssh`, `sshpass` and `ssh-copy-id *` (`scripts/sudoers.depl0y`).
- Others: `services/host_ssh.py`, `ssh_hw.py`, `hazfs.py`, `time_sync.py`, `api/idrac.py`, `api/llm.py` (an LLM generates cloud-init), and an in-app self-updater run as root via `depl0y-update apply`.
- Cloud-init (`services/cloudinit.py` L27-49) enables `PermitRootLogin yes` and `PasswordAuthentication yes` on the guests it deploys.

**Do NOT replicate.**
1. Instructing operators to create a privsep=0 token on `root@pam`.
2. `verify_ssl` defaulting to False, and the TOFU default. Use a pinned CA or fingerprint, supplied out of band.
3. A global monkeypatch of `requests.Session`.
4. Silent fallback from decrypted to plaintext secrets.
5. Password auth to Proxmox (`root@pam` password) as a code path.
6. Free-form exec (`agent/exec`), termproxy, SSH-as-root and an LLM-to-cloud-init pipeline.
7. A broad sudoers file and a root-run self-updater inside the control plane.
8. Guest hardening that is the reverse of a baseline (root and password SSH on).
9. `request_body` stored in `audit_logs` (`models/database.py` L316). This risks logging secrets. The audit table is also mutable.
10. A pass-through endpoint such as `vzdump.post(**backup)` in `api/node.py` that forwards an arbitrary dict to Proxmox. ICS needs typed parameters.

**Worth reusing or adapting.**
- `backend/app/services/proxmox.py`: `get_nodes`, `get_cluster_node_status`, `get_node_resources`, `get_storage_list`, `get_network_interfaces`, `get_vms`, `get_lxc`, `get_all_vms`, `get_vm_config`, `get_vm_status`, `get_next_vmid`. These are the read-only core. L22 `is_cloud_template` is a good template detector.
- `poll_proxmox_resources` (L887) and `services/task_tracker.py` for polling plus UPID tracking.
- `services/vmid_reservations.py` for VMID allocation without races.
- `services/tls_trust.py`: the pin/CA/strict decision logic and the `CertificateNotTrustedError` pattern. Adapt it per-session, not globally.
- `services/cloud_images.py`, `api/cloud_images.py`, `CLOUD_IMAGES_GUIDE.md` and `services/cloudinit.py`: image catalog and download. Adapt them in the deploy phase.
- `services/ssh_trust.py`: known_hosts approval workflow with `StrictHostKeyChecking=yes`.
- `api/cluster.py`, `api/topology.py`, `api/dashboard.py`: inventory and aggregation shapes only.
- `middleware/rate_limit.py`, `middleware/security.py`: boilerplate.

## 2. rem0te

**Stack.** TypeScript. API is NestJS with Prisma on **PostgreSQL** (`apps/api`). Web is Next.js. Agent is Go for Windows (`tools/windows-installer`). Argon2id for passwords (`apps/api/src/auth/auth.service.ts` L322, 64 MiB, t=3, p=4). Remote control is delegated to RustDesk. It is an MSP Windows RMM, not an infrastructure controller.

**Agent architecture.**
- A Go agent heartbeats to the portal. The portal is only a courier.
- Commands are a closed allowlist: inventory refresh, update scan, event-log query, and "approved actions".
- Approved actions (`docs/approved-actions.md`): a catalog of twelve compiled-in actions, each with closed parameters. There is no free-text command channel and no plan to add one.

**Request signing and approval.**
- A separate **approval signer** process runs under its own Unix user (`rem0te-approver`) with its own key and roster. The portal never holds the signing key.
- Plans are canonical JSON, prefixed `rem0te-action-plan-v1\n`, signed with **Ed25519**.
- The signed plan covers: action and version, parameters, agent build SHA-256, target identity (business, host, device class, RustDesk ID, SHA-256 of the device secret), requester and origin, the policy (risk, approver count), approvers (user, role, passkey credential hash, time), a validity window (`notBefore` to `notAfter`, max 24h) and a single-use job id.
- Approvers use WebAuthn passkeys with user verification. The challenge is derived from the plan digest, so the signature binds the exact plan.
- Approver count is 1 for a standard workstation and 2 distinct people otherwise. The requester can never approve. Customer sign-off is an optional extra. A single-operator "direct mode" signs immediately but still applies all other checks.
- The agent re-verifies in order: journal, signature (keys from an offline-rooted signed update chain), strict parse (unknown field means refuse), catalog match, target identity, window by its own clock, build, then approvals. It recomputes risk from its own product type.

**Replay protection.**
- The agent keeps a per-job-id **journal** (fsync, then rename) and runs each job at most once. A job found "executing" after a crash is reported "uncertain" and never re-run. Uncertain jobs must be reconciled by a person before a retry.
- Server-side: connection grants live 90 s, launcher tokens 120 s, and enrollment tokens are single-use by conditional DB update.
- The ClientSt0r integration (`docs/integration-clientst0r.md`) signs requests with HMAC and a nonce. The skew limit is **120 s**. The nonce or delegation `jti` is stored in Postgres so it survives restart. A reused nonce returns 401 `REPLAYED`.

**Enrollment.** `apps/api/src/enrollment/` (`enrollment.service.ts`, `device-secret.ts`). The device secret is stored on the endpoint in `heartbeat.dat` and only its SHA-256 is bound into plans. I did not trace the exact enrollment key exchange.

**Key storage.** Release keys are offline. The approval key is in the signer's own state directory. Approval public keys are distributed to agents only as a signed update target. See `docs/update-signing.md`.

**Audit.** `apps/api/src/audit/chain.ts`: `hash(n) = sha256(hash(n-1) + "\n" + canonical(entry n))`, genesis is 64 zeros, and sequence gaps must be declared in the next row. A DB trigger guards sealed rows. The chain is verified hourly. Checkpoints can be exported with Ed25519 signatures (`rem0te-audit verify --export`).

**Containment.** A global or per-business write pause. See `docs/containment.md` and `apps/api/src/containment`.

**Extractable?** The code is not. It is tied to Nest, Prisma and a Go Windows agent. The **designs** are extractable and map well onto ICS:
- typed action catalog with closed parameters;
- separate signer process that the control plane cannot reach;
- plan digest bound to target, window and single-use id;
- journaled run-once execution;
- hash-chained audit;
- pause switch.

ICS does not need an endpoint agent. The "agent" role is played by the ICS executor, which calls the Proxmox API itself.

## 3. clientst0r

Django 6, DRF, MySQL, Argon2, django-axes, gunicorn (`requirements.txt`).

- **Org/permissions.** `core/models.py` has `Organization`. `accounts/models.py` has `Membership` (L47; roles admin, editor, owner and readonly at L37), `RoleTemplate` (L828) and `LDAPGroupMapping`. See `ORGANIZATIONS.md`, `accounts/permission_registry.py`, `accounts/scope.py`, `accounts/authz_cache.py`. Every row is scoped to an org. Roles can be overridden by granular templates. ICS is single-tenant, so only a flat role to capability map is useful.
- **Audit log.** `audit/models.py` `AuditLog` records user, a denormalized username, an action enum (create, read, update, delete, login, and so on), object type/id/repr, plus request metadata and `audit/middleware.py`. It is a plain mutable table with no integrity chain. The rem0te chain is better.
- **WOPI/Collabora.** `office/providers/collabora/wopi.py`, `discovery.py`, `proof.py` (WOPI proof-key check), `locks.py`, `views.py`, `urls.py`. Also `office/tokens.py` for access tokens, and docs in `docs/office/COLLABORA.md`. Not needed for ICS.

## 4. St0r

Node/TypeScript (`backend/src`) managing UrBackup. See `docs/recovery-verification.md` and `backend/src/services/drills/`.
- Backup status, offsite replication status and verified recovery are kept as three separate statuses, never merged. A backup that was never restored is "a hope".
- A file-restore drill restores a canary file from the offsite copy. It compares SHA-256 against a checksum stored in St0r's own DB, independent of the backup, so a corrupted backup cannot "fix" it.
- An optional isolated-boot drill clones a Windows image onto a disposable Proxmox node, checks an app service, then removes everything. The code is `services/drills/proxmox.ts` and `bootDrill.ts`, with `ledger.ts` tracking created resources for cleanup.
- `drills/proxmox.ts` is a minimal PVE client: `Authorization: PVEAPIToken=id=secret`, retries on idempotent reads, task polling, and TLS either CA-verified or pinned to a fingerprint. The pin check at L95 deliberately uses `rejectUnauthorized: false` only to read the peer certificate, then compares the fingerprint. Good model for ICS.

## Recommended ICS stack

- **Language/framework: Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + pydantic v2.** Depl0y already proves this against Proxmox with `proxmoxer`, and its read-only inventory and task-tracking code ports with the least rework. TypeScript (rem0te, St0r) is the alternative, and St0r's pinned PVE client is also usable. Pick one language so the signer, executor and audit code share types. Python is my pick because of the Depl0y inventory code.
- **DB: PostgreSQL.** rem0te uses it for nonces and audit. Use trigger-guarded append-only audit rows. SQLite is fine for a dev profile only.
- **Proxmox access:** a dedicated user with a privilege-separated token. Start with a read-only role built from `Sys.Audit VM.Audit Datastore.Audit Mapping.Audit` (the Depl0y maintenance-preview role). Add per-action privileges (for example `VM.Allocate`, `VM.Clone`, `Datastore.AllocateSpace`) only when typed actions need them, scoped by path. Use CA-verified TLS or an operator-supplied pinned fingerprint, with no TOFU default.
- **Secrets:** keep the Proxmox token outside the web process (a systemd credential or a file readable only by the executor user). Fernet-in-DB is a fallback with no plaintext fallback path.
- **Control flow (from rem0te):** typed action catalog with closed parameter schemas, a plan digest, a single-use job id with an expiry window, a separate approver/signer process, a journaled run-once executor, a hash-chained audit with a pause switch.
- **Phase 1 (read-only inventory):** adapt Depl0y's list/status calls and the St0r or Depl0y TLS pin. No write methods, no SSH, no exec, no termproxy.
- **License:** all four repos are MIT. Keep the copyright notices on any copied code.

## Caveats
- I did not run any code or tests, and did not review every Depl0y endpoint for authorization. The "exec" findings come from grep plus reading specific functions.
- rem0te's own docs say its enforcement paths are "fixture-tested only" against simulated endpoints, so treat its security claims as design intent.
