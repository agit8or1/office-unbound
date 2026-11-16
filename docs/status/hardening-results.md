# Production hardening results (agent BN, branch `hardening`, 2026-11-16)

Follow-up to the three items security review 5 left open ("Remediation" table in [security-review-5-2026-11-15.md](security-review-5-2026-11-15.md)):
the dedicated guest-bootstrap listener, the in-process limiter and the Proxmox log exposure. Nothing was run against the production ICS service/DB or Proxmox.

## 1. Dedicated guest-bootstrap listener (`ics-bootstrap.service`)

| Property | Implementation |
|---|---|
| Own process, port, certificate | `python -m ics.serve_callback` (`ics/ics/serve_callback.py`), `IP:8444` by default, direct TLS in uvicorn with its own self-signed P-256 certificate (`/etc/office-unbound/callback-tls/`); key root 0600 passed to the unit with `LoadCredential` (the unit cannot read `/etc/office-unbound/tls` or `callback-tls`). The guests pin the SHA-256 of the DER certificate (`ICS_GUEST_CALLBACK_PIN_SHA256`, written by the installer) |
| Only its route | the app has exactly `POST /api/v1/guest-bootstrap/report` and `GET /healthz`; no session/CSRF middleware, no cookies, no console routes, no static files, no OpenAPI. Everything else: 404 |
| Server-level limits | `RequestLimits` (pure ASGI, runs before the app): body cap 4096 B by Content-Length and by counting streamed (chunked) bytes (413, the app is told the client went away), 10 s per request (408), uvicorn `limit_concurrency=64`, `timeout_keep_alive=5`, `h11_max_incomplete_event_size=16 KiB`, backlog 128, no HTTP/2, no WebSocket, no access log, no `Server` header |
| Console no longer serves the route | `ICS_GUEST_CALLBACK_DEDICATED=true` (set by `bootstrap.sh --callback-listen`; default stays `false` = transition) |
| Firewall | `ics-callback-fw.service`, nftables table `inet ics_callback`: only `--callback-allow-cidr` networks reach the port, per source at most 8 concurrent connections and 30 new connections/min |
| Install / upgrade | `deploy/install.sh` always installs and enables `ics-bootstrap.service` (replaces `ics-callback.service`); the unit has `ConditionPathExists=/etc/office-unbound/callback.env` so it is inert until `bootstrap.sh --callback-listen IP[:PORT] --callback-allow-cidr CIDR` writes that file, the certificate, the firewall and the three `ics.env` keys. Re-running changes nothing. Backup includes `callback.env`, `callback-tls/`, the unit and the firewall file; restore starts the listener when `callback.env` exists |

Not covered by the listener itself: a client that sends headers byte by byte (slowloris) is bounded by `limit_concurrency` and the firewall's per-source connection and rate limits, not by a header deadline (uvicorn has none; the 10 s deadline starts when the request is dispatched).

## 2. Shared rate limiting

`ics/ratelimit.py`, migration `0011` (`rate_limits`, UNLOGGED): one token bucket per key, a single atomic `INSERT .. ON CONFLICT DO UPDATE ..` per decision (capacity = limit, refill = limit/window, database clock, denied calls consume nothing, 1-in-200 opportunistic purge of rows idle for 1 h). The row lock serialises callers of one key across all processes: no advisory locks, no read-modify-write in Python. A database error is a 5xx (fail closed). Moved: guest callback (per source, per bootstrap id, unknown ids), public approval links, identity enrollment. Login throttling already lived in `login_attempts` (database).
`ics.service` now runs `ICS_WORKERS=2` (`ics/ics/serve.py` uses uvicorn's `Multiprocess` supervisor; 1..16 via `ics.env`). The background worker (jobs, monitor, inventory, backups) runs in exactly one process: a PostgreSQL session advisory lock taken in the app lifespan elects it; `kill -9` of the leader: the supervisor restarted it and the lock was held again within 6 s, heartbeat fresh, `/readyz` ok.

## 3. Proxmox: where the SMBIOS secret can appear (from source, no experiment on pve06)

Sources (public, read on 2026-11-16): `proxmox/qemu-server` `src/PVE/API2/Qemu.pm` (`update_vm_api`, `update_vm`, `update_vm_async`, `vm_config`), `proxmox/pve-manager` `PVE/API2/Cluster.pm` (`log`), `proxmox/pve-cluster` `src/PVE/Cluster.pm` (`log_msg`) and `src/pmxcfs/{logger.h,logger.c,status.c}`. Line numbers are of the master branch on that day.

| Place | Verdict | Evidence |
|---|---|---|
| PVE task log of the config call | **No task exists for the call the ICS makes.** The ICS uses `PUT .../config` (`update_vm`, "synchronous API", `&$update_vm_api($param, 1)`, Qemu.pm ~2772-2826, returns null). Only `POST .../config` (`update_vm_async`) forks a `qmconfig` task (~2653). So `task_log_mentions` (review 5 M2) looked at a log that does not exist for this call: it could never fire. For the async variant the log would contain the value (`print "update VM $vmid: ..."`, ~2304) | Qemu.pm |
| **Cluster log** | **YES, in clear.** `$updatefn` calls `PVE::Cluster::log_msg('info', $authuser, "update VM $vmid: " . join(' ', @paramarr))` (~2302) for sync and async. `@paramarr` is built from every parameter and only `cipassword` is masked (~2130). So the line is `update VM 140: -smbios1 uuid=...,base64=1,serial=<base64 bid+secret>,sku=<b64 URL>,family=<b64 pin> -sshkeys ... -ciuser ...`. It is the BASE64 form (base64=1), not encrypted. The cluster log is a 128 KiB ring buffer in pmxcfs memory (`CLOG_DEFAULT_SIZE 8192*16`, entries max 4096 B), replicated to every node (`dfsm_send_message KVSTORE_MESSAGE_LOG`), cannot be edited through the API, and is overwritten as it fills. `GET /cluster/log` returns, for a user without `Sys.Syslog` on `/`, only that user's own entries; with `Sys.Syslog` on `/` all of them (Cluster.pm log, ~190-230) | Qemu.pm 2302; Cluster.pm; logger.h/c, status.c `cfs_cluster_log` |
| **Node syslog / journal** | **YES.** `log_msg` also calls `syslog($priority, "<%s> %s", $ident, $msg)` (Cluster.pm `sub log_msg`), i.e. the same line lands in the node journal (retention = journald config; readable with `Sys.Syslog` on the node or by root) | Cluster.pm |
| `qm config` / `GET .../config` | YES while set (it is a config value). Readable with `VM.Audit`. **Running VM caveat:** `smbios1` is not hot-pluggable; `update_vm_api` stores new values and deletes in `$conf->{pending}` and `vmconfig_hotplug_pending` leaves it pending (Qemu.pm ~2625-2640). The default `GET .../config` returns "pending changes applied" (vm_config description, ~1832), so after the ICS "clears" a running VM the default view shows no secret while the ACTIVE section (`current=1`, `qm config --current`, `qm pending`) still holds it until the VM is stopped and started (a reboot through the API also applies pending). Before this work `bootstrap_material_present` read the default view and so reported "gone" too early | Qemu.pm; this repo's sim now models it |
| vzdump / snapshots | A backup of a running VM and a snapshot taken while the secret is in the active config contain it (a snapshot stores the config section; deleting the snapshot removes it). A vzdump of the stopped, cleared VM does not | reasoning from the config model; not run |
| Config history | none: pmxcfs keeps no history of `/etc/pve/qemu-server/<id>.conf` | (absence; no code path writes one) |
| pveproxy access log | request line only, no body | standard pveproxy behaviour; not re-read in source |

Consequence: the earlier plan "check the task log" could not work. What is exposed is the one-time secret (+ the public URL and pin) in the cluster log and journal for as long as those retain the line, and in the active config of a running VM until restart. The secret is single use and expires (`ICS_GUEST_BOOTSTRAP_TTL_SECONDS`, default 1800): after the report it is inert (a second valid proof is a replay alarm and fails the record), after expiry it is rejected; the reporting address must also match the VM's `net0` MAC in the ICS host's ARP table (M2). A reader of the log therefore needs L2 presence AND must win the race before the genuine guest reports.

Changes made (code, tested with the extended simulator in `tests/test_hardening_pve.py`):
- `ProxmoxProvider.cluster_log_mentions` replaces the vacuous task-log check as the primary detector (it reads `GET /cluster/log`, which every user may read for its own entries, so the ICS token needs no extra privilege); the executor looks for the secret and its base64 form and flags `pve_log_has_bootstrap_material` in the step result and the step log. Never returns log text.
- `bootstrap_material_state` reports `effective` and `current`; `bootstrap_material_present` is true if either holds material; the audit event `guest.bootstrap_completed` carries `active_config_holds_material_until_restart` so an operator sees that a running VM still holds the value in its active config.
- The simulator (`tests/pve_sim.py`) now models the cluster log line, `current=1` and the pending behaviour of `smbios1` on running VMs (applied on start/stop/reboot).

Recommendations (operator, documented in [security.md](../admin/security.md)):
1. Grant `Sys.Syslog` on `/` and `VM.Audit` on guest pools only to Proxmox administrators; give the ICS token no `Sys.Syslog`.
2. Set `ICS_GUEST_BOOTSTRAP_TTL_SECONDS` to 300-900 (the guest first-boot unit retries for 600 s).
3. Stop/start (not just reboot from inside) a customer VM after enrollment if the active config must be free of the value; the ICS does not restart customer VMs on its own. Do not snapshot or back up a VM between configure and enrollment.
4. Treat PVE log entries older than the TTL as inert. They cannot be purged through the API; the ring buffer is overwritten by normal activity, the journal by its retention.
Not done: setting SMBIOS in a separate config call (it would not change what is logged: every call logs its own parameters), and delivering the secret by another channel (PVE offers none that avoids update_vm for a cloned VM; `POST /qemu` create-time parameters are not logged by `log_msg`, but the golden-image flow clones a template and configures it, so a create-time delivery would need a different provisioning flow).

## 4. Lab proof: `ou-hard1` (clone of `ou-base-noble`, `MemoryMax=1500M`, 192.168.186.161), installed with `bootstrap.sh` from this branch

`--listen-ip 192.168.186.161 --allow-cidr 192.168.186.0/24 --hostname ics-h.ou-lab.internal --admin alice --callback-listen 192.168.186.161:8444 --callback-allow-cidr 192.168.186.0/24`. The lab found three defects in the first version, all fixed before the final run: the argument validation ran after the certificate step (empty IP in the certificate), `uvicorn 0.54`'s `Multiprocess(config, sockets)` has no `target` argument (console crash loop with 2 workers), and the TLS certificate was read from a root-only directory (now a credential like the key).

| Check | Result (measured, `docs/status` scratch log `lab-hard.out`) |
|---|---|
| Install | first complete run rc 0; second identical run: `changes this run: none`; units `ics`, `ics-bootstrap`, `ics-admin-fw`, `ics-callback-fw` active; `callback.env`: only the listen address; `ics.env`: `ICS_GUEST_CALLBACK_DEDICATED=true`, URL, pin |
| Console with 2 workers | `ps`: 2 uvicorn worker processes under `ics.serve`; enroll + TOTP confirm + login (`__Host-ics_session`), 6 x `GET /auth/me` over new connections all 200 (session is in the database), `/readyz` 200; both workers burned CPU during the test (96 and 98 ticks) |
| Rate limit across workers | 60 requests on 30 threads, fresh connections, same source against `identity/enroll` (limit 20/min): **20 not rate limited, 40 x 429** in 0.48 s (an in-process limiter would have allowed about 40 with two workers); `rate_limits` held one row for the key |
| Leader election | exactly 1 advisory lock held; leader `kill -9`: lock held again after 6 s, 2 workers back, heartbeat fresh |
| Listener answers only its route | TLS 1.3, served certificate SHA-256 equals the pin in `ics.env`; `/healthz` 200; `/`, `/docs`, `/openapi.json`, `/readyz`, `/api/v1/auth/login`, `/api/v1/version`, `/static/index.html` -> 404 for GET and POST; `GET` on the report route 405; 5000 B body -> 413; the same report route on the CONSOLE (443) -> 404; stalled body (headers promise 100 B, none sent) -> 408 after 10.0 s |
| Listener rate limit | 20 sequential bad-proof reports from one source: 18 x 401, 2 x 429 (token bucket 12 per 60 s; the ~1.5 s per request of the test client refilled ~6 tokens) |
| Not exercised | the nftables source restriction from a denied network (the lab zone has only the permitted /24; the ruleset loaded and was rendered by `nft list`), guest-side enrolment through the real listener (covered by the existing callback tests), the upgrade of a previously installed `ics-callback.service` host |

## 5. Tests

`ics/tests/test_hardening.py` (17): bucket semantics, denied calls do not extend a lock-out, **6 OS processes x 40 attempts on one key give exactly 30 allowed**, 8 threads, purge, console buckets use the table, listener app exposes only 2 routes and no middleware, no cookies, 404 elsewhere, the console drops the route when dedicated, body cap by Content-Length and chunked, 408 deadline, TLS required off loopback, a real `python -m ics.serve_callback` process over TLS (own certificate, pin, no Server header, 413, 404), leader election among three app instances and take-over, installer/unit/backup contents. `ics/tests/test_hardening_pve.py` (2): cluster-log detection and the running-VM pending behaviour.
## 6. Full suite

`ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-b.env ics/.venv/bin/pytest -q -p no:cacheprovider` (whole suite, 867 tests, host under heavy load): **865 passed, 2 failed** (`test_migration_chain.py::test_single_linear_chain` and `::test_upgrade_from_production_head_0008i`: they pin the Alembic head, which is now `0011`). The pins were updated; `test_migration_chain.py`, `test_hardening.py`, `test_hardening_pve.py` were re-run afterwards: 21 passed. The full suite was not repeated after that test-only change (the run started before the last edits to `ics/serve.py`, the unit file and `bootstrap.sh`, which the lab run covers; `test_hardening.py` re-ran on the final tree).
