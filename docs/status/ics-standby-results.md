# ICS warm standby + fenced promotion - lab results, 2026-11-15 (agent AW)

Design: [ADR-0012](../adr/0012-ics-warm-standby.md). Procedure: [ics-recovery.md](../runbooks/ics-recovery.md#warm-standby-and-fenced-promotion-adr-0012-lab-proven-results).
Lab: `ou-ha1` (192.168.186.52, primary), `ou-ha2` (.123, standby), `ou-ha-node1` (.27, one node agent, runbooks `service.status`, `disk.usage`); clones of `ou-base-noble`, zone oulab, `MemoryMax` 1500M / 1500M / 768M (host `free -g` available 7-8 GiB throughout, never below the 2 GiB abort line). All machines powered off afterwards. The production ICS on this host and Proxmox were not touched.
Status values (ADR-0000): rows below are **verified** only where an executed result is shown.

## What was built
Agent protocol epoch (`ou_agent.proto.EpochGate`, optional signed `epoch` field, backward compatible), `controller_state` + monotonic trigger (migration `0009a`), `ics.epoch` (role/epoch decisions, self-fencing), `ICS_ROLE=standby` (no worker, mutation guard, standby page, `/readyz` role + replication), `ics.cli promote|controller-status|standby-note`, `ics/deploy/standby/{ics-standby-prepare-primary,ics-promote,ics-standby-status}.sh`, `bootstrap.sh --standby-of ... --key-bundle ... --bundle-passphrase-file ... [--rebuild]`, `ics.keybundle` (scrypt + AES-256-GCM).

## Lab proof (executed, in order)
| # | Step | Result |
|---|---|---|
| 1 | `bootstrap.sh --listen-ip .52 --allow-cidr 192.168.186.0/24 --admin alice` on ha1 (incl. new migration) | rc 0, 83 s. Node agent installed on ha-node1 (new code), enrolled into ha1 with `scripts/lab_enroll_node.py` (the same agentclient enroll + `nodes` row as the plan executor; the approval UI was not driven) |
| 2 | ha1 drives the node: `service.status systemd-networkd` (`scripts/lab_drive_node.py`, epoch via `Runtime.agent_epoch()`) | ok; agent mark 0 -> 1 |
| 3 | `ics-standby-prepare-primary.sh --primary-ip .52 --standby-ip .123` | role `replicator`, slot, hostssl line, nft table, PostgreSQL restarted once; bundle 2081 bytes + separate passphrase; audit `standby.keys_exported` |
| 4 | `bootstrap.sh --standby-of .52 ...` on ha2 (fresh machine; a first attempt stopped at an unreadable bundle - file ownership of my copy, nothing changed) | 43 s total incl. packages + `pg_basebackup` (TLS verify-full against the primary CA). `/readyz`: `{"ready":true,"role":"standby","epoch":1,"checks":{"replication":{"ok":true,"in_recovery":true,...}}}`; `ics-migrate` logged "hot standby: skipping"; worker not started |
| 5 | Standby passivity | `POST /api/v1/auth/login` -> **503** `X-OU-Role: standby` + `retry-after`; `GET /` (text/html) -> standby page with banner (CSP `style-src 'self'`); `ics.cli verify-chain` on the standby: ok, 505 rows |
| 6 | Replication lag | idle: write/flush/replay lag 0.3/0.6/0.7 ms. Under load (500 audited commits in 1.5 s on the primary, sampled every 0.5 s): replay_lag 0.4-0.9 ms, backlog peak 648 bytes, 0 after 0.5 s. Standby `/readyz` `replay_backlog_bytes: 0`; `heartbeat_age_seconds` 1.7-2.6 (bounded by the 5 s primary heartbeat) |
| 7 | `ics-promote.sh` while ha1 still alive | **refused** (rc 1): "the primary is still streaming ... stop it first or give --fence-old-dsn-file"; nothing changed |
| 8 | **Kill ha1** (`machinectl terminate`, T0) -> `ics-promote.sh --confirm 'promote ou-ha2'` | position `replay_lsn=0/30658D0`, last replayed commit 1.7 s before the kill, `audit_rows=505`; epoch **1 -> 2**; audit chain `ok`, 506 rows; announce to the node: `ok`, `agent_epoch: 2`; pg_promote 0.7 s, command total 1.1 s |
| 9 | ha2 drives the node (`service.status`) | `status ok`, `sent_epoch 2`, `agent_epoch 2` (in the audit log as `runbook.executed` epoch 2) |
| 10 | **RTO** (measured from the kill, zero operator think time) | **3.1 s** to "promotion finished", **4.4 s** to the first signed request executed by an agent through the new primary. A human decision to promote (verify the primary is dead) comes on top; the mechanism itself is seconds. RPO: data replicated within the lag (< 1 ms observed; the promote event records the replay position) |
| 11 | Restart ha1 (old primary comes back as a primary: epoch 1, role primary, `/readyz` ready) and send the same harmless runbook | agent response **`rejected` / `stale_epoch`**, "controller epoch 1 is lower than the highest seen 2", `agent_epoch: 2`; nothing executed. ha1 **self-fenced**: `controller_state.role='fenced'`, note "self-fenced: an agent has seen epoch 2 > ours 1"; a second attempt is refused in code before anything is sent; `/readyz` -> `ready:false, fenced:true` |
| 12 | Audit chain on the new primary | `verify-chain` ok, 507 rows, head continues the replicated chain; events `standby.keys_exported`, `controller.promoted` (old/new epoch, replay lsn, last replayed commit, rows at promotion), `runbook.executed` epoch 1 (before) and epoch 2 (after) |
| 13 | Old primary returns as a standby: prepare on ha2 (`--standby-ip .52`), bundle copied, `bootstrap.sh --standby-of .123 ... --rebuild` on ha1 | 26 s; ha1 `/readyz` standby, epoch 2, replication ok; ha2 `pg_stat_replication`: streaming, replay_lag 0.8 ms |

## Tests
New: `tests/test_agent_epoch.py` (agent protocol, via the real HTTPS fake agent: epoch-less compat, lower epoch refused and nothing executed, higher epoch learned, persistence across restart, malformed epoch types, fencing hook), `tests/test_standby.py` (role decisions, DB monotonic trigger, self-fence + audit, standby refuses to sign, read-only API + banner + readyz on a non-replica is 503, key bundle seal/tamper/wrong passphrase/path names, env flip). Full suite (`ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-b.env pytest -q -p no:cacheprovider`): **545 passed** (528 before + 17 new).

## Limits / not proven
- Network partition (primary alive, standby cannot see it) was not simulated; the code path is the `streaming`/`--fence-old-dsn-file` refusal (step 7 shows the refusal while alive).
- Agents that are unreachable during promotion learn the epoch late; until then a resurrected old primary could still drive *them* (ADR-0012, residual risks). One node was tested.
- The console SPA has no in-app banner; the standby serves a static standby page and `X-OU-Role` (a standby cannot log in anyway: login writes sessions). No operator login/plan flow was exercised on the promoted controller beyond `/readyz` and a 422 from the login endpoint (accepting writes).
- Enrollment/runbook driving in the lab used scripts that mirror the executor (no plan/approval UI).
- Customer-facing front-end cut-over (address/DNS move) is manual (runbook).
- Witness/automatic failover: design only. Backups remain required (replication replicates corruption and deletes).
- Not exercised: PostgreSQL restart/WAL-retention edge (`max_slot_wal_keep_size` slot loss), key rotation re-bundle, `--fence-old-dsn-file` happy path.
