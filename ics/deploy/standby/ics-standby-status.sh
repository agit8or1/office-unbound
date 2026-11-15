#!/usr/bin/env bash
# Replication status. On the PRIMARY: connected standbys with lag. On the STANDBY: receiver state and replay position.
# Also: sudo -u ics /opt/office-unbound/ics/.venv/bin/python -m ics.cli controller-status   and   curl -s http://127.0.0.1:8088/readyz
set -euo pipefail
q() { runuser -u postgres -- psql -X -q -P pager=off -c "$1"; }
if [ "$(runuser -u postgres -- psql -X -Atc 'select pg_is_in_recovery()')" = t ]; then
  echo "== STANDBY"; q "select status, sender_host, flushed_lsn, latest_end_time from pg_stat_wal_receiver"
  q "select pg_last_wal_replay_lsn() replay_lsn, pg_last_xact_replay_timestamp() last_replayed_commit, now() - pg_last_xact_replay_timestamp() replay_delay"
else
  echo "== PRIMARY"; q "select client_addr, state, sync_state, sent_lsn, replay_lsn, write_lag, flush_lag, replay_lag from pg_stat_replication"
  q "select slot_name, active, restart_lsn, wal_status from pg_replication_slots"
fi
