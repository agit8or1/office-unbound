#!/bin/bash
# LAB ONLY. Two-controller partition / failover proof (docs/status/ha-partition-results.md). Needs sudo (machinectl / systemd-run -M) on the lab host.
#   blueprints/lab/ha/partition-test.sh up               start ou-ha1 ou-ha2 ou-ha-node1 (aborts when host MemAvailable < 2 GiB; MemoryMax 1.5G/1.5G/1G)
#   blueprints/lab/ha/partition-test.sh deploy           push this checkout to the machines (controllers, agent, recorder) and restart the services
#   blueprints/lab/ha/partition-test.sh run [S1..S8]     run scenarios (default: S1 S2(+S3) S4 S5 S6 S7 S8); roles swap between scenarios, the standby is rebuilt as needed
#   blueprints/lab/ha/partition-test.sh down             power the three machines off
# From-scratch machine build (create-machine.sh, bootstrap, enrol, seed, first standby): see "Rebuild from nothing" in docs/status/ha-partition-results.md.
# Env: HA_OBSERVE_SECONDS (default 45), HA_LEASE_SECONDS (default 30; the self-fence timeout T of the lease, used by S8), HA_EVIDENCE (output JSON).
exec python3 "$(dirname "$0")/partition_test.py" "$@"
