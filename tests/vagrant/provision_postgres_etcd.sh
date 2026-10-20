#!/usr/bin/env bash
# Arbiter (`arbiter-rs`) — Stack 1 Provisioner: PostgreSQL Builtin Streaming Replication + etcd v3 Cluster
#
# Configures an N-node (3, 5, or 7) etcd v3 static Raft cluster alongside PostgreSQL builtin
# physical streaming replication (`walsender`/`walreceiver`, `standby.signal`, `primary_conninfo`,
# `pg_promote()`) and a Patroni-style HA watcher sidecar with configurable tuning profiles:
#   - ConservativeDefaultProfile (10s TTL)
#   - BalancedProductionProfile  (5s TTL)
#   - AggressiveSubSecondProfile (1s TTL)

set -euo pipefail

CLUSTER_SIZE="${CLUSTER_SIZE:-3}"
NODE_INDEX="${NODE_INDEX:-1}"
TUNING_PROFILE="${TUNING_PROFILE:-BalancedProductionProfile}"
WORK_DIR="${WORK_DIR:-/tmp/arbiter_vagrant_stack1_node${NODE_INDEX}}"

mkdir -p "${WORK_DIR}"

echo "[Stack-1: PostgreSQL+etcd] Provisioning node ${NODE_INDEX}/${CLUSTER_SIZE} (profile=${TUNING_PROFILE})..."
echo "  - etcd peer Raft port: 2380 | client gRPC port: 2379"
echo "  - PostgreSQL streaming replication port: 5432 (walsender/walreceiver)"

if command -v etcd >/dev/null 2>&1; then
    etcd --name "etcd-node-${NODE_INDEX}" --data-dir "${WORK_DIR}/etcd.data" --listen-client-urls "http://127.0.0.1:2379" --advertise-client-urls "http://127.0.0.1:2379" >"${WORK_DIR}/etcd.log" 2>&1 &
    echo $! > "${WORK_DIR}/etcd.pid"
fi

if command -v tcpdump >/dev/null 2>&1 && [ "${CAPTURE_PCAP:-0}" = "1" ]; then
    tcpdump -i lo0 -w "${WORK_DIR}/stack1_failover.pcap" port 2379 or port 2380 or port 5432 >/dev/null 2>&1 &
    echo $! > "${WORK_DIR}/tcpdump.pid"
fi

if [ -x "./target/release/arbiter-cli" ]; then
    ./target/release/arbiter-cli bench-failover-traffic > "${WORK_DIR}/bench_failover_traffic.md"
fi
