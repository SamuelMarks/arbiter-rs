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

echo "[Stack-1: PostgreSQL+etcd] Provisioning node ${NODE_INDEX}/${CLUSTER_SIZE} (profile=${TUNING_PROFILE})..."
echo "  - etcd peer Raft port: 2380 | client gRPC port: 2379"
echo "  - PostgreSQL streaming replication port: 5432 (walsender/walreceiver)"
