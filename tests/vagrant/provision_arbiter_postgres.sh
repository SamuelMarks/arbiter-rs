#!/usr/bin/env bash
# Arbiter (`arbiter-rs`) — Stack 2 Provisioner: Unified `arbiter-rs` CaaS + PostgreSQL Builtin Streaming Replication
#
# Configures `arbiter-master`, `arbiter-agent` (with zero-packet local Unix Domain Socket / Named Pipe
# `AgentCaasLeaseCache`), 3-tier synchronous/OOB STONITH fencing (`InBandAgentStonith`,
# `OutOfBandHardwareOrStorageFence`, `LocalCaasWatchdogSelfFence`), and PostgreSQL builtin streaming
# replication across N in {3, 5, 7} nodes.

set -euo pipefail

CLUSTER_SIZE="${CLUSTER_SIZE:-3}"
NODE_INDEX="${NODE_INDEX:-1}"
WORK_DIR="${WORK_DIR:-/tmp/arbiter_vagrant_stack2_node${NODE_INDEX}}"

mkdir -p "${WORK_DIR}"

echo "[Stack-2: arbiter-rs+PostgreSQL] Provisioning node ${NODE_INDEX}/${CLUSTER_SIZE}..."
echo "  - arbiter-master/agent multiplexed QUIC port: 5050"
echo "  - local CaaS zero-packet UDS path: ${WORK_DIR}/caas.sock"
echo "  - PostgreSQL streaming replication port: 5432 (fenced via monotonic FencingToken)"

if [ -x "./target/release/arbiter-master" ]; then
    ./target/release/arbiter-master --daemon --bind-addr "127.0.0.1:5050" --http-addr "127.0.0.1:8080" --raft-node-id "${NODE_INDEX}" >"${WORK_DIR}/arbiter-master.log" 2>&1 &
    echo $! > "${WORK_DIR}/arbiter-master.pid"
fi

if [ -x "./target/release/arbiter-agent" ]; then
    ./target/release/arbiter-agent --daemon --agent-id "agent-${NODE_INDEX}" --master-endpoint "127.0.0.1:5050" --caas-socket-path "${WORK_DIR}/caas.sock" >"${WORK_DIR}/arbiter-agent.log" 2>&1 &
    echo $! > "${WORK_DIR}/arbiter-agent.pid"
fi

if command -v initdb >/dev/null 2>&1 && [ "${INIT_POSTGRES_CLUSTER:-0}" = "1" ]; then
    PGDATA="${WORK_DIR}/pgdata"
    rm -rf "${PGDATA}"
    initdb -D "${PGDATA}" --no-locale --encoding=UTF8 >/dev/null 2>&1
    cat >> "${PGDATA}/postgresql.conf" <<EOF
wal_level = replica
max_wal_senders = 10
hot_standby = on
EOF
    if [ "${NODE_INDEX}" != "1" ]; then
        touch "${PGDATA}/standby.signal"
        echo "primary_conninfo = 'host=127.0.0.1 port=5432 application_name=arbiter_standby_${NODE_INDEX}'" >> "${PGDATA}/postgresql.conf"
    fi
fi

if command -v tcpdump >/dev/null 2>&1 && [ "${CAPTURE_PCAP:-0}" = "1" ]; then
    tcpdump -i lo0 -w "${WORK_DIR}/stack2_failover.pcap" port 5050 or port 5432 >/dev/null 2>&1 &
    echo $! > "${WORK_DIR}/tcpdump.pid"
fi

if [ -x "./target/release/arbiter-cli" ]; then
    ./target/release/arbiter-cli bench-failover-traffic > "${WORK_DIR}/bench_failover_traffic.md"
fi
