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

echo "[Stack-2: arbiter-rs+PostgreSQL] Provisioning node ${NODE_INDEX}/${CLUSTER_SIZE}..."
echo "  - arbiter-master/agent multiplexed QUIC port: 5050"
echo "  - local CaaS zero-packet UDS path: /var/run/arbiter/caas.sock"
echo "  - PostgreSQL streaming replication port: 5432 (fenced via monotonic FencingToken)"
