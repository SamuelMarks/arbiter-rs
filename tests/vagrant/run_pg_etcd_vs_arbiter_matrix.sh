#!/usr/bin/env bash
# Arbiter (`arbiter-rs`) — 3, 5, and 7-Node PostgreSQL + etcd vs. `arbiter-rs` HA Failover & Wire-Traffic Matrix Runner
#
# Iterates over N in 3 5 7, executes the deterministic multicluster benchmark (`bench-multicluster`)
# and 3/5/7-node failover & L2-L7 wire-traffic matrix (`bench-failover-traffic`), and when
# `RUN_VAGRANT_VMS=1` is set, boots the 3, 5, and 7-node Vagrant topologies and captures live
# `nftables` / `ip -s link` / `tcpdump` wire counters to verify `< 5%` calibration drift.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

echo "=== [1/3] Running Multicluster vs. Non-Multicluster Benchmark Suite ==="
cargo test --package arbiter-master --lib bench::tests::test_exact_percentiles_and_multicluster_benchmark_suite -- --nocapture

echo "=== [2/3] Running 3, 5, and 7-Node PostgreSQL + etcd vs. arbiter-rs Failover & L2-L7 Wire-Traffic Matrix ==="
cargo test --package arbiter-master --lib bench::tests::test_failover_traffic_matrix_3_5_7_nodes -- --nocapture
cargo test --package arbiter-telemetry --lib wire_accounting::tests::test_l2_l7_wire_accounting_across_3_5_7_and_1000_nodes -- --nocapture

if [[ "${RUN_VAGRANT_VMS:-0}" == "1" ]]; then
    for n in 3 5 7; do
        echo "=== [3/3] Validating live Vagrant topology for CLUSTER_SIZE=${n} ==="
        CLUSTER_SIZE="${n}" bash "${SCRIPT_DIR}/provision_postgres_etcd.sh"
        CLUSTER_SIZE="${n}" bash "${SCRIPT_DIR}/provision_arbiter_postgres.sh"
    done
else
    echo "=== [3/3] Verifying provisioning scripts in dry-run mode across CLUSTER_SIZE in 3 5 7 ==="
    for n in 3 5 7; do
        CLUSTER_SIZE="${n}" bash "${SCRIPT_DIR}/provision_postgres_etcd.sh"
        CLUSTER_SIZE="${n}" bash "${SCRIPT_DIR}/provision_arbiter_postgres.sh"
    done
fi

echo "=== 3/5/7-Node PostgreSQL+etcd vs. arbiter-rs Matrix Complete ==="
