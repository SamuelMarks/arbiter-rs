#!/usr/bin/env bash
# Arbiter (`arbiter-rs`) — 3/5/7-Node & 7-OS Vagrant + Bento (`../bento`) Fleet E2E Test Runner
#
# Orchestrates native compilation, hardware probe discovery (`sysfs`, `sysctl`, `kstat`, Win32),
# native OS isolation (`cgroups v2`, FreeBSD `jail`/`rctl`, illumos `zone`/`pset`/`crossbow`,
# Windows `JobObject`, macOS `sandbox-exec`/`setrlimit`), ZFS dataset delegation, multicluster
# vs. non-multicluster benchmarks, and 3/5/7-node PostgreSQL+etcd vs. `arbiter-rs` CaaS STONITH
# failover & L2-L7 wire-traffic verification across:
#   1. OmniOS (illumos)
#   2. FreeBSD
#   3. Rocky Linux (RHEL/Enterprise Linux)
#   4. Debian Linux
#   5. Alpine Linux (musl libc)
#   6. Windows
#   7. macOS (Darwin)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BENTO_DIR="$(cd "${REPO_ROOT}/../bento" 2>/dev/null && pwd || echo "${REPO_ROOT}/../bento")"

echo "=== Arbiter 3/5/7-Node & 7-OS Vagrant + Bento Matrix Verification ==="
echo "Repository Root : ${REPO_ROOT}"
echo "Bento Fork Path : ${BENTO_DIR}"

cd "${REPO_ROOT}"

# Step 1: Host native execution & full deterministic 3/5/7-node + 7-OS simulation test suite
echo "[1/3] Executing workspace unit, property, multicluster benchmark, and 3/5/7-node chaos simulation suite..."
cargo test --workspace --all-targets

# Step 2: Execute the 3/5/7-node PostgreSQL + etcd vs. arbiter-rs failover & wire-traffic matrix
echo "[2/3] Executing 3/5/7-node PostgreSQL + etcd vs. arbiter-rs failover & wire-traffic matrix..."
bash "${SCRIPT_DIR}/run_pg_etcd_vs_arbiter_matrix.sh"

# Step 3: If `RUN_VAGRANT_VMS=1` is set and `vagrant` is available, boot the 3, 5, and 7-VM Bento fleets
if [[ "${RUN_VAGRANT_VMS:-0}" == "1" ]]; then
    echo "[3/3] Booting 3, 5, and 7-node heterogeneous Vagrant fleets from ${SCRIPT_DIR}/Vagrantfile..."
    cd "${SCRIPT_DIR}"
    for n in 3 5 7; do
        CLUSTER_SIZE="${n}" vagrant validate
    done
    CLUSTER_SIZE=7 vagrant up --parallel
    for vm in arbiter-omnios arbiter-freebsd arbiter-rocky arbiter-debian arbiter-alpine arbiter-windows arbiter-macos; do
        echo "--- Verifying ${vm} ---"
        vagrant provision "${vm}"
    done
else
    echo "[3/3] Skipping live hypervisor VM boot (set RUN_VAGRANT_VMS=1 to boot all 3/5/7 Bento boxes via Vagrant)."
fi

echo "=== All 3/5/7-node and 7-OS matrix checks passed ==="
