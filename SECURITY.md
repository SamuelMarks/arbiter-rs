# Arbiter (`arbiter-rs`) — Security & Safety Model

This document outlines the zero-trust security architecture, split-brain prevention guarantees, and compile-time safety invariants enforced across the `arbiter-rs` workspace.

---

## 1. Zero-Trust Workload Identity & Wire Security (`arbiter-net::security`)

- **SPIFFE / SPIRE Mutual TLS (mTLS)**: Every Master, Agent, Executor, and Task is identified by a validated [`SpiffeId`](crates/arbiter-core/src/ids.rs) (`spiffe://<trust-domain>/role/<role>/task/<task-id>`) backed by short-lived X.509 and JWT SVIDs with automated background rotation.
- **Declarative RBAC / ABAC Policy Engine**: All control-plane mutations (task submission, quota modification, election group failover, STONITH fencing) are authorized against role and attribute policies prior to state-store execution.
- **AEAD Secret Envelopes**: Workload secrets are sealed with authenticated encryption with associated data (`AEAD`) in transit and at rest, and unsealed exclusively into ephemeral in-memory `tmpfs` mounts inside the task's isolated sandbox.

---

## 2. Split-Brain Immunity & Linearizability Guarantees (`arbiter-store::election`, `arbiter-store::ha_generic`)

- **Monotonic Fencing Tokens (`FencingToken`)**: Every lease acquisition or standby promotion increments a strictly monotonic 64-bit `FencingToken`. Downstream storage engines, ZFS datasets, and peer replicas reject any I/O or replication frame carrying a token $< T_{	ext{current}}$.
- **3-Tier Deterministic STONITH**: No standby replica is promoted prior to lease expiration unless a verified `FenceVerificationReceipt` proves isolation via Tier 1 (in-band isolator `SIGKILL` + storage unmount + VNIC/VNET drop), Tier 2 (out-of-band BMC chassis power-off + SCSI-3/NVMe-oF reservation preemption + switch port isolation), or Tier 3 (local monotonic hardware watchdog self-demotion).

---

## 3. Compile-Time Memory & Arithmetic Safety Invariants

Every crate and binary in `arbiter-rs` is compiled with:

```rust
#![forbid(
    unsafe_code,
    missing_docs,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing
)]
#![deny(clippy::float_arithmetic)]
```

- **Zero `unsafe` Code**: Eliminates memory corruption, data races, and undefined behavior across all 14 crates and 5 binaries.
- **Zero Panics or Unchecked Indexing**: All slice/collection accesses use `.get()` / `.first()` / `.last()` and all arithmetic uses checked or saturating fixed-point operations funneling into the single unified `arbiter_core::error::ArbiterError` enum.
