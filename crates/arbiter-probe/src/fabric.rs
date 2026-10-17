//! High-speed interconnect, `PCIe` switch, `InfiniBand`/`RoCE`, FreeBSD `VNET`, illumos Crossbow (`dladm`) discovery, and [`HardwareTopologyGraph`] assembly (`arbiter-probe::fabric`).
//!
//! Discovers RDMA NICs and interconnect edges and assembles a complete, validated
//! [`HardwareTopologyGraph`] combining NUMA domains, CPU cores, GPUs, TPU chips, and fabric NICs.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::DeviceId;
use arbiter_core::resources::{GpuDevice, RdmaDevice, RdmaFabricKind, TpuDevice};
use arbiter_core::topology::{
    HardwareTopologyGraph, InterconnectEdge, InterconnectKind, TopologyNode, TopologyNodeKind,
};
use arbiter_core::units::{BandwidthBps, LatencyNanoseconds};
use serde::{Deserialize, Serialize};

use crate::traits::{DiscoveredSystemTopology, FabricProbe};

/// Raw fabric NIC record discovered from `/sys/class/infiniband`, FreeBSD `ifconfig`, or illumos `dladm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricNicRecord {
    /// Device name (e.g., `"mlx5_0"`, `"vnic0"`, `"vnet0"`).
    pub name: String,
    /// Fabric technology kind.
    pub fabric_kind: RdmaFabricKind,
    /// Affinitized NUMA node ID.
    pub numa_node_id: u32,
    /// Line rate in Gbps.
    pub speed_gbps: u64,
    /// Available SR-IOV virtual functions.
    pub sriov_vfs: u32,
}

/// High-speed RDMA and OS virtualized fabric collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighSpeedFabricProbe {
    /// Whether the fabric probe succeeded.
    pub probe_healthy: bool,
    /// Discovered NIC records.
    pub nics: Vec<FabricNicRecord>,
}

impl FabricProbe for HighSpeedFabricProbe {
    fn probe_fabric(&self) -> ArbiterResult<(Vec<RdmaDevice>, Vec<InterconnectEdge>)> {
        if !self.probe_healthy {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "HighSpeedFabricProbe".to_owned(),
                reason: "ibverbs / dladm / sysfs fabric discovery failed".to_owned(),
            });
        }

        let mut devices = Vec::with_capacity(self.nics.len());
        let mut edges = Vec::with_capacity(self.nics.len());

        for nic in &self.nics {
            let dev_id = DeviceId::new(&nic.name).map_err(|_| ArbiterError::ProbeFailed {
                probe_name: "HighSpeedFabricProbe".to_owned(),
                reason: format!("invalid NIC device ID '{}'", nic.name),
            })?;
            let bw = BandwidthBps::new(nic.speed_gbps.saturating_mul(1_000_000_000));
            devices.push(RdmaDevice {
                device_id: dev_id.clone(),
                fabric_kind: nic.fabric_kind,
                numa_node_id: nic.numa_node_id,
                bandwidth: bw,
                sriov_vfs: nic.sriov_vfs,
            });

            let numa_dev_id =
                DeviceId::new(&format!("numa-{}", nic.numa_node_id)).unwrap_or_default();
            edges.push(InterconnectEdge {
                source: numa_dev_id,
                target: dev_id,
                kind: InterconnectKind::PcieGen5,
                bandwidth: bw,
                latency: LatencyNanoseconds::new(150),
            });
        }

        Ok((devices, edges))
    }
}

/// Assembles discovered system, GPU, TPU, and fabric components into a validated [`HardwareTopologyGraph`].
///
/// Registers:
/// - `numa-<id>` [`TopologyNodeKind::NumaNode`]s for every NUMA pool.
/// - `cpu-<id>` [`TopologyNodeKind::CpuCoreNode`]s linked to their affinitized NUMA node.
/// - GPU [`TopologyNodeKind::GpuNode`]s linked to their NUMA node + any `gpu_edges`.
/// - TPU [`TopologyNodeKind::TpuChipNode`]s linked to `numa-0`.
/// - RDMA [`TopologyNodeKind::NicNode`]s + any `fabric_edges`.
///
/// # Arguments
///
/// * `system` - Discovered CPU and NUMA topology.
/// * `gpus` - Discovered GPU devices.
/// * `gpu_edges` - Discovered GPU interconnect edges (`NVLink`, Infinity Fabric).
/// * `tpus` - Discovered TPU devices.
/// * `nics` - Discovered RDMA NICs.
/// * `fabric_edges` - Discovered `PCIe`/fabric edges.
///
/// # Returns
///
/// Validated [`HardwareTopologyGraph`].
///
/// # Errors
///
/// Returns an [`ArbiterError`] if any duplicate device ID or invalid edge is encountered.
pub fn assemble_hardware_topology_graph(
    system: &DiscoveredSystemTopology,
    gpus: &[GpuDevice],
    gpu_edges: &[InterconnectEdge],
    tpus: &[TpuDevice],
    nics: &[RdmaDevice],
    fabric_edges: &[InterconnectEdge],
) -> ArbiterResult<HardwareTopologyGraph> {
    let mut nodes: Vec<TopologyNode> = Vec::new();
    let mut all_edges: Vec<InterconnectEdge> = Vec::new();

    for pool in &system.numa_pools {
        let numa_id = DeviceId::new(&format!("numa-{}", pool.numa_node_id)).unwrap_or_default();
        nodes.push(TopologyNode {
            id: numa_id,
            kind: TopologyNodeKind::NumaNode,
            numa_node_id: pool.numa_node_id,
        });
    }

    for core in &system.cores {
        let core_id =
            DeviceId::new(&format!("cpu-{}", core.hardware_thread_id)).unwrap_or_default();
        let numa_id = DeviceId::new(&format!("numa-{}", core.numa_node_id)).unwrap_or_default();
        nodes.push(TopologyNode {
            id: core_id.clone(),
            kind: TopologyNodeKind::CpuCoreNode,
            numa_node_id: core.numa_node_id,
        });
        all_edges.push(InterconnectEdge {
            source: numa_id,
            target: core_id,
            kind: InterconnectKind::NumaQpiUpi,
            bandwidth: BandwidthBps::new(800_000_000_000),
            latency: LatencyNanoseconds::new(40),
        });
    }

    for gpu in gpus {
        let numa_id = DeviceId::new(&format!("numa-{}", gpu.numa_node_id)).unwrap_or_default();
        nodes.push(TopologyNode {
            id: gpu.device_id.clone(),
            kind: TopologyNodeKind::GpuNode,
            numa_node_id: gpu.numa_node_id,
        });
        all_edges.push(InterconnectEdge {
            source: numa_id,
            target: gpu.device_id.clone(),
            kind: InterconnectKind::PcieGen5,
            bandwidth: BandwidthBps::new(512_000_000_000),
            latency: LatencyNanoseconds::new(120),
        });
    }

    for tpu in tpus {
        let numa0 = DeviceId::new("numa-0").unwrap_or_default();
        nodes.push(TopologyNode {
            id: tpu.device_id.clone(),
            kind: TopologyNodeKind::TpuChipNode,
            numa_node_id: 0,
        });
        all_edges.push(InterconnectEdge {
            source: numa0,
            target: tpu.device_id.clone(),
            kind: InterconnectKind::TpuIci,
            bandwidth: BandwidthBps::new(3_200_000_000_000),
            latency: LatencyNanoseconds::new(80),
        });
    }

    for nic in nics {
        nodes.push(TopologyNode {
            id: nic.device_id.clone(),
            kind: TopologyNodeKind::NicNode,
            numa_node_id: nic.numa_node_id,
        });
    }

    all_edges.extend_from_slice(gpu_edges);
    all_edges.extend_from_slice(fabric_edges);

    let mut graph = HardwareTopologyGraph::new();
    for node in nodes {
        graph.add_node(node)?;
    }
    for edge in all_edges {
        graph.add_edge(edge)?;
    }

    Ok(graph)
}

#[cfg(test)]
mod tests {
    use arbiter_core::platform::CpuArch;
    use arbiter_core::resources::{TorusCoordinate, TpuGeneration};

    use super::*;
    use crate::cpu::MacOsSysctlProbe;
    use crate::gpu::AppleMetalProbe;
    use crate::tpu::{GoogleTpuProbe, TpuAccelRecord};
    use crate::traits::{GpuProbe, SystemProbe, TpuProbe};

    #[test]
    fn test_fabric_probe_and_full_topology_assembly() {
        let sys = MacOsSysctlProbe {
            perf_cores: 2,
            eff_cores: 2,
            unified_mem_bytes: 64 * 1024 * 1024 * 1024,
        }
        .probe_system()
        .unwrap_or_default();

        let (gpus, gpu_edges) = AppleMetalProbe {
            metal_available: true,
            gpu_cores: 40,
            unified_vram_bytes: 48 * 1024 * 1024 * 1024,
            neural_engine_present: true,
        }
        .probe_gpus()
        .unwrap_or_default();

        let tpus = GoogleTpuProbe {
            driver_ready: true,
            records: vec![TpuAccelRecord {
                dev_name: "edge-tpu-0".to_owned(),
                generation: TpuGeneration::EdgeTpu,
                chip_index: 0,
                hbm_bytes: 8 * 1024 * 1024,
                coordinate: TorusCoordinate { x: 0, y: 0, z: 0 },
                ici_healthy: true,
                wrap_around: false,
                slice_id: "edge-slice-0".to_owned(),
            }],
        }
        .probe_tpus()
        .unwrap_or_default();

        let fab_probe = HighSpeedFabricProbe {
            probe_healthy: true,
            nics: vec![FabricNicRecord {
                name: "mlx5_0".to_owned(),
                fabric_kind: RdmaFabricKind::RoCEv2,
                numa_node_id: 0,
                speed_gbps: 200,
                sriov_vfs: 4,
            }],
        };
        let (nics, fab_edges) = fab_probe.probe_fabric().unwrap_or_default();

        let graph =
            assemble_hardware_topology_graph(&sys, &gpus, &gpu_edges, &tpus, &nics, &fab_edges);
        assert!(graph.is_ok());

        // Error cases in HighSpeedFabricProbe
        assert!(
            HighSpeedFabricProbe {
                probe_healthy: false,
                ..fab_probe.clone()
            }
            .probe_fabric()
            .is_err()
        );

        let mut bad_nic_probe = fab_probe;
        for n in &mut bad_nic_probe.nics {
            n.name = String::new();
        }
        assert!(bad_nic_probe.probe_fabric().is_err());

        // Error case 1: duplicate node in assemble_hardware_topology_graph
        let dup_nics: Vec<RdmaDevice> = nics.iter().chain(nics.iter()).cloned().collect();
        assert!(assemble_hardware_topology_graph(&sys, &gpus, &[], &tpus, &dup_nics, &[]).is_err());

        // Error case 2: missing NUMA node when adding edge in assemble_hardware_topology_graph
        let empty_sys = DiscoveredSystemTopology {
            os_kind: arbiter_core::platform::OsKind::Linux,
            cpu_arch: CpuArch::X86_64,
            cores: sys.cores,
            numa_pools: Vec::new(),
        };
        assert!(assemble_hardware_topology_graph(&empty_sys, &[], &[], &[], &[], &[]).is_err());
    }
}
