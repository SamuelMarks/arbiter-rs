//! Hardware interconnect topology graph (`HardwareTopologyGraph`) for single-host and multi-host fabrics.
//!
//! Models CPU sockets, NUMA nodes, `PCIe` root complexes/switches, GPUs, TPU chips, RDMA NICs,
//! and storage controllers connected by weighted edges (`NVLink`, `NVSwitch`, Infinity Fabric,
//! TPU ICI, `PCIe` Gen3..Gen6, QPI/UPI, `InfiniBand`, and `RoCE`).

use std::collections::{BTreeMap, VecDeque};

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};
use crate::ids::DeviceId;
use crate::units::{BandwidthBps, LatencyNanoseconds};

/// Classification of a hardware node inside a [`HardwareTopologyGraph`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum TopologyNodeKind {
    /// Physical CPU socket package.
    SocketNode,
    /// Non-Uniform Memory Access (`NUMA`) domain.
    NumaNode,
    /// `PCIe` Root Complex attached to a CPU/NUMA domain.
    PcieRootComplex,
    /// Dedicated `PCIe` switch (e.g., Broadcom PEX).
    PcieSwitch,
    /// Physical or logical CPU core.
    CpuCoreNode,
    /// Physical GPU or hardware MIG partition.
    GpuNode,
    /// Physical Google Cloud TPU or Edge TPU chip.
    TpuChipNode,
    /// Network or RDMA Fabric NIC (`InfiniBand`, `RoCEv2`, `EFA`, Crossbow, `VNET`).
    NicNode,
    /// `NVMe` or storage host bus adapter controller.
    StorageControllerNode,
}

/// Hardware node in the topology graph.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TopologyNode {
    /// Unique identifier for this hardware node.
    pub id: DeviceId,
    /// Hardware classification of this node.
    pub kind: TopologyNodeKind,
    /// Affinitized NUMA domain index.
    pub numa_node_id: u32,
}

/// Physical interconnect link technology between two hardware nodes.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum InterconnectKind {
    /// Cross-socket CPU coherent interconnect (`Intel UPI`/`QPI`, `AMD xGMI`).
    NumaQpiUpi,
    /// `PCIe` Generation 3.0 link.
    PcieGen3,
    /// `PCIe` Generation 4.0 link.
    PcieGen4,
    /// `PCIe` Generation 5.0 link.
    PcieGen5,
    /// `PCIe` Generation 6.0 link.
    PcieGen6,
    /// Direct point-to-point NVIDIA `NVLink` bridge.
    NvLink,
    /// Switched fabric NVIDIA `NVSwitch` interconnect.
    NvSwitch,
    /// AMD Infinity Fabric (`xGMI`) GPU-to-GPU or GPU-to-CPU link.
    AmdInfinityFabric,
    /// Google TPU Inter-Chip Interconnect (`ICI`) optical/copper torus link.
    TpuIci,
    /// Switched `InfiniBand` RDMA fabric link.
    InfiniBandFabric,
    /// Switched RDMA over Converged Ethernet (`RoCEv2`) fabric link.
    RoCEFabric,
}

/// Directed or bidirectional weighted interconnect edge between two [`TopologyNode`]s.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct InterconnectEdge {
    /// Source hardware node ID.
    pub source: DeviceId,
    /// Target hardware node ID.
    pub target: DeviceId,
    /// Physical link technology.
    pub kind: InterconnectKind,
    /// Link bandwidth in bits per second (must be non-zero).
    pub bandwidth: BandwidthBps,
    /// Single-hop traversal latency in nanoseconds.
    pub latency: LatencyNanoseconds,
}

/// Computed shortest-path / highest-affinity metrics between two nodes in a [`HardwareTopologyGraph`].
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AffinityScore {
    /// Number of interconnect hops along the optimal path (`0` if same node).
    pub hops: u32,
    /// Bottleneck (minimum) link bandwidth along the path in bits per second.
    pub bottleneck_bandwidth: BandwidthBps,
    /// Cumulative hop latency along the path in nanoseconds.
    pub total_latency: LatencyNanoseconds,
    /// Composite integer affinity score (higher is better; favors fewer hops, higher bandwidth, lower latency).
    pub composite_score: u64,
}

/// Hardware topology graph representing all compute, memory, accelerator, storage, and fabric nodes on an Agent or Pod.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(derive(Debug))]
pub struct HardwareTopologyGraph {
    /// Registered hardware nodes keyed by [`DeviceId`].
    nodes: BTreeMap<DeviceId, TopologyNode>,
    /// Directed interconnect edges in the topology.
    edges: Vec<InterconnectEdge>,
}

impl HardwareTopologyGraph {
    /// Creates an empty [`HardwareTopologyGraph`].
    ///
    /// # Returns
    ///
    /// Empty [`HardwareTopologyGraph`].
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
        }
    }

    /// Registers a hardware node in the topology graph.
    ///
    /// # Arguments
    ///
    /// * `node` - The [`TopologyNode`] to insert.
    ///
    /// # Returns
    ///
    /// `Ok(())` if inserted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DuplicateDeviceId`] if a node with the same [`DeviceId`] already exists.
    pub fn add_node(&mut self, node: TopologyNode) -> ArbiterResult<()> {
        if self.nodes.contains_key(&node.id) {
            return Err(ArbiterError::DuplicateDeviceId {
                device_id: node.id.to_string(),
            });
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// Adds a directed interconnect edge between two existing hardware nodes.
    ///
    /// # Arguments
    ///
    /// * `edge` - The [`InterconnectEdge`] to add.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid and added.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArbiterError::DeviceNotFound`] if `edge.source` or `edge.target` is not in the graph.
    /// - [`ArbiterError::InvalidTopologyGraph`] if `edge.source == edge.target` (self-loop).
    /// - [`ArbiterError::InvalidResourceQuantity`] if `edge.bandwidth` is zero.
    pub fn add_edge(&mut self, edge: InterconnectEdge) -> ArbiterResult<()> {
        if !self.nodes.contains_key(&edge.source) {
            return Err(ArbiterError::DeviceNotFound {
                device_id: edge.source.to_string(),
            });
        }
        if !self.nodes.contains_key(&edge.target) {
            return Err(ArbiterError::DeviceNotFound {
                device_id: edge.target.to_string(),
            });
        }
        if edge.source == edge.target {
            return Err(ArbiterError::InvalidTopologyGraph {
                reason: format!("self-loop edge on node '{}' is not permitted", edge.source),
            });
        }
        if edge.bandwidth.is_zero() {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "InterconnectEdge::bandwidth".to_owned(),
                quantity: 0,
                reason: "interconnect bandwidth must be greater than zero".to_owned(),
            });
        }
        self.edges.push(edge);
        Ok(())
    }

    /// Adds a bidirectional pair of interconnect edges between `node_a` and `node_b`.
    ///
    /// # Arguments
    ///
    /// * `node_a` - First endpoint [`DeviceId`].
    /// * `node_b` - Second endpoint [`DeviceId`].
    /// * `kind` - [`InterconnectKind`] of the link.
    /// * `bandwidth` - Link [`BandwidthBps`].
    /// * `latency` - Link [`LatencyNanoseconds`].
    ///
    /// # Returns
    ///
    /// `Ok(())` when both directions are added.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if either endpoint is missing, identical, or has zero bandwidth.
    pub fn add_bidirectional_link(
        &mut self,
        node_a: DeviceId,
        node_b: DeviceId,
        kind: InterconnectKind,
        bandwidth: BandwidthBps,
        latency: LatencyNanoseconds,
    ) -> ArbiterResult<()> {
        self.add_edge(InterconnectEdge {
            source: node_a.clone(),
            target: node_b.clone(),
            kind,
            bandwidth,
            latency,
        })?;
        self.add_edge(InterconnectEdge {
            source: node_b,
            target: node_a,
            kind,
            bandwidth,
            latency,
        })
    }

    /// Returns a reference to the map of nodes in this graph.
    ///
    /// # Returns
    ///
    /// Reference to `BTreeMap<DeviceId, TopologyNode>`.
    pub const fn nodes(&self) -> &BTreeMap<DeviceId, TopologyNode> {
        &self.nodes
    }

    /// Returns the slice of directed interconnect edges in this graph.
    ///
    /// # Returns
    ///
    /// Slice `&[InterconnectEdge]`.
    pub fn edges(&self) -> &[InterconnectEdge] {
        &self.edges
    }

    /// Validates that the directed graph is a strict Directed Acyclic Graph (DAG) when hierarchical
    /// containment is required (e.g., `Socket -> Numa -> PcieRootComplex -> PcieSwitch -> Device`).
    ///
    /// Uses Kahn's topological sort algorithm.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the directed edges contain no cycles.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidTopologyGraph`] if a directed cycle is detected.
    pub fn validate_dag(&self) -> ArbiterResult<()> {
        let mut in_degree: BTreeMap<&DeviceId, usize> =
            self.nodes.keys().map(|id| (id, 0_usize)).collect();
        for edge in &self.edges {
            *in_degree.entry(&edge.target).or_insert(0) += 1;
        }
        let mut queue: VecDeque<&DeviceId> = in_degree
            .iter()
            .filter_map(|(&id, &deg)| if deg == 0 { Some(id) } else { None })
            .collect();

        let mut visited_count = 0_usize;
        while let Some(current) = queue.pop_front() {
            visited_count += 1;
            for edge in &self.edges {
                if &edge.source == current {
                    let deg = in_degree.entry(&edge.target).or_insert(1);
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(&edge.target);
                    }
                }
            }
        }
        if visited_count != self.nodes.len() {
            return Err(ArbiterError::InvalidTopologyGraph {
                reason: "cycle detected in directed topology graph".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the highest-affinity path between `source` and `target`.
    ///
    /// Evaluates reachable paths using breadth-first / widest-bandwidth path discovery,
    /// returning the [`AffinityScore`] that maximizes `composite_score`.
    ///
    /// # Arguments
    ///
    /// * `source` - Starting [`DeviceId`].
    /// * `target` - Destination [`DeviceId`].
    ///
    /// # Returns
    ///
    /// Optimal [`AffinityScore`] between `source` and `target`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeviceNotFound`] if `source` or `target` does not exist, or
    /// [`ArbiterError::IncompatibleInterconnect`] if `target` is unreachable from `source`.
    pub fn compute_affinity(
        &self,
        source: &DeviceId,
        target: &DeviceId,
    ) -> ArbiterResult<AffinityScore> {
        if !self.nodes.contains_key(source) {
            return Err(ArbiterError::DeviceNotFound {
                device_id: source.to_string(),
            });
        }
        if !self.nodes.contains_key(target) {
            return Err(ArbiterError::DeviceNotFound {
                device_id: target.to_string(),
            });
        }
        if source == target {
            return Ok(AffinityScore {
                hops: 0,
                bottleneck_bandwidth: BandwidthBps::MAX,
                total_latency: LatencyNanoseconds::ZERO,
                composite_score: u64::MAX,
            });
        }

        // State per node: best AffinityScore seen so far
        let mut best: BTreeMap<&DeviceId, AffinityScore> = BTreeMap::new();
        let mut queue: VecDeque<(&DeviceId, u32, BandwidthBps, LatencyNanoseconds)> =
            VecDeque::new();
        queue.push_back((source, 0, BandwidthBps::MAX, LatencyNanoseconds::ZERO));

        while let Some((curr, hops, bw_so_far, lat_so_far)) = queue.pop_front() {
            for edge in &self.edges {
                if &edge.source != curr {
                    continue;
                }
                let next_hops = hops.saturating_add(1);
                let next_bw = if edge.bandwidth < bw_so_far {
                    edge.bandwidth
                } else {
                    bw_so_far
                };
                let next_lat = lat_so_far.saturating_add(edge.latency);
                // Composite score: bandwidth in Gbps * 1000 / hops - latency penalty
                let bw_gbps = next_bw.get() / 1_000_000_000;
                let hop_adjusted = (bw_gbps.saturating_mul(1000)) / u64::from(next_hops);
                let lat_penalty = next_lat.get() / 100;
                let score = hop_adjusted.saturating_sub(lat_penalty).max(1);

                let candidate = AffinityScore {
                    hops: next_hops,
                    bottleneck_bandwidth: next_bw,
                    total_latency: next_lat,
                    composite_score: score,
                };

                let should_update = best
                    .get(&edge.target)
                    .is_none_or(|existing| candidate.composite_score > existing.composite_score);

                if should_update {
                    best.insert(&edge.target, candidate);
                    queue.push_back((&edge.target, next_hops, next_bw, next_lat));
                }
            }
        }

        best.get(target)
            .copied()
            .ok_or_else(|| ArbiterError::IncompatibleInterconnect {
                interconnect: "any".to_owned(),
                source_node: source.to_string(),
                target_node: target.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_graph_node_and_edge_errors() {
        let mut graph = HardwareTopologyGraph::new();
        assert!(graph.nodes().is_empty());
        assert!(graph.edges().is_empty());

        let n0 = DeviceId(String::from("numa-0"));
        let sw0 = DeviceId(String::from("pcie-sw-0"));
        let missing = DeviceId(String::from("missing-99"));

        assert!(
            graph
                .add_node(TopologyNode {
                    id: n0.clone(),
                    kind: TopologyNodeKind::NumaNode,
                    numa_node_id: 0,
                })
                .is_ok()
        );

        // Duplicate node rejection
        assert!(
            graph
                .add_node(TopologyNode {
                    id: n0.clone(),
                    kind: TopologyNodeKind::NumaNode,
                    numa_node_id: 0,
                })
                .is_err()
        );

        assert!(
            graph
                .add_node(TopologyNode {
                    id: sw0.clone(),
                    kind: TopologyNodeKind::PcieSwitch,
                    numa_node_id: 0,
                })
                .is_ok()
        );

        // Missing source or target
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: missing.clone(),
                    target: sw0.clone(),
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(500_000_000_000),
                    latency: LatencyNanoseconds::new(100),
                })
                .is_err()
        );
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: n0.clone(),
                    target: missing,
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(500_000_000_000),
                    latency: LatencyNanoseconds::new(100),
                })
                .is_err()
        );

        // Self-loop rejection
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: n0.clone(),
                    target: n0.clone(),
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(500_000_000_000),
                    latency: LatencyNanoseconds::new(100),
                })
                .is_err()
        );

        // Zero bandwidth rejection
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: n0,
                    target: sw0,
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::ZERO,
                    latency: LatencyNanoseconds::new(100),
                })
                .is_err()
        );
    }

    #[test]
    fn test_topology_graph_dag_validation() {
        let mut graph = HardwareTopologyGraph::new();
        let n0 = DeviceId(String::from("numa-0"));
        let sw0 = DeviceId(String::from("pcie-sw-0"));
        let gpu0 = DeviceId(String::from("gpu-0"));

        for id in [&n0, &sw0, &gpu0] {
            let _ = graph.add_node(TopologyNode {
                id: id.clone(),
                kind: TopologyNodeKind::GpuNode,
                numa_node_id: 0,
            });
        }

        // Valid diamond DAG edges: n0 -> sw0 -> gpu0 and n0 -> gpu0 (so gpu0 has in_degree 2)
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: n0.clone(),
                    target: sw0.clone(),
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(512_000_000_000),
                    latency: LatencyNanoseconds::new(150),
                })
                .is_ok()
        );
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: n0.clone(),
                    target: gpu0.clone(),
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(512_000_000_000),
                    latency: LatencyNanoseconds::new(150),
                })
                .is_ok()
        );
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: sw0,
                    target: gpu0.clone(),
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(512_000_000_000),
                    latency: LatencyNanoseconds::new(150),
                })
                .is_ok()
        );

        assert!(graph.validate_dag().is_ok());

        // Introduce cycle gpu0 -> n0
        assert!(
            graph
                .add_edge(InterconnectEdge {
                    source: gpu0,
                    target: n0,
                    kind: InterconnectKind::PcieGen5,
                    bandwidth: BandwidthBps::new(512_000_000_000),
                    latency: LatencyNanoseconds::new(150),
                })
                .is_ok()
        );
        assert!(graph.validate_dag().is_err());
    }

    #[test]
    fn test_topology_affinity_scoring() {
        let mut graph = HardwareTopologyGraph::new();
        let gpu0 = DeviceId(String::from("gpu-0"));
        let gpu1 = DeviceId(String::from("gpu-1"));
        let pcie = DeviceId(String::from("pcie-0"));
        let isolated = DeviceId(String::from("nic-isolated"));
        let unknown = DeviceId(String::from("unknown"));

        for id in [&gpu0, &gpu1, &pcie, &isolated] {
            let _ = graph.add_node(TopologyNode {
                id: id.clone(),
                kind: TopologyNodeKind::GpuNode,
                numa_node_id: 0,
            });
        }

        // Slow 2-hop path via PCIe (64 Gbps) and fast 1-hop path via NVLink (7200 Gbps)
        assert!(
            graph
                .add_bidirectional_link(
                    gpu0.clone(),
                    pcie.clone(),
                    InterconnectKind::PcieGen4,
                    BandwidthBps::new(256_000_000_000),
                    LatencyNanoseconds::new(500),
                )
                .is_ok()
        );
        assert!(
            graph
                .add_bidirectional_link(
                    pcie,
                    gpu1.clone(),
                    InterconnectKind::PcieGen4,
                    BandwidthBps::new(128_000_000_000),
                    LatencyNanoseconds::new(500),
                )
                .is_ok()
        );
        assert!(
            graph
                .add_bidirectional_link(
                    gpu0.clone(),
                    gpu1.clone(),
                    InterconnectKind::NvLink,
                    BandwidthBps::new(7_200_000_000_000),
                    LatencyNanoseconds::new(50),
                )
                .is_ok()
        );

        // Error cases in compute_affinity
        assert!(graph.compute_affinity(&unknown, &gpu0).is_err());
        assert!(graph.compute_affinity(&gpu0, &unknown).is_err());
        assert!(graph.compute_affinity(&gpu0, &isolated).is_err());
        assert!(
            graph
                .add_bidirectional_link(
                    unknown,
                    gpu0.clone(),
                    InterconnectKind::NvLink,
                    BandwidthBps::new(100),
                    LatencyNanoseconds::new(10),
                )
                .is_err()
        );

        // Self affinity
        let self_score = graph.compute_affinity(&gpu0, &gpu0).unwrap_or_default();
        assert_eq!(self_score.hops, 0);

        // NVLink 1-hop path must win over 2-hop PCIe path
        let affinity = graph.compute_affinity(&gpu0, &gpu1).unwrap_or_default();
        assert_eq!(affinity.hops, 1);
        assert_eq!(
            affinity.bottleneck_bandwidth,
            BandwidthBps::new(7_200_000_000_000)
        );
    }
}
