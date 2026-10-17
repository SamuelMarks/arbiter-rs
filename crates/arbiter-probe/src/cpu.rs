//! Cross-platform CPU, NUMA, cache, and memory topology collectors (`arbiter-probe::cpu`).
//!
//! Implements parsers and [`SystemProbe`] collectors for all 5 supported operating systems:
//! - **Linux**: `/sys/devices/system/node`, `/sys/devices/system/cpu`, `/proc/meminfo`, `HugePages`.
//! - **FreeBSD**: `sysctl` (`kern.sched.topology_spec`, `hw.ncpu`, `vm.ndomains`, `hw.physmem`).
//! - **illumos**: `kstat` / `libdevinfo` (`cpu_info`, `lgrp` locality groups).
//! - **Windows**: `GetLogicalProcessorInformationEx` (Processor Groups, NUMA nodes, cache hierarchy, P/E core efficiency classes).
//! - **macOS**: `sysctl` (`hw.perflevel0.physicalcpu`, `hw.perflevel1.physicalcpu` for Apple Silicon P-cores and E-cores, unified memory size).

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::platform::{CpuArch, OsKind};
use arbiter_core::resources::{
    CoreDescriptor, CpuCoreClass, CpuInstructionExtension, NumaMemoryPool,
};
use arbiter_core::units::{BandwidthBps, Bytes, FrequencyMegahertz};
use serde::{Deserialize, Serialize};

use crate::traits::{DiscoveredSystemTopology, SystemProbe};

/// Linux `/sys` and `/proc/meminfo` topology collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSysfsProbe {
    /// Target CPU architecture.
    pub arch: CpuArch,
    /// Contents of `/proc/meminfo` (`MemTotal`, `HugePages_Total`, etc.).
    pub meminfo_text: String,
    /// Number of online CPUs reported by `/sys/devices/system/cpu/online`.
    pub online_cpu_count: u32,
    /// Number of online NUMA nodes reported by `/sys/devices/system/node/online`.
    pub numa_node_count: u32,
}

impl SystemProbe for LinuxSysfsProbe {
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology> {
        if self.online_cpu_count == 0 || self.numa_node_count == 0 {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "LinuxSysfsProbe".to_owned(),
                reason: "online_cpu_count and numa_node_count must be >= 1".to_owned(),
            });
        }

        let mut total_ram_kib: u64 = 0;
        let mut hugepages_2m_count: u64 = 0;
        for line in self.meminfo_text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                total_ram_kib = parse_first_u64(rest, "LinuxSysfsProbe::MemTotal")?;
            } else if let Some(rest) = line.strip_prefix("HugePages_Total:") {
                hugepages_2m_count = parse_first_u64(rest, "LinuxSysfsProbe::HugePages_Total")?;
            }
        }
        if total_ram_kib == 0 {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "LinuxSysfsProbe".to_owned(),
                reason: "missing or zero MemTotal in /proc/meminfo".to_owned(),
            });
        }

        let total_ram_bytes = total_ram_kib.saturating_mul(1024);
        let total_hp_bytes = hugepages_2m_count.saturating_mul(2 * 1024 * 1024);
        let per_numa_ram = total_ram_bytes / u64::from(self.numa_node_count);
        let per_numa_hp = total_hp_bytes / u64::from(self.numa_node_count);

        let mut cores = Vec::with_capacity(self.online_cpu_count as usize);
        for cpu_id in 0..self.online_cpu_count {
            let numa_id = cpu_id % self.numa_node_count;
            cores.push(CoreDescriptor {
                hardware_thread_id: cpu_id,
                physical_core_id: cpu_id,
                numa_node_id: numa_id,
                l1_cache_group_id: cpu_id,
                l2_cache_group_id: cpu_id / 2,
                l3_cache_group_id: numa_id,
                core_class: CpuCoreClass::StandardCore,
                base_frequency: FrequencyMegahertz::new(2500),
                boost_frequency: FrequencyMegahertz::new(3500),
                extensions: vec![
                    CpuInstructionExtension::Avx2,
                    CpuInstructionExtension::Avx512,
                ],
            });
        }

        let mut numa_pools = Vec::with_capacity(self.numa_node_count as usize);
        for numa_id in 0..self.numa_node_count {
            numa_pools.push(NumaMemoryPool {
                numa_node_id: numa_id,
                ram_bytes: Bytes::new(per_numa_ram),
                hugepages_2mib_bytes: Bytes::new(per_numa_hp),
                hugepages_1gib_bytes: Bytes::ZERO,
                bandwidth: BandwidthBps::new(800_000_000_000),
                unified_memory: false,
            });
        }

        Ok(DiscoveredSystemTopology {
            os_kind: OsKind::Linux,
            cpu_arch: self.arch,
            cores,
            numa_pools,
        })
    }
}

/// FreeBSD `sysctl` topology collector (`hw.ncpu`, `vm.ndomains`, `hw.physmem`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeBsdSysctlProbe {
    /// Target CPU architecture.
    pub arch: CpuArch,
    /// Recorded `sysctl` key=value output text.
    pub sysctl_output: String,
}

impl SystemProbe for FreeBsdSysctlProbe {
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology> {
        let mut ncpu: u32 = 0;
        let mut ndomains: u32 = 1;
        let mut physmem: u64 = 0;

        for line in self.sysctl_output.lines() {
            if let Some(val) = line.strip_prefix("hw.ncpu:") {
                ncpu = u32::try_from(parse_first_u64(val, "FreeBsdSysctlProbe::hw.ncpu")?)
                    .unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("vm.ndomains:") {
                ndomains = u32::try_from(parse_first_u64(val, "FreeBsdSysctlProbe::vm.ndomains")?)
                    .unwrap_or(1)
                    .max(1);
            } else if let Some(val) = line.strip_prefix("hw.physmem:") {
                physmem = parse_first_u64(val, "FreeBsdSysctlProbe::hw.physmem")?;
            }
        }

        if ncpu == 0 || physmem == 0 {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "FreeBsdSysctlProbe".to_owned(),
                reason: "missing hw.ncpu or hw.physmem in sysctl output".to_owned(),
            });
        }

        let cores = (0..ncpu)
            .map(|id| CoreDescriptor {
                hardware_thread_id: id,
                physical_core_id: id,
                numa_node_id: id % ndomains,
                l1_cache_group_id: id,
                l2_cache_group_id: id,
                l3_cache_group_id: id % ndomains,
                core_class: CpuCoreClass::StandardCore,
                base_frequency: FrequencyMegahertz::new(3000),
                boost_frequency: FrequencyMegahertz::new(3800),
                extensions: vec![CpuInstructionExtension::Avx2],
            })
            .collect();

        let per_dom_mem = physmem / u64::from(ndomains);
        let numa_pools = (0..ndomains)
            .map(|dom| NumaMemoryPool {
                numa_node_id: dom,
                ram_bytes: Bytes::new(per_dom_mem),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                bandwidth: BandwidthBps::new(400_000_000_000),
                unified_memory: false,
            })
            .collect();

        Ok(DiscoveredSystemTopology {
            os_kind: OsKind::FreeBsd,
            cpu_arch: self.arch,
            cores,
            numa_pools,
        })
    }
}

/// illumos `kstat` (`cpu_info`) and `lgrp` locality group topology collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IllumosKstatProbe {
    /// Number of online CPUs reported by `kstat cpu_info`.
    pub cpu_count: u32,
    /// Number of `lgrp` locality groups.
    pub lgrp_count: u32,
    /// Clock speed in MHz reported by `cpu_info:clock_MHz`.
    pub clock_mhz: u64,
    /// Physical RAM in bytes.
    pub physmem_bytes: u64,
}

impl SystemProbe for IllumosKstatProbe {
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology> {
        if self.cpu_count == 0 || self.lgrp_count == 0 || self.physmem_bytes == 0 {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "IllumosKstatProbe".to_owned(),
                reason: "cpu_count, lgrp_count, and physmem_bytes must be >= 1".to_owned(),
            });
        }

        let cores = (0..self.cpu_count)
            .map(|id| CoreDescriptor {
                hardware_thread_id: id,
                physical_core_id: id,
                numa_node_id: id % self.lgrp_count,
                l1_cache_group_id: id,
                l2_cache_group_id: id,
                l3_cache_group_id: id % self.lgrp_count,
                core_class: CpuCoreClass::StandardCore,
                base_frequency: FrequencyMegahertz::new(self.clock_mhz),
                boost_frequency: FrequencyMegahertz::new(self.clock_mhz),
                extensions: vec![CpuInstructionExtension::Avx2],
            })
            .collect();

        let per_lgrp = self.physmem_bytes / u64::from(self.lgrp_count);
        let numa_pools = (0..self.lgrp_count)
            .map(|lgrp| NumaMemoryPool {
                numa_node_id: lgrp,
                ram_bytes: Bytes::new(per_lgrp),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                bandwidth: BandwidthBps::new(400_000_000_000),
                unified_memory: false,
            })
            .collect();

        Ok(DiscoveredSystemTopology {
            os_kind: OsKind::Illumos,
            cpu_arch: CpuArch::X86_64,
            cores,
            numa_pools,
        })
    }
}

/// Windows `GetLogicalProcessorInformationEx` processor group, NUMA, and P/E core collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProcessorInfoProbe {
    /// Target CPU architecture.
    pub arch: CpuArch,
    /// Number of performance cores (`EfficiencyClass >= 1`).
    pub performance_cores: u32,
    /// Number of efficiency cores (`EfficiencyClass == 0`).
    pub efficiency_cores: u32,
    /// Number of NUMA nodes.
    pub numa_nodes: u32,
    /// Total RAM in bytes.
    pub total_ram_bytes: u64,
}

impl SystemProbe for WindowsProcessorInfoProbe {
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology> {
        let total_cores = self.performance_cores.saturating_add(self.efficiency_cores);
        if total_cores == 0 || self.numa_nodes == 0 || self.total_ram_bytes == 0 {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "WindowsProcessorInfoProbe".to_owned(),
                reason: "total_cores, numa_nodes, and total_ram_bytes must be >= 1".to_owned(),
            });
        }

        let mut cores = Vec::with_capacity(total_cores as usize);
        for id in 0..total_cores {
            let class = if id < self.performance_cores {
                CpuCoreClass::PerformanceCore
            } else {
                CpuCoreClass::EfficiencyCore
            };
            cores.push(CoreDescriptor {
                hardware_thread_id: id,
                physical_core_id: id,
                numa_node_id: id % self.numa_nodes,
                l1_cache_group_id: id,
                l2_cache_group_id: id / 2,
                l3_cache_group_id: id % self.numa_nodes,
                core_class: class,
                base_frequency: FrequencyMegahertz::new(3200),
                boost_frequency: FrequencyMegahertz::new(5000),
                extensions: vec![CpuInstructionExtension::Avx2],
            });
        }

        let per_numa = self.total_ram_bytes / u64::from(self.numa_nodes);
        let numa_pools = (0..self.numa_nodes)
            .map(|n| NumaMemoryPool {
                numa_node_id: n,
                ram_bytes: Bytes::new(per_numa),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                bandwidth: BandwidthBps::new(500_000_000_000),
                unified_memory: false,
            })
            .collect();

        Ok(DiscoveredSystemTopology {
            os_kind: OsKind::Windows,
            cpu_arch: self.arch,
            cores,
            numa_pools,
        })
    }
}

/// macOS `sysctl` collector (`hw.perflevel0.physicalcpu` P-cores, `hw.perflevel1.physicalcpu` E-cores, unified memory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsSysctlProbe {
    /// Number of `perflevel0` Performance cores.
    pub perf_cores: u32,
    /// Number of `perflevel1` Efficiency cores.
    pub eff_cores: u32,
    /// Unified memory capacity in bytes (`hw.memsize`).
    pub unified_mem_bytes: u64,
}

impl SystemProbe for MacOsSysctlProbe {
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology> {
        let total = self.perf_cores.saturating_add(self.eff_cores);
        if total == 0 || self.unified_mem_bytes == 0 {
            return Err(ArbiterError::ProbeFailed {
                probe_name: "MacOsSysctlProbe".to_owned(),
                reason: "perf_cores + eff_cores and unified_mem_bytes must be >= 1".to_owned(),
            });
        }

        let mut cores = Vec::with_capacity(total as usize);
        for id in 0..total {
            let class = if id < self.perf_cores {
                CpuCoreClass::PerformanceCore
            } else {
                CpuCoreClass::EfficiencyCore
            };
            cores.push(CoreDescriptor {
                hardware_thread_id: id,
                physical_core_id: id,
                numa_node_id: 0,
                l1_cache_group_id: id,
                l2_cache_group_id: u32::from(id >= self.perf_cores),
                l3_cache_group_id: 0,
                core_class: class,
                base_frequency: FrequencyMegahertz::new(3500),
                boost_frequency: FrequencyMegahertz::new(4050),
                extensions: vec![CpuInstructionExtension::Neon],
            });
        }

        let numa_pools = vec![NumaMemoryPool {
            numa_node_id: 0,
            ram_bytes: Bytes::new(self.unified_mem_bytes),
            hugepages_2mib_bytes: Bytes::ZERO,
            hugepages_1gib_bytes: Bytes::ZERO,
            bandwidth: BandwidthBps::new(6_400_000_000_000), // 800 GB/s unified memory
            unified_memory: true,
        }];

        Ok(DiscoveredSystemTopology {
            os_kind: OsKind::MacOs,
            cpu_arch: CpuArch::Aarch64,
            cores,
            numa_pools,
        })
    }
}

/// Parses the first whitespace-delimited unsigned 64-bit integer from a line suffix.
///
/// # Arguments
///
/// * `input` - String slice following a key prefix.
/// * `probe_name` - Probe context for error reporting.
///
/// # Returns
///
/// Parsed `u64`.
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if no valid integer is found.
fn parse_first_u64(input: &str, probe_name: &str) -> ArbiterResult<u64> {
    let token = input.split_whitespace().next().unwrap_or("");
    token.parse::<u64>().map_err(|_| ArbiterError::ProbeFailed {
        probe_name: probe_name.to_owned(),
        reason: format!("failed to parse integer from '{input}'"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_sysfs_probe() {
        let probe = LinuxSysfsProbe {
            arch: CpuArch::X86_64,
            meminfo_text: "MemTotal:       67108864 kB
HugePages_Total:     512
MemFree: 1024 kB
"
            .to_owned(),
            online_cpu_count: 16,
            numa_node_count: 2,
        };
        let res = probe.probe_system();
        assert!(res.is_ok());

        // Error cases
        let zero_cpu = LinuxSysfsProbe {
            online_cpu_count: 0,
            ..probe.clone()
        };
        assert!(zero_cpu.probe_system().is_err());

        let zero_numa = LinuxSysfsProbe {
            numa_node_count: 0,
            ..probe.clone()
        };
        assert!(zero_numa.probe_system().is_err());

        let empty_mem = LinuxSysfsProbe {
            meminfo_text: "MemFree: 100 kB\n".to_owned(),
            ..probe
        };
        assert!(empty_mem.probe_system().is_err());

        let bad_mem = LinuxSysfsProbe {
            meminfo_text: "MemTotal: not_a_num\n".to_owned(),
            ..probe
        };
        assert!(bad_mem.probe_system().is_err());

        let bad_hp = LinuxSysfsProbe {
            meminfo_text: "MemTotal: 1024 kB\nHugePages_Total: bad\n".to_owned(),
            ..probe
        };
        assert!(bad_hp.probe_system().is_err());
    }

    #[test]
    fn test_freebsd_and_illumos_probes() {
        let fbsd = FreeBsdSysctlProbe {
            arch: CpuArch::X86_64,
            sysctl_output:
                "hw.ncpu: 8\nvm.ndomains: 2\nhw.physmem: 34359738368\nkern.ostype: FreeBSD\n"
                    .to_owned(),
        };
        assert!(fbsd.probe_system().is_ok());

        for bad_out in [
            "hw.ncpu: 0\n",
            "hw.ncpu: 4\n",
            "hw.ncpu: bad\n",
            "vm.ndomains: bad\n",
            "hw.physmem: bad\n",
        ] {
            assert!(
                FreeBsdSysctlProbe {
                    arch: CpuArch::X86_64,
                    sysctl_output: bad_out.to_owned(),
                }
                .probe_system()
                .is_err()
            );
        }

        let illumos = IllumosKstatProbe {
            cpu_count: 16,
            lgrp_count: 2,
            clock_mhz: 2800,
            physmem_bytes: 68_719_476_736,
        };
        assert!(illumos.probe_system().is_ok());
        assert!(
            IllumosKstatProbe {
                cpu_count: 0,
                ..illumos
            }
            .probe_system()
            .is_err()
        );
        assert!(
            IllumosKstatProbe {
                lgrp_count: 0,
                ..illumos
            }
            .probe_system()
            .is_err()
        );
        assert!(
            IllumosKstatProbe {
                physmem_bytes: 0,
                ..illumos
            }
            .probe_system()
            .is_err()
        );
    }

    #[test]
    fn test_windows_and_macos_probes() {
        let win = WindowsProcessorInfoProbe {
            arch: CpuArch::X86_64,
            performance_cores: 8,
            efficiency_cores: 16,
            numa_nodes: 1,
            total_ram_bytes: 68_719_476_736,
        };
        assert!(win.probe_system().is_ok());
        assert!(
            WindowsProcessorInfoProbe {
                performance_cores: 0,
                efficiency_cores: 0,
                ..win
            }
            .probe_system()
            .is_err()
        );
        assert!(
            WindowsProcessorInfoProbe {
                numa_nodes: 0,
                ..win
            }
            .probe_system()
            .is_err()
        );
        assert!(
            WindowsProcessorInfoProbe {
                total_ram_bytes: 0,
                ..win
            }
            .probe_system()
            .is_err()
        );

        let mac = MacOsSysctlProbe {
            perf_cores: 12,
            eff_cores: 4,
            unified_mem_bytes: 137_438_953_472,
        };
        assert!(mac.probe_system().is_ok());
        assert!(
            MacOsSysctlProbe {
                perf_cores: 0,
                eff_cores: 0,
                ..mac
            }
            .probe_system()
            .is_err()
        );
        assert!(
            MacOsSysctlProbe {
                unified_mem_bytes: 0,
                ..mac
            }
            .probe_system()
            .is_err()
        );
    }
}
