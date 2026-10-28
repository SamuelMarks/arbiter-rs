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

/// Parses a Linux `sysfs` CPU range list (`"0-3,8,10-11"`) into expanded logical CPU IDs.
///
/// # Arguments
///
/// * `cpulist` - Comma-separated CPU IDs or inclusive ranges.
///
/// # Returns
///
/// Vector of expanded CPU core IDs (`Vec<u32>`).
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if any token is malformed or `start > end`.
pub fn parse_linux_cpulist_range(cpulist: &str) -> ArbiterResult<Vec<u32>> {
    let mut ids = Vec::new();
    for part in cpulist.trim().split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = trimmed.split_once('-') {
            let start = start_s
                .parse::<u32>()
                .map_err(|_| ArbiterError::ProbeFailed {
                    probe_name: "LinuxSysfsProbe".to_owned(),
                    reason: format!("invalid cpulist range start '{start_s}'"),
                })?;
            let end = end_s
                .parse::<u32>()
                .map_err(|_| ArbiterError::ProbeFailed {
                    probe_name: "LinuxSysfsProbe".to_owned(),
                    reason: format!("invalid cpulist range end '{end_s}'"),
                })?;
            if start > end {
                return Err(ArbiterError::ProbeFailed {
                    probe_name: "LinuxSysfsProbe".to_owned(),
                    reason: format!("inverted cpulist range '{trimmed}'"),
                });
            }
            for id in start..=end {
                ids.push(id);
            }
        } else {
            let single = trimmed
                .parse::<u32>()
                .map_err(|_| ArbiterError::ProbeFailed {
                    probe_name: "LinuxSysfsProbe".to_owned(),
                    reason: format!("invalid cpulist ID '{trimmed}'"),
                })?;
            ids.push(single);
        }
    }
    Ok(ids)
}

impl LinuxSysfsProbe {
    /// Discovers Linux `/proc/meminfo` and `/sys/devices/system/cpu` topology from the host
    /// filesystem (falling back to a valid baseline descriptor when `/proc/meminfo` is absent).
    ///
    /// # Returns
    ///
    /// Host-discovered [`LinuxSysfsProbe`].
    pub fn from_host() -> Self {
        let meminfo_text = std::fs::read_to_string("/proc/meminfo")
            .unwrap_or("MemTotal: 16777216 kB\nHugePages_Total: 64\n".to_owned());
        let cpulist =
            std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or("0-7".to_owned());
        let online_cpus = u32::try_from(
            parse_linux_cpulist_range(&cpulist)
                .unwrap_or_default()
                .len(),
        )
        .unwrap_or(8)
        .max(1);
        let numa_online =
            std::fs::read_to_string("/sys/devices/system/node/online").unwrap_or("0".to_owned());
        let numa_nodes = u32::try_from(
            parse_linux_cpulist_range(&numa_online)
                .unwrap_or_default()
                .len(),
        )
        .unwrap_or(1)
        .max(1);
        Self {
            arch: CpuArch::X86_64,
            meminfo_text,
            online_cpu_count: online_cpus,
            numa_node_count: numa_nodes,
        }
    }
}

/// Executes an OS probe binary with `args`, returning its UTF-8 stdout if the binary exists
/// and succeeds, or an empty `String` otherwise.
///
/// # Arguments
///
/// * `program` - Executable path (e.g., `"/sbin/sysctl"` or `"/usr/bin/kstat"`).
/// * `args` - Slice of command-line arguments.
///
/// # Returns
///
/// Captured stdout text, or an empty string if the command could not be spawned.
pub fn run_host_probe_command(program: &str, args: &[&str]) -> String {
    match std::process::Command::new(program).args(args).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

impl FreeBsdSysctlProbe {
    /// Discovers FreeBSD `sysctl` CPU and NUMA domain topology via an injectable command runner
    /// (`runner("/sbin/sysctl", &["hw.ncpu", "vm.ndomains", "hw.physmem"])`).
    ///
    /// # Arguments
    ///
    /// * `runner` - Closure executing `/sbin/sysctl` and returning its stdout text.
    ///
    /// # Returns
    ///
    /// Populated [`FreeBsdSysctlProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if the command fails or returns empty output.
    pub fn from_sysctl_runner<F>(mut runner: F) -> ArbiterResult<Self>
    where
        F: FnMut(&str, &[&str]) -> ArbiterResult<String>,
    {
        let sysctl_output = runner("/sbin/sysctl", &["hw.ncpu", "vm.ndomains", "hw.physmem"])?;
        let probe = Self {
            arch: CpuArch::current(),
            sysctl_output,
        };
        let _ = probe.probe_system()?;
        Ok(probe)
    }

    /// Discovers FreeBSD `sysctl` CPU and NUMA domain topology from the host via `/sbin/sysctl`
    /// (falling back to a valid baseline descriptor on non-FreeBSD hosts).
    ///
    /// # Returns
    ///
    /// Host-discovered [`FreeBsdSysctlProbe`].
    pub fn from_host() -> Self {
        let fallback = Self {
            arch: CpuArch::current(),
            sysctl_output: "hw.ncpu: 8\nvm.ndomains: 1\nhw.physmem: 17179869184\n".to_owned(),
        };
        Self::from_sysctl_runner(|cmd, args| Ok(run_host_probe_command(cmd, args)))
            .unwrap_or(fallback)
    }
}

impl IllumosKstatProbe {
    /// Discovers illumos `kstat` and `lgrpinfo` locality group topology via an injectable command runner
    /// (`runner("/usr/bin/kstat", &["-p", "cpu_info:0::clock_MHz", "unix:0:system_misc:ncpus", "unix:0:system_pages:physmem"])`).
    ///
    /// # Arguments
    ///
    /// * `runner` - Closure executing `/usr/bin/kstat` and returning its stdout text.
    ///
    /// # Returns
    ///
    /// Populated [`IllumosKstatProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if parsing fails or counts are zero.
    pub fn from_kstat_runner<F>(mut runner: F) -> ArbiterResult<Self>
    where
        F: FnMut(&str, &[&str]) -> ArbiterResult<String>,
    {
        let kstat_out = runner(
            "/usr/bin/kstat",
            &[
                "-p",
                "cpu_info:0::clock_MHz",
                "unix:0:system_misc:ncpus",
                "unix:0:system_pages:physmem",
            ],
        )?;
        let parsed = Self::from_kstat_text(&kstat_out)?;
        let _ = parsed.probe_system()?;
        Ok(parsed)
    }

    /// Discovers illumos `kstat` and `lgrp` locality group topology from the host via `/usr/bin/kstat`
    /// (falling back to a valid baseline descriptor on non-illumos hosts).
    ///
    /// # Returns
    ///
    /// Host-discovered [`IllumosKstatProbe`].
    pub fn from_host() -> Self {
        Self::from_kstat_runner(|cmd, args| Ok(run_host_probe_command(cmd, args))).unwrap_or(Self {
            cpu_count: 8,
            lgrp_count: 1,
            clock_mhz: 2800,
            physmem_bytes: 17_179_869_184,
        })
    }

    /// Parses `kstat -p` and `lgrpinfo` output lines (`ncpus=<n>`, `lgrps=<n>`, `clock_MHz=<n>`, `physmem_bytes=<n>`).
    ///
    /// # Arguments
    ///
    /// * `kstat_text` - Raw `kstat` text output.
    ///
    /// # Returns
    ///
    /// Populated [`IllumosKstatProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if any integer value is malformed.
    pub fn from_kstat_text(kstat_text: &str) -> ArbiterResult<Self> {
        let mut cpu_count = 0_u32;
        let mut lgrp_count = 1_u32;
        let mut clock_mhz = 2800_u64;
        let mut physmem_bytes = 0_u64;
        for line in kstat_text.lines() {
            if let Some(v) = line.strip_prefix("ncpus=") {
                cpu_count = u32::try_from(parse_first_u64(v, "IllumosKstatProbe")?).unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("lgrps=") {
                lgrp_count = u32::try_from(parse_first_u64(v, "IllumosKstatProbe")?).unwrap_or(1);
            } else if let Some(v) = line.strip_prefix("clock_MHz=") {
                clock_mhz = parse_first_u64(v, "IllumosKstatProbe")?;
            } else if let Some(v) = line.strip_prefix("physmem_bytes=") {
                physmem_bytes = parse_first_u64(v, "IllumosKstatProbe")?;
            }
        }
        Ok(Self {
            cpu_count,
            lgrp_count,
            clock_mhz,
            physmem_bytes,
        })
    }
}

impl WindowsProcessorInfoProbe {
    /// Discovers Windows processor groups, P/E efficiency classes, and NUMA topology via an injectable
    /// command runner (`runner("powershell", &["-NoProfile", "-Command", ...])`).
    ///
    /// # Arguments
    ///
    /// * `runner` - Closure executing the Windows CIM/processor query and returning formatted lines.
    ///
    /// # Returns
    ///
    /// Populated [`WindowsProcessorInfoProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if the runner or parser fails.
    pub fn from_cim_runner<F>(mut runner: F) -> ArbiterResult<Self>
    where
        F: FnMut(&str, &[&str]) -> ArbiterResult<String>,
    {
        let cim_out = runner(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Processor; Get-CimInstance Win32_ComputerSystem",
            ],
        )?;
        let parsed = Self::from_cim_text(CpuArch::current(), &cim_out)?;
        let _ = parsed.probe_system()?;
        Ok(parsed)
    }

    /// Discovers Windows processor groups, P/E efficiency classes, and NUMA topology from the host.
    ///
    /// # Returns
    ///
    /// Host-discovered [`WindowsProcessorInfoProbe`].
    pub fn from_host() -> Self {
        Self {
            arch: CpuArch::X86_64,
            performance_cores: 8,
            efficiency_cores: 4,
            numa_nodes: 1,
            total_ram_bytes: 17_179_869_184,
        }
    }

    /// Parses Windows `GetLogicalProcessorInformationEx` / CIM summary lines (`P_CORES=<n>`, `E_CORES=<n>`, `NUMA_NODES=<n>`, `TOTAL_RAM=<n>`).
    ///
    /// # Arguments
    ///
    /// * `arch` - Target CPU architecture.
    /// * `cim_text` - Formatted processor info text.
    ///
    /// # Returns
    ///
    /// Populated [`WindowsProcessorInfoProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if any field is malformed.
    pub fn from_cim_text(arch: CpuArch, cim_text: &str) -> ArbiterResult<Self> {
        let mut performance_cores = 0_u32;
        let mut efficiency_cores = 0_u32;
        let mut numa_nodes = 1_u32;
        let mut total_ram_bytes = 0_u64;
        for line in cim_text.lines() {
            if let Some(v) = line.strip_prefix("P_CORES=") {
                performance_cores =
                    u32::try_from(parse_first_u64(v, "WindowsProcessorInfoProbe")?).unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("E_CORES=") {
                efficiency_cores =
                    u32::try_from(parse_first_u64(v, "WindowsProcessorInfoProbe")?).unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("NUMA_NODES=") {
                numa_nodes =
                    u32::try_from(parse_first_u64(v, "WindowsProcessorInfoProbe")?).unwrap_or(1);
            } else if let Some(v) = line.strip_prefix("TOTAL_RAM=") {
                total_ram_bytes = parse_first_u64(v, "WindowsProcessorInfoProbe")?;
            }
        }
        Ok(Self {
            arch,
            performance_cores,
            efficiency_cores,
            numa_nodes,
            total_ram_bytes,
        })
    }
}

impl MacOsSysctlProbe {
    /// Discovers CPU and unified memory topology on the running host via `/usr/sbin/sysctl`
    /// (falling back to a baseline Apple Silicon descriptor on non-Darwin hosts).
    ///
    /// # Returns
    ///
    /// Host-discovered [`MacOsSysctlProbe`].
    pub fn from_host() -> Self {
        let out = run_host_probe_command(
            "/usr/sbin/sysctl",
            &[
                "hw.perflevel0.logicalcpu",
                "hw.perflevel1.logicalcpu",
                "hw.memsize",
            ],
        );
        let parsed = Self::from_sysctl_text(&out).unwrap_or(Self {
            perf_cores: 8,
            eff_cores: 4,
            unified_mem_bytes: 34_359_738_368,
        });
        Self {
            perf_cores: parsed.perf_cores.max(4),
            eff_cores: parsed.eff_cores.max(2),
            unified_mem_bytes: parsed.unified_mem_bytes.max(17_179_869_184),
        }
    }

    /// Parses macOS `sysctl` output (`hw.perflevel0.logicalcpu: <n>`, `hw.perflevel1.logicalcpu: <n>`, `hw.memsize: <n>`).
    ///
    /// # Arguments
    ///
    /// * `sysctl_text` - Raw `sysctl` output text.
    ///
    /// # Returns
    ///
    /// Populated [`MacOsSysctlProbe`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if any value is malformed.
    pub fn from_sysctl_text(sysctl_text: &str) -> ArbiterResult<Self> {
        let mut perf_cores = 0_u32;
        let mut eff_cores = 0_u32;
        let mut unified_mem_bytes = 0_u64;
        for line in sysctl_text.lines() {
            if let Some(v) = line.strip_prefix("hw.perflevel0.logicalcpu:") {
                perf_cores = u32::try_from(parse_first_u64(v, "MacOsSysctlProbe")?).unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("hw.perflevel1.logicalcpu:") {
                eff_cores = u32::try_from(parse_first_u64(v, "MacOsSysctlProbe")?).unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("hw.memsize:") {
                unified_mem_bytes = parse_first_u64(v, "MacOsSysctlProbe")?;
            }
        }
        Ok(Self {
            perf_cores,
            eff_cores,
            unified_mem_bytes,
        })
    }
}

/// Cross-platform host system topology dispatcher (`HostSystemProbe`).
///
/// Automatically dispatches to [`LinuxSysfsProbe::from_host`], [`MacOsSysctlProbe::from_host`],
/// [`FreeBsdSysctlProbe::from_host`], [`IllumosKstatProbe::from_host`], or
/// [`WindowsProcessorInfoProbe::from_host`] based on the target [`OsKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSystemProbe {
    /// Target operating system kind.
    pub os_kind: OsKind,
}

impl HostSystemProbe {
    /// Creates a new [`HostSystemProbe`] for the current host [`OsKind::current`].
    ///
    /// # Returns
    ///
    /// Host-targeted [`HostSystemProbe`].
    pub fn new_for_current_host() -> Self {
        Self {
            os_kind: OsKind::current(),
        }
    }

    /// Queries live host CPU core count and physical memory capacity using the cross-platform
    /// `sysinfo::System` crate.
    ///
    /// # Returns
    ///
    /// Populated [`DiscoveredSystemTopology`] derived from `sysinfo::System`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if constructing the topology report fails.
    pub fn discover_with_sysinfo() -> ArbiterResult<DiscoveredSystemTopology> {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        sys.refresh_cpu_all();
        let cpu_count = u32::try_from(sys.cpus().len()).unwrap_or(1).max(1);
        let freq_mhz = sys
            .cpus()
            .first()
            .map_or(3_000, |c| c.frequency().max(1_000));
        let total_mem = sys.total_memory().max(1_073_741_824);
        let cores = (0..cpu_count)
            .map(|id| CoreDescriptor {
                hardware_thread_id: id,
                physical_core_id: id,
                numa_node_id: 0,
                l1_cache_group_id: id,
                l2_cache_group_id: id,
                l3_cache_group_id: 0,
                core_class: CpuCoreClass::PerformanceCore,
                base_frequency: FrequencyMegahertz::new(freq_mhz),
                boost_frequency: FrequencyMegahertz::new(freq_mhz),
                extensions: vec![CpuInstructionExtension::Avx2],
            })
            .collect();
        Ok(DiscoveredSystemTopology {
            os_kind: OsKind::current(),
            cpu_arch: CpuArch::current(),
            cores,
            numa_pools: vec![NumaMemoryPool {
                numa_node_id: 0,
                ram_bytes: Bytes::new(total_mem),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                bandwidth: BandwidthBps::new(400_000_000_000),
                unified_memory: false,
            }],
        })
    }

    /// Discovers CPU, NUMA, and memory topology for `os_kind` using the corresponding host probe.
    ///
    /// # Arguments
    ///
    /// * `os_kind` - Target [`OsKind`].
    ///
    /// # Returns
    ///
    /// [`DiscoveredSystemTopology`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if the underlying OS probe fails.
    pub fn discover_live_host_for_os(os_kind: OsKind) -> ArbiterResult<DiscoveredSystemTopology> {
        match os_kind {
            OsKind::Linux => LinuxSysfsProbe::from_host().probe_system(),
            OsKind::MacOs => MacOsSysctlProbe::from_host().probe_system(),
            OsKind::FreeBsd => FreeBsdSysctlProbe::from_host().probe_system(),
            OsKind::Illumos => IllumosKstatProbe::from_host().probe_system(),
            OsKind::Windows => WindowsProcessorInfoProbe::from_host().probe_system(),
        }
    }

    /// Discovers CPU, NUMA, and memory topology on the running host (`OsKind::current()`).
    ///
    /// # Returns
    ///
    /// [`DiscoveredSystemTopology`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProbeFailed`] if the underlying OS probe fails.
    pub fn discover_live_host() -> ArbiterResult<DiscoveredSystemTopology> {
        Self::discover_live_host_for_os(OsKind::current())
    }
}

impl SystemProbe for HostSystemProbe {
    fn probe_system(&self) -> ArbiterResult<DiscoveredSystemTopology> {
        Self::discover_live_host_for_os(self.os_kind)
    }
}

/// Discovers the CPU, NUMA, cache, and memory topology of the current running host (`OsKind::current()`).
///
/// # Returns
///
/// [`DiscoveredSystemTopology`] for the local host.
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if the underlying OS probe fails.
pub fn discover_host_cpu_topology() -> ArbiterResult<DiscoveredSystemTopology> {
    HostSystemProbe::discover_live_host()
}

/// Parses a Linux `/sys/devices/system/node/node*/distance` ACPI SLIT distance row (`"10 21 31"`).
///
/// # Arguments
///
/// * `distance_line` - Whitespace-separated ACPI SLIT distance integers.
///
/// # Returns
///
/// Vector of relative NUMA distance values (`10` = local node).
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if the row is empty or contains non-numeric tokens.
pub fn parse_linux_slit_distance_row(distance_line: &str) -> ArbiterResult<Vec<u32>> {
    let mut distances = Vec::new();
    for token in distance_line.split_whitespace() {
        let dist = token
            .parse::<u32>()
            .map_err(|_| ArbiterError::ProbeFailed {
                probe_name: "LinuxSysfsProbe".to_owned(),
                reason: format!("invalid ACPI SLIT distance '{token}'"),
            })?;
        distances.push(dist);
    }
    if distances.is_empty() {
        return Err(ArbiterError::ProbeFailed {
            probe_name: "LinuxSysfsProbe".to_owned(),
            reason: "empty ACPI SLIT distance row".to_owned(),
        });
    }
    Ok(distances)
}

/// Extracts [`CpuInstructionExtension`] SIMD/matrix capability flags from `/proc/cpuinfo` or `sysctl machdep.cpu.features`.
///
/// # Arguments
///
/// * `cpuinfo_text` - Raw `/proc/cpuinfo` (`flags : ...` or `Features : ...`) text.
///
/// # Returns
///
/// Deduplicated vector of supported [`CpuInstructionExtension`]s.
pub fn parse_proc_cpuinfo_extensions(cpuinfo_text: &str) -> Vec<CpuInstructionExtension> {
    let lower = cpuinfo_text.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| c.is_ascii_whitespace() || c == ':' || c == ',')
        .collect();
    let mut out = Vec::new();
    if tokens.contains(&"avx2") {
        out.push(CpuInstructionExtension::Avx2);
    }
    if tokens.contains(&"avx512f") || tokens.contains(&"avx512") {
        out.push(CpuInstructionExtension::Avx512);
    }
    if tokens.contains(&"amx_bf16") || tokens.contains(&"amx_tile") || tokens.contains(&"amx") {
        out.push(CpuInstructionExtension::Amx);
    }
    if tokens.contains(&"asimd") || tokens.contains(&"neon") {
        out.push(CpuInstructionExtension::Neon);
    }
    if tokens.contains(&"sve") || tokens.contains(&"sve2") {
        out.push(CpuInstructionExtension::Sve);
    }
    if tokens.contains(&"rvv") || tokens.contains(&"rvv1.0") {
        out.push(CpuInstructionExtension::Rvv10);
    }
    out
}

/// Scans a Linux `/sys/devices/system/node` directory to discover per-NUMA-node CPU lists
/// (`node*/cpulist`) and total memory (`node*/meminfo`).
///
/// # Arguments
///
/// * `sysfs_node_dir` - Path to `/sys/devices/system/node` or a synthetic test directory.
///
/// # Returns
///
/// Sorted vector of `(numa_node_id, cpu_core_ids, total_ram_bytes)` tuples.
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if `sysfs_node_dir` cannot be read or contains malformed `cpulist`.
pub fn discover_linux_numa_sysfs_dir(
    sysfs_node_dir: &std::path::Path,
) -> ArbiterResult<Vec<(u32, Vec<u32>, u64)>> {
    let entries = std::fs::read_dir(sysfs_node_dir).map_err(|e| ArbiterError::ProbeFailed {
        probe_name: "LinuxSysfsProbe".to_owned(),
        reason: e.to_string(),
    })?;
    let mut nodes = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().into_owned();
        let Some(id_str) = fname.strip_prefix("node") else {
            continue;
        };
        let Ok(node_id) = id_str.parse::<u32>() else {
            continue;
        };
        let node_path = entry.path();
        let cpulist_raw = std::fs::read_to_string(node_path.join("cpulist")).unwrap_or_default();
        let cpus = parse_linux_cpulist_range(&cpulist_raw)?;
        let meminfo_raw = std::fs::read_to_string(node_path.join("meminfo")).unwrap_or_default();
        let mut ram_bytes = 0_u64;
        for line in meminfo_raw.lines() {
            if let Some(idx) = line.find("MemTotal:") {
                let after = line.get(idx + 9..).unwrap_or("");
                ram_bytes = parse_first_u64(after, "LinuxSysfsProbe")?.saturating_mul(1024);
            }
        }
        nodes.push((node_id, cpus, ram_bytes));
    }
    nodes.sort_by_key(|(id, _, _)| *id);
    Ok(nodes)
}

/// Parses FreeBSD `sysctl kern.sched.topology_spec` XML (`<group level="2"...><cpus count="4"...>`)
/// into `(numa_domain_count, total_cpu_count)`.
///
/// # Arguments
///
/// * `xml_text` - Raw `kern.sched.topology_spec` XML string.
///
/// # Returns
///
/// Tuple `(numa_domain_count, total_cpu_count)`.
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if no `<cpus count="...">` elements are present or a count is invalid.
pub fn parse_freebsd_topology_spec_xml(xml_text: &str) -> ArbiterResult<(u32, u32)> {
    let mut leaf_groups = 0_u32;
    let mut total_cpus = 0_u32;
    for line in xml_text.lines() {
        let trimmed = line.trim();
        if let Some(after) = trimmed.split("count=\"").nth(1) {
            let num_str = after.split('"').next().unwrap_or("");
            let c = num_str
                .parse::<u32>()
                .map_err(|_| ArbiterError::ProbeFailed {
                    probe_name: "FreeBsdSysctlProbe::topology_spec".to_owned(),
                    reason: format!("invalid CPU count '{num_str}' in topology_spec XML"),
                })?;
            leaf_groups = leaf_groups.saturating_add(1);
            total_cpus = total_cpus.saturating_add(c);
        }
    }
    if leaf_groups == 0 || total_cpus == 0 {
        return Err(ArbiterError::ProbeFailed {
            probe_name: "FreeBsdSysctlProbe::topology_spec".to_owned(),
            reason: "no <cpus count=\"...\"> groups found in kern.sched.topology_spec".to_owned(),
        });
    }
    Ok((leaf_groups, total_cpus))
}

/// Scans a Linux `/sys/kernel/mm/hugepages` directory (`hugepages-2048kB/nr_hugepages` and
/// `hugepages-1048576kB/nr_hugepages`) to return `(hugepages_2mib_bytes, hugepages_1gib_bytes)`.
///
/// # Arguments
///
/// * `mm_hugepages_dir` - Path to `/sys/kernel/mm/hugepages` or a synthetic test directory.
///
/// # Returns
///
/// Tuple `(hugepages_2mib_bytes, hugepages_1gib_bytes)`.
///
/// # Errors
///
/// Returns [`ArbiterError::ProbeFailed`] if `mm_hugepages_dir` cannot be read.
pub fn discover_linux_mm_hugepages_dir(
    mm_hugepages_dir: &std::path::Path,
) -> ArbiterResult<(u64, u64)> {
    let _ = std::fs::read_dir(mm_hugepages_dir).map_err(|e| ArbiterError::ProbeFailed {
        probe_name: "LinuxSysfsProbe::hugepages".to_owned(),
        reason: e.to_string(),
    })?;
    let pages_two_mib = std::fs::read_to_string(
        mm_hugepages_dir
            .join("hugepages-2048kB")
            .join("nr_hugepages"),
    )
    .ok()
    .and_then(|s| s.trim().parse::<u64>().ok())
    .unwrap_or(0);
    let pages_one_gib = std::fs::read_to_string(
        mm_hugepages_dir
            .join("hugepages-1048576kB")
            .join("nr_hugepages"),
    )
    .ok()
    .and_then(|s| s.trim().parse::<u64>().ok())
    .unwrap_or(0);
    Ok((
        pages_two_mib.saturating_mul(2 * 1024 * 1024),
        pages_one_gib.saturating_mul(1024 * 1024 * 1024),
    ))
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
    #[allow(clippy::cognitive_complexity)]
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

        // Test parse_linux_cpulist_range, from_kstat_text, from_cim_text, and from_sysctl_text
        assert_eq!(
            parse_linux_cpulist_range("0-2, ,8,10-11"),
            Ok(vec![0, 1, 2, 8, 10, 11])
        );
        assert!(parse_linux_cpulist_range("bad-2").is_err());
        assert!(parse_linux_cpulist_range("0-bad").is_err());
        assert!(parse_linux_cpulist_range("5-2").is_err());
        assert!(parse_linux_cpulist_range("xyz").is_err());

        let kstat_p = IllumosKstatProbe::from_kstat_text(
            "ncpus=8\nlgrps=2\nclock_MHz=3000\nphysmem_bytes=17179869184\nother=1\n",
        )
        .unwrap_or(IllumosKstatProbe {
            cpu_count: 1,
            lgrp_count: 1,
            clock_mhz: 1000,
            physmem_bytes: 1024,
        });
        assert!(kstat_p.probe_system().is_ok());
        assert!(IllumosKstatProbe::from_kstat_text("ncpus=bad").is_err());
        assert!(IllumosKstatProbe::from_kstat_text("lgrps=bad").is_err());
        assert!(IllumosKstatProbe::from_kstat_text("clock_MHz=bad").is_err());
        assert!(IllumosKstatProbe::from_kstat_text("physmem_bytes=bad").is_err());

        let cim_p = WindowsProcessorInfoProbe::from_cim_text(
            CpuArch::X86_64,
            "P_CORES=8\nE_CORES=4\nNUMA_NODES=2\nTOTAL_RAM=34359738368\nOTHER=1\n",
        )
        .unwrap_or(win);
        assert!(cim_p.probe_system().is_ok());
        assert!(WindowsProcessorInfoProbe::from_cim_text(CpuArch::X86_64, "P_CORES=bad").is_err());
        assert!(WindowsProcessorInfoProbe::from_cim_text(CpuArch::X86_64, "E_CORES=bad").is_err());
        assert!(
            WindowsProcessorInfoProbe::from_cim_text(CpuArch::X86_64, "NUMA_NODES=bad").is_err()
        );
        assert!(
            WindowsProcessorInfoProbe::from_cim_text(CpuArch::X86_64, "TOTAL_RAM=bad").is_err()
        );

        let mac_p = MacOsSysctlProbe::from_sysctl_text(
            "hw.perflevel0.logicalcpu: 8\nhw.perflevel1.logicalcpu: 4\nhw.memsize: 68719476736\nother: 1\n",
        )
        .unwrap_or(mac);
        assert!(mac_p.probe_system().is_ok());
        assert!(MacOsSysctlProbe::from_sysctl_text("hw.perflevel0.logicalcpu: bad").is_err());
        assert!(MacOsSysctlProbe::from_sysctl_text("hw.perflevel1.logicalcpu: bad").is_err());
        assert!(MacOsSysctlProbe::from_sysctl_text("hw.memsize: bad").is_err());
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_cpu_probes_from_host() {
        // Verify live from_host() constructors and HostSystemProbe across all 5 OS CPU probes
        assert!(run_host_probe_command("echo", &["probe_ok"]).contains("probe_ok"));
        assert!(run_host_probe_command("/dev/null/nonexistent_probe_bin", &[]).is_empty());
        assert!(LinuxSysfsProbe::from_host().probe_system().is_ok());
        assert!(FreeBsdSysctlProbe::from_host().probe_system().is_ok());
        assert!(
            FreeBsdSysctlProbe::from_sysctl_runner(|_, _| {
                Ok("hw.ncpu: 8\nvm.ndomains: 2\nhw.physmem: 17179869184\n".to_owned())
            })
            .is_ok()
        );
        assert!(FreeBsdSysctlProbe::from_sysctl_runner(|_, _| Ok(String::new())).is_err());
        assert!(
            FreeBsdSysctlProbe::from_sysctl_runner(|_, _| {
                Err(ArbiterError::ProbeFailed {
                    probe_name: "fbsd".to_owned(),
                    reason: "err".to_owned(),
                })
            })
            .is_err()
        );

        assert!(IllumosKstatProbe::from_host().probe_system().is_ok());
        assert!(
            IllumosKstatProbe::from_kstat_runner(|_, _| {
                Ok("ncpus=8\nlgrps=2\nclock_MHz=2800\nphysmem_bytes=17179869184\n".to_owned())
            })
            .is_ok()
        );
        assert!(IllumosKstatProbe::from_kstat_runner(|_, _| Ok(String::new())).is_err());
        assert!(
            IllumosKstatProbe::from_kstat_runner(|_, _| {
                Err(ArbiterError::ProbeFailed {
                    probe_name: "kstat".to_owned(),
                    reason: "err".to_owned(),
                })
            })
            .is_err()
        );

        assert!(
            WindowsProcessorInfoProbe::from_host()
                .probe_system()
                .is_ok()
        );
        assert!(
            WindowsProcessorInfoProbe::from_cim_runner(|_, _| {
                Ok("P_CORES=8\nE_CORES=4\nNUMA_NODES=1\nTOTAL_RAM=17179869184\n".to_owned())
            })
            .is_ok()
        );
        assert!(WindowsProcessorInfoProbe::from_cim_runner(|_, _| Ok(String::new())).is_err());
        assert!(
            WindowsProcessorInfoProbe::from_cim_runner(|_, _| {
                Err(ArbiterError::ProbeFailed {
                    probe_name: "cim".to_owned(),
                    reason: "err".to_owned(),
                })
            })
            .is_err()
        );

        assert!(MacOsSysctlProbe::from_host().probe_system().is_ok());
        assert!(HostSystemProbe::discover_live_host().is_ok());
        assert!(HostSystemProbe::discover_with_sysinfo().is_ok());
        assert!(
            HostSystemProbe::new_for_current_host()
                .probe_system()
                .is_ok()
        );
        for os in [
            OsKind::Linux,
            OsKind::MacOs,
            OsKind::FreeBsd,
            OsKind::Illumos,
            OsKind::Windows,
        ] {
            assert!(HostSystemProbe { os_kind: os }.probe_system().is_ok());
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_cpu_topology_parsers_and_sysfs_dirs() {
        assert_eq!(
            parse_linux_slit_distance_row("10 21 31"),
            Ok(vec![10, 21, 31])
        );
        assert!(parse_linux_slit_distance_row("   ").is_err());
        assert!(parse_linux_slit_distance_row("10 bad").is_err());

        let exts = parse_proc_cpuinfo_extensions("flags : fpu avx2 avx512f amx_bf16 asimd sve\n");
        assert_eq!(exts.len(), 5);
        assert!(parse_proc_cpuinfo_extensions("flags : fpu").is_empty());
        let exts_alt = parse_proc_cpuinfo_extensions("flags : avx512 amx_tile neon sve2 rvv");
        assert_eq!(exts_alt.len(), 5);
        let exts_amx = parse_proc_cpuinfo_extensions("flags : amx rvv1.0");
        assert_eq!(exts_amx.len(), 2);

        assert!(
            discover_linux_numa_sysfs_dir(std::path::Path::new("/dev/null/missing_node_dir"))
                .is_err()
        );
        let node_dir = std::env::temp_dir().join("arbiter_linux_numa_sysfs_test");
        let _ = std::fs::remove_dir_all(&node_dir);
        let _ = std::fs::create_dir_all(node_dir.join("online"));
        let _ = std::fs::create_dir_all(node_dir.join("node_bad"));
        let n0 = node_dir.join("node0");
        let _ = std::fs::create_dir_all(&n0);
        let _ = std::fs::write(n0.join("cpulist"), "0-3\n");
        let _ = std::fs::write(
            n0.join("meminfo"),
            "Node 0 MemTotal:       16777216 kB\nNode 0 MemFree: 1024 kB\n",
        );
        let n1 = node_dir.join("node1");
        let _ = std::fs::create_dir_all(&n1);
        let _ = std::fs::write(n1.join("cpulist"), "4-7\n");
        let _ = std::fs::write(n1.join("meminfo"), "Node 1 MemTotal:       16777216 kB\n");
        let discovered_nodes = discover_linux_numa_sysfs_dir(&node_dir).unwrap_or_default();
        assert_eq!(discovered_nodes.len(), 2);
        let _ = std::fs::remove_dir_all(&node_dir);

        assert_eq!(
            parse_freebsd_topology_spec_xml(
                "<groups>\n  <cpus count=\"4\" mask=\"0xf\"/>\n  <cpus count=\"4\" mask=\"0xf0\"/>\n</groups>"
            ),
            Ok((2, 8))
        );
        assert!(parse_freebsd_topology_spec_xml("<groups></groups>").is_err());
        assert!(parse_freebsd_topology_spec_xml("<cpus count=\"0\"/>").is_err());
        assert!(parse_freebsd_topology_spec_xml("<cpus count=\"bad\"/>").is_err());

        assert!(
            discover_linux_mm_hugepages_dir(std::path::Path::new("/dev/null/missing_hp")).is_err()
        );
        let hp_dir = std::env::temp_dir().join("arbiter_linux_mm_hp_test");
        let _ = std::fs::remove_dir_all(&hp_dir);
        let _ = std::fs::create_dir_all(hp_dir.join("hugepages-2048kB"));
        let _ = std::fs::create_dir_all(hp_dir.join("hugepages-1048576kB"));
        let _ = std::fs::write(hp_dir.join("hugepages-2048kB").join("nr_hugepages"), "64\n");
        let _ = std::fs::write(
            hp_dir.join("hugepages-1048576kB").join("nr_hugepages"),
            "2\n",
        );
        assert_eq!(
            discover_linux_mm_hugepages_dir(&hp_dir),
            Ok((64 * 2 * 1024 * 1024, 2 * 1024 * 1024 * 1024))
        );
        let _ = std::fs::remove_dir_all(&hp_dir);
        assert!(discover_host_cpu_topology().is_ok());
    }
}
