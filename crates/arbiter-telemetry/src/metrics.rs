//! Prometheus text-format & OpenTelemetry metric registry and hardware counters (`arbiter-telemetry::metrics`).
//!
//! Tracks cluster capacity, allocated/idle resources per role, DRF dominant shares, offer latency,
//! gang scheduling latency, preemption counts, and per-task/per-device hardware counters
//! (CPU cycles, memory RSS, GPU SM utilization, VRAM usage, `NVLink`/`PCIe`/RDMA TX/RX bytes,
//! TPU duty cycle, power draw in milliwatts, and temperature in millicelsius).

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{DeviceId, TaskId};
use arbiter_core::units::{Bytes, PowerMilliwatts, TemperatureMilliCelsius};
use serde::{Deserialize, Serialize};

/// Type of metric registered in [`TelemetryRegistry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricKind {
    /// Monotonically increasing 64-bit unsigned counter.
    Counter,
    /// Point-in-time signed 64-bit integer gauge.
    Gauge,
}

impl MetricKind {
    /// Returns the Prometheus `TYPE` string (`"counter"` or `"gauge"`).
    ///
    /// # Returns
    ///
    /// Static Prometheus type name.
    pub const fn prometheus_type(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

/// Registered metric definition and current value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricEntry {
    /// Metric name (e.g., `"arbiter_cluster_cpu_millicores"`).
    pub name: String,
    /// Human-readable `HELP` description.
    pub help: String,
    /// Metric kind (`Counter` or `Gauge`).
    pub kind: MetricKind,
    /// Current integer value.
    pub value: i64,
}

/// Per-task and per-device hardware counter snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareCounterSnapshot {
    /// Optional task identifier.
    pub task_id: Option<TaskId>,
    /// Hardware device identifier.
    pub device_id: DeviceId,
    /// CPU instructions/cycles executed.
    pub cpu_cycles: u64,
    /// Resident Set Size (`RSS`) memory in bytes.
    pub memory_rss: Bytes,
    /// GPU Streaming Multiprocessor (`SM`) / Compute Unit utilization in basis points (`0..=10_000`).
    pub gpu_sm_utilization_bps: u64,
    /// GPU VRAM or TPU HBM memory consumed in bytes.
    pub accelerator_memory_used: Bytes,
    /// Interconnect (`NVLink`/`PCIe`/RDMA/ICI) transmitted bytes.
    pub interconnect_tx_bytes: Bytes,
    /// Interconnect (`NVLink`/`PCIe`/RDMA/ICI) received bytes.
    pub interconnect_rx_bytes: Bytes,
    /// TPU `TensorCore` duty cycle in basis points (`0..=10_000`).
    pub tpu_duty_cycle_bps: u64,
    /// Power draw in milliwatts.
    pub power_draw: PowerMilliwatts,
    /// Device temperature in millicelsius.
    pub temperature: TemperatureMilliCelsius,
}

/// Prometheus and OpenTelemetry metric registry.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryRegistry {
    /// Registered metrics keyed by metric name.
    metrics: BTreeMap<String, MetricEntry>,
    /// Latest hardware counter snapshots keyed by [`DeviceId`].
    hardware_counters: BTreeMap<DeviceId, HardwareCounterSnapshot>,
}

impl TelemetryRegistry {
    /// Creates an empty [`TelemetryRegistry`].
    ///
    /// # Returns
    ///
    /// Empty [`TelemetryRegistry`].
    pub const fn new() -> Self {
        Self {
            metrics: BTreeMap::new(),
            hardware_counters: BTreeMap::new(),
        }
    }

    /// Registers a new metric definition.
    ///
    /// # Arguments
    ///
    /// * `name` - Metric identifier.
    /// * `help` - Help string.
    /// * `kind` - [`MetricKind`].
    ///
    /// # Returns
    ///
    /// `Ok(())` on registration.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MetricRegistrationError`] if `name` is empty or already registered.
    pub fn register_metric(
        &mut self,
        name: &str,
        help: &str,
        kind: MetricKind,
    ) -> ArbiterResult<()> {
        if name.is_empty() || self.metrics.contains_key(name) {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: name.to_owned(),
                reason: "metric name is empty or already registered".to_owned(),
            });
        }
        self.metrics.insert(
            name.to_owned(),
            MetricEntry {
                name: name.to_owned(),
                help: help.to_owned(),
                kind,
                value: 0,
            },
        );
        Ok(())
    }

    /// Increments a registered `Counter` metric by `delta`.
    ///
    /// # Arguments
    ///
    /// * `name` - Registered counter name.
    /// * `delta` - Non-negative increment (`i64::try_from(delta)`).
    ///
    /// # Returns
    ///
    /// Updated counter value.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MetricRegistrationError`] if `name` is not registered or is not a `Counter`.
    pub fn increment_counter(&mut self, name: &str, delta: u64) -> ArbiterResult<i64> {
        let Some(entry) = self.metrics.get_mut(name) else {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: name.to_owned(),
                reason: "counter metric not registered".to_owned(),
            });
        };
        if entry.kind != MetricKind::Counter {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: name.to_owned(),
                reason: "cannot call increment_counter on a Gauge metric".to_owned(),
            });
        }
        let add_val = i64::try_from(delta).unwrap_or(i64::MAX);
        entry.value = entry.value.saturating_add(add_val);
        Ok(entry.value)
    }

    /// Sets the value of a registered `Gauge` metric.
    ///
    /// # Arguments
    ///
    /// * `name` - Registered gauge name.
    /// * `value` - New signed integer value.
    ///
    /// # Returns
    ///
    /// `Ok(())` on update.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MetricRegistrationError`] if `name` is not registered or is not a `Gauge`.
    pub fn set_gauge(&mut self, name: &str, value: i64) -> ArbiterResult<()> {
        let Some(entry) = self.metrics.get_mut(name) else {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: name.to_owned(),
                reason: "gauge metric not registered".to_owned(),
            });
        };
        if entry.kind != MetricKind::Gauge {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: name.to_owned(),
                reason: "cannot call set_gauge on a Counter metric".to_owned(),
            });
        }
        entry.value = value;
        Ok(())
    }

    /// Records a [`HardwareCounterSnapshot`] for a device.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - [`HardwareCounterSnapshot`] to record.
    pub fn record_hardware_counters(&mut self, snapshot: HardwareCounterSnapshot) {
        self.hardware_counters
            .insert(snapshot.device_id.clone(), snapshot);
    }

    /// Registers and populates Prometheus metrics from a [`TrafficComparisonReport`](crate::wire_accounting::TrafficComparisonReport).
    ///
    /// # Arguments
    ///
    /// * `report` - Reference to the [`TrafficComparisonReport`](crate::wire_accounting::TrafficComparisonReport).
    ///
    /// # Returns
    ///
    /// `Ok(())` when all failover wire-traffic metrics are registered and updated.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MetricRegistrationError`] if metric registration or update fails.
    pub fn record_wire_traffic_comparison(
        &mut self,
        report: &crate::wire_accounting::TrafficComparisonReport,
    ) -> ArbiterResult<()> {
        self.register_metric(
            "arbiter_failover_etcd_pg_wire_bytes_total",
            "Total L2-L7 wire bytes for etcd+PostgreSQL stack",
            MetricKind::Counter,
        )?;
        self.register_metric(
            "arbiter_failover_unified_wire_bytes_total",
            "Total L2-L7 wire bytes for arbiter-rs+PostgreSQL stack",
            MetricKind::Counter,
        )?;
        self.register_metric(
            "arbiter_failover_wire_bytes_saved_total",
            "Total L2-L7 wire bytes saved by arbiter-rs",
            MetricKind::Counter,
        )?;
        self.register_metric(
            "arbiter_local_caas_zero_packet_queries_total",
            "Local UDS CaaS primary lease verifications with 0 network packets",
            MetricKind::Counter,
        )?;

        let _ = self.increment_counter(
            "arbiter_failover_etcd_pg_wire_bytes_total",
            report.etcd_pg_accountant.total_l2_l7_wire_bytes.get(),
        );
        let _ = self.increment_counter(
            "arbiter_failover_unified_wire_bytes_total",
            report.arbiter_pg_accountant.total_l2_l7_wire_bytes.get(),
        );
        let _ = self.increment_counter(
            "arbiter_failover_wire_bytes_saved_total",
            report.wire_bytes_saved.get(),
        );
        let _ = self.increment_counter(
            "arbiter_local_caas_zero_packet_queries_total",
            report.arbiter_pg_accountant.total_local_caas_queries,
        );
        Ok(())
    }

    /// Renders all registered metrics and hardware counters in standard Prometheus text exposition format (`0.0.4`).
    ///
    /// # Returns
    ///
    /// Formatted Prometheus exposition string.
    pub fn render_prometheus(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        for entry in self.metrics.values() {
            let _ = writeln!(out, "# HELP {} {}", entry.name, entry.help);
            let _ = writeln!(
                out,
                "# TYPE {} {}",
                entry.name,
                entry.kind.prometheus_type()
            );
            let _ = writeln!(out, "{} {}", entry.name, entry.value);
        }
        for hw in self.hardware_counters.values() {
            let _ = writeln!(
                out,
                r#"arbiter_hw_power_milliwatts{{device="{}"}} {}"#,
                hw.device_id,
                hw.power_draw.get()
            );
            let _ = writeln!(
                out,
                r#"arbiter_hw_temperature_millicelsius{{device="{}"}} {}"#,
                hw.device_id,
                hw.temperature.get()
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_registry_and_prometheus_rendering() {
        let mut reg = TelemetryRegistry::new();

        // Empty name rejected
        assert!(reg.register_metric("", "bad", MetricKind::Counter).is_err());

        // Register counter and gauge
        assert!(
            reg.register_metric(
                "arbiter_preemptions_total",
                "Total preemptions",
                MetricKind::Counter
            )
            .is_ok()
        );
        assert!(
            reg.register_metric(
                "arbiter_cluster_cpu_millicores",
                "Cluster CPU capacity",
                MetricKind::Gauge
            )
            .is_ok()
        );

        // Duplicate registration rejected
        assert!(
            reg.register_metric(
                "arbiter_preemptions_total",
                "Duplicate",
                MetricKind::Counter
            )
            .is_err()
        );

        // Update counter and gauge
        assert_eq!(reg.increment_counter("arbiter_preemptions_total", 3), Ok(3));
        assert!(
            reg.set_gauge("arbiter_cluster_cpu_millicores", 64_000)
                .is_ok()
        );

        // Type mismatch & unknown metric errors
        assert!(reg.increment_counter("unknown", 1).is_err());
        assert!(
            reg.increment_counter("arbiter_cluster_cpu_millicores", 1)
                .is_err()
        );
        assert!(reg.set_gauge("unknown", 1).is_err());
        assert!(reg.set_gauge("arbiter_preemptions_total", 1).is_err());

        // Hardware counters
        reg.record_hardware_counters(HardwareCounterSnapshot {
            task_id: Some(TaskId::new("t-1").unwrap_or_default()),
            device_id: DeviceId::new("gpu-0").unwrap_or_default(),
            cpu_cycles: 1_000_000,
            memory_rss: Bytes::new(4096),
            gpu_sm_utilization_bps: 8_500,
            accelerator_memory_used: Bytes::new(40 * 1024 * 1024 * 1024),
            interconnect_tx_bytes: Bytes::new(1024),
            interconnect_rx_bytes: Bytes::new(2048),
            tpu_duty_cycle_bps: 0,
            power_draw: PowerMilliwatts::new(320_000),
            temperature: TemperatureMilliCelsius::new(55_000),
        });

        let prom = reg.render_prometheus();
        assert!(prom.contains("# TYPE arbiter_preemptions_total counter"));
        assert!(prom.contains("arbiter_preemptions_total 3"));
        assert!(prom.contains("arbiter_cluster_cpu_millicores 64000"));
        assert!(prom.contains(r#"arbiter_hw_power_milliwatts{device="gpu-0"} 320000"#));

        let traffic_report = crate::wire_accounting::compare_etcd_pg_vs_arbiter(
            arbiter_core::units::NodeCount::new_quorum(3).unwrap_or_default(),
            5_000,
            false,
        )
        .unwrap_or_default();
        assert!(reg.record_wire_traffic_comparison(&traffic_report).is_ok());
        // Duplicate call fails on first register_metric
        assert!(reg.record_wire_traffic_comparison(&traffic_report).is_err());

        // Also cover error propagation on 2nd, 3rd, and 4th register_metric in record_wire_traffic_comparison
        for existing_metric in [
            "arbiter_failover_unified_wire_bytes_total",
            "arbiter_failover_wire_bytes_saved_total",
            "arbiter_local_caas_zero_packet_queries_total",
        ] {
            let mut partial_reg = TelemetryRegistry::new();
            let _ =
                partial_reg.register_metric(existing_metric, "pre-existing", MetricKind::Counter);
            assert!(
                partial_reg
                    .record_wire_traffic_comparison(&traffic_report)
                    .is_err()
            );
        }
    }
}
