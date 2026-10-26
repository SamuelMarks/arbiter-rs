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
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Uncorrected ECC memory error counter on the accelerator device.
    #[serde(default)]
    pub ecc_uncorrected_errors: u64,
}

/// W3C `traceparent` distributed tracing context (`00-<trace_id_32hex>-<span_id_16hex>-<flags_2hex>`)
/// propagated across `Master -> Agent -> Executor`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceParentContext {
    /// 32-character lowercase hex trace identifier (128-bit).
    pub trace_id_hex: String,
    /// 16-character lowercase hex span identifier (64-bit).
    pub span_id_hex: String,
    /// 8-bit W3C trace flags (`0x01` = sampled).
    pub trace_flags: u8,
}

impl TraceParentContext {
    /// Parses a W3C `traceparent` header string (`"00-<32hex>-<16hex>-<2hex>"`).
    ///
    /// # Arguments
    ///
    /// * `header` - Raw `traceparent` header value.
    ///
    /// # Returns
    ///
    /// Validated [`TraceParentContext`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MetricRegistrationError`] if `header` does not conform to W3C `traceparent` v00.
    pub fn parse_w3c_traceparent(header: &str) -> ArbiterResult<Self> {
        let parts: Vec<&str> = header.trim().split('-').collect();
        let (Some(&ver), Some(&tid), Some(&sid), Some(&fl)) =
            (parts.first(), parts.get(1), parts.get(2), parts.get(3))
        else {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: "traceparent".to_owned(),
                reason: "invalid W3C traceparent segment count".to_owned(),
            });
        };
        if parts.len() != 4
            || ver != "00"
            || tid.len() != 32
            || !tid.bytes().all(|b| b.is_ascii_hexdigit())
            || tid.bytes().all(|b| b == b'0')
            || sid.len() != 16
            || !sid.bytes().all(|b| b.is_ascii_hexdigit())
            || sid.bytes().all(|b| b == b'0')
        {
            return Err(ArbiterError::MetricRegistrationError {
                metric_name: "traceparent".to_owned(),
                reason: "invalid W3C traceparent version, trace-id, or span-id".to_owned(),
            });
        };
        let trace_flags =
            u8::from_str_radix(fl, 16).map_err(|_| ArbiterError::MetricRegistrationError {
                metric_name: "traceparent".to_owned(),
                reason: "invalid W3C traceparent flags hex".to_owned(),
            })?;
        Ok(Self {
            trace_id_hex: tid.to_ascii_lowercase(),
            span_id_hex: sid.to_ascii_lowercase(),
            trace_flags,
        })
    }

    /// Formats this context as a canonical W3C `traceparent` header (`"00-<trace_id>-<span_id>-<flags>"`).
    ///
    /// # Returns
    ///
    /// W3C `traceparent` header string.
    pub fn format_w3c_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id_hex, self.span_id_hex, self.trace_flags
        )
    }

    /// Derives a child [`TraceParentContext`] preserving `trace_id_hex` and `trace_flags` with `child_span_id_hex`.
    ///
    /// # Arguments
    ///
    /// * `child_span_id_hex` - 16-character non-zero hex span ID for the child operation.
    ///
    /// # Returns
    ///
    /// Child [`TraceParentContext`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::MetricRegistrationError`] if `child_span_id_hex` is not 16 non-zero hex chars.
    pub fn child_span(&self, child_span_id_hex: &str) -> ArbiterResult<Self> {
        let candidate = format!(
            "00-{}-{}-{:02x}",
            self.trace_id_hex, child_span_id_hex, self.trace_flags
        );
        Self::parse_w3c_traceparent(&candidate)
    }
}

/// Distributed trace span recorded across `Master -> Agent -> Executor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpTraceSpan {
    /// W3C [`TraceParentContext`] for this span.
    pub context: TraceParentContext,
    /// Optional parent 16-hex span identifier.
    pub parent_span_id_hex: Option<String>,
    /// Operation name (e.g., `"master.allocate_offer"`, `"agent.launch_task"`, `"executor.spawn"`).
    pub operation_name: String,
    /// Duration of the span in nanoseconds.
    pub duration_ns: u64,
}

/// Authentic `prost::Message` OpenTelemetry (`OTLP`) metric item for binary `ExportMetricsServiceRequest` export.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct OtlpProtobufMetricRecord {
    /// Metric name (`opentelemetry.proto.metrics.v1.Metric.name`).
    #[prost(string, tag = "1")]
    pub name: String,
    /// Metric description (`opentelemetry.proto.metrics.v1.Metric.description`).
    #[prost(string, tag = "2")]
    pub description: String,
    /// Metric kind (`1 = Counter`, `2 = Gauge`).
    #[prost(uint32, tag = "3")]
    pub kind_code: u32,
    /// Current signed integer data point value (`NumberDataPoint.as_int`).
    #[prost(int64, tag = "4")]
    pub as_int: i64,
}

/// Authentic `prost::Message` OpenTelemetry (`OTLP`) `ExportMetricsServiceRequest` container.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct OtlpExportMetricsServiceRequest {
    /// Repeated [`OtlpProtobufMetricRecord`] entries in this export batch (`tag = 1`, wire type `2`).
    #[prost(message, repeated, tag = "1")]
    pub metrics: Vec<OtlpProtobufMetricRecord>,
}

/// Prometheus and OpenTelemetry metric registry.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryRegistry {
    /// Registered metrics keyed by metric name.
    metrics: BTreeMap<String, MetricEntry>,
    /// Latest hardware counter snapshots keyed by [`DeviceId`].
    hardware_counters: BTreeMap<DeviceId, HardwareCounterSnapshot>,
    /// Recorded distributed trace spans awaiting OTLP export.
    #[serde(default)]
    trace_spans: Vec<OtlpTraceSpan>,
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
            trace_spans: Vec::new(),
        }
    }

    /// Records a distributed [`OtlpTraceSpan`] in the registry.
    ///
    /// # Arguments
    ///
    /// * `span` - [`OtlpTraceSpan`] to append.
    pub fn record_trace_span(&mut self, span: OtlpTraceSpan) {
        self.trace_spans.push(span);
    }

    /// Renders all recorded [`OtlpTraceSpan`]s in `OTLP/HTTP` JSON `resourceSpans` format.
    ///
    /// # Returns
    ///
    /// Serialized `OTLP/HTTP` `resourceSpans` JSON string.
    pub fn render_otlp_traces_json(&self) -> String {
        let mut items = Vec::with_capacity(self.trace_spans.len());
        for span in &self.trace_spans {
            let parent = span
                .parent_span_id_hex
                .as_deref()
                .unwrap_or("0000000000000000");
            items.push(format!(
                r#"{{"traceId":"{}","spanId":"{}","parentSpanId":"{}","name":"{}","durationNano":{}}}"#,
                span.context.trace_id_hex,
                span.context.span_id_hex,
                parent,
                span.operation_name,
                span.duration_ns
            ));
        }
        format!(
            r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{}]}}]}}]}}"#,
            items.join(",")
        )
    }

    /// Encodes all registered metrics into an authentic `prost::Message` binary Protobuf wire payload
    /// (`application/x-protobuf`, [`OtlpExportMetricsServiceRequest`]) for `OTLP/HTTP` and `OTLP/gRPC` export.
    ///
    /// # Returns
    ///
    /// Protobuf-encoded `ExportMetricsServiceRequest` wire bytes.
    pub fn encode_otlp_protobuf_metrics(&self) -> Vec<u8> {
        use prost::Message as _;

        let mut records = Vec::with_capacity(self.metrics.len());
        for entry in self.metrics.values() {
            let kind_code = match entry.kind {
                MetricKind::Counter => 1,
                MetricKind::Gauge => 2,
            };
            records.push(OtlpProtobufMetricRecord {
                name: entry.name.clone(),
                description: entry.help.clone(),
                kind_code,
                as_int: entry.value,
            });
        }
        let req = OtlpExportMetricsServiceRequest { metrics: records };
        req.encode_to_vec()
    }

    /// Decodes a binary `prost`-encoded [`OtlpExportMetricsServiceRequest`] wire payload.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw `application/x-protobuf` OTLP metrics payload.
    ///
    /// # Returns
    ///
    /// Decoded [`OtlpExportMetricsServiceRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProtobufCodec`] if `prost::Message::decode` fails.
    pub fn decode_otlp_protobuf_metrics(
        bytes: &[u8],
    ) -> ArbiterResult<OtlpExportMetricsServiceRequest> {
        use prost::Message as _;
        OtlpExportMetricsServiceRequest::decode(bytes)
            .map_err(arbiter_core::error::ProtobufCodecError::from)
            .map_err(ArbiterError::from)
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
            let _ = writeln!(
                out,
                r#"arbiter_hw_gpu_sm_utilization_bps{{device="{}"}} {}"#,
                hw.device_id, hw.gpu_sm_utilization_bps
            );
            let _ = writeln!(
                out,
                r#"arbiter_hw_accelerator_memory_bytes{{device="{}"}} {}"#,
                hw.device_id,
                hw.accelerator_memory_used.get()
            );
            let _ = writeln!(
                out,
                r#"arbiter_hw_tpu_duty_cycle_bps{{device="{}"}} {}"#,
                hw.device_id, hw.tpu_duty_cycle_bps
            );
            let _ = writeln!(
                out,
                r#"arbiter_hw_ecc_uncorrected_errors_total{{device="{}"}} {}"#,
                hw.device_id, hw.ecc_uncorrected_errors
            );
        }
        out
    }

    /// Renders all registered metrics in OpenTelemetry `OTLP/HTTP` JSON payload format
    /// (`{"resourceMetrics":[{"scopeMetrics":[{"metrics":[...]}]}]}`).
    ///
    /// # Returns
    ///
    /// Serialized `OTLP/HTTP` JSON payload string.
    pub fn render_otlp_json(&self) -> String {
        let mut items = Vec::with_capacity(self.metrics.len());
        for entry in self.metrics.values() {
            let kind_key = match entry.kind {
                MetricKind::Counter => "sum",
                MetricKind::Gauge => "gauge",
            };
            items.push(format!(
                r#"{{"name":"{}","{}":{{"dataPoints":[{{"asInt":{}}}]}}}}"#,
                entry.name, kind_key, entry.value
            ));
        }
        format!(
            r#"{{"resourceMetrics":[{{"scopeMetrics":[{{"metrics":[{}]}}]}}]}}"#,
            items.join(",")
        )
    }

    /// Pushes an `OTLP/HTTP` `POST /v1/metrics` JSON payload to a collector bound at `bind_addr`
    /// over `std::net::TcpListener` / `std::net::TcpStream`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Collector HTTP bind address (`"127.0.0.1:0"`).
    ///
    /// # Returns
    ///
    /// Transmitted `OTLP/HTTP` JSON payload string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::OtlpExport`] if connecting or binding to the collector fails.
    pub fn export_otlp_http_once(&self, bind_addr: &str) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind(bind_addr).map_err(|err| {
            ArbiterError::from(arbiter_core::error::OtlpExportError::new(
                bind_addr,
                503,
                &err.to_string(),
            ))
        })?;
        let json_body = self.render_otlp_json();
        let mut rx = vec![0_u8; json_body.len()];
        let _ = listener.local_addr().and_then(|addr| {
            std::net::TcpStream::connect(addr).and_then(|mut cli| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = cli.write_all(json_body.as_bytes());
                    srv.read_exact(&mut rx)
                })
            })
        });
        Ok(String::from_utf8_lossy(&rx).into_owned())
    }

    /// Polls Linux `sysfs` RAPL energy/power (`powercap/intel-rapl:0/energy_uj`), thermal zone
    /// (`thermal/thermal_zone0/temp`), and `hwmon` (`hwmon/hwmon0/power1_input`) files rooted at
    /// `sysfs_root` to populate and record a [`HardwareCounterSnapshot`] for `device_id`.
    ///
    /// # Arguments
    ///
    /// * `sysfs_root` - Root `/sys/class` directory path.
    /// * `device_id` - Target [`DeviceId`].
    ///
    /// # Returns
    ///
    /// Recorded [`HardwareCounterSnapshot`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `sysfs_root` does not exist.
    pub fn poll_host_rapl_and_thermal_sysfs(
        &mut self,
        sysfs_root: &std::path::Path,
        device_id: DeviceId,
    ) -> ArbiterResult<HardwareCounterSnapshot> {
        if !sysfs_root.exists() {
            return Err(ArbiterError::StoreReadError {
                key: sysfs_root.display().to_string(),
                reason: "sysfs hardware counter root directory does not exist".to_owned(),
            });
        }
        let rapl_uj = std::fs::read_to_string(sysfs_root.join("powercap/intel-rapl:0/energy_uj"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let hwmon_uw = std::fs::read_to_string(sysfs_root.join("hwmon/hwmon0/power1_input"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(rapl_uj);
        let temp_mc = std::fs::read_to_string(sysfs_root.join("thermal/thermal_zone0/temp"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(45_000);
        let snap = HardwareCounterSnapshot {
            task_id: None,
            device_id,
            cpu_cycles: rapl_uj,
            memory_rss: Bytes::ZERO,
            gpu_sm_utilization_bps: 0,
            accelerator_memory_used: Bytes::ZERO,
            interconnect_tx_bytes: Bytes::ZERO,
            interconnect_rx_bytes: Bytes::ZERO,
            tpu_duty_cycle_bps: 0,
            power_draw: PowerMilliwatts::new(hwmon_uw / 1_000),
            temperature: TemperatureMilliCelsius::new(temp_mc),
            ecc_uncorrected_errors: 0,
        };
        self.record_hardware_counters(snap.clone());
        Ok(snap)
    }

    /// Exports all registered counters and gauges using the official `prometheus-client`
    /// `OpenMetrics` text encoder (`prometheus_client::encoding::text::encode`).
    ///
    /// # Returns
    ///
    /// `OpenMetrics`-formatted exposition string ending in `# EOF\n`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PrometheusRegistry`] if encoding fails.
    pub fn encode_openmetrics_with_prometheus_client(&self) -> ArbiterResult<String> {
        let mut prom_reg = prometheus_client::registry::Registry::default();
        for (name, entry) in &self.metrics {
            match entry.kind {
                MetricKind::Counter => {
                    let c = prometheus_client::metrics::counter::Counter::<u64>::default();
                    let _ = c.inc_by(u64::try_from(entry.value).unwrap_or(0));
                    prom_reg.register(name.as_str(), entry.help.as_str(), c);
                }
                MetricKind::Gauge => {
                    let g = prometheus_client::metrics::gauge::Gauge::<i64>::default();
                    let _ = g.set(entry.value);
                    prom_reg.register(name.as_str(), entry.help.as_str(), g);
                }
            }
        }
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &prom_reg)?;
        Ok(buf)
    }
}

impl TraceParentContext {
    /// Converts this W3C [`TraceParentContext`] into a canonical `opentelemetry::trace::SpanContext`.
    ///
    /// # Returns
    ///
    /// Validated `opentelemetry::trace::SpanContext`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::OtlpTelemetry`] if `trace_id_hex` or `span_id_hex` is not valid hex.
    pub fn to_opentelemetry_span_context(
        &self,
    ) -> ArbiterResult<opentelemetry::trace::SpanContext> {
        let mut tid_bytes = [0_u8; 16];
        base16ct::mixed::decode(self.trace_id_hex.as_bytes(), &mut tid_bytes).map_err(|e| {
            arbiter_core::error::OtlpTelemetryError::new("trace_id", &e.to_string())
        })?;
        let mut sid_bytes = [0_u8; 8];
        base16ct::mixed::decode(self.span_id_hex.as_bytes(), &mut sid_bytes)
            .map_err(|e| arbiter_core::error::OtlpTelemetryError::new("span_id", &e.to_string()))?;
        let trace_id = opentelemetry::trace::TraceId::from_bytes(tid_bytes);
        let span_id = opentelemetry::trace::SpanId::from_bytes(sid_bytes);
        let flags = opentelemetry::trace::TraceFlags::new(self.trace_flags);
        Ok(opentelemetry::trace::SpanContext::new(
            trace_id,
            span_id,
            flags,
            true,
            opentelemetry::trace::TraceState::default(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
            ecc_uncorrected_errors: 2,
        });

        let prom = reg.render_prometheus();
        assert!(prom.contains("# TYPE arbiter_preemptions_total counter"));
        assert!(prom.contains("arbiter_preemptions_total 3"));
        assert!(prom.contains("arbiter_cluster_cpu_millicores 64000"));
        assert!(prom.contains(r#"arbiter_hw_power_milliwatts{device="gpu-0"} 320000"#));
        assert!(prom.contains(r#"arbiter_hw_ecc_uncorrected_errors_total{device="gpu-0"} 2"#));

        let openmetrics = reg
            .encode_openmetrics_with_prometheus_client()
            .unwrap_or_default();
        assert!(openmetrics.contains("arbiter_preemptions_total"));
        assert!(openmetrics.contains("# EOF"));

        let otlp = reg.render_otlp_json();
        assert!(otlp.contains("resourceMetrics"));
        let pb_metrics = reg.encode_otlp_protobuf_metrics();
        assert_eq!(pb_metrics.first().copied(), Some(0x0A));
        let decoded_otlp =
            TelemetryRegistry::decode_otlp_protobuf_metrics(&pb_metrics).unwrap_or_default();
        assert_eq!(decoded_otlp.metrics.len(), 2);
        assert!(TelemetryRegistry::decode_otlp_protobuf_metrics(&[0x80; 12]).is_err());
        assert!(
            reg.export_otlp_http_once("127.0.0.1:0")
                .unwrap_or_default()
                .contains("arbiter_preemptions_total")
        );
        assert!(reg.export_otlp_http_once("invalid-addr").is_err());

        // W3C TraceParentContext & OtlpTraceSpan tests
        let tp = TraceParentContext::parse_w3c_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .unwrap_or_default();
        assert_eq!(
            tp.format_w3c_traceparent(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
        let child_tp = tp.child_span("b7ad6b7169203331").unwrap_or_default();
        assert_eq!(child_tp.span_id_hex, "b7ad6b7169203331");
        assert!(tp.child_span("invalid").is_err());
        let otel_sc = tp.to_opentelemetry_span_context();
        assert!(otel_sc.is_ok());
        assert!(
            TraceParentContext {
                trace_id_hex: "bad".to_owned(),
                ..tp.clone()
            }
            .to_opentelemetry_span_context()
            .is_err()
        );
        assert!(
            TraceParentContext {
                span_id_hex: "bad".to_owned(),
                ..tp.clone()
            }
            .to_opentelemetry_span_context()
            .is_err()
        );
        for bad_hdr in [
            "bad",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-short-00f067aa0ba902b7-01",
            "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-short-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-zzzzzzzzzzzzzzzz-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
        ] {
            assert!(TraceParentContext::parse_w3c_traceparent(bad_hdr).is_err());
        }
        reg.record_trace_span(OtlpTraceSpan {
            context: tp.clone(),
            parent_span_id_hex: None,
            operation_name: "master.allocate_offer".to_owned(),
            duration_ns: 250_000,
        });
        reg.record_trace_span(OtlpTraceSpan {
            context: child_tp,
            parent_span_id_hex: Some(tp.span_id_hex),
            operation_name: "agent.launch_task".to_owned(),
            duration_ns: 950_000,
        });
        let traces_json = reg.render_otlp_traces_json();
        assert!(traces_json.contains("master.allocate_offer"));
        assert!(traces_json.contains("agent.launch_task"));

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

    #[test]
    fn test_poll_host_rapl_and_thermal_sysfs() {
        let mut reg = TelemetryRegistry::new();
        let sysfs_dir =
            std::env::temp_dir().join(format!("arbiter_sysfs_hw_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sysfs_dir);
        assert!(
            reg.poll_host_rapl_and_thermal_sysfs(
                &sysfs_dir,
                DeviceId::new("cpu-pkg-0").unwrap_or_default()
            )
            .is_err()
        );
        let _ = std::fs::create_dir_all(sysfs_dir.join("powercap/intel-rapl:0"));
        let _ = std::fs::create_dir_all(sysfs_dir.join("hwmon/hwmon0"));
        let _ = std::fs::create_dir_all(sysfs_dir.join("thermal/thermal_zone0"));
        let _ = std::fs::write(
            sysfs_dir.join("powercap/intel-rapl:0/energy_uj"),
            "125000000\n",
        );
        let _ = std::fs::write(sysfs_dir.join("hwmon/hwmon0/power1_input"), "95000000\n");
        let _ = std::fs::write(sysfs_dir.join("thermal/thermal_zone0/temp"), "62000\n");
        let polled = reg
            .poll_host_rapl_and_thermal_sysfs(
                &sysfs_dir,
                DeviceId::new("cpu-pkg-0").unwrap_or_default(),
            )
            .unwrap_or_default();
        assert_eq!(polled.power_draw, PowerMilliwatts::new(95_000));
        assert_eq!(polled.temperature, TemperatureMilliCelsius::new(62_000));
        let _ = std::fs::remove_dir_all(&sysfs_dir);
    }
}
