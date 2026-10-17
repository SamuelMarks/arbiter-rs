//! Built-in cluster service discovery and active readiness/liveness health probes (`arbiter-telemetry::discovery`).
//!
//! Implements:
//! - Cluster-wide DNS/SRV service registry mapping `<task>.<service>.<role>.arbiter.internal`
//!   to allocated IP and [`PortNumber`] endpoints.
//! - Active health probe state machine (`TCP`, `HTTP`, `QUIC`) tracking consecutive probe failures
//!   and emitting [`ArbiterError::HealthCheckFailed`] once `unhealthy_threshold` is reached.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{RoleName, TaskId};
use arbiter_core::units::PortNumber;
use arbiter_core::workload::HealthCheckSpec;
use serde::{Deserialize, Serialize};

/// Registered service endpoint record (`A` + `SRV` equivalent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpointRecord {
    /// Internal DNS name (`<task>.<service>.<role>.arbiter.internal`).
    pub dns_name: String,
    /// Task identifier backing this endpoint.
    pub task_id: TaskId,
    /// IPv4 or IPv6 address of the Agent/container.
    pub ip_address: String,
    /// Allocated service port.
    pub port: PortNumber,
}

/// Cluster-wide internal DNS and SRV service discovery registry.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDiscoveryRegistry {
    /// Registered records keyed by `dns_name`.
    records: BTreeMap<String, ServiceEndpointRecord>,
}

impl ServiceDiscoveryRegistry {
    /// Creates an empty [`ServiceDiscoveryRegistry`].
    ///
    /// # Returns
    ///
    /// Empty [`ServiceDiscoveryRegistry`].
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Registers a task's service endpoint under `<task>.<service>.<role>.arbiter.internal`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `service` - Service name (e.g., `"api"`, `"postgres"`).
    /// * `role` - Scheduling role name.
    /// * `ip_address` - Host/container IP address.
    /// * `port` - Service [`PortNumber`].
    ///
    /// # Returns
    ///
    /// Registered [`ServiceEndpointRecord`].
    pub fn register_endpoint(
        &mut self,
        task_id: &TaskId,
        service: &str,
        role: &RoleName,
        ip_address: String,
        port: PortNumber,
    ) -> ServiceEndpointRecord {
        let dns_name = format!("{task_id}.{service}.{role}.arbiter.internal");
        let rec = ServiceEndpointRecord {
            dns_name: dns_name.clone(),
            task_id: task_id.clone(),
            ip_address,
            port,
        };
        self.records.insert(dns_name, rec.clone());
        rec
    }

    /// Resolves a `<task>.<service>.<role>.arbiter.internal` DNS query.
    ///
    /// # Arguments
    ///
    /// * `dns_name` - Internal DNS query string.
    ///
    /// # Returns
    ///
    /// Optional reference to [`ServiceEndpointRecord`].
    pub fn resolve(&self, dns_name: &str) -> Option<&ServiceEndpointRecord> {
        self.records.get(dns_name)
    }

    /// Deregisters a service endpoint when a task terminates or becomes unhealthy.
    ///
    /// # Arguments
    ///
    /// * `dns_name` - Internal DNS name to remove.
    ///
    /// # Returns
    ///
    /// `true` if the record existed and was removed.
    pub fn deregister(&mut self, dns_name: &str) -> bool {
        self.records.remove(dns_name).is_some()
    }
}

/// Health status of a monitored task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskHealthStatus {
    /// Task is passing active readiness/liveness probes.
    Healthy,
    /// Task has failed one or more probes but is still below `unhealthy_threshold`.
    Degraded {
        /// Current consecutive failure count.
        consecutive_failures: u32,
    },
    /// Task has reached or exceeded `unhealthy_threshold` and must be restarted/rescheduled.
    Unhealthy {
        /// Consecutive failure count that triggered failure.
        consecutive_failures: u32,
    },
}

/// Active readiness/liveness health probe tracker for a running task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbeTracker {
    /// Monitored task identifier.
    pub task_id: TaskId,
    /// Health check specification.
    pub spec: HealthCheckSpec,
    /// Current consecutive failure counter.
    pub consecutive_failures: u32,
}

impl HealthProbeTracker {
    /// Creates a new [`HealthProbeTracker`] for `task_id` and `spec`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Monitored [`TaskId`].
    /// * `spec` - [`HealthCheckSpec`].
    ///
    /// # Returns
    ///
    /// Initialized [`HealthProbeTracker`].
    pub const fn new(task_id: TaskId, spec: HealthCheckSpec) -> Self {
        Self {
            task_id,
            spec,
            consecutive_failures: 0,
        }
    }

    /// Records the outcome of a single active health probe execution (`TCP`, `HTTP`, or `QUIC`).
    ///
    /// - If `probe_succeeded` is `true`, resets `consecutive_failures` to `0` and returns `Ok(TaskHealthStatus::Healthy)`.
    /// - If `probe_succeeded` is `false`, increments `consecutive_failures`. If `consecutive_failures >= spec.unhealthy_threshold`,
    ///   returns [`ArbiterError::HealthCheckFailed`] so the Agent/Executor can trigger task failure/restart.
    ///
    /// # Arguments
    ///
    /// * `probe_succeeded` - Whether the probe check passed.
    /// * `diagnostic` - Diagnostic reason if the probe failed.
    ///
    /// # Returns
    ///
    /// Current [`TaskHealthStatus`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HealthCheckFailed`] when `consecutive_failures >= spec.unhealthy_threshold`.
    pub fn record_probe_outcome(
        &mut self,
        probe_succeeded: bool,
        diagnostic: &str,
    ) -> ArbiterResult<TaskHealthStatus> {
        if probe_succeeded {
            self.consecutive_failures = 0;
            return Ok(TaskHealthStatus::Healthy);
        }

        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.spec.unhealthy_threshold {
            return Err(ArbiterError::HealthCheckFailed {
                task_id: self.task_id.to_string(),
                consecutive_failures: self.consecutive_failures,
                reason: diagnostic.to_owned(),
            });
        }

        Ok(TaskHealthStatus::Degraded {
            consecutive_failures: self.consecutive_failures,
        })
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::workload::HealthCheckProtocol;

    use super::*;

    #[test]
    fn test_service_discovery_and_health_probe_transitions() {
        let mut dns = ServiceDiscoveryRegistry::new();
        let tid = TaskId::new("web-0").unwrap_or_default();
        let role = RoleName::new("prod").unwrap_or_default();
        let port = PortNumber::new(8080).unwrap_or_default();

        let rec = dns.register_endpoint(&tid, "frontend", &role, "10.1.0.5".to_owned(), port);
        assert_eq!(rec.dns_name, "web-0.frontend.prod.arbiter.internal");
        assert_eq!(dns.resolve(&rec.dns_name), Some(&rec));
        assert!(dns.deregister(&rec.dns_name));
        assert!(!dns.deregister(&rec.dns_name));
        assert!(dns.resolve(&rec.dns_name).is_none());

        // HealthProbeTracker: threshold = 3
        let spec = HealthCheckSpec {
            protocol: HealthCheckProtocol::HttpGet("/healthz".to_owned()),
            port,
            interval_ms: 1000,
            timeout_ms: 200,
            unhealthy_threshold: 3,
        };
        let mut tracker = HealthProbeTracker::new(tid, spec);

        // Failure 1 -> Degraded(1)
        assert_eq!(
            tracker.record_probe_outcome(false, "timeout"),
            Ok(TaskHealthStatus::Degraded {
                consecutive_failures: 1
            })
        );
        // Success -> resets to Healthy
        assert_eq!(
            tracker.record_probe_outcome(true, "200 OK"),
            Ok(TaskHealthStatus::Healthy)
        );
        // 3 consecutive failures -> Degraded(1) -> Degraded(2) -> Err(HealthCheckFailed)
        assert!(tracker.record_probe_outcome(false, "503").is_ok());
        assert!(tracker.record_probe_outcome(false, "503").is_ok());
        assert_eq!(
            tracker.record_probe_outcome(false, "connection refused"),
            Err(ArbiterError::HealthCheckFailed {
                task_id: "web-0".to_owned(),
                consecutive_failures: 3,
                reason: "connection refused".to_owned(),
            })
        );
    }
}
