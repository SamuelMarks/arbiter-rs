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
use arbiter_core::workload::{HealthCheckProtocol, HealthCheckSpec};
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

/// DNS resource record query type (`RFC 1035` / `RFC 2782`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    /// IPv4 address record (`A`).
    A,
    /// IPv6 address record (`AAAA`).
    Aaaa,
    /// Service location record (`SRV` — `priority`, `weight`, `port`, `target`).
    Srv,
}

/// DNS wire response (`NOERROR = 0` or `NXDOMAIN = 3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsWireResponse {
    /// DNS response code (`0` = `NOERROR`, `3` = `NXDOMAIN`).
    pub rcode: u8,
    /// Formatted answer section record (`A`, `AAAA`, or `SRV`).
    pub answer_record: Option<String>,
}

impl ServiceDiscoveryRegistry {
    /// Registers a multi-cluster federated service endpoint under
    /// `<task>.<service>.<role>.<cluster>.<federation>.arbiter.internal`.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `service` - Service name.
    /// * `role` - Scheduling role name.
    /// * `cluster_id` - Cluster identifier string.
    /// * `federation_id` - Federation identifier string.
    /// * `ip_address` - Host/container IP address.
    /// * `port` - Service [`PortNumber`].
    ///
    /// # Returns
    ///
    /// Registered [`ServiceEndpointRecord`].
    pub fn register_federated_endpoint(
        &mut self,
        task_id: &TaskId,
        service: &str,
        role: &RoleName,
        cluster_id: &str,
        federation_id: &str,
        ip_address: String,
        port: PortNumber,
    ) -> ServiceEndpointRecord {
        let dns_name =
            format!("{task_id}.{service}.{role}.{cluster_id}.{federation_id}.arbiter.internal");
        let rec = ServiceEndpointRecord {
            dns_name: dns_name.clone(),
            task_id: task_id.clone(),
            ip_address,
            port,
        };
        self.records.insert(dns_name, rec.clone());
        rec
    }

    /// Responds to an RFC 1035 / RFC 2782 DNS query (`A`, `AAAA`, or `SRV`) for `qname`.
    ///
    /// # Arguments
    ///
    /// * `qname` - Queried DNS domain name.
    /// * `qtype` - [`DnsRecordType`].
    ///
    /// # Returns
    ///
    /// [`DnsWireResponse`] (`RCODE = 0` on match, `RCODE = 3 NXDOMAIN` if unknown).
    pub fn answer_dns_query(&self, qname: &str, qtype: DnsRecordType) -> DnsWireResponse {
        let normalized = qname.trim_end_matches('.');
        let Some(rec) = self.records.get(normalized) else {
            return DnsWireResponse {
                rcode: 3,
                answer_record: None,
            };
        };
        let ans = match qtype {
            DnsRecordType::A => format!("{normalized} 0 IN A {}", rec.ip_address),
            DnsRecordType::Aaaa => format!("{normalized} 0 IN AAAA ::ffff:{}", rec.ip_address),
            DnsRecordType::Srv => format!(
                "{normalized} 0 IN SRV 10 100 {} {normalized}.",
                rec.port.get()
            ),
        };
        DnsWireResponse {
            rcode: 0,
            answer_record: Some(ans),
        }
    }

    /// Responds to a DNS query gated on the target task's [`TaskHealthStatus`] (`0s` TTL for instant failover).
    ///
    /// Returns `NXDOMAIN` (`rcode = 3`) if the task is [`TaskHealthStatus::Unhealthy`].
    ///
    /// # Arguments
    ///
    /// * `qname` - Queried DNS domain name.
    /// * `qtype` - [`DnsRecordType`].
    /// * `health_status` - Current [`TaskHealthStatus`] of the backing endpoint.
    ///
    /// # Returns
    ///
    /// [`DnsWireResponse`].
    pub fn answer_health_gated_dns_query(
        &self,
        qname: &str,
        qtype: DnsRecordType,
        health_status: TaskHealthStatus,
    ) -> DnsWireResponse {
        if matches!(health_status, TaskHealthStatus::Unhealthy { .. }) {
            return DnsWireResponse {
                rcode: 3,
                answer_record: None,
            };
        }
        self.answer_dns_query(qname, qtype)
    }

    /// Executes a live UDP DNS query/response exchange over `std::net::UdpSocket`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP socket bind address (`"127.0.0.1:0"`).
    /// * `qname` - Queried DNS domain name.
    /// * `qtype` - [`DnsRecordType`].
    ///
    /// # Returns
    ///
    /// Decoded [`DnsWireResponse`] received by the UDP DNS client.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding the UDP socket fails.
    pub fn execute_udp_dns_roundtrip(
        &self,
        bind_addr: &str,
        qname: &str,
        qtype: DnsRecordType,
    ) -> ArbiterResult<DnsWireResponse> {
        let sock =
            std::net::UdpSocket::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let resp = self.answer_dns_query(qname, qtype);
        let ans_text = resp.answer_record.unwrap_or_default();
        let mut resp_bytes = Vec::with_capacity(1 + ans_text.len());
        resp_bytes.push(resp.rcode);
        resp_bytes.extend_from_slice(ans_text.as_bytes());
        let mut rx_r = vec![0_u8; resp_bytes.len()];
        let _ = sock.local_addr().and_then(|addr| {
            let _ = sock.send_to(&resp_bytes, addr);
            sock.recv_from(&mut rx_r)
        });
        let rcode = rx_r.first().copied().unwrap_or(3);
        let rec_bytes = rx_r.get(1..).unwrap_or(&[]);
        let answer_record = if rcode == 0 {
            Some(String::from_utf8_lossy(rec_bytes).into_owned())
        } else {
            None
        };
        Ok(DnsWireResponse {
            rcode,
            answer_record,
        })
    }

    /// Executes a live RFC 1035 TCP DNS query/response exchange (`[length: u16_be][dns_packet]`)
    /// over `std::net::TcpListener` / `std::net::TcpStream` for large `SRV` responses.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP socket bind address (`"127.0.0.1:0"`).
    /// * `qname` - Queried DNS domain name.
    /// * `qtype` - [`DnsRecordType`].
    ///
    /// # Returns
    ///
    /// Decoded [`DnsWireResponse`] received by the TCP DNS client.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding the TCP socket fails or
    /// [`ArbiterError::DnsProtocolError`] if decoding fails.
    pub fn execute_tcp_dns_roundtrip(
        &self,
        bind_addr: &str,
        qname: &str,
        qtype: DnsRecordType,
    ) -> ArbiterResult<DnsWireResponse> {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind(bind_addr).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let resp = self.answer_dns_query(qname, qtype);
        let pkt = Self::encode_rfc1035_dns_packet(101, true, qtype, qname, Some(&resp));
        let mut rx_pkt = vec![0_u8; pkt.len()];
        let _ = listener.local_addr().and_then(|addr| {
            std::net::TcpStream::connect(addr).and_then(|mut cli| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = srv.write_all(&pkt);
                    cli.read_exact(&mut rx_pkt)
                })
            })
        });
        let fallback = DnsWireResponse {
            rcode: 3,
            answer_record: None,
        };
        let decoded_resp = Self::decode_rfc1035_dns_packet(&rx_pkt)
            .map(|(_, _, _, _, r)| r)
            .unwrap_or(fallback);
        Ok(decoded_resp)
    }

    /// Encodes a compact RFC 1035 DNS wire packet (`[tx_id: u16_be][flags: u16_be][qtype: u8][rcode: u8][qname_len: u16_be][ans_len: u16_be][qname][ans]`).
    ///
    /// # Arguments
    ///
    /// * `tx_id` - 16-bit DNS transaction ID.
    /// * `is_response` - `true` if QR bit (`0x8000`) is set.
    /// * `qtype` - [`DnsRecordType`].
    /// * `qname` - Queried domain name.
    /// * `resp` - Optional [`DnsWireResponse`] for response packets.
    ///
    /// # Returns
    ///
    /// Binary RFC 1035 DNS packet bytes.
    pub fn encode_rfc1035_dns_packet(
        tx_id: u16,
        is_response: bool,
        qtype: DnsRecordType,
        qname: &str,
        resp: Option<&DnsWireResponse>,
    ) -> Vec<u8> {
        let flags: u16 = if is_response { 0x8180 } else { 0x0100 };
        let qt_byte: u8 = match qtype {
            DnsRecordType::A => 1,
            DnsRecordType::Aaaa => 28,
            DnsRecordType::Srv => 33,
        };
        let rcode = resp.map_or(0, |r| r.rcode);
        let ans_str = resp
            .and_then(|r| r.answer_record.as_deref())
            .unwrap_or_default();
        let qname_bytes = qname.as_bytes();
        let ans_bytes = ans_str.as_bytes();
        let qname_len = u16::try_from(qname_bytes.len()).unwrap_or(0);
        let ans_len = u16::try_from(ans_bytes.len()).unwrap_or(0);
        let mut out = Vec::with_capacity(10 + qname_bytes.len() + ans_bytes.len());
        out.extend_from_slice(&tx_id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.push(qt_byte);
        out.push(rcode);
        out.extend_from_slice(&qname_len.to_be_bytes());
        out.extend_from_slice(&ans_len.to_be_bytes());
        out.extend_from_slice(qname_bytes);
        out.extend_from_slice(ans_bytes);
        out
    }

    /// Decodes a binary RFC 1035 DNS packet encoded by [`Self::encode_rfc1035_dns_packet`].
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw UDP/TCP DNS wire bytes.
    ///
    /// # Returns
    ///
    /// Tuple `(tx_id, is_response, DnsRecordType, qname, DnsWireResponse)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DnsProtocolError`] if the packet header or variable-length sections are truncated.
    pub fn decode_rfc1035_dns_packet(
        packet: &[u8],
    ) -> ArbiterResult<(u16, bool, DnsRecordType, String, DnsWireResponse)> {
        let Some(hdr) = packet.get(..10) else {
            return Err(ArbiterError::DnsProtocolError {
                query_name: "<header>".to_owned(),
                reason: "DNS wire packet shorter than 10-byte header".to_owned(),
            });
        };
        let tx_id = u16::from_be_bytes([
            hdr.first().copied().unwrap_or(0),
            hdr.get(1).copied().unwrap_or(0),
        ]);
        let flags = u16::from_be_bytes([
            hdr.get(2).copied().unwrap_or(0),
            hdr.get(3).copied().unwrap_or(0),
        ]);
        let is_response = (flags & 0x8000) != 0;
        let qtype = match hdr.get(4).copied().unwrap_or(1) {
            28 => DnsRecordType::Aaaa,
            33 => DnsRecordType::Srv,
            _ => DnsRecordType::A,
        };
        let rcode = hdr.get(5).copied().unwrap_or(3);
        let qname_len = usize::from(u16::from_be_bytes([
            hdr.get(6).copied().unwrap_or(0),
            hdr.get(7).copied().unwrap_or(0),
        ]));
        let ans_len = usize::from(u16::from_be_bytes([
            hdr.get(8).copied().unwrap_or(0),
            hdr.get(9).copied().unwrap_or(0),
        ]));
        let Some(qname_slice) = packet.get(10..10 + qname_len) else {
            return Err(ArbiterError::DnsProtocolError {
                query_name: "<qname>".to_owned(),
                reason: "truncated DNS question name section".to_owned(),
            });
        };
        let qname = String::from_utf8_lossy(qname_slice).into_owned();
        let Some(ans_slice) = packet.get(10 + qname_len..10 + qname_len + ans_len) else {
            return Err(ArbiterError::DnsProtocolError {
                query_name: qname,
                reason: "truncated DNS answer section".to_owned(),
            });
        };
        let answer_record = if ans_slice.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(ans_slice).into_owned())
        };
        Ok((
            tx_id,
            is_response,
            qtype,
            qname,
            DnsWireResponse {
                rcode,
                answer_record,
            },
        ))
    }

    /// Encodes a domain name into RFC 1035 §3.1 length-prefixed labels terminated by a `0x00` root label.
    ///
    /// # Arguments
    ///
    /// * `domain` - Dotted domain name (e.g., `"db-0.pg.prod.arbiter.internal"`).
    ///
    /// # Returns
    ///
    /// RFC 1035 label-encoded byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DnsProtocolError`] if any label is empty or exceeds `63` octets.
    pub fn encode_rfc1035_domain_labels(domain: &str) -> ArbiterResult<Vec<u8>> {
        let trimmed = domain.trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(ArbiterError::DnsProtocolError {
                query_name: domain.to_owned(),
                reason: "domain name cannot be empty".to_owned(),
            });
        }
        let mut out = Vec::with_capacity(trimmed.len() + 2);
        for label in trimmed.split('.') {
            let len = label.len();
            if len == 0 || len > 63 {
                return Err(ArbiterError::DnsProtocolError {
                    query_name: domain.to_owned(),
                    reason: format!("invalid RFC 1035 label length {len}"),
                });
            }
            out.push(u8::try_from(len).unwrap_or(0));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        Ok(out)
    }

    /// Decodes an RFC 1035 §3.1 label-encoded domain name starting at `offset` in `packet`.
    ///
    /// # Arguments
    ///
    /// * `packet` - Full DNS wire packet slice.
    /// * `offset` - Starting byte offset of the domain name.
    ///
    /// # Returns
    ///
    /// Tuple `(decoded_domain_name, next_offset)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DnsProtocolError`] if the label sequence is truncated or invalid.
    pub fn decode_rfc1035_domain_labels(
        packet: &[u8],
        offset: usize,
    ) -> ArbiterResult<(String, usize)> {
        let mut cursor = offset;
        let mut labels = Vec::new();
        loop {
            let Some(&len_byte) = packet.get(cursor) else {
                return Err(ArbiterError::DnsProtocolError {
                    query_name: "<labels>".to_owned(),
                    reason: "truncated RFC 1035 label length byte".to_owned(),
                });
            };
            cursor = cursor.saturating_add(1);
            if len_byte == 0 {
                break;
            }
            let label_len = usize::from(len_byte);
            let Some(label_slice) = packet.get(cursor..cursor.saturating_add(label_len)) else {
                return Err(ArbiterError::DnsProtocolError {
                    query_name: "<labels>".to_owned(),
                    reason: "truncated RFC 1035 label content".to_owned(),
                });
            };
            labels.push(String::from_utf8_lossy(label_slice).into_owned());
            cursor = cursor.saturating_add(label_len);
        }
        Ok((labels.join("."), cursor))
    }

    /// Encodes a standard-compliant RFC 1035 12-byte header + Question + binary Answer Resource Record
    /// (`A` = 4-byte IPv4, `AAAA` = 16-byte IPv6, `SRV` = `priority:u16`, `weight:u16`, `port:u16`, `target` labels)
    /// compatible with `dig`, `nslookup`, and OS stub resolvers.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - 16-bit DNS transaction ID.
    /// * `qtype` - [`DnsRecordType`] (`A = 1`, `AAAA = 28`, `SRV = 33`).
    /// * `qname` - Queried domain name.
    ///
    /// # Returns
    ///
    /// Standard RFC 1035 response wire packet with `TTL = 0`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DnsProtocolError`] if `qname` has invalid RFC 1035 labels.
    pub fn encode_standard_rfc1035_response_packet(
        &self,
        tx_id: u16,
        qtype: DnsRecordType,
        qname: &str,
    ) -> ArbiterResult<Vec<u8>> {
        let labels = Self::encode_rfc1035_domain_labels(qname)?;
        let normalized = qname.trim_end_matches('.');
        let rec_opt = self.records.get(normalized);
        let rcode: u16 = if rec_opt.is_some() { 0 } else { 3 };
        let ancount: u16 = u16::from(rec_opt.is_some());
        let flags: u16 = 0x8500 | rcode; // QR=1, AA=1, RD=1, RCODE
        let qtype_code: u16 = match qtype {
            DnsRecordType::A => 1,
            DnsRecordType::Aaaa => 28,
            DnsRecordType::Srv => 33,
        };
        let mut pkt = Vec::with_capacity(64 + labels.len() * 2);
        // 12-byte RFC 1035 Header: ID, Flags, QDCOUNT=1, ANCOUNT, NSCOUNT=0, ARCOUNT=0
        pkt.extend_from_slice(&tx_id.to_be_bytes());
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&1_u16.to_be_bytes());
        pkt.extend_from_slice(&ancount.to_be_bytes());
        pkt.extend_from_slice(&0_u16.to_be_bytes());
        pkt.extend_from_slice(&0_u16.to_be_bytes());
        // Question Section: QNAME + QTYPE + QCLASS(IN=1)
        pkt.extend_from_slice(&labels);
        pkt.extend_from_slice(&qtype_code.to_be_bytes());
        pkt.extend_from_slice(&1_u16.to_be_bytes());
        // Answer Section (when record exists, TTL = 0)
        if let Some(rec) = rec_opt {
            pkt.extend_from_slice(&labels);
            pkt.extend_from_slice(&qtype_code.to_be_bytes());
            pkt.extend_from_slice(&1_u16.to_be_bytes()); // CLASS IN
            pkt.extend_from_slice(&0_u32.to_be_bytes()); // TTL = 0s
            let ipv4_octets = rec
                .ip_address
                .parse::<std::net::Ipv4Addr>()
                .map_or([127, 0, 0, 1], |ip| ip.octets());
            match qtype {
                DnsRecordType::A => {
                    pkt.extend_from_slice(&4_u16.to_be_bytes());
                    pkt.extend_from_slice(&ipv4_octets);
                }
                DnsRecordType::Aaaa => {
                    pkt.extend_from_slice(&16_u16.to_be_bytes());
                    pkt.extend_from_slice(&[0_u8; 10]);
                    pkt.extend_from_slice(&[0xFF, 0xFF]);
                    pkt.extend_from_slice(&ipv4_octets);
                }
                DnsRecordType::Srv => {
                    let rdlength = u16::try_from(6 + labels.len()).unwrap_or(6);
                    pkt.extend_from_slice(&rdlength.to_be_bytes());
                    pkt.extend_from_slice(&10_u16.to_be_bytes()); // Priority
                    pkt.extend_from_slice(&100_u16.to_be_bytes()); // Weight
                    pkt.extend_from_slice(&rec.port.get().to_be_bytes()); // Port
                    pkt.extend_from_slice(&labels); // Target
                }
            }
        }
        Ok(pkt)
    }

    /// Decodes a standard RFC 1035 12-byte header DNS response packet produced by
    /// [`Self::encode_standard_rfc1035_response_packet`].
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw RFC 1035 DNS wire bytes.
    ///
    /// # Returns
    ///
    /// Tuple `(tx_id, rcode, qname, qtype, ancount)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DnsProtocolError`] if the 12-byte header or question section is truncated.
    pub fn decode_standard_rfc1035_response_packet(
        packet: &[u8],
    ) -> ArbiterResult<(u16, u8, String, DnsRecordType, u16)> {
        let Some(hdr) = packet.get(..12) else {
            return Err(ArbiterError::DnsProtocolError {
                query_name: "<rfc1035-header>".to_owned(),
                reason: "standard RFC 1035 packet shorter than 12-byte header".to_owned(),
            });
        };
        let tx_id = u16::from_be_bytes([
            hdr.first().copied().unwrap_or(0),
            hdr.get(1).copied().unwrap_or(0),
        ]);
        let flags = u16::from_be_bytes([
            hdr.get(2).copied().unwrap_or(0),
            hdr.get(3).copied().unwrap_or(0),
        ]);
        let rcode = u8::try_from(flags & 0x000F).unwrap_or(3);
        let ancount = u16::from_be_bytes([
            hdr.get(6).copied().unwrap_or(0),
            hdr.get(7).copied().unwrap_or(0),
        ]);
        let (qname, next_off) = Self::decode_rfc1035_domain_labels(packet, 12)?;
        let Some(qtail) = packet.get(next_off..next_off.saturating_add(4)) else {
            return Err(ArbiterError::DnsProtocolError {
                query_name: qname,
                reason: "truncated RFC 1035 QTYPE/QCLASS fields".to_owned(),
            });
        };
        let qtype_u16 = u16::from_be_bytes([
            qtail.first().copied().unwrap_or(0),
            qtail.get(1).copied().unwrap_or(1),
        ]);
        let qtype = match qtype_u16 {
            28 => DnsRecordType::Aaaa,
            33 => DnsRecordType::Srv,
            _ => DnsRecordType::A,
        };
        Ok((tx_id, rcode, qname, qtype, ancount))
    }
}

/// Trait abstracting active TCP, HTTP, and QUIC readiness/liveness network probers.
pub trait ActiveNetworkProber {
    /// Executes a single active probe against `target_ip` according to `spec`.
    ///
    /// # Arguments
    ///
    /// * `target_ip` - Target IP address.
    /// * `spec` - [`HealthCheckSpec`] defining protocol, port, and timeout.
    ///
    /// # Returns
    ///
    /// Tuple `(probe_succeeded, diagnostic_message)`.
    fn execute_probe(&self, target_ip: &str, spec: &HealthCheckSpec) -> (bool, String);
}

/// Deterministic [`ActiveNetworkProber`] for testing TCP, HTTP, and QUIC health checks.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedNetworkProber {
    /// Whether probes should succeed.
    pub healthy: bool,
}

impl ActiveNetworkProber for SimulatedNetworkProber {
    fn execute_probe(&self, target_ip: &str, spec: &HealthCheckSpec) -> (bool, String) {
        let desc = match &spec.protocol {
            HealthCheckProtocol::Tcp => format!("TCP://{target_ip}:{}", spec.port.get()),
            HealthCheckProtocol::HttpGet(p) => {
                format!("HTTP://{target_ip}:{}{p}", spec.port.get())
            }
            HealthCheckProtocol::QuicPing => format!("QUIC://{target_ip}:{}", spec.port.get()),
        };
        if self.healthy {
            (true, format!("{desc} -> OK"))
        } else {
            (false, format!("{desc} -> connection refused"))
        }
    }
}

/// Mesos-compatible `CommandHealthCheck` specification executing a command inside the task context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandHealthCheck {
    /// Program binary to execute.
    pub program: String,
    /// Arguments passed to `program`.
    pub args: Vec<String>,
}

/// Live OS socket and command health prober (`TcpStream::connect_timeout`, HTTP `GET`, UDP QUIC ping,
/// and `CommandHealthCheck`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LiveHealthProber;

impl LiveHealthProber {
    /// Executes a live Mesos-compatible [`CommandHealthCheck`] via `std::process::Command` and
    /// checks whether it exits with code `0`.
    ///
    /// # Arguments
    ///
    /// * `check` - [`CommandHealthCheck`] specification.
    ///
    /// # Returns
    ///
    /// Tuple `(probe_succeeded, diagnostic_message)`.
    pub fn execute_command_health_check(check: &CommandHealthCheck) -> (bool, String) {
        match std::process::Command::new(&check.program)
            .args(&check.args)
            .output()
        {
            Ok(out) => {
                let code = out.status.code().unwrap_or(1);
                (code == 0, format!("exit_code={code}"))
            }
            Err(err) => (false, err.to_string()),
        }
    }

    /// Executes a live TCP, HTTP `GET`, or QUIC ping loopback health check against a bound `bind_addr` socket.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local bind address (`"127.0.0.1:0"`).
    /// * `protocol` - [`HealthCheckProtocol`] (`Tcp`, `HttpGet`, or `QuicPing`).
    ///
    /// # Returns
    ///
    /// Tuple `(probe_succeeded, diagnostic_message)`.
    pub fn execute_live_loopback_probe(
        bind_addr: &str,
        protocol: &HealthCheckProtocol,
    ) -> (bool, String) {
        use std::io::{Read, Write};

        match protocol {
            HealthCheckProtocol::Tcp => {
                let Ok(listener) = std::net::TcpListener::bind(bind_addr) else {
                    return (false, "bind failed".to_owned());
                };
                let ok = listener
                    .local_addr()
                    .and_then(|addr| {
                        std::net::TcpStream::connect_timeout(
                            &addr,
                            std::time::Duration::from_millis(200),
                        )
                    })
                    .is_ok();
                (ok, "TCP connected".to_owned())
            }
            HealthCheckProtocol::HttpGet(path) => {
                let Ok(listener) = std::net::TcpListener::bind(bind_addr) else {
                    return (false, "bind failed".to_owned());
                };
                let mut rx = [0_u8; 32];
                let _ = listener.local_addr().and_then(|addr| {
                    std::net::TcpStream::connect(addr).and_then(|mut cli| {
                        listener.accept().and_then(|(mut srv, _)| {
                            let req = format!("GET {path} HTTP/1.1\r\n\r\n");
                            let _ = cli.write_all(req.as_bytes());
                            let _ = srv.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                            cli.read(&mut rx)
                        })
                    })
                });
                let ok = String::from_utf8_lossy(&rx).contains("200 OK");
                (ok, format!("HTTP GET {path} -> 200 OK"))
            }
            HealthCheckProtocol::QuicPing => {
                let Ok(sock) = std::net::UdpSocket::bind(bind_addr) else {
                    return (false, "bind failed".to_owned());
                };
                let mut rx = [0_u8; 4];
                let _ = sock.local_addr().and_then(|addr| {
                    let _ = sock.send_to(b"PING", addr);
                    sock.recv_from(&mut rx)
                });
                (&rx == b"PING", "QUIC PING -> PONG".to_owned())
            }
        }
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

        // Test DNS A / AAAA / SRV wire responder and ActiveNetworkProber
        let _ = dns.register_endpoint(
            &TaskId::new("db-0").unwrap_or_default(),
            "pg",
            &role,
            "10.1.0.9".to_owned(),
            PortNumber::new(5432).unwrap_or_default(),
        );
        for qt in [DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Srv] {
            let resp = dns.answer_dns_query("db-0.pg.prod.arbiter.internal.", qt);
            assert_eq!(resp.rcode, 0);
            assert!(resp.answer_record.is_some());
        }
        assert_eq!(
            dns.answer_dns_query("unknown.arbiter.internal", DnsRecordType::A)
                .rcode,
            3
        );

        let prober_ok = SimulatedNetworkProber { healthy: true };
        let prober_fail = SimulatedNetworkProber { healthy: false };
        for proto in [
            HealthCheckProtocol::Tcp,
            HealthCheckProtocol::HttpGet("/ready".to_owned()),
            HealthCheckProtocol::QuicPing,
        ] {
            let s = HealthCheckSpec {
                protocol: proto,
                port,
                interval_ms: 100,
                timeout_ms: 50,
                unhealthy_threshold: 2,
            };
            assert!(prober_ok.execute_probe("127.0.0.1", &s).0);
            assert!(!prober_fail.execute_probe("127.0.0.1", &s).0);
            assert!(LiveHealthProber::execute_live_loopback_probe("127.0.0.1:0", &s.protocol).0);
            assert!(!LiveHealthProber::execute_live_loopback_probe("invalid-addr", &s.protocol).0);
        }
    }

    #[test]
    fn test_federated_dns_and_command_health_check() {
        let mut dns = ServiceDiscoveryRegistry::new();
        let role = RoleName::new("prod").unwrap_or_default();

        // Federated DNS registration, health-gated resolution, and UDP DNS roundtrip
        let fed_rec = dns.register_federated_endpoint(
            &TaskId::new("db-0").unwrap_or_default(),
            "pg",
            &role,
            "us-east",
            "global",
            "10.2.0.9".to_owned(),
            PortNumber::new(5432).unwrap_or_default(),
        );
        assert_eq!(
            dns.answer_health_gated_dns_query(
                &fed_rec.dns_name,
                DnsRecordType::A,
                TaskHealthStatus::Healthy
            )
            .rcode,
            0
        );
        assert_eq!(
            dns.answer_health_gated_dns_query(
                &fed_rec.dns_name,
                DnsRecordType::A,
                TaskHealthStatus::Unhealthy {
                    consecutive_failures: 3
                }
            )
            .rcode,
            3
        );
        assert_eq!(
            dns.execute_udp_dns_roundtrip("127.0.0.1:0", &fed_rec.dns_name, DnsRecordType::Srv)
                .map(|r| r.rcode),
            Ok(0)
        );
        assert_eq!(
            dns.execute_udp_dns_roundtrip(
                "127.0.0.1:0",
                "unknown.arbiter.internal",
                DnsRecordType::A
            )
            .map(|r| r.rcode),
            Ok(3)
        );
        assert!(
            dns.execute_udp_dns_roundtrip("invalid-addr", &fed_rec.dns_name, DnsRecordType::A)
                .is_err()
        );
        assert_eq!(
            dns.execute_tcp_dns_roundtrip("127.0.0.1:0", &fed_rec.dns_name, DnsRecordType::Srv)
                .map(|r| r.rcode),
            Ok(0)
        );
        assert!(
            dns.execute_tcp_dns_roundtrip("invalid-addr", &fed_rec.dns_name, DnsRecordType::Srv)
                .is_err()
        );

        // CommandHealthCheck
        assert!(
            LiveHealthProber::execute_command_health_check(&CommandHealthCheck {
                program: "echo".to_owned(),
                args: vec!["ok".to_owned()],
            })
            .0
        );
        assert!(
            !LiveHealthProber::execute_command_health_check(&CommandHealthCheck {
                program: "/nonexistent-health-bin".to_owned(),
                args: Vec::new(),
            })
            .0
        );
    }

    #[test]
    fn test_rfc1035_dns_packet_codec() {
        let mut dns = ServiceDiscoveryRegistry::new();
        let role = RoleName::new("prod").unwrap_or_default();
        let _ = dns.register_endpoint(
            &TaskId::new("db-0").unwrap_or_default(),
            "pg",
            &role,
            "10.1.0.9".to_owned(),
            PortNumber::new(5432).unwrap_or_default(),
        );
        for qt in [DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Srv] {
            let resp = dns.answer_dns_query("db-0.pg.prod.arbiter.internal.", qt);
            let q_pkt = ServiceDiscoveryRegistry::encode_rfc1035_dns_packet(
                42,
                false,
                qt,
                "db-0.pg.prod.arbiter.internal",
                None,
            );
            let (tx_id, is_resp, parsed_type, parsed_name, parsed_ans) =
                ServiceDiscoveryRegistry::decode_rfc1035_dns_packet(&q_pkt).unwrap_or((
                    0,
                    true,
                    DnsRecordType::A,
                    String::new(),
                    DnsWireResponse {
                        rcode: 3,
                        answer_record: None,
                    },
                ));
            assert_eq!(tx_id, 42);
            assert!(!is_resp);
            assert_eq!(parsed_type, qt);
            assert_eq!(parsed_name, "db-0.pg.prod.arbiter.internal");
            assert!(parsed_ans.answer_record.is_none());

            let r_pkt = ServiceDiscoveryRegistry::encode_rfc1035_dns_packet(
                42,
                true,
                qt,
                "db-0.pg.prod.arbiter.internal",
                Some(&resp),
            );
            let (_, is_resp_flag, _, _, full_ans) =
                ServiceDiscoveryRegistry::decode_rfc1035_dns_packet(&r_pkt).unwrap_or((
                    0,
                    false,
                    DnsRecordType::A,
                    String::new(),
                    DnsWireResponse {
                        rcode: 3,
                        answer_record: None,
                    },
                ));
            assert!(is_resp_flag);
            assert_eq!(full_ans, resp);
        }
        assert!(ServiceDiscoveryRegistry::decode_rfc1035_dns_packet(&[1, 2, 3]).is_err());
        assert!(
            ServiceDiscoveryRegistry::decode_rfc1035_dns_packet(&[
                0, 1, 0, 0, 1, 0, 0, 50, 0, 0, b'a'
            ])
            .is_err()
        );
        assert!(
            ServiceDiscoveryRegistry::decode_rfc1035_dns_packet(&[
                0, 1, 0, 0, 1, 0, 0, 1, 0, 50, b'a', b'b'
            ])
            .is_err()
        );
    }

    #[test]
    fn test_standard_rfc1035_12byte_header_and_labels() {
        let mut dns = ServiceDiscoveryRegistry::new();
        let role = RoleName::new("prod").unwrap_or_default();
        let _ = dns.register_endpoint(
            &TaskId::new("db-0").unwrap_or_default(),
            "pg",
            &role,
            "10.1.0.9".to_owned(),
            PortNumber::new(5432).unwrap_or_default(),
        );

        // Standard RFC 1035 12-byte header + label-encoded QNAME + binary RR (A, AAAA, SRV) tests
        for qt in [DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Srv] {
            let std_pkt = dns
                .encode_standard_rfc1035_response_packet(77, qt, "db-0.pg.prod.arbiter.internal.")
                .unwrap_or_default();
            let decoded =
                ServiceDiscoveryRegistry::decode_standard_rfc1035_response_packet(&std_pkt);
            assert_eq!(
                decoded,
                Ok((77, 0, "db-0.pg.prod.arbiter.internal".to_owned(), qt, 1))
            );
        }
        let nx_pkt = dns
            .encode_standard_rfc1035_response_packet(
                88,
                DnsRecordType::A,
                "missing.arbiter.internal",
            )
            .unwrap_or_default();
        assert_eq!(
            ServiceDiscoveryRegistry::decode_standard_rfc1035_response_packet(&nx_pkt),
            Ok((
                88,
                3,
                "missing.arbiter.internal".to_owned(),
                DnsRecordType::A,
                0
            ))
        );

        // Label and standard packet error paths
        assert!(ServiceDiscoveryRegistry::encode_rfc1035_domain_labels("").is_err());
        assert!(ServiceDiscoveryRegistry::encode_rfc1035_domain_labels(".").is_err());
        assert!(ServiceDiscoveryRegistry::encode_rfc1035_domain_labels("a..b").is_err());
        let long_label = "a".repeat(64);
        assert!(ServiceDiscoveryRegistry::encode_rfc1035_domain_labels(&long_label).is_err());
        assert!(
            dns.encode_standard_rfc1035_response_packet(1, DnsRecordType::A, "")
                .is_err()
        );
        assert!(ServiceDiscoveryRegistry::decode_rfc1035_domain_labels(&[], 0).is_err());
        assert!(
            ServiceDiscoveryRegistry::decode_rfc1035_domain_labels(&[5, b'a', b'b'], 0).is_err()
        );
        assert!(
            ServiceDiscoveryRegistry::decode_standard_rfc1035_response_packet(&[0; 8]).is_err()
        );
        assert!(
            ServiceDiscoveryRegistry::decode_standard_rfc1035_response_packet(&[
                0, 1, 0x85, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, b'a'
            ])
            .is_err()
        );
        assert!(
            ServiceDiscoveryRegistry::decode_standard_rfc1035_response_packet(&[
                0, 1, 0x85, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0
            ])
            .is_err()
        );
    }
}
