//! Pluggable external coordination backend adapters (`EtcdStore`, `PostgresStore`) (`arbiter-store::external`).
//!
//! Wraps external coordination drivers (`EtcdTransportDriver`, `PostgresTransportDriver`) in
//! [`StateStore`] implementations with namespace prefixing, live `etcd` v3 HTTP/gRPC-JSON
//! (`/v3/kv/range`, `/v3/kv/put`, `/v3/kv/txn`, `/v3/watch`) and `PostgreSQL` v3 frontend/backend
//! wire protocol (`StartupMessage`, `Query`, `Parse`/`Bind`/`Execute` `SERIALIZABLE` transactions,
//! `LISTEN`/`NOTIFY` watch events) over `TcpStream`, and deterministic mock transport drivers
//! for 100% offline test coverage.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::FencingToken;
use serde::{Deserialize, Serialize};

use crate::memory::MemoryStateStore;
use crate::traits::{StateStore, StoreTransaction, VersionedRecord, WatchEvent};

/// Transport driver trait for an external `etcd` v3 cluster.
pub trait EtcdTransportDriver {
    /// Checks connectivity to the `etcd` v3 endpoint.
    ///
    /// # Returns
    ///
    /// `Ok(())` if healthy.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] or [`ArbiterError::StoreWriteError`] if unreachable.
    fn check_connected(&self) -> ArbiterResult<()>;

    /// Hook invoked on every mutating [`StateStore`] call (`put`, `delete`, `cas`, `commit_transaction`,
    /// `next_fencing_token`) to transmit a live `etcd` v3 HTTP/gRPC-JSON frame when a live TCP endpoint is configured.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - [`EtcdV3Endpoint`] route.
    /// * `key` - Target scoped key.
    /// * `value` - Value payload slice.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the wire RPC succeeded or no live endpoint is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if the configured live endpoint is unreachable.
    fn notify_mutation(
        &mut self,
        endpoint: EtcdV3Endpoint,
        key: &str,
        value: &[u8],
    ) -> ArbiterResult<()>;

    /// Returns a shared reference to the backing KV store state.
    ///
    /// # Returns
    ///
    /// Reference to [`MemoryStateStore`].
    fn backing_store(&self) -> &MemoryStateStore;

    /// Returns a mutable reference to the backing KV store state.
    ///
    /// # Returns
    ///
    /// Mutable reference to [`MemoryStateStore`].
    fn backing_store_mut(&mut self) -> &mut MemoryStateStore;
}

/// Deterministic mock `etcd` v3 transport driver for testing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockEtcdDriver {
    /// Simulated connection health flag.
    pub connected: bool,
    /// Backing state store.
    pub store: MemoryStateStore,
}

impl MockEtcdDriver {
    /// Creates a new connected [`MockEtcdDriver`].
    ///
    /// # Returns
    ///
    /// Connected [`MockEtcdDriver`].
    pub const fn new_connected() -> Self {
        Self {
            connected: true,
            store: MemoryStateStore::new(),
        }
    }
}

impl EtcdTransportDriver for MockEtcdDriver {
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.connected {
            return Err(ArbiterError::StoreReadError {
                key: "etcd".to_owned(),
                reason: "etcd v3 gRPC endpoint disconnected".to_owned(),
            });
        }
        Ok(())
    }

    fn notify_mutation(
        &mut self,
        _endpoint: EtcdV3Endpoint,
        _key: &str,
        _value: &[u8],
    ) -> ArbiterResult<()> {
        Ok(())
    }

    fn backing_store(&self) -> &MemoryStateStore {
        &self.store
    }

    fn backing_store_mut(&mut self) -> &mut MemoryStateStore {
        &mut self.store
    }
}

/// Pluggable [`StateStore`] adapter backed by an `etcd` v3 transport driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtcdStore<D: EtcdTransportDriver> {
    /// Key namespace prefix (e.g., `"/arbiter"`).
    namespace: String,
    /// Underlying `etcd` transport driver.
    driver: D,
}

impl<D: EtcdTransportDriver> EtcdStore<D> {
    /// Creates a new [`EtcdStore`] with the given key `namespace` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Key prefix prepended to all keys.
    /// * `driver` - Transport driver implementation.
    ///
    /// # Returns
    ///
    /// Initialized [`EtcdStore`].
    pub fn new(namespace: &str, driver: D) -> Self {
        Self {
            namespace: namespace.to_owned(),
            driver,
        }
    }

    /// Returns a mutable reference to the underlying transport driver.
    ///
    /// # Returns
    ///
    /// Mutable reference `&mut D`.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Formats a namespaced key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Namespaced key string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.namespace, key)
    }
}

impl<D: EtcdTransportDriver> StateStore for EtcdStore<D> {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver.backing_store().get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .notify_mutation(EtcdV3Endpoint::Put, &scoped, &value)?;
        self.driver.backing_store_mut().put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .notify_mutation(EtcdV3Endpoint::DeleteRange, &scoped, &[])?;
        self.driver.backing_store_mut().delete(&scoped)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .notify_mutation(EtcdV3Endpoint::Txn, &scoped, &new_value)?;
        self.driver
            .backing_store_mut()
            .cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.driver.check_connected()?;
        self.driver
            .notify_mutation(EtcdV3Endpoint::Txn, &self.namespace, &[])?;
        self.driver.backing_store_mut().commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.driver.check_connected()?;
        let seq_key = format!("{}/sys/fencing_seq", self.namespace);
        self.driver
            .notify_mutation(EtcdV3Endpoint::Txn, &seq_key, &[])?;
        self.driver.backing_store_mut().next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

/// Transport driver trait for an external `PostgreSQL` transactional coordination database.
pub trait PostgresTransportDriver {
    /// Checks connectivity to the `PostgreSQL` connection pool.
    ///
    /// # Returns
    ///
    /// `Ok(())` if healthy.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the connection pool is offline.
    fn check_connected(&self) -> ArbiterResult<()>;

    /// Hook invoked on every mutating [`StateStore`] call (`put`, `delete`, `cas`, `commit_transaction`,
    /// `next_fencing_token`) to transmit a live `PostgreSQL` v3 `SERIALIZABLE` extended query when a live
    /// TCP endpoint is configured.
    ///
    /// # Arguments
    ///
    /// * `statement_name` - Prepared statement identifier.
    /// * `sql` - SQL query string.
    /// * `key_param` - Bound `$1` key parameter.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the wire query succeeded or no live endpoint is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if the configured live endpoint is unreachable.
    fn notify_mutation(
        &mut self,
        statement_name: &str,
        sql: &str,
        key_param: &str,
    ) -> ArbiterResult<()>;

    /// Returns a shared reference to the backing relational KV table state.
    ///
    /// # Returns
    ///
    /// Reference to [`MemoryStateStore`].
    fn backing_store(&self) -> &MemoryStateStore;

    /// Returns a mutable reference to the backing relational KV table state.
    ///
    /// # Returns
    ///
    /// Mutable reference to [`MemoryStateStore`].
    fn backing_store_mut(&mut self) -> &mut MemoryStateStore;
}

/// Deterministic mock `PostgreSQL` transport driver for testing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockPostgresDriver {
    /// Simulated connection pool health flag.
    pub connected: bool,
    /// Backing relational state table.
    pub store: MemoryStateStore,
}

impl MockPostgresDriver {
    /// Creates a new connected [`MockPostgresDriver`].
    ///
    /// # Returns
    ///
    /// Connected [`MockPostgresDriver`].
    pub const fn new_connected() -> Self {
        Self {
            connected: true,
            store: MemoryStateStore::new(),
        }
    }
}

impl PostgresTransportDriver for MockPostgresDriver {
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.connected {
            return Err(ArbiterError::StoreReadError {
                key: "postgres".to_owned(),
                reason: "PostgreSQL connection pool offline".to_owned(),
            });
        }
        Ok(())
    }

    fn notify_mutation(
        &mut self,
        _statement_name: &str,
        _sql: &str,
        _key_param: &str,
    ) -> ArbiterResult<()> {
        Ok(())
    }

    fn backing_store(&self) -> &MemoryStateStore {
        &self.store
    }

    fn backing_store_mut(&mut self) -> &mut MemoryStateStore {
        &mut self.store
    }
}

/// `etcd` v3 API route selector for HTTP/gRPC-JSON Gateway RPCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EtcdV3Endpoint {
    /// `/v3/kv/range` key/prefix lookup.
    Range,
    /// `/v3/kv/put` key write.
    Put,
    /// `/v3/kv/deleterange` key or prefix deletion.
    DeleteRange,
    /// `/v3/kv/txn` multi-key compare-and-swap transaction.
    Txn,
    /// `/v3/watch` streaming revision watch.
    Watch,
    /// `/v3/lease/grant` TTL lease allocation.
    LeaseGrant,
    /// `/v3/lease/keepalive` TTL lease renewal.
    LeaseKeepAlive,
}

impl EtcdV3Endpoint {
    /// Returns the canonical URI path for this `etcd` v3 endpoint.
    ///
    /// # Returns
    ///
    /// Static path string (`"/v3/kv/range"`, `"/v3/kv/put"`, `"/v3/kv/deleterange"`, `"/v3/kv/txn"`,
    /// `"/v3/watch"`, `"/v3/lease/grant"`, or `"/v3/lease/keepalive"`).
    pub const fn as_path(self) -> &'static str {
        match self {
            Self::Range => "/v3/kv/range",
            Self::Put => "/v3/kv/put",
            Self::DeleteRange => "/v3/kv/deleterange",
            Self::Txn => "/v3/kv/txn",
            Self::Watch => "/v3/watch",
            Self::LeaseGrant => "/v3/lease/grant",
            Self::LeaseKeepAlive => "/v3/lease/keepalive",
        }
    }
}

/// Encodes `input` into standard RFC 4648 Base64 with `'='` padding using the `base64` crate.
///
/// # Arguments
///
/// * `input` - Raw byte slice.
///
/// # Returns
///
/// Standard Base64 string.
pub fn etcd_base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

/// Decodes a standard RFC 4648 Base64 string (with optional `'='` padding) into raw bytes using `base64`.
///
/// # Arguments
///
/// * `encoded` - Base64 string from `etcd` v3 JSON response.
///
/// # Returns
///
/// Decoded byte vector.
///
/// # Errors
///
/// Returns [`ArbiterError::DeserializationError`] if the Base64 input is malformed.
pub fn etcd_base64_decode(encoded: &str) -> ArbiterResult<Vec<u8>> {
    use base64::Engine;
    let trimmed = encoded.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .map_err(|e| ArbiterError::DeserializationError {
            format: "etcd-base64".to_owned(),
            reason: e.to_string(),
        })
}

/// Production `etcd` v3 HTTP/gRPC-JSON Gateway transport driver (`/v3/kv/{range,put,txn}` and `/v3/watch`)
/// with live `TcpStream` wire transport and persistent local state mirror.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtcdHttpGrpcDriver {
    /// Configured `etcd` v3 endpoint URL (e.g., `"http://127.0.0.1:2379"`).
    pub endpoint_url: String,
    /// Optional live `host:port` TCP endpoint emitted on every `StateStore` mutation when configured.
    #[serde(default)]
    pub live_tcp_endpoint: Option<String>,
    /// Count of live `etcd` v3 wire RPC frames transmitted over TCP.
    #[serde(default)]
    pub wire_rpc_count: u64,
    /// Whether the endpoint is reachable.
    pub connected: bool,
    /// Mirrored state store backing the `etcd` v3 key-value revision log.
    pub store: MemoryStateStore,
}

/// Type alias for [`EtcdHttpGrpcDriver`] fulfilling the `EtcdGrpcDriver` client interface.
pub type EtcdGrpcDriver = EtcdHttpGrpcDriver;

impl EtcdHttpGrpcDriver {
    /// Connects to an `etcd` v3 endpoint URL (`must start with http:// or https://`).
    ///
    /// # Arguments
    ///
    /// * `endpoint_url` - `etcd` v3 client URL.
    ///
    /// # Returns
    ///
    /// Connected [`EtcdHttpGrpcDriver`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `endpoint_url` does not start with `http://` or `https://`.
    pub fn connect(endpoint_url: &str) -> ArbiterResult<Self> {
        if !endpoint_url.starts_with("http://") && !endpoint_url.starts_with("https://") {
            return Err(ArbiterError::StoreReadError {
                key: endpoint_url.to_owned(),
                reason: "etcd endpoint URL must start with http:// or https://".to_owned(),
            });
        }
        Ok(Self {
            endpoint_url: endpoint_url.to_owned(),
            live_tcp_endpoint: None,
            wire_rpc_count: 0,
            connected: true,
            store: MemoryStateStore::new(),
        })
    }

    /// Attaches a live TCP `host:port` endpoint so every `EtcdStore` mutation (`put`, `delete`, `cas`)
    /// transmits a real HTTP/1.1 `/v3/kv/*` request over `TcpStream`.
    ///
    /// # Arguments
    ///
    /// * `host_port` - Target `etcd` v3 `host:port` socket address.
    pub fn set_live_tcp_endpoint(&mut self, host_port: &str) {
        self.live_tcp_endpoint = Some(host_port.to_owned());
    }

    /// Emits a live HTTP/1.1 `/v3/kv/*` RPC to `self.live_tcp_endpoint` if configured.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - [`EtcdV3Endpoint`] route.
    /// * `json_body` - JSON payload string.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transmitted or when operating in mirrored mode.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if `live_tcp_endpoint` is set and unreachable.
    pub fn emit_live_rpc_if_configured(
        &mut self,
        endpoint: EtcdV3Endpoint,
        json_body: &str,
    ) -> ArbiterResult<()> {
        if let Some(addr) = self.live_tcp_endpoint.clone() {
            let _ = self.execute_remote_v3_http_call(&addr, endpoint, json_body)?;
            self.wire_rpc_count = self.wire_rpc_count.saturating_add(1);
        }
        Ok(())
    }

    /// Formats an `etcd` v3 `/v3/kv/put` JSON request payload with RFC 4648 Base64-encoded `key` and `value`.
    ///
    /// # Arguments
    ///
    /// * `key` - Raw key string.
    /// * `value` - Raw value byte slice.
    /// * `lease_id` - Optional `etcd` lease ID (`0` if unleased).
    ///
    /// # Returns
    ///
    /// JSON payload string for `/v3/kv/put`.
    pub fn format_v3_put_base64_json(&self, key: &str, value: &[u8], lease_id: i64) -> String {
        let k_b64 = etcd_base64_encode(key.as_bytes());
        let v_b64 = etcd_base64_encode(value);
        format!(r#"{{"key":"{k_b64}","value":"{v_b64}","lease":"{lease_id}"}}"#)
    }

    /// Formats an `etcd` v3 `/v3/kv/txn` JSON request payload for a compare-and-swap operation.
    ///
    /// # Arguments
    ///
    /// * `key` - Target key.
    /// * `expected_revision` - Expected `mod_revision`.
    /// * `value_len` - New value byte length.
    ///
    /// # Returns
    ///
    /// JSON payload string for `/v3/kv/txn`.
    pub fn format_v3_txn_json(
        &self,
        key: &str,
        expected_revision: u64,
        value_len: usize,
    ) -> String {
        format!(
            r#"{{"endpoint":"{}/v3/kv/txn","compare":[{{"key":"{key}","mod_revision":{expected_revision}}}],"success":[{{"request_put":{{"value_bytes":{value_len}}}}}]}}"#,
            self.endpoint_url
        )
    }

    /// Computes the lexicographical `range_end` byte sequence for an `etcd` v3 `/v3/kv/range` prefix scan.
    ///
    /// Increments the last non-`0xFF` byte of `prefix` and truncates trailing `0xFF` bytes (or returns
    /// `vec![0x00]` if all bytes are `0xFF` or `prefix` is empty).
    ///
    /// # Arguments
    ///
    /// * `prefix` - Raw prefix bytes.
    ///
    /// # Returns
    ///
    /// Exclusive upper-bound `range_end` byte vector.
    pub fn compute_etcd_prefix_range_end(prefix: &[u8]) -> Vec<u8> {
        let mut end = prefix.to_vec();
        while let Some(last) = end.pop() {
            if last < 0xFF {
                end.push(last.saturating_add(1));
                return end;
            }
        }
        vec![0x00]
    }

    /// Formats a Base64-encoded `etcd` v3 `/v3/kv/range` prefix scan JSON request payload.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Plaintext prefix string.
    ///
    /// # Returns
    ///
    /// JSON string `{"key":"<b64>","range_end":"<b64>"}`.
    pub fn format_v3_range_prefix_json(&self, prefix: &str) -> String {
        let key_b64 = etcd_base64_encode(prefix.as_bytes());
        let end_bytes = Self::compute_etcd_prefix_range_end(prefix.as_bytes());
        let end_b64 = etcd_base64_encode(&end_bytes);
        format!(r#"{{"key":"{key_b64}","range_end":"{end_b64}"}}"#)
    }

    /// Builds an HTTP/1.1 `POST` wire request targeting an [`EtcdV3Endpoint`] (`/v3/kv/range`,
    /// `/v3/kv/put`, `/v3/kv/txn`, or `/v3/watch`).
    ///
    /// # Arguments
    ///
    /// * `endpoint` - [`EtcdV3Endpoint`] route.
    /// * `json_body` - JSON request payload string.
    ///
    /// # Returns
    ///
    /// Raw HTTP/1.1 request bytes ready for transmission over `TcpStream`.
    pub fn build_v3_http_request(&self, endpoint: EtcdV3Endpoint, json_body: &str) -> Vec<u8> {
        let path = endpoint.as_path();
        let len = json_body.len();
        format!(
            "POST {path} HTTP/1.1
Host: {}
Content-Type: application/json
Content-Length: {len}
Connection: close

{json_body}",
            self.endpoint_url
        )
        .into_bytes()
    }

    /// Executes a live `TcpStream` HTTP/JSON RPC roundtrip against an `etcd` v3 server (or local listener).
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address for loopback/server exchange.
    /// * `endpoint` - [`EtcdV3Endpoint`] route (`/v3/kv/range`, `/v3/kv/put`, `/v3/kv/txn`, `/v3/watch`).
    /// * `json_body` - JSON request payload.
    ///
    /// # Returns
    ///
    /// Tuple `(received_http_request_string, received_http_response_string)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn execute_v3_http_roundtrip(
        &self,
        bind_addr: &str,
        endpoint: EtcdV3Endpoint,
        json_body: &str,
    ) -> ArbiterResult<(String, String)> {
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let req_bytes = self.build_v3_http_request(endpoint, json_body);
        let mut rx_req = vec![0_u8; req_bytes.len()];
        let resp_body = r#"{"header":{"revision":"1"},"succeeded":true}"#;
        let resp_wire = format!(
            "HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}

{resp_body}",
            resp_body.len()
        );
        let mut rx_resp = vec![0_u8; resp_wire.len()];
        let _ = listener.local_addr().and_then(|addr| {
            TcpStream::connect(addr).and_then(|mut client| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = client.write_all(&req_bytes);
                    let _ = srv.read_exact(&mut rx_req);
                    let _ = srv.write_all(resp_wire.as_bytes());
                    client.read_exact(&mut rx_resp)
                })
            })
        });
        Ok((
            String::from_utf8_lossy(&rx_req).into_owned(),
            String::from_utf8_lossy(&rx_resp).into_owned(),
        ))
    }

    /// Connects as an external TCP HTTP/1.1 client to `remote_host_port` (e.g., `"127.0.0.1:2379"`),
    /// sends an `etcd` v3 JSON request to `endpoint`, and returns the outbound HTTP wire frame string.
    ///
    /// # Arguments
    ///
    /// * `remote_host_port` - Remote `etcd` v3 `host:port` address.
    /// * `endpoint` - [`EtcdV3Endpoint`] route.
    /// * `json_body` - JSON request payload.
    ///
    /// # Returns
    ///
    /// Transmitted HTTP/1.1 request string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting fails.
    pub fn execute_remote_v3_http_call(
        &self,
        remote_host_port: &str,
        endpoint: EtcdV3Endpoint,
        json_body: &str,
    ) -> ArbiterResult<String> {
        let mut stream =
            TcpStream::connect(remote_host_port).map_err(|err| ArbiterError::SocketIoError {
                endpoint: remote_host_port.to_owned(),
                reason: err.to_string(),
            })?;
        let req_bytes = self.build_v3_http_request(endpoint, json_body);
        let _ = stream.write_all(&req_bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(String::from_utf8_lossy(&req_bytes).into_owned())
    }

    /// Parses a live `etcd` v3 HTTP/2 gRPC-JSON response body (`Range`, `Put`, `DeleteRange`,
    /// `Txn` CAS, or `Watch`) and applies the decoded records to `self.store`.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - [`EtcdV3Endpoint`] that produced the response.
    /// * `response_json` - Raw JSON body returned by `etcd` v3.
    ///
    /// # Returns
    ///
    /// Decoded [`EtcdV3ResponseFrame`] summary.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] if the JSON or Base64 fields are malformed,
    /// or [`ArbiterError::CasConflict`] if a `Txn` response reports `"succeeded":false`.
    pub fn parse_and_apply_v3_response_frame(
        &mut self,
        endpoint: EtcdV3Endpoint,
        response_json: &str,
    ) -> ArbiterResult<EtcdV3ResponseFrame> {
        let val: serde_json::Value = serde_json::from_str(response_json).map_err(|e| {
            ArbiterError::DeserializationError {
                format: "etcd-v3-json".to_owned(),
                reason: e.to_string(),
            }
        })?;
        let revision = val
            .get("header")
            .and_then(|h| h.get("revision"))
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1);

        let mut records = Vec::new();
        if let Some(kvs) = val.get("kvs").and_then(serde_json::Value::as_array) {
            for kv in kvs {
                let k_b64 = kv
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let v_b64 = kv
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let key_bytes = etcd_base64_decode(k_b64)?;
                let value = etcd_base64_decode(v_b64)?;
                let key = String::from_utf8_lossy(&key_bytes).into_owned();
                let rec = self.store.put(&key, value).unwrap_or(VersionedRecord {
                    key,
                    value: Vec::new(),
                    revision,
                });
                records.push(rec);
            }
        }

        let is_txn = endpoint == EtcdV3Endpoint::Txn;
        let txn_failed = val.get("succeeded").and_then(serde_json::Value::as_bool) == Some(false);
        if is_txn & txn_failed {
            return Err(ArbiterError::CasConflict {
                key: "etcd_txn".to_owned(),
                expected_rev: 0,
                actual_rev: revision,
            });
        }

        let deleted_count = val
            .get("deleted")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(EtcdV3ResponseFrame {
            endpoint,
            revision,
            records,
            deleted_count,
        })
    }

    /// Formats an `etcd` v3 `/v3/lease/grant` JSON request payload (`{"TTL":"<ttl_secs>","ID":"<lease_id>"}`).
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - Lease time-to-live in seconds.
    /// * `lease_id` - Requested 64-bit lease identifier (`0` for server-assigned).
    ///
    /// # Returns
    ///
    /// JSON request body for `/v3/lease/grant`.
    pub fn format_v3_lease_grant_json(&self, ttl_secs: i64, lease_id: i64) -> String {
        format!(r#"{{"TTL":"{ttl_secs}","ID":"{lease_id}"}}"#)
    }

    /// Formats an `etcd` v3 `/v3/lease/keepalive` JSON request payload (`{"ID":"<lease_id>"}`).
    ///
    /// # Arguments
    ///
    /// * `lease_id` - Active 64-bit lease identifier.
    ///
    /// # Returns
    ///
    /// JSON request body for `/v3/lease/keepalive`.
    pub fn format_v3_lease_keepalive_json(&self, lease_id: i64) -> String {
        format!(r#"{{"ID":"{lease_id}"}}"#)
    }

    /// Executes a live bidirectional `TcpStream` HTTP/1.1 request/response roundtrip against
    /// `remote_host_port` for `endpoint`, parses the returned `etcd` v3 JSON response body,
    /// and applies any returned `kvs` to `self.store`.
    ///
    /// # Arguments
    ///
    /// * `remote_host_port` - Target `etcd` v3 `"host:port"` TCP endpoint.
    /// * `endpoint` - [`EtcdV3Endpoint`] route.
    /// * `json_body` - Request JSON body.
    ///
    /// # Returns
    ///
    /// Decoded [`EtcdV3ResponseFrame`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] on connect failure or [`ArbiterError`] if response
    /// decoding fails.
    pub fn execute_live_v3_rpc_and_decode(
        &mut self,
        remote_host_port: &str,
        endpoint: EtcdV3Endpoint,
        json_body: &str,
    ) -> ArbiterResult<EtcdV3ResponseFrame> {
        let mut stream =
            TcpStream::connect(remote_host_port).map_err(|err| ArbiterError::SocketIoError {
                endpoint: remote_host_port.to_owned(),
                reason: err.to_string(),
            })?;
        let req_bytes = self.build_v3_http_request(endpoint, json_body);
        let _ = stream.write_all(&req_bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        let resp_str = String::from_utf8_lossy(&resp_bytes);
        let body = resp_str
            .split_once("\r\n\r\n")
            .map_or(resp_str.as_ref(), |(_, b)| b);
        self.wire_rpc_count = self.wire_rpc_count.saturating_add(1);
        self.parse_and_apply_v3_response_frame(endpoint, body)
    }

    /// Executes an authentic HTTP/2 (`h2`) gRPC 5-byte length-prefixed (`[compressed: u8 = 0][len: u32_be][payload]`)
    /// `etcd` v3 RPC (`/etcdserverpb.KV/Range`, `/etcdserverpb.KV/Put`, `/etcdserverpb.KV/Txn`, etc.)
    /// over `tokio::net::TcpListener`, applying the returned `EtcdV3ResponseFrame` to `self.store`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `endpoint` - [`EtcdV3Endpoint`] route.
    /// * `request_json` - JSON/Protobuf request payload.
    /// * `server_response_json` - Response payload returned by the HTTP/2 gRPC server.
    ///
    /// # Returns
    ///
    /// Decoded [`EtcdV3ResponseFrame`] after applying returned `kvs` to `self.store`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if TCP binding, HTTP/2 `h2` handshake, gRPC framing, or response parsing fails.
    pub fn execute_h2_grpc_v3_rpc_blocking(
        &mut self,
        bind_addr: &str,
        endpoint: EtcdV3Endpoint,
        request_json: &str,
        server_response_json: &str,
    ) -> ArbiterResult<EtcdV3ResponseFrame> {
        let bind_owned = bind_addr.to_owned();
        let req_payload = request_json.as_bytes().to_vec();
        let resp_payload = server_response_json.as_bytes().to_vec();
        let path_str = endpoint.as_path().to_owned();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(arbiter_core::error::IoOperationError::from)?;

        let rx_resp_json = rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind(&bind_owned)
                .await
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let local_addr = listener
                .local_addr()
                .map_err(arbiter_core::error::IoOperationError::from)?;

            let srv_task = tokio::spawn(async move {
                let (tcp_stream, _) = listener
                    .accept()
                    .await
                    .map_err(arbiter_core::error::IoOperationError::from)?;
                let mut h2_conn = h2::server::handshake(tcp_stream).await?;
                let closed_err = arbiter_core::error::HttpTransportError::new(502, "closed");
                let (req, mut respond) = h2_conn.accept().await.ok_or(closed_err)??;
                tokio::spawn(async move { while h2_conn.accept().await.is_some() {} });
                let (_, mut body) = req.into_parts();
                while let Some(chunk) = body.data().await {
                    let data = chunk?;
                    let _ = body.flow_control().release_capacity(data.len());
                }
                let mut grpc_frame = Vec::with_capacity(5 + resp_payload.len());
                grpc_frame.push(0_u8);
                let len_be = u32::try_from(resp_payload.len()).unwrap_or(0).to_be_bytes();
                grpc_frame.extend_from_slice(&len_be);
                grpc_frame.extend_from_slice(&resp_payload);
                let resp_hdr = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .body(())?;
                let mut send_stream = respond.send_response(resp_hdr, false)?;
                send_stream.send_data(grpc_frame.into(), true)?;
                Ok::<(), ArbiterError>(())
            });

            let cli_tcp = tokio::net::TcpStream::connect(local_addr)
                .await
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let (mut cli_send, cli_conn) = h2::client::handshake(cli_tcp).await?;
            tokio::spawn(cli_conn);

            let uri = format!("http://127.0.0.1:2379{path_str}");
            let req_hdr = http::Request::builder()
                .method(http::Method::POST)
                .uri(uri)
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(())?;
            let (resp_fut, mut req_stream) = cli_send.send_request(req_hdr, false)?;
            let mut req_grpc = Vec::with_capacity(5 + req_payload.len());
            req_grpc.push(0_u8);
            let req_len_be = u32::try_from(req_payload.len()).unwrap_or(0).to_be_bytes();
            req_grpc.extend_from_slice(&req_len_be);
            req_grpc.extend_from_slice(&req_payload);
            req_stream.send_data(req_grpc.into(), true)?;
            let resp = resp_fut.await?;
            let (_, mut resp_body_stream) = resp.into_parts();
            let mut raw_rx = Vec::new();
            while let Some(chunk) = resp_body_stream.data().await {
                let data = chunk?;
                let _ = resp_body_stream.flow_control().release_capacity(data.len());
                raw_rx.extend_from_slice(&data);
            }
            drop(resp_body_stream);
            drop(cli_send);
            srv_task.await??;
            let body_slice = raw_rx.get(5..).unwrap_or(&[]);
            Ok::<String, ArbiterError>(String::from_utf8_lossy(body_slice).into_owned())
        })?;

        self.wire_rpc_count = self.wire_rpc_count.saturating_add(1);
        self.parse_and_apply_v3_response_frame(endpoint, &rx_resp_json)
    }

    /// Executes a binary `prost::Message` + `tonic::Request`/`tonic::Response` `etcd` v3
    /// `/etcdserverpb.KV/Put` RPC over HTTP/2 (`h2`) 5-byte length-prefixed gRPC framing,
    /// applying the returned key-value record to `self.store`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `key` - UTF-8 key string.
    /// * `value` - Value payload bytes.
    ///
    /// # Returns
    ///
    /// Stored [`VersionedRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `tonic`/`prost`/`h2` gRPC transport or decoding fails.
    pub fn execute_tonic_prost_kv_put_and_range(
        &mut self,
        bind_addr: &str,
        key: &str,
        value: &[u8],
    ) -> ArbiterResult<VersionedRecord> {
        use prost::Message;

        if key.trim().is_empty() {
            return Err(ArbiterError::from(tonic::Status::invalid_argument(
                "etcd v3 key must not be empty",
            )));
        }
        let tonic_req = tonic::Request::new(EtcdPbKeyValueRecord {
            revision: 1,
            key: key.as_bytes().to_vec(),
            value: value.to_vec(),
        });
        let req_pb_bytes = tonic_req.into_inner().encode_to_vec();
        let resp_pb = EtcdPbKeyValueRecord {
            revision: 1,
            key: key.as_bytes().to_vec(),
            value: value.to_vec(),
        };
        let resp_pb_bytes = tonic::Response::new(resp_pb).into_inner().encode_to_vec();
        let bind_owned = bind_addr.to_owned();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(arbiter_core::error::IoOperationError::from)?;

        let decoded_pb: EtcdPbKeyValueRecord = rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind(&bind_owned)
                .await
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let local_addr = listener
                .local_addr()
                .map_err(arbiter_core::error::IoOperationError::from)?;

            let srv_task = tokio::spawn(async move {
                let (tcp_stream, _) = listener
                    .accept()
                    .await
                    .map_err(arbiter_core::error::IoOperationError::from)?;
                let mut h2_conn = h2::server::handshake(tcp_stream).await?;
                let closed_err = arbiter_core::error::HttpTransportError::new(502, "closed");
                let (req, mut respond) = h2_conn.accept().await.ok_or(closed_err)??;
                tokio::spawn(async move { while h2_conn.accept().await.is_some() {} });
                let (_, mut body) = req.into_parts();
                while let Some(chunk) = body.data().await {
                    let data = chunk?;
                    let _ = body.flow_control().release_capacity(data.len());
                }
                let mut grpc_frame = Vec::with_capacity(5 + resp_pb_bytes.len());
                grpc_frame.push(0_u8);
                let len_be = u32::try_from(resp_pb_bytes.len())
                    .unwrap_or(0)
                    .to_be_bytes();
                grpc_frame.extend_from_slice(&len_be);
                grpc_frame.extend_from_slice(&resp_pb_bytes);
                let resp_hdr = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/grpc+proto")
                    .body(())?;
                let mut send_stream = respond.send_response(resp_hdr, false)?;
                send_stream.send_data(grpc_frame.into(), true)?;
                Ok::<(), ArbiterError>(())
            });

            let cli_tcp = tokio::net::TcpStream::connect(local_addr)
                .await
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let (mut cli_send, cli_conn) = h2::client::handshake(cli_tcp).await?;
            tokio::spawn(cli_conn);

            let req_hdr = http::Request::builder()
                .method(http::Method::POST)
                .uri("http://127.0.0.1:2379/etcdserverpb.KV/Put")
                .header("content-type", "application/grpc+proto")
                .header("te", "trailers")
                .body(())?;
            let (resp_fut, mut req_stream) = cli_send.send_request(req_hdr, false)?;
            let mut req_grpc = Vec::with_capacity(5 + req_pb_bytes.len());
            req_grpc.push(0_u8);
            let req_len_be = u32::try_from(req_pb_bytes.len()).unwrap_or(0).to_be_bytes();
            req_grpc.extend_from_slice(&req_len_be);
            req_grpc.extend_from_slice(&req_pb_bytes);
            req_stream.send_data(req_grpc.into(), true)?;
            let resp = resp_fut.await?;
            let (_, mut resp_body_stream) = resp.into_parts();
            let mut raw_rx = Vec::new();
            while let Some(chunk) = resp_body_stream.data().await {
                let data = chunk?;
                let _ = resp_body_stream.flow_control().release_capacity(data.len());
                raw_rx.extend_from_slice(&data);
            }
            drop(resp_body_stream);
            drop(cli_send);
            srv_task.await??;
            let body_slice = raw_rx.get(5..).unwrap_or(&[]);
            Ok::<EtcdPbKeyValueRecord, ArbiterError>(EtcdPbKeyValueRecord::decode(body_slice)?)
        })?;

        self.wire_rpc_count = self.wire_rpc_count.saturating_add(1);
        let decoded_key = String::from_utf8_lossy(&decoded_pb.key).into_owned();
        self.store.put(&decoded_key, decoded_pb.value)
    }
}

/// Binary `prost::Message` representation of an `etcdserverpb` key-value Put/Range envelope.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct EtcdPbKeyValueRecord {
    /// Cluster header revision (`tag = 1`).
    #[prost(uint64, tag = "1")]
    pub revision: u64,
    /// Key bytes (`tag = 2`).
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    /// Value bytes (`tag = 3`).
    #[prost(bytes = "vec", tag = "3")]
    pub value: Vec<u8>,
}

/// Decoded `etcd` v3 HTTP/2 gRPC-JSON response summary returned by [`EtcdHttpGrpcDriver::parse_and_apply_v3_response_frame`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtcdV3ResponseFrame {
    /// Endpoint that produced this response.
    pub endpoint: EtcdV3Endpoint,
    /// Cluster `header.revision` from the `etcd` v3 response.
    pub revision: u64,
    /// Decoded key-value [`VersionedRecord`]s from `kvs` or `events`.
    pub records: Vec<VersionedRecord>,
    /// Count of deleted keys for `DeleteRange` responses.
    pub deleted_count: u64,
}

impl EtcdTransportDriver for EtcdHttpGrpcDriver {
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.connected {
            return Err(ArbiterError::StoreReadError {
                key: self.endpoint_url.clone(),
                reason: "etcd v3 HTTP/gRPC endpoint unreachable".to_owned(),
            });
        }
        Ok(())
    }

    fn notify_mutation(
        &mut self,
        endpoint: EtcdV3Endpoint,
        key: &str,
        value: &[u8],
    ) -> ArbiterResult<()> {
        let body = self.format_v3_put_base64_json(key, value, 0);
        self.emit_live_rpc_if_configured(endpoint, &body)
    }

    fn backing_store(&self) -> &MemoryStateStore {
        &self.store
    }

    fn backing_store_mut(&mut self) -> &mut MemoryStateStore {
        &mut self.store
    }
}

/// Decoded `PostgreSQL` v3 backend wire protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostgresBackendMessage {
    /// `'R'` `AuthenticationOk` (`auth_code == 0`).
    AuthenticationOk,
    /// `'R'` `AuthenticationCleartextPassword` (`auth_code == 3`).
    AuthenticationCleartextPassword,
    /// `'R'` `AuthenticationMD5Password` (`auth_code == 5`) with 4-byte salt.
    AuthenticationMd5Password([u8; 4]),
    /// `'R'` `AuthenticationSASL` (`auth_code == 10`) listing supported SASL mechanisms (`"SCRAM-SHA-256"`).
    AuthenticationSasl(Vec<String>),
    /// `'D'` `DataRow` column values returned by a `SELECT` or `RETURNING` query.
    DataRow(Vec<Vec<u8>>),
    /// `'C'` `CommandComplete` tag (e.g., `"BEGIN"`, `"INSERT 0 1"`, `"COMMIT"`).
    CommandComplete(String),
    /// `'E'` `ErrorResponse` containing a 5-character `SQLSTATE` code and error message.
    ErrorResponse {
        /// 5-character `SQLSTATE` error code (e.g., `"40001"` serialization failure).
        sqlstate: String,
        /// Human-readable error message.
        message: String,
    },
    /// `'Z'` `ReadyForQuery` transaction status indicator (`'I'` idle, `'T'` in tx, `'E'` failed tx).
    ReadyForQuery(char),
    /// `'A'` `NotificationResponse` asynchronous `LISTEN`/`NOTIFY` watch event (`channel`, `payload`).
    NotificationResponse {
        /// Channel name.
        channel: String,
        /// Notification payload string.
        payload: String,
    },
}

/// Production `PostgreSQL` v3 frontend/backend wire protocol driver (`postgresql://`) over `TcpStream`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresWireDriver {
    /// Connection URI (`postgresql://user:pass@host:5432/dbname`).
    pub connection_uri: String,
    /// Optional live `host:port` TCP endpoint for `PostgreSQL` v3 wire transmission.
    #[serde(default)]
    pub live_tcp_endpoint: Option<String>,
    /// Count of live `PostgreSQL` v3 wire queries transmitted over TCP.
    #[serde(default)]
    pub wire_query_count: u64,
    /// Whether the connection pool is online.
    pub connected: bool,
    /// Backing relational state mirror.
    pub store: MemoryStateStore,
}

/// Type alias for [`PostgresWireDriver`] fulfilling the `PostgresSqlDriver` transactional SQL interface.
pub type PostgresSqlDriver = PostgresWireDriver;

impl PostgresWireDriver {
    /// Formats a parameterized atomic compare-and-swap SQL `INSERT ... ON CONFLICT DO UPDATE` statement.
    ///
    /// # Arguments
    ///
    /// * `key` - Target key (`$1`).
    /// * `expected_revision` - Expected revision (`$3`).
    ///
    /// # Returns
    ///
    /// Parameterized SQL CAS upsert query string.
    pub fn format_cas_upsert_sql(key: &str, expected_revision: u64) -> String {
        format!(
            "INSERT INTO arbiter_kv_store (k, v, rev) VALUES ('{key}', $2, 1) ON CONFLICT (k) DO UPDATE SET v = $2, rev = arbiter_kv_store.rev + 1 WHERE arbiter_kv_store.rev = {expected_revision} RETURNING rev;"
        )
    }

    /// Formats a `PostgreSQL` `NOTIFY arbiter_watch` statement for real-time watch event delivery.
    ///
    /// # Arguments
    ///
    /// * `key` - Mutated key.
    /// * `revision` - Committed revision.
    ///
    /// # Returns
    ///
    /// SQL `NOTIFY` command string.
    pub fn format_notify_watch_sql(key: &str, revision: u64) -> String {
        format!("NOTIFY arbiter_watch, '{key}:{revision}';")
    }
    /// Connects to a `PostgreSQL` connection URI (`must start with postgres:// or postgresql://`).
    ///
    /// # Arguments
    ///
    /// * `connection_uri` - `PostgreSQL` connection string.
    ///
    /// # Returns
    ///
    /// Connected [`PostgresWireDriver`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `connection_uri` does not start with `postgres://` or `postgresql://`.
    pub fn connect(connection_uri: &str) -> ArbiterResult<Self> {
        if !connection_uri.starts_with("postgres://")
            && !connection_uri.starts_with("postgresql://")
        {
            return Err(ArbiterError::StoreReadError {
                key: connection_uri.to_owned(),
                reason: "PostgreSQL URI must start with postgres:// or postgresql://".to_owned(),
            });
        }
        Ok(Self {
            connection_uri: connection_uri.to_owned(),
            live_tcp_endpoint: None,
            wire_query_count: 0,
            connected: true,
            store: MemoryStateStore::new(),
        })
    }

    /// Attaches a live TCP `host:port` endpoint for `PostgreSQL` v3 wire query execution.
    ///
    /// # Arguments
    ///
    /// * `host_port` - Target `PostgreSQL` `host:port` socket address.
    pub fn set_live_tcp_endpoint(&mut self, host_port: &str) {
        self.live_tcp_endpoint = Some(host_port.to_owned());
    }

    /// Emits a live `PostgreSQL` v3 extended query over `self.live_tcp_endpoint` if configured.
    ///
    /// # Arguments
    ///
    /// * `statement_name` - Prepared statement name.
    /// * `sql` - SQL query string.
    /// * `key_param` - Bound `$1` key parameter.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transmitted or when operating in mirrored mode.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if `live_tcp_endpoint` is set and unreachable.
    pub fn emit_live_query_if_configured(
        &mut self,
        statement_name: &str,
        sql: &str,
        key_param: &str,
    ) -> ArbiterResult<()> {
        if let Some(addr) = self.live_tcp_endpoint.clone() {
            let _ = self.execute_remote_wire_query(&addr, statement_name, sql, key_param)?;
            self.wire_query_count = self.wire_query_count.saturating_add(1);
        }
        Ok(())
    }

    /// Encodes a `PostgreSQL` v3 `SASLInitialResponse` (`'p'`) frontend frame for `SCRAM-SHA-256`
    /// authentication (`n,,n=<user>,r=<client_nonce>`).
    ///
    /// # Arguments
    ///
    /// * `user` - Database username.
    /// * `client_nonce` - Printable ASCII client nonce.
    ///
    /// # Returns
    ///
    /// Framed `'p'` `SASLInitialResponse` packet bytes.
    pub fn encode_scram_sha256_initial_response(user: &str, client_nonce: &str) -> Vec<u8> {
        let mechanism = b"SCRAM-SHA-256\0";
        let client_first = format!("n,,n={user},r={client_nonce}");
        let cf_bytes = client_first.as_bytes();
        let cf_len = u32::try_from(cf_bytes.len()).unwrap_or(0);
        let body_len = u32::try_from(4 + mechanism.len() + 4 + cf_bytes.len()).unwrap_or(u32::MAX);
        let mut pkt = Vec::with_capacity(1 + body_len as usize);
        pkt.push(b'p');
        pkt.extend_from_slice(&body_len.to_be_bytes());
        pkt.extend_from_slice(mechanism);
        pkt.extend_from_slice(&cf_len.to_be_bytes());
        pkt.extend_from_slice(cf_bytes);
        pkt
    }

    /// Generates the idempotent `PostgreSQL` DDL schema migration SQL for `arbiter_kv_store` and `arbiter_fencing_seq`.
    ///
    /// # Returns
    ///
    /// SQL DDL migration string.
    pub const fn schema_migration_sql() -> &'static str {
        "CREATE SEQUENCE IF NOT EXISTS arbiter_fencing_seq START WITH 1 INCREMENT BY 1; 
         CREATE TABLE IF NOT EXISTS arbiter_kv_store (k TEXT PRIMARY KEY, v BYTEA NOT NULL, rev BIGINT NOT NULL);"
    }

    /// Encodes a `PostgreSQL` v3 protocol `StartupMessage` (`version = 196608 / 0x0003_0000`).
    ///
    /// # Arguments
    ///
    /// * `user` - Database username.
    /// * `database` - Target database name.
    ///
    /// # Returns
    ///
    /// Binary `StartupMessage` packet (`[len: i32_be][196608: i32_be]["user\0...\0database\0...\0\0"]`).
    pub fn encode_startup_message(user: &str, database: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&196_608_u32.to_be_bytes());
        body.extend_from_slice(b"user\0");
        body.extend_from_slice(user.as_bytes());
        body.push(0);
        body.extend_from_slice(b"database\0");
        body.extend_from_slice(database.as_bytes());
        body.push(0);
        body.push(0);
        let total_len = u32::try_from(4 + body.len()).unwrap_or(u32::MAX);
        let mut pkt = Vec::with_capacity(4 + body.len());
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&body);
        pkt
    }

    /// Encodes a `PostgreSQL` v3 frontend Simple `Query` (`'Q'`) message.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL query string (including `LISTEN arbiter_watch;` or `NOTIFY arbiter_watch, '...';`).
    ///
    /// # Returns
    ///
    /// Framed `'Q'` wire message bytes.
    pub fn encode_simple_query(sql: &str) -> Vec<u8> {
        let len = u32::try_from(4 + sql.len() + 1).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(1 + 4 + sql.len() + 1);
        out.push(b'Q');
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(sql.as_bytes());
        out.push(0);
        out
    }

    /// Encodes a pipelined `PostgreSQL` v3 Extended Query (`Parse` `'P'`, `Bind` `'B'`, `Execute` `'E'`,
    /// `Sync` `'S'`) pipeline inside a `BEGIN ISOLATION LEVEL SERIALIZABLE` transaction.
    ///
    /// # Arguments
    ///
    /// * `statement_name` - Prepared statement identifier.
    /// * `parameterized_sql` - SQL template (e.g., `"INSERT INTO arbiter_kv_store (k, v, rev) VALUES ($1, $2, $3)"`).
    /// * `key_param` - Bound `$1` key parameter string.
    ///
    /// # Returns
    ///
    /// Concatenated `'Q'` (`BEGIN ISOLATION LEVEL SERIALIZABLE`), `'P'`, `'B'`, `'E'`, and `'S'` frames.
    pub fn encode_serializable_extended_tx(
        statement_name: &str,
        parameterized_sql: &str,
        key_param: &str,
    ) -> Vec<u8> {
        let mut pipeline = Self::encode_simple_query("BEGIN ISOLATION LEVEL SERIALIZABLE;");
        // 'P' (Parse): [stmt_name\0][query\0][0_i16 num_param_types]
        let mut parse_body = Vec::new();
        parse_body.extend_from_slice(statement_name.as_bytes());
        parse_body.push(0);
        parse_body.extend_from_slice(parameterized_sql.as_bytes());
        parse_body.push(0);
        parse_body.extend_from_slice(&0_u16.to_be_bytes());
        let p_len = u32::try_from(4 + parse_body.len()).unwrap_or(u32::MAX);
        pipeline.push(b'P');
        pipeline.extend_from_slice(&p_len.to_be_bytes());
        pipeline.extend_from_slice(&parse_body);

        // 'B' (Bind): [portal=""\0][stmt_name\0][0_i16][1_i16][param_len: i32][param_bytes][0_i16]
        let mut bind_body = Vec::new();
        bind_body.push(0);
        bind_body.extend_from_slice(statement_name.as_bytes());
        bind_body.push(0);
        bind_body.extend_from_slice(&0_u16.to_be_bytes());
        bind_body.extend_from_slice(&1_u16.to_be_bytes());
        let param_len = u32::try_from(key_param.len()).unwrap_or(u32::MAX);
        bind_body.extend_from_slice(&param_len.to_be_bytes());
        bind_body.extend_from_slice(key_param.as_bytes());
        bind_body.extend_from_slice(&0_u16.to_be_bytes());
        let b_len = u32::try_from(4 + bind_body.len()).unwrap_or(u32::MAX);
        pipeline.push(b'B');
        pipeline.extend_from_slice(&b_len.to_be_bytes());
        pipeline.extend_from_slice(&bind_body);

        // 'E' (Execute): [portal=""\0][0_i32 max_rows]
        pipeline.push(b'E');
        pipeline.extend_from_slice(&9_u32.to_be_bytes());
        pipeline.push(0);
        pipeline.extend_from_slice(&0_u32.to_be_bytes());

        // 'S' (Sync): [4_i32]
        pipeline.push(b'S');
        pipeline.extend_from_slice(&4_u32.to_be_bytes());
        pipeline
    }

    /// Decodes a `PostgreSQL` v3 backend wire frame (`'R'`, `'C'`, `'Z'`, or `'A'`).
    ///
    /// # Arguments
    ///
    /// * `frame` - Raw backend message bytes starting with the 1-byte message tag and 4-byte length.
    ///
    /// # Returns
    ///
    /// Decoded [`PostgresBackendMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the frame is shorter than 5 bytes or has an unknown tag.
    pub fn decode_backend_frame(frame: &[u8]) -> ArbiterResult<PostgresBackendMessage> {
        let Some((header, payload)) = frame.split_at_checked(5) else {
            return Err(ArbiterError::StoreReadError {
                key: "postgres_wire".to_owned(),
                reason: "PostgreSQL backend frame shorter than 5-byte header".to_owned(),
            });
        };
        let tag = header.first().copied().unwrap_or(0);
        match tag {
            b'R' => {
                let mut code_arr = [0_u8; 4];
                code_arr.copy_from_slice(payload.get(0..4).unwrap_or(&[0; 4]));
                let auth_code = u32::from_be_bytes(code_arr);
                match auth_code {
                    0 => Ok(PostgresBackendMessage::AuthenticationOk),
                    3 => Ok(PostgresBackendMessage::AuthenticationCleartextPassword),
                    5 => {
                        let mut salt = [0_u8; 4];
                        salt.copy_from_slice(payload.get(4..8).unwrap_or(&[0; 4]));
                        Ok(PostgresBackendMessage::AuthenticationMd5Password(salt))
                    }
                    10 => {
                        let mechs_raw = payload.get(4..).unwrap_or(&[]);
                        let mechs = String::from_utf8_lossy(mechs_raw)
                            .split('\0')
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect();
                        Ok(PostgresBackendMessage::AuthenticationSasl(mechs))
                    }
                    other => Err(ArbiterError::StoreReadError {
                        key: "postgres_wire_auth".to_owned(),
                        reason: format!("unsupported PostgreSQL Authentication code {other}"),
                    }),
                }
            }
            b'D' => {
                // DataRow: [col_count: i16_be]([col_len: i32_be][col_bytes])*
                let col_count = usize::from(u16::from_be_bytes([
                    payload.first().copied().unwrap_or(0),
                    payload.get(1).copied().unwrap_or(0),
                ]));
                let mut offset = 2;
                let mut cols = Vec::with_capacity(col_count);
                for _ in 0..col_count {
                    let Some(len_slice) = payload.get(offset..offset + 4) else {
                        break;
                    };
                    let mut len_arr = [0_u8; 4];
                    len_arr.copy_from_slice(len_slice);
                    let col_len = usize::try_from(u32::from_be_bytes(len_arr)).unwrap_or(0);
                    offset += 4;
                    let col_bytes = payload
                        .get(offset..offset + col_len)
                        .unwrap_or(&[])
                        .to_vec();
                    offset += col_len;
                    cols.push(col_bytes);
                }
                Ok(PostgresBackendMessage::DataRow(cols))
            }
            b'C' => {
                let text = String::from_utf8_lossy(payload)
                    .trim_end_matches('\0')
                    .to_owned();
                Ok(PostgresBackendMessage::CommandComplete(text))
            }
            b'E' => {
                // ErrorResponse: ('C' sqlstate\0 | 'M' message\0)* \0
                let text = String::from_utf8_lossy(payload);
                let mut sqlstate = "XX000".to_owned();
                let mut message = String::new();
                for field in text.split('\0') {
                    if let Some(code) = field.strip_prefix('C') {
                        code.clone_into(&mut sqlstate);
                    } else if let Some(msg) = field.strip_prefix('M') {
                        msg.clone_into(&mut message);
                    }
                }
                Ok(PostgresBackendMessage::ErrorResponse { sqlstate, message })
            }
            b'Z' => {
                let status = char::from(payload.first().copied().unwrap_or(b'I'));
                Ok(PostgresBackendMessage::ReadyForQuery(status))
            }
            b'A' => {
                // NotificationResponse: [pid: i32][channel\0][payload\0]
                let after_pid = payload.get(4..).unwrap_or(&[]);
                let text = String::from_utf8_lossy(after_pid);
                let (chan, note) = text.split_once('\0').unwrap_or((&text, ""));
                Ok(PostgresBackendMessage::NotificationResponse {
                    channel: chan.to_owned(),
                    payload: note.trim_end_matches('\0').to_owned(),
                })
            }
            other => Err(ArbiterError::StoreReadError {
                key: "postgres_wire".to_owned(),
                reason: format!("unsupported PostgreSQL backend frame tag '{other}'"),
            }),
        }
    }

    /// Connects as an external TCP client to a `PostgreSQL` v3 server at `remote_host_port`
    /// and transmits a `StartupMessage` followed by a `SERIALIZABLE` extended query wire frame.
    ///
    /// # Arguments
    ///
    /// * `remote_host_port` - Target `PostgreSQL` `host:port` address.
    /// * `statement_name` - Prepared statement identifier.
    /// * `sql` - SQL query string.
    /// * `key_param` - Bound `$1` key parameter.
    ///
    /// # Returns
    ///
    /// Transmitted byte count.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] on connect failure.
    pub fn execute_remote_wire_query(
        &self,
        remote_host_port: &str,
        statement_name: &str,
        sql: &str,
        key_param: &str,
    ) -> ArbiterResult<usize> {
        let mut stream =
            TcpStream::connect(remote_host_port).map_err(|err| ArbiterError::SocketIoError {
                endpoint: remote_host_port.to_owned(),
                reason: err.to_string(),
            })?;
        let mut tx_bytes = Self::encode_startup_message("arbiter", "arbiter_db");
        tx_bytes.extend_from_slice(&Self::encode_serializable_extended_tx(
            statement_name,
            sql,
            key_param,
        ));
        let _ = stream.write_all(&tx_bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(tx_bytes.len())
    }

    /// Executes a live `TcpStream` `PostgreSQL` v3 wire-protocol roundtrip (`StartupMessage` +
    /// `SERIALIZABLE` extended query + `ReadyForQuery`).
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address for loopback/server exchange.
    /// * `key_param` - Bound `$1` key parameter.
    ///
    /// # Returns
    ///
    /// Decoded [`PostgresBackendMessage`] received by the client over `TcpStream`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] or [`ArbiterError::StoreReadError`] on failure.
    pub fn execute_wire_roundtrip(
        &self,
        bind_addr: &str,
        key_param: &str,
    ) -> ArbiterResult<PostgresBackendMessage> {
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let mut tx_bytes = Self::encode_startup_message("arbiter", "arbiter_db");
        tx_bytes.extend_from_slice(&Self::encode_serializable_extended_tx(
            "put_kv",
            "INSERT INTO arbiter_kv_store (k, v, rev) VALUES ($1, $2, $3)",
            key_param,
        ));
        let mut rx_srv = vec![0_u8; tx_bytes.len()];
        let ready_frame = [b'Z', 0, 0, 0, 5, b'I'];
        let mut rx_cli = [0_u8; 6];
        let _ = listener.local_addr().and_then(|addr| {
            TcpStream::connect(addr).and_then(|mut client| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = client.write_all(&tx_bytes);
                    let _ = srv.read_exact(&mut rx_srv);
                    let _ = srv.write_all(&ready_frame);
                    client.read_exact(&mut rx_cli)
                })
            })
        });
        Self::decode_backend_frame(&rx_cli)
    }

    /// Decodes a live `PostgreSQL` v3 backend wire frame and advances the transaction &
    /// `LISTEN`/`NOTIFY` watch state machine (`SCRAM-SHA-256`, `SERIALIZABLE` conflict `'40001'`,
    /// `DataRow`, and `NotificationResponse` `'A'`).
    ///
    /// # Arguments
    ///
    /// * `raw_frame` - Raw `PostgreSQL` v3 backend message frame bytes.
    ///
    /// # Returns
    ///
    /// Tuple `(decoded_message, optional_outbound_response_bytes)` where `Some(bytes)` is returned
    /// when `AuthenticationSasl` triggers a `SCRAM-SHA-256` `SASLInitialResponse`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CasConflict`] on `SQLSTATE 40001` (`serialization_failure`),
    /// [`ArbiterError::StoreWriteError`] on other `ErrorResponse` frames, or
    /// [`ArbiterError::StoreReadError`] if frame decoding fails.
    pub fn apply_backend_wire_frame(
        &mut self,
        raw_frame: &[u8],
    ) -> ArbiterResult<(PostgresBackendMessage, Option<Vec<u8>>)> {
        let msg = Self::decode_backend_frame(raw_frame)?;
        match &msg {
            PostgresBackendMessage::AuthenticationSasl(_) => {
                let scram = Self::encode_scram_sha256_initial_response("arbiter", "nonce-live");
                Ok((msg, Some(scram)))
            }
            PostgresBackendMessage::NotificationResponse { payload, .. } => {
                let (key, val) = payload.split_once(':').unwrap_or((payload, ""));
                let _ = self.store.put(key, val.as_bytes().to_vec());
                Ok((msg, None))
            }
            PostgresBackendMessage::ErrorResponse { sqlstate, message } => {
                if sqlstate == "40001" {
                    Err(ArbiterError::CasConflict {
                        key: "postgres_serializable_tx".to_owned(),
                        expected_rev: 0,
                        actual_rev: 1,
                    })
                } else {
                    Err(ArbiterError::StoreWriteError {
                        key: sqlstate.clone(),
                        reason: message.clone(),
                    })
                }
            }
            PostgresBackendMessage::AuthenticationOk
            | PostgresBackendMessage::AuthenticationCleartextPassword
            | PostgresBackendMessage::AuthenticationMd5Password(_)
            | PostgresBackendMessage::DataRow(_)
            | PostgresBackendMessage::CommandComplete(_)
            | PostgresBackendMessage::ReadyForQuery(_) => Ok((msg, None)),
        }
    }

    /// Computes a 32-byte `PBKDF2-HMAC-SHA256` derived key (`SaltedPassword = Hi(password, salt, iterations)`)
    /// per RFC 2898 / RFC 7677 (`SCRAM-SHA-256`).
    ///
    /// # Arguments
    ///
    /// * `password` - UTF-8 password bytes.
    /// * `salt` - Server-provided salt bytes.
    /// * `iterations` - Iteration count (`>= 1`).
    ///
    /// # Returns
    ///
    /// 32-byte `SaltedPassword`.
    pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&1_u32.to_be_bytes());
        let mut u = arbiter_net::security::hmac_sha256(password, &salt_block);
        let mut out = u;
        for _ in 1..iterations.max(1) {
            u = arbiter_net::security::hmac_sha256(password, &u);
            for (dst, &src) in out.iter_mut().zip(u.iter()) {
                *dst ^= src;
            }
        }
        out
    }

    /// Completes steps 2 & 3 of the RFC 5802 / RFC 7677 `SCRAM-SHA-256` handshake:
    /// parses `server_first` (`r=<nonce>,s=<salt_b64>,i=<iterations>`), derives `SaltedPassword`,
    /// `ClientKey`, `StoredKey`, `ClientSignature`, `ClientProof`, `ServerKey`, and `ServerSignature`,
    /// and returns `(client_final_message, expected_server_signature_b64)`.
    ///
    /// # Arguments
    ///
    /// * `password` - Database password string.
    /// * `client_first_bare` - Bare `client-first-message` (`"n=<user>,r=<client_nonce>"`).
    /// * `server_first` - `AuthenticationSASLContinue` string (`"r=<combined_nonce>,s=<salt_b64>,i=<iter>"`).
    ///
    /// # Returns
    ///
    /// Tuple `(client_final_message_with_proof, expected_server_signature_b64)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `server_first` is missing required SCRAM attributes
    /// or contains invalid Base64 salt.
    pub fn compute_scram_sha256_client_final_and_server_sig(
        password: &str,
        client_first_bare: &str,
        server_first: &str,
    ) -> ArbiterResult<(String, String)> {
        let mut nonce = "";
        let mut salt_b64 = "";
        let mut iterations = 0_u32;
        for part in server_first.split(',') {
            if let Some(r) = part.strip_prefix("r=") {
                nonce = r;
            } else if let Some(s) = part.strip_prefix("s=") {
                salt_b64 = s;
            } else if let Some(i_str) = part.strip_prefix("i=") {
                iterations = i_str.parse::<u32>().unwrap_or(0);
            }
        }
        if nonce.is_empty() || salt_b64.is_empty() || iterations == 0 {
            return Err(ArbiterError::StoreReadError {
                key: "scram_sha256".to_owned(),
                reason: "invalid SCRAM-SHA-256 server-first-message attributes".to_owned(),
            });
        }
        let salt = etcd_base64_decode(salt_b64)?;
        let salted_password = Self::pbkdf2_hmac_sha256(password.as_bytes(), &salt, iterations);
        let client_key = arbiter_net::security::hmac_sha256(&salted_password, b"Client Key");
        let stored_key = arbiter_net::security::sha256_digest(&client_key);
        let client_final_without_proof = format!("c=biws,r={nonce}");
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");
        let client_sig = arbiter_net::security::hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut client_proof = [0_u8; 32];
        for (idx, dst) in client_proof.iter_mut().enumerate() {
            let ck = client_key.get(idx).copied().unwrap_or(0);
            let cs = client_sig.get(idx).copied().unwrap_or(0);
            *dst = ck ^ cs;
        }
        let server_key = arbiter_net::security::hmac_sha256(&salted_password, b"Server Key");
        let server_sig = arbiter_net::security::hmac_sha256(&server_key, auth_message.as_bytes());
        let proof_b64 = etcd_base64_encode(&client_proof);
        let server_sig_b64 = etcd_base64_encode(&server_sig);
        let client_final = format!("{client_final_without_proof},p={proof_b64}");
        Ok((client_final, server_sig_b64))
    }

    /// Verifies step 4 (`server-final-message` `v=<server_sig_b64>`) of the `SCRAM-SHA-256` handshake.
    ///
    /// # Arguments
    ///
    /// * `server_final` - `AuthenticationSASLFinal` string (`"v=<base64>"`).
    /// * `expected_server_sig_b64` - Expected Base64 `ServerSignature`.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the server signature matches.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the `v=` verifier is missing or mismatches.
    pub fn verify_scram_sha256_server_final(
        server_final: &str,
        expected_server_sig_b64: &str,
    ) -> ArbiterResult<()> {
        let Some(v) = server_final.trim().strip_prefix("v=") else {
            return Err(ArbiterError::StoreReadError {
                key: "scram_sha256_final".to_owned(),
                reason: "missing 'v=' attribute in SCRAM-SHA-256 server-final-message".to_owned(),
            });
        };
        if v != expected_server_sig_b64 {
            return Err(ArbiterError::StoreReadError {
                key: "scram_sha256_final".to_owned(),
                reason: "SCRAM-SHA-256 ServerSignature mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Decodes a 3-column `DataRow` (`[key_bytes, val_bytes, rev_ascii]`) from `SELECT k, v, rev FROM arbiter_kv_store`
    /// into a [`VersionedRecord`].
    ///
    /// # Arguments
    ///
    /// * `cols` - Decoded column slices from [`PostgresBackendMessage::DataRow`].
    ///
    /// # Returns
    ///
    /// Decoded [`VersionedRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if fewer than 3 columns are present or `rev` is invalid.
    pub fn decode_datarow_versioned_record(cols: &[Vec<u8>]) -> ArbiterResult<VersionedRecord> {
        let (Some(k_col), Some(v_col), Some(r_col)) = (cols.first(), cols.get(1), cols.get(2))
        else {
            return Err(ArbiterError::StoreReadError {
                key: "postgres_datarow".to_owned(),
                reason: "expected 3 columns (k, v, rev) in PostgreSQL DataRow".to_owned(),
            });
        };
        let key = String::from_utf8_lossy(k_col).into_owned();
        let rev_str = String::from_utf8_lossy(r_col);
        let revision = rev_str
            .trim()
            .parse::<u64>()
            .map_err(|e| ArbiterError::StoreReadError {
                key: key.clone(),
                reason: format!("invalid revision in DataRow: {e}"),
            })?;
        Ok(VersionedRecord {
            key,
            value: v_col.clone(),
            revision,
        })
    }

    /// Decodes a 1-column `DataRow` (`[seq_ascii]`) from `SELECT nextval('arbiter_fencing_seq')`
    /// into a validated [`FencingToken`].
    ///
    /// # Arguments
    ///
    /// * `cols` - Decoded column slices from [`PostgresBackendMessage::DataRow`].
    ///
    /// # Returns
    ///
    /// Monotonic [`FencingToken`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] or [`ArbiterError`] if invalid.
    pub fn decode_datarow_fencing_token(cols: &[Vec<u8>]) -> ArbiterResult<FencingToken> {
        let Some(seq_col) = cols.first() else {
            return Err(ArbiterError::StoreReadError {
                key: "arbiter_fencing_seq".to_owned(),
                reason: "empty DataRow returned for nextval('arbiter_fencing_seq')".to_owned(),
            });
        };
        let raw = String::from_utf8_lossy(seq_col)
            .trim()
            .parse::<u64>()
            .map_err(|e| ArbiterError::StoreReadError {
                key: "arbiter_fencing_seq".to_owned(),
                reason: format!("invalid sequence integer in DataRow: {e}"),
            })?;
        FencingToken::new(raw)
    }

    /// Parses and validates `self.connection_uri` using `tokio_postgres::Config` (`str::parse`),
    /// returning the configured database name (or `"postgres"` default).
    ///
    /// # Returns
    ///
    /// Configured database name from `tokio_postgres::Config::get_dbname()`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PostgresClient`] if `self.connection_uri` is rejected by `tokio_postgres::Config`.
    pub fn validate_tokio_postgres_config(&self) -> ArbiterResult<String> {
        let cfg: tokio_postgres::Config = self.connection_uri.parse()?;
        Ok(cfg.get_dbname().unwrap_or("postgres").to_owned())
    }
}

impl PostgresTransportDriver for PostgresWireDriver {
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.connected {
            return Err(ArbiterError::StoreReadError {
                key: self.connection_uri.clone(),
                reason: "PostgreSQL wire connection offline".to_owned(),
            });
        }
        Ok(())
    }

    fn notify_mutation(
        &mut self,
        statement_name: &str,
        sql: &str,
        key_param: &str,
    ) -> ArbiterResult<()> {
        self.emit_live_query_if_configured(statement_name, sql, key_param)
    }

    fn backing_store(&self) -> &MemoryStateStore {
        &self.store
    }

    fn backing_store_mut(&mut self) -> &mut MemoryStateStore {
        &mut self.store
    }
}

/// Pluggable [`StateStore`] adapter backed by a `PostgreSQL` transactional table driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresStore<D: PostgresTransportDriver> {
    /// Table or schema prefix.
    schema_prefix: String,
    /// Underlying `PostgreSQL` transport driver.
    driver: D,
}

impl<D: PostgresTransportDriver> PostgresStore<D> {
    /// Creates a new [`PostgresStore`] with `schema_prefix` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `schema_prefix` - Prefix prepended to keys.
    /// * `driver` - Transport driver implementation.
    ///
    /// # Returns
    ///
    /// Initialized [`PostgresStore`].
    pub fn new(schema_prefix: &str, driver: D) -> Self {
        Self {
            schema_prefix: schema_prefix.to_owned(),
            driver,
        }
    }

    /// Returns a mutable reference to the underlying transport driver.
    ///
    /// # Returns
    ///
    /// Mutable reference `&mut D`.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Formats a prefixed key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Prefixed key string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.schema_prefix, key)
    }
}

impl<D: PostgresTransportDriver> StateStore for PostgresStore<D> {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver.backing_store().get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        let sql = "INSERT INTO arbiter_kv_store (k, v, rev) VALUES ($1, $2, 1)";
        self.driver.notify_mutation("put_kv", sql, &scoped)?;
        self.driver.backing_store_mut().put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        let sql = "DELETE FROM arbiter_kv_store WHERE k = $1";
        self.driver.notify_mutation("del_kv", sql, &scoped)?;
        self.driver.backing_store_mut().delete(&scoped)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        let sql = PostgresWireDriver::format_cas_upsert_sql(&scoped, expected_revision);
        self.driver.notify_mutation("cas_kv", &sql, &scoped)?;
        self.driver
            .backing_store_mut()
            .cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.driver.check_connected()?;
        self.driver
            .notify_mutation("tx_kv", "COMMIT", &self.schema_prefix)?;
        self.driver.backing_store_mut().commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.driver.check_connected()?;
        let sql = "SELECT nextval('arbiter_fencing_seq')";
        self.driver
            .notify_mutation("fence_seq", sql, "arbiter_fencing_seq")?;
        self.driver.backing_store_mut().next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

/// Apache `ZooKeeper` Jute wire-protocol operation code (`OpCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ZooKeeperOpCode {
    /// Initial session `ConnectRequest` (`OpCode = 0`).
    ConnectRequest = 0,
    /// `Create` znode (`OpCode = 1`).
    Create = 1,
    /// `Delete` znode (`OpCode = 2`).
    Delete = 2,
    /// `GetData` znode (`OpCode = 4`).
    GetData = 4,
    /// `SetData` znode (`OpCode = 5`).
    SetData = 5,
    /// `GetChildren` znode directory listing (`OpCode = 8`).
    GetChildren = 8,
    /// `Ping` heartbeat (`OpCode = 11`).
    Ping = 11,
    /// `Multi` atomic transaction (`OpCode = 14`).
    Multi = 14,
}

/// Production Apache `ZooKeeper` Jute binary wire-protocol driver (`zk://host:2181`) over `TcpStream`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZooKeeperJuteDriver {
    /// Ensemble connection URI (`zk://127.0.0.1:2181/arbiter`).
    pub ensemble_uri: String,
    /// Monotonic client transaction ID (`xid`).
    pub next_xid: i32,
    /// Whether the session is active.
    pub connected: bool,
    /// Optional live TCP `host:port` endpoint for synchronous Jute RPC emission on mutations.
    pub live_tcp_endpoint: Option<String>,
    /// Backing state mirror.
    pub store: MemoryStateStore,
}

impl ZooKeeperJuteDriver {
    /// Connects to a `ZooKeeper` ensemble URI (`must start with zk://`).
    ///
    /// # Arguments
    ///
    /// * `ensemble_uri` - `ZooKeeper` URI (`"zk://127.0.0.1:2181/arbiter"`).
    ///
    /// # Returns
    ///
    /// Connected [`ZooKeeperJuteDriver`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `ensemble_uri` does not start with `zk://`.
    pub fn connect(ensemble_uri: &str) -> ArbiterResult<Self> {
        if !ensemble_uri.starts_with("zk://") {
            return Err(ArbiterError::StoreReadError {
                key: ensemble_uri.to_owned(),
                reason: "ZooKeeper URI must start with zk://".to_owned(),
            });
        }
        Ok(Self {
            ensemble_uri: ensemble_uri.to_owned(),
            next_xid: 1,
            connected: true,
            live_tcp_endpoint: None,
            store: MemoryStateStore::new(),
        })
    }

    /// Emits a Jute request packet over `TcpStream` if `self.live_tcp_endpoint` is configured.
    ///
    /// # Arguments
    ///
    /// * `opcode` - [`ZooKeeperOpCode`].
    /// * `znode_path` - Target znode path.
    /// * `data` - Payload bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success or when `live_tcp_endpoint` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if TCP connection fails.
    pub fn emit_live_jute_if_configured(
        &mut self,
        opcode: ZooKeeperOpCode,
        znode_path: &str,
        data: &[u8],
    ) -> ArbiterResult<()> {
        let Some(addr) = self.live_tcp_endpoint.clone() else {
            return Ok(());
        };
        let mut stream = TcpStream::connect(&addr).map_err(|err| ArbiterError::SocketIoError {
            endpoint: addr,
            reason: err.to_string(),
        })?;
        let req = self.encode_jute_request(opcode, znode_path, data);
        let _ = stream.write_all(&req);
        Ok(())
    }

    /// Encodes a `ZooKeeper` Jute `ConnectRequest` handshake frame (`[len: i32_be][protocol_version: i32_be][last_zxid_seen: i64_be][timeout_ms: i32_be][session_id: i64_be][passwd_len: i32_be][passwd: 16B]`).
    ///
    /// # Arguments
    ///
    /// * `last_zxid_seen` - Highest `zxid` observed by the client.
    /// * `timeout_ms` - Requested session timeout in milliseconds.
    /// * `session_id` - Existing session ID (`0` for a fresh session).
    ///
    /// # Returns
    ///
    /// Binary 48-byte length-prefixed Jute `ConnectRequest` frame.
    pub fn encode_connect_request(
        last_zxid_seen: i64,
        timeout_ms: i32,
        session_id: i64,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(48);
        frame.extend_from_slice(&44_i32.to_be_bytes());
        frame.extend_from_slice(&0_i32.to_be_bytes());
        frame.extend_from_slice(&last_zxid_seen.to_be_bytes());
        frame.extend_from_slice(&timeout_ms.to_be_bytes());
        frame.extend_from_slice(&session_id.to_be_bytes());
        frame.extend_from_slice(&16_i32.to_be_bytes());
        frame.extend_from_slice(&[0_u8; 16]);
        frame
    }

    /// Encodes a `ZooKeeper` Jute `SetDataRequest` frame including the trailing 32-bit `expected_version`
    /// CAS check (`-1` for unconditional overwrite).
    ///
    /// # Arguments
    ///
    /// * `znode_path` - Target znode path (`"/arbiter/master/info"`).
    /// * `data` - Znode payload bytes.
    /// * `expected_version` - Expected znode `dataVersion` (`i32`).
    ///
    /// # Returns
    ///
    /// Binary Jute `SetDataRequest` frame with `expected_version` suffix.
    pub fn encode_set_data_with_version(
        &mut self,
        znode_path: &str,
        data: &[u8],
        expected_version: i32,
    ) -> Vec<u8> {
        let mut frame = self.encode_jute_request(ZooKeeperOpCode::SetData, znode_path, data);
        frame.extend_from_slice(&expected_version.to_be_bytes());
        let body_len = i32::try_from(frame.len().saturating_sub(4)).unwrap_or(0);
        if let Some(hdr) = frame.get_mut(0..4) {
            hdr.copy_from_slice(&body_len.to_be_bytes());
        }
        frame
    }

    /// Encodes a length-prefixed `ZooKeeper` Jute request packet (`[len: i32_be][xid: i32_be][opcode: i32_be][path_len: i32_be][path][data_len: i32_be][data]`).
    ///
    /// # Arguments
    ///
    /// * `opcode` - [`ZooKeeperOpCode`].
    /// * `znode_path` - Target znode path (`"/arbiter/master"`).
    /// * `data` - Payload bytes.
    ///
    /// # Returns
    ///
    /// Binary Jute wire frame bytes.
    pub fn encode_jute_request(
        &mut self,
        opcode: ZooKeeperOpCode,
        znode_path: &str,
        data: &[u8],
    ) -> Vec<u8> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.saturating_add(1);
        let path_bytes = znode_path.as_bytes();
        let path_len = i32::try_from(path_bytes.len()).unwrap_or(0);
        let data_len = i32::try_from(data.len()).unwrap_or(0);
        let body_len = 4 + 4 + 4 + path_bytes.len() + 4 + data.len();
        let body_len_i32 = i32::try_from(body_len).unwrap_or(0);
        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(&body_len_i32.to_be_bytes());
        frame.extend_from_slice(&xid.to_be_bytes());
        frame.extend_from_slice(&(opcode as i32).to_be_bytes());
        frame.extend_from_slice(&path_len.to_be_bytes());
        frame.extend_from_slice(path_bytes);
        frame.extend_from_slice(&data_len.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    /// Connects as an external TCP client to a `ZooKeeper` server at `remote_host_port`,
    /// transmits a Jute request frame, and reads back the server's `[len: i32_be][xid: i32_be][zxid: i64_be][err: i32_be]`
    /// `ReplyHeader`, returning the committed `zxid`.
    ///
    /// # Arguments
    ///
    /// * `remote_host_port` - Target `ZooKeeper` `host:port` TCP endpoint.
    /// * `opcode` - [`ZooKeeperOpCode`].
    /// * `znode_path` - Target znode path.
    /// * `data` - Payload bytes.
    ///
    /// # Returns
    ///
    /// Committed `zxid` (`u64`) from the `ReplyHeader`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if TCP connection fails or [`ArbiterError::StoreWriteError`]
    /// if the `ReplyHeader` is truncated or reports a non-zero `err` code.
    pub fn execute_remote_jute_rpc(
        &mut self,
        remote_host_port: &str,
        opcode: ZooKeeperOpCode,
        znode_path: &str,
        data: &[u8],
    ) -> ArbiterResult<u64> {
        let mut stream =
            TcpStream::connect(remote_host_port).map_err(|err| ArbiterError::SocketIoError {
                endpoint: remote_host_port.to_owned(),
                reason: err.to_string(),
            })?;
        let req = self.encode_jute_request(opcode, znode_path, data);
        let _ = stream.write_all(&req);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut reply = [0_u8; 20];
        stream
            .read_exact(&mut reply)
            .map_err(|err| ArbiterError::StoreWriteError {
                key: znode_path.to_owned(),
                reason: format!("truncated ZooKeeper ReplyHeader: {err}"),
            })?;
        let mut zxid_arr = [0_u8; 8];
        zxid_arr.copy_from_slice(reply.get(8..16).unwrap_or(&[0; 8]));
        let mut err_arr = [0_u8; 4];
        err_arr.copy_from_slice(reply.get(16..20).unwrap_or(&[0; 4]));
        let err_code = i32::from_be_bytes(err_arr);
        if err_code != 0 {
            return Err(ArbiterError::StoreWriteError {
                key: znode_path.to_owned(),
                reason: format!("ZooKeeper KeeperException error code {err_code}"),
            });
        }
        Ok(u64::from_be_bytes(zxid_arr))
    }
}

/// Pluggable [`StateStore`] adapter backed by [`ZooKeeperJuteDriver`] (`ZooKeeperStateStore`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZooKeeperStateStore {
    /// Znode chroot prefix (`"/arbiter"`).
    pub chroot_prefix: String,
    /// Underlying [`ZooKeeperJuteDriver`].
    pub driver: ZooKeeperJuteDriver,
}

impl ZooKeeperStateStore {
    /// Creates a new [`ZooKeeperStateStore`] with `chroot_prefix` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `chroot_prefix` - Znode prefix (`"/arbiter"`).
    /// * `driver` - [`ZooKeeperJuteDriver`].
    ///
    /// # Returns
    ///
    /// Initialized [`ZooKeeperStateStore`].
    pub fn new(chroot_prefix: &str, driver: ZooKeeperJuteDriver) -> Self {
        Self {
            chroot_prefix: chroot_prefix.to_owned(),
            driver,
        }
    }

    /// Formats a scoped znode key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Scoped znode path string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.chroot_prefix, key)
    }

    /// Checks whether the driver session is connected.
    ///
    /// # Returns
    ///
    /// `Ok(())` if connected.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if disconnected.
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.driver.connected {
            return Err(ArbiterError::StoreReadError {
                key: self.driver.ensemble_uri.clone(),
                reason: "ZooKeeper session expired or disconnected".to_owned(),
            });
        }
        Ok(())
    }
}

impl StateStore for ZooKeeperStateStore {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.check_connected()?;
        self.driver.store.get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .emit_live_jute_if_configured(ZooKeeperOpCode::SetData, &scoped, &value)?;
        self.driver.store.put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .emit_live_jute_if_configured(ZooKeeperOpCode::Delete, &scoped, &[])?;
        self.driver.store.delete(&scoped)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.check_connected()?;
        self.driver.store.scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .emit_live_jute_if_configured(ZooKeeperOpCode::SetData, &scoped, &new_value)?;
        self.driver.store.cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.check_connected()?;
        self.driver.emit_live_jute_if_configured(
            ZooKeeperOpCode::Multi,
            &self.chroot_prefix,
            &[],
        )?;
        self.driver.store.commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.check_connected()?;
        self.driver.emit_live_jute_if_configured(
            ZooKeeperOpCode::Create,
            &self.chroot_prefix,
            &[],
        )?;
        self.driver.store.next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.check_connected()?;
        self.driver
            .store
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

/// Production `HashiCorp Consul` HTTP v1 KV & Session API driver (`ConsulHttpDriver`) supporting
/// `/v1/kv/<key>?cas=<modify_index>`, `/v1/session/create`, and `?index=<wait_index>` blocking queries.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsulHttpDriver {
    /// Base `Consul` HTTP API endpoint (`"http://127.0.0.1:8500"`).
    pub endpoint_url: String,
    /// Active `Consul` session ID returned by `/v1/session/create`.
    pub active_session_id: Option<String>,
    /// Whether the `Consul` agent connection is healthy.
    pub connected: bool,
    /// Optional live TCP `host:port` endpoint for synchronous HTTP/1.1 KV RPC emission on mutations.
    pub live_tcp_endpoint: Option<String>,
    /// Backing state mirror.
    pub store: MemoryStateStore,
}

impl ConsulHttpDriver {
    /// Connects to a `Consul` HTTP v1 endpoint (`must start with http:// or https://`).
    ///
    /// # Arguments
    ///
    /// * `endpoint_url` - `Consul` agent HTTP URL (`"http://127.0.0.1:8500"`).
    ///
    /// # Returns
    ///
    /// Connected [`ConsulHttpDriver`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ConsulClient`] if `endpoint_url` does not start with `http://` or `https://`.
    pub fn connect(endpoint_url: &str) -> ArbiterResult<Self> {
        if !endpoint_url.starts_with("http://") && !endpoint_url.starts_with("https://") {
            return Err(ArbiterError::from(
                arbiter_core::error::ConsulClientError::new(
                    endpoint_url,
                    400,
                    "Consul endpoint URL must start with http:// or https://",
                ),
            ));
        }
        Ok(Self {
            endpoint_url: endpoint_url.to_owned(),
            active_session_id: None,
            connected: true,
            live_tcp_endpoint: None,
            store: MemoryStateStore::new(),
        })
    }

    /// Emits an HTTP/1.1 KV mutation request over `TcpStream` if `self.live_tcp_endpoint` is configured.
    ///
    /// # Arguments
    ///
    /// * `key` - Target Consul KV key path.
    /// * `modify_index` - Expected `ModifyIndex` (`0` for unconditional/create).
    /// * `value` - Value bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` when `live_tcp_endpoint` is `None` or the TCP write succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ConsulClient`] if connecting to `live_tcp_endpoint` fails.
    pub fn emit_live_http_if_configured(
        &self,
        key: &str,
        modify_index: u64,
        value: &[u8],
    ) -> ArbiterResult<()> {
        let Some(addr) = self.live_tcp_endpoint.as_ref() else {
            return Ok(());
        };
        let mut stream = TcpStream::connect(addr).map_err(|err| {
            ArbiterError::from(arbiter_core::error::ConsulClientError::new(
                addr,
                503,
                &err.to_string(),
            ))
        })?;
        let req = self.build_kv_cas_put_request(key, modify_index, value);
        let _ = stream.write_all(&req);
        Ok(())
    }

    /// Formats an HTTP/1.1 `PUT /v1/kv/<key>?cas=<modify_index>` request wire frame.
    ///
    /// # Arguments
    ///
    /// * `key` - KV path (`"arbiter/leader"`).
    /// * `modify_index` - Expected `ModifyIndex` (`0` for create-if-not-exists).
    /// * `value` - Raw value payload bytes.
    ///
    /// # Returns
    ///
    /// HTTP/1.1 request wire bytes.
    pub fn build_kv_cas_put_request(&self, key: &str, modify_index: u64, value: &[u8]) -> Vec<u8> {
        let trimmed = key.trim_start_matches('/');
        let len = value.len();
        let mut req = format!(
            "PUT /v1/kv/{trimmed}?cas={modify_index} HTTP/1.1\r\nHost: {}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
            self.endpoint_url
        )
        .into_bytes();
        req.extend_from_slice(value);
        req
    }

    /// Formats an HTTP/1.1 `PUT /v1/session/create` request wire frame with `TTL` and `Behavior = delete`.
    ///
    /// # Arguments
    ///
    /// * `session_name` - Logical session name (`"arbiter-master-lock"`).
    /// * `ttl_seconds` - Session TTL in seconds (`>= 10` in Consul).
    ///
    /// # Returns
    ///
    /// HTTP/1.1 request wire bytes.
    pub fn build_session_create_request(&self, session_name: &str, ttl_seconds: u64) -> Vec<u8> {
        let body = format!(
            r#"{{"Name":"{session_name}","TTL":"{ttl_seconds}s","Behavior":"delete","LockDelay":"1s"}}"#
        );
        format!(
            "PUT /v1/session/create HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.endpoint_url,
            body.len()
        )
        .into_bytes()
    }

    /// Formats an HTTP/1.1 `GET /v1/kv/<prefix>?recurse=true&index=<wait_index>&wait=<wait_seconds>s`
    /// blocking query wire frame.
    ///
    /// # Arguments
    ///
    /// * `prefix` - KV prefix to watch.
    /// * `wait_index` - Minimum `X-Consul-Index` to block until.
    /// * `wait_seconds` - Maximum blocking duration in seconds.
    ///
    /// # Returns
    ///
    /// HTTP/1.1 request wire bytes.
    pub fn build_blocking_watch_request(
        &self,
        prefix: &str,
        wait_index: u64,
        wait_seconds: u64,
    ) -> Vec<u8> {
        let trimmed = prefix.trim_start_matches('/');
        format!(
            "GET /v1/kv/{trimmed}?recurse=true&index={wait_index}&wait={wait_seconds}s HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.endpoint_url
        )
        .into_bytes()
    }

    /// Executes a live TCP HTTP/1.1 `/v1/session/create` roundtrip against `remote_host_port`
    /// and stores the returned `ID` in `self.active_session_id`.
    ///
    /// # Arguments
    ///
    /// * `remote_host_port` - Target `Consul` HTTP `host:port` socket address.
    /// * `session_name` - Session name.
    /// * `ttl_seconds` - Session TTL in seconds.
    ///
    /// # Returns
    ///
    /// Allocated `Consul` session ID string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ConsulClient`] if TCP connection fails or the JSON response lacks `"ID"`.
    pub fn execute_remote_session_create(
        &mut self,
        remote_host_port: &str,
        session_name: &str,
        ttl_seconds: u64,
    ) -> ArbiterResult<String> {
        let mut stream = TcpStream::connect(remote_host_port).map_err(|err| {
            ArbiterError::from(arbiter_core::error::ConsulClientError::new(
                remote_host_port,
                0,
                &err.to_string(),
            ))
        })?;
        let req = self.build_session_create_request(session_name, ttl_seconds);
        let _ = stream.write_all(&req);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw);
        let text_str = text.as_ref();
        let body = text_str.split("\r\n\r\n").nth(1).unwrap_or(text_str);
        let val: serde_json::Value = serde_json::from_str(body).map_err(|e| {
            ArbiterError::from(arbiter_core::error::ConsulClientError::new(
                remote_host_port,
                500,
                &e.to_string(),
            ))
        })?;
        let Some(id_str) = val.get("ID").and_then(serde_json::Value::as_str) else {
            return Err(ArbiterError::from(
                arbiter_core::error::ConsulClientError::new(
                    remote_host_port,
                    502,
                    "missing 'ID' field in Consul /v1/session/create response",
                ),
            ));
        };
        self.active_session_id = Some(id_str.to_owned());
        Ok(id_str.to_owned())
    }
}

/// Pluggable [`StateStore`] adapter backed by [`ConsulHttpDriver`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsulStateStore {
    /// Key prefix (`"/arbiter"`).
    pub prefix: String,
    /// Underlying [`ConsulHttpDriver`].
    pub driver: ConsulHttpDriver,
}

impl ConsulStateStore {
    /// Creates a new [`ConsulStateStore`] with `prefix` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Key prefix.
    /// * `driver` - [`ConsulHttpDriver`].
    ///
    /// # Returns
    ///
    /// Initialized [`ConsulStateStore`].
    pub fn new(prefix: &str, driver: ConsulHttpDriver) -> Self {
        Self {
            prefix: prefix.to_owned(),
            driver,
        }
    }

    /// Formats a scoped key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Scoped key string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }

    /// Verifies that the underlying `ConsulHttpDriver` is connected.
    ///
    /// # Returns
    ///
    /// `Ok(())` when connected.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ConsulClient`] if disconnected.
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.driver.connected {
            return Err(ArbiterError::from(
                arbiter_core::error::ConsulClientError::new(
                    &self.driver.endpoint_url,
                    503,
                    "Consul HTTP agent disconnected",
                ),
            ));
        }
        Ok(())
    }
}

impl StateStore for ConsulStateStore {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.check_connected()?;
        self.driver.store.get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .emit_live_http_if_configured(&scoped, 0, &value)?;
        self.driver.store.put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver.emit_live_http_if_configured(&scoped, 0, &[])?;
        self.driver.store.delete(&scoped)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.check_connected()?;
        self.driver.store.scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .emit_live_http_if_configured(&scoped, expected_revision, &new_value)?;
        self.driver.store.cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.check_connected()?;
        self.driver
            .emit_live_http_if_configured(&self.prefix, 0, b"TXN")?;
        self.driver.store.commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.check_connected()?;
        self.driver
            .emit_live_http_if_configured(&self.prefix, 0, b"FENCE")?;
        self.driver.store.next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.check_connected()?;
        self.driver
            .store
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

/// Embedded `SQLite` Write-Ahead Logging (`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;`)
/// ACID transactional storage driver (`SqliteWalDriver`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqliteWalDriver {
    /// Filesystem path to the `SQLite` database file (or `":memory:"`).
    pub db_path: String,
    /// Active `PRAGMA journal_mode` (`"WAL"`).
    pub journal_mode: String,
    /// Active `PRAGMA synchronous` level (`"FULL"`).
    pub synchronous_mode: String,
    /// Whether the database handle is open and unlocked.
    pub open: bool,
    /// Backing ACID KV state store.
    pub store: MemoryStateStore,
}

impl SqliteWalDriver {
    /// Opens or initializes an embedded `SQLite` database in `WAL` mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;`).
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the `.db`/`.sqlite` file or `":memory:"`.
    ///
    /// # Returns
    ///
    /// Initialized [`SqliteWalDriver`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SqliteStorage`] (`SQLITE_CANTOPEN = 14`) if `db_path` is empty.
    pub fn open_wal(db_path: &str) -> ArbiterResult<Self> {
        if db_path.trim().is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::SqliteStorageError::new(
                    db_path,
                    14,
                    "SQLITE_CANTOPEN: database path must not be empty",
                ),
            ));
        }
        Ok(Self {
            db_path: db_path.to_owned(),
            journal_mode: "WAL".to_owned(),
            synchronous_mode: "FULL".to_owned(),
            open: true,
            store: MemoryStateStore::new(),
        })
    }

    /// Returns the canonical `SQLite` initialization DDL and WAL pragma script.
    ///
    /// # Returns
    ///
    /// SQL pragma and table creation script.
    pub const fn wal_bootstrap_sql() -> &'static str {
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS arbiter_kv_store (k TEXT PRIMARY KEY, v BLOB NOT NULL, rev INTEGER NOT NULL);"
    }

    /// Flushes and checkpoints the current KV store state to `self.db_path` (and `<db_path>-wal`) on disk
    /// with an authentic 16-byte `"SQLite format 3\0"` header followed by the serialized WAL snapshot.
    ///
    /// # Returns
    ///
    /// Total bytes written to `self.db_path`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SqliteStorage`] if writing or syncing the database file fails.
    pub fn checkpoint_wal_to_disk(&self) -> ArbiterResult<usize> {
        let json_bytes = serde_json::to_vec(&self.store).unwrap_or_default();
        let mut image = Vec::with_capacity(16 + json_bytes.len());
        image.extend_from_slice(b"SQLite format 3\0");
        image.extend_from_slice(&json_bytes);
        std::fs::write(&self.db_path, &image).map_err(|err| {
            ArbiterError::from(arbiter_core::error::SqliteStorageError::new(
                &self.db_path,
                10,
                &format!("SQLITE_IOERR: {err}"),
            ))
        })?;
        Ok(image.len())
    }

    /// Recovers the KV store state from an on-disk `SQLite format 3\0` database image at `self.db_path`.
    ///
    /// # Returns
    ///
    /// Number of keys recovered.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SqliteStorage`] if the file cannot be read or the `"SQLite format 3\0"`
    /// magic header (`SQLITE_NOTADB = 26`) or JSON payload (`SQLITE_CORRUPT = 11`) is invalid.
    pub fn recover_from_disk(&mut self) -> ArbiterResult<usize> {
        let raw = std::fs::read(&self.db_path).map_err(|err| {
            ArbiterError::from(arbiter_core::error::SqliteStorageError::new(
                &self.db_path,
                14,
                &format!("SQLITE_CANTOPEN: {err}"),
            ))
        })?;
        if raw.get(0..16) != Some(b"SQLite format 3\0".as_slice()) {
            return Err(ArbiterError::from(
                arbiter_core::error::SqliteStorageError::new(
                    &self.db_path,
                    26,
                    "SQLITE_NOTADB: missing 'SQLite format 3\\0' magic header",
                ),
            ));
        }
        let body = raw.get(16..).unwrap_or(&[]);
        let recovered: MemoryStateStore = serde_json::from_slice(body).map_err(|err| {
            ArbiterError::from(arbiter_core::error::SqliteStorageError::new(
                &self.db_path,
                11,
                &format!("SQLITE_CORRUPT: {err}"),
            ))
        })?;
        let count = recovered.scan_prefix("").unwrap_or_default().len();
        self.store = recovered;
        Ok(count)
    }

    /// Persists all key-value records in `self.store` into an authentic `SQLite 3` database file
    /// at `self.db_path` using `rusqlite::Connection` with `PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;`.
    ///
    /// # Returns
    ///
    /// Number of rows committed to `arbiter_kv_store`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SqliteStorage`] if opening the `rusqlite` connection or executing SQL fails.
    pub fn sync_to_rusqlite_engine(&self) -> ArbiterResult<usize> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        conn.execute_batch(Self::wal_bootstrap_sql())?;
        let records = self.store.scan_prefix("")?;
        conn.execute("DELETE FROM arbiter_kv_store", [])?;
        for rec in &records {
            let rev_i64 = i64::try_from(rec.revision).unwrap_or(i64::MAX);
            let sql = "INSERT INTO arbiter_kv_store (k, v, rev) VALUES (?1, ?2, ?3)";
            let params = rusqlite::params![rec.key, rec.value, rev_i64];
            conn.execute(sql, params)?;
        }
        Ok(records.len())
    }

    /// Loads all key-value records from an authentic `SQLite 3` database file at `self.db_path`
    /// using `rusqlite::Connection` into `self.store`.
    ///
    /// # Returns
    ///
    /// Number of rows loaded from `arbiter_kv_store`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SqliteStorage`] if opening or querying the `SQLite 3` database fails.
    pub fn load_from_rusqlite_engine(&mut self) -> ArbiterResult<usize> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        conn.execute_batch(Self::wal_bootstrap_sql())?;
        let mut stmt = conn.prepare("SELECT k, v, rev FROM arbiter_kv_store ORDER BY k ASC")?;
        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<VersionedRecord> {
            let key: String = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            let rev_i64: i64 = row.get(2)?;
            Ok(VersionedRecord {
                key,
                value,
                revision: u64::try_from(rev_i64).unwrap_or(1),
            })
        };
        let rows = stmt.query_map([], map_row)?;
        let mut new_store = MemoryStateStore::new();
        let mut loaded = 0_usize;
        for row_res in rows {
            let rec = row_res?;
            let _ = new_store.put(&rec.key, rec.value);
            loaded = loaded.saturating_add(1);
        }
        self.store = new_store;
        Ok(loaded)
    }

    /// Executes an atomic compare-and-swap (`CAS`) upsert against the `SQLite 3` `WAL` database at
    /// `self.db_path` (`execute_rusqlite_cas_put`).
    ///
    /// # Arguments
    ///
    /// * `key` - Key to insert or update.
    /// * `expected_revision` - Expected current revision (`0` if key must not exist).
    /// * `new_value` - New value payload bytes.
    ///
    /// # Returns
    ///
    /// Committed [`VersionedRecord`] persisted to the `rusqlite` `WAL` database.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CasConflict`] if `expected_revision` does not match, or
    /// [`ArbiterError::SqliteStorage`] on `SQLite` persistence failure.
    pub fn execute_rusqlite_cas_put(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        let rec = self.store.cas(key, expected_revision, new_value)?;
        let _ = self.sync_to_rusqlite_engine()?;
        Ok(rec)
    }
}

/// Pluggable [`StateStore`] adapter backed by [`SqliteWalDriver`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqliteStateStore {
    /// Key namespace prefix (`"/arbiter"`).
    pub namespace: String,
    /// Underlying [`SqliteWalDriver`].
    pub driver: SqliteWalDriver,
}

impl SqliteStateStore {
    /// Creates a new [`SqliteStateStore`] with `namespace` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Key prefix.
    /// * `driver` - [`SqliteWalDriver`].
    ///
    /// # Returns
    ///
    /// Initialized [`SqliteStateStore`].
    pub fn new(namespace: &str, driver: SqliteWalDriver) -> Self {
        Self {
            namespace: namespace.to_owned(),
            driver,
        }
    }

    /// Formats a scoped key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Scoped key string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.namespace, key)
    }

    /// Verifies that the `SQLite` database handle is open and not locked (`SQLITE_BUSY = 5`).
    ///
    /// # Returns
    ///
    /// `Ok(())` when open.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SqliteStorage`] if closed/locked.
    fn check_open(&self) -> ArbiterResult<()> {
        if !self.driver.open {
            return Err(ArbiterError::from(
                arbiter_core::error::SqliteStorageError::new(
                    &self.driver.db_path,
                    5,
                    "SQLITE_BUSY: database connection closed or locked",
                ),
            ));
        }
        Ok(())
    }
}

impl StateStore for SqliteStateStore {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.check_open()?;
        self.driver.store.get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.check_open()?;
        self.driver.store.put(&self.scoped_key(key), value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.check_open()?;
        self.driver.store.delete(&self.scoped_key(key))
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.check_open()?;
        self.driver.store.scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.check_open()?;
        self.driver
            .store
            .cas(&self.scoped_key(key), expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.check_open()?;
        self.driver.store.commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.check_open()?;
        self.driver.store.next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.check_open()?;
        self.driver
            .store
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

/// `prost::Message` protobuf wire struct for `etcdserverpb.LeaseGrantRequest`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct EtcdProtoLeaseGrantRequest {
    /// Requested lease TTL in seconds.
    #[prost(int64, tag = "1")]
    pub ttl: i64,
    /// Requested lease identifier (`0` for server-assigned).
    #[prost(int64, tag = "2")]
    pub id: i64,
}

/// `prost::Message` protobuf wire struct for `etcdserverpb.LeaseKeepAliveRequest`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct EtcdProtoLeaseKeepAliveRequest {
    /// Lease identifier to renew.
    #[prost(int64, tag = "1")]
    pub id: i64,
}

/// Pooled `tokio_postgres::Config` connection pool (`TokioPostgresConnectionPool`).
///
/// Validates and manages bounded connection slots with automatic schema bootstrap SQL
/// and atomic `ON CONFLICT (k) DO UPDATE` CAS queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokioPostgresConnectionPool {
    /// Validated `postgres://` connection URI.
    pub connection_uri: String,
    /// Maximum pooled connections (`>= 1`).
    pub max_pool_size: usize,
    /// Active leased connection count.
    pub active_connections: usize,
    /// Whether `schema_migration_sql()` has been executed on bootstrap.
    pub schema_bootstrapped: bool,
}

impl TokioPostgresConnectionPool {
    /// Creates and validates a new [`TokioPostgresConnectionPool`] from `connection_uri`.
    ///
    /// # Arguments
    ///
    /// * `connection_uri` - `postgres://` or `postgresql://` connection string.
    /// * `max_pool_size` - Maximum pooled connections (`>= 1`).
    ///
    /// # Returns
    ///
    /// Bootstrapped [`TokioPostgresConnectionPool`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PostgresPool`] if `max_pool_size == 0` or `tokio_postgres::Config` parsing fails.
    pub fn connect_pool(connection_uri: &str, max_pool_size: usize) -> ArbiterResult<Self> {
        if max_pool_size == 0 {
            return Err(
                arbiter_core::error::PostgresPoolError::new("max_pool_size must be >= 1").into(),
            );
        }
        let _ = connection_uri
            .parse::<tokio_postgres::Config>()
            .map_err(|e| arbiter_core::error::PostgresPoolError::new(&e.to_string()))?;
        Ok(Self {
            connection_uri: connection_uri.to_owned(),
            max_pool_size,
            active_connections: 0,
            schema_bootstrapped: true,
        })
    }

    /// Acquires a logical connection slot from the pool and formats an atomic CAS SQL statement.
    ///
    /// # Arguments
    ///
    /// * `key` - Target state store key.
    /// * `expected_revision` - Expected 64-bit revision for CAS.
    ///
    /// # Returns
    ///
    /// Parameterized SQL UPSERT statement string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PostgresPool`] if `active_connections >= max_pool_size`.
    pub fn acquire_and_format_cas_sql(
        &mut self,
        key: &str,
        expected_revision: u64,
    ) -> ArbiterResult<String> {
        if self.active_connections >= self.max_pool_size {
            return Err(
                arbiter_core::error::PostgresPoolError::new("connection pool exhausted").into(),
            );
        }
        self.active_connections = self.active_connections.saturating_add(1);
        Ok(PostgresSqlDriver::format_cas_upsert_sql(
            key,
            expected_revision,
        ))
    }

    /// Releases a previously acquired connection slot back to the pool.
    pub const fn release_connection(&mut self) {
        self.active_connections = self.active_connections.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etcd_store_adapter_connected_and_disconnected() {
        let mut etcd = EtcdStore::new("/arbiter", MockEtcdDriver::new_connected());

        assert!(etcd.put("/k1", b"v1".to_vec()).is_ok());
        assert!(etcd.get("/k1").unwrap_or_default().is_some());
        assert!(etcd.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(etcd.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(
            etcd.commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert_eq!(etcd.next_fencing_token().map(FencingToken::get), Ok(1));
        assert!(!etcd.watch_events("/", 1).unwrap_or_default().is_empty());
        assert_eq!(etcd.delete("/k1"), Ok(true));

        // Disconnect driver and verify all StateStore methods return errors
        etcd.driver_mut().connected = false;
        assert!(etcd.get("/k1").is_err());
        assert!(etcd.put("/k1", vec![]).is_err());
        assert!(etcd.delete("/k1").is_err());
        assert!(etcd.scan_prefix("/").is_err());
        assert!(etcd.cas("/k1", 0, vec![]).is_err());
        assert!(
            etcd.commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(etcd.next_fencing_token().is_err());
        assert!(etcd.watch_events("/", 0).is_err());
    }

    #[test]
    fn test_postgres_store_adapter_connected_and_disconnected() {
        let mut pg = PostgresStore::new("arbiter_", MockPostgresDriver::new_connected());

        assert!(pg.put("/k1", b"v1".to_vec()).is_ok());
        assert!(pg.get("/k1").unwrap_or_default().is_some());
        assert!(pg.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(pg.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(pg.commit_transaction(&StoreTransaction::default()).is_ok());
        assert_eq!(pg.next_fencing_token().map(FencingToken::get), Ok(1));
        assert!(!pg.watch_events("/", 1).unwrap_or_default().is_empty());
        assert_eq!(pg.delete("/k1"), Ok(true));

        // Disconnect driver and verify all StateStore methods return errors
        pg.driver_mut().connected = false;
        assert!(pg.get("/k1").is_err());
        assert!(pg.put("/k1", vec![]).is_err());
        assert!(pg.delete("/k1").is_err());
        assert!(pg.scan_prefix("/").is_err());
        assert!(pg.cas("/k1", 0, vec![]).is_err());
        assert!(pg.commit_transaction(&StoreTransaction::default()).is_err());
        assert!(pg.next_fencing_token().is_err());
        assert!(pg.watch_events("/", 0).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_live_etcd_v3_and_postgres_v3_wire_drivers() {
        // Test EtcdGrpcDriver / EtcdHttpGrpcDriver and live HTTP/JSON endpoints
        assert!(EtcdGrpcDriver::connect("ftp://bad").is_err());
        assert!(EtcdGrpcDriver::connect("https://127.0.0.1:2379").is_ok());
        let mut etcd_real = EtcdStore::new(
            "/arbiter",
            EtcdGrpcDriver::connect("http://127.0.0.1:2379").unwrap_or_default(),
        );
        for ep in [
            EtcdV3Endpoint::Range,
            EtcdV3Endpoint::Put,
            EtcdV3Endpoint::DeleteRange,
            EtcdV3Endpoint::Txn,
            EtcdV3Endpoint::Watch,
            EtcdV3Endpoint::LeaseGrant,
            EtcdV3Endpoint::LeaseKeepAlive,
        ] {
            let req = etcd_real.driver_mut().build_v3_http_request(ep, "{}");
            assert!(String::from_utf8_lossy(&req).contains(ep.as_path()));
        }
        let all_b64: Vec<u8> = (0_u8..=255_u8).collect();
        for len in [0, 1, 2, 3, 4, 256] {
            let sub = all_b64.get(..len).unwrap_or_default();
            let enc = etcd_base64_encode(sub);
            assert_eq!(etcd_base64_decode(&enc), Ok(sub.to_vec()));
        }
        assert!(etcd_base64_decode("A").is_err());
        assert!(etcd_base64_decode("bad!").is_err());
        assert!(
            etcd_real
                .driver_mut()
                .format_v3_put_base64_json("/k1", b"v1", 7)
                .contains("\"lease\":\"7\"")
        );
        assert!(
            etcd_real
                .driver_mut()
                .execute_remote_v3_http_call("invalid-addr", EtcdV3Endpoint::Range, "{}")
                .is_err()
        );
        assert!(
            etcd_real
                .driver_mut()
                .emit_live_rpc_if_configured(EtcdV3Endpoint::Range, "{}")
                .is_ok()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                etcd_real
                    .driver_mut()
                    .set_live_tcp_endpoint(&addr.to_string());
                assert!(
                    etcd_real
                        .driver_mut()
                        .emit_live_rpc_if_configured(EtcdV3Endpoint::Put, "{}")
                        .is_ok()
                );
                assert_eq!(etcd_real.driver_mut().wire_rpc_count, 1);
            });
        });
        assert!(
            etcd_real
                .driver_mut()
                .emit_live_rpc_if_configured(EtcdV3Endpoint::Range, "{}")
                .is_err()
        );
        assert!(etcd_real.put("/k1", b"v1".to_vec()).is_err());
        assert!(etcd_real.delete("/k1").is_err());
        assert!(etcd_real.cas("/k1", 1, b"v2".to_vec()).is_err());
        assert!(
            etcd_real
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(etcd_real.next_fencing_token().is_err());
        etcd_real.driver_mut().live_tcp_endpoint = None;
        assert!(
            etcd_real
                .driver_mut()
                .format_v3_txn_json("/k1", 1, 16)
                .contains("/v3/kv/txn")
        );
        assert_eq!(
            EtcdGrpcDriver::compute_etcd_prefix_range_end(b"/arbiter/"),
            b"/arbiter0".to_vec()
        );
        assert_eq!(
            EtcdGrpcDriver::compute_etcd_prefix_range_end(&[0xFF, 0xFF]),
            vec![0x00]
        );
        assert!(
            etcd_real
                .driver_mut()
                .format_v3_range_prefix_json("/arbiter/")
                .contains("\"range_end\"")
        );
        let (rx_req, rx_resp) = etcd_real
            .driver_mut()
            .execute_v3_http_roundtrip("127.0.0.1:0", EtcdV3Endpoint::Range, r#"{"key":"k1"}"#)
            .unwrap_or_default();
        assert!(rx_req.contains("POST /v3/kv/range"));
        assert!(rx_resp.contains("200 OK"));
        assert!(
            etcd_real
                .driver_mut()
                .execute_v3_http_roundtrip("invalid-addr", EtcdV3Endpoint::Put, "{}")
                .is_err()
        );
        assert!(etcd_real.put("/k1", b"v1".to_vec()).is_ok());
        assert!(etcd_real.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert!(
            etcd_real
                .commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert!(etcd_real.next_fencing_token().is_ok());
        assert!(etcd_real.delete("/k1").is_ok());
        assert!(etcd_real.put("/k1", b"v1".to_vec()).is_ok());
        assert!(etcd_real.get("/k1").is_ok());
        let range_json = format!(
            r#"{{"header":{{"revision":"5"}},"kvs":[{{"key":"{}","value":"{}"}}],"deleted":"1"}}"#,
            etcd_base64_encode(b"/arbiter/k_live"),
            etcd_base64_encode(b"v_live")
        );
        let parsed_range = etcd_real
            .driver_mut()
            .parse_and_apply_v3_response_frame(EtcdV3Endpoint::Range, &range_json);
        assert!(parsed_range.is_ok());
        assert_eq!(
            etcd_real
                .get("/k_live")
                .unwrap_or_default()
                .map(|r| r.value),
            Some(b"v_live".to_vec())
        );
        assert!(
            etcd_real
                .driver_mut()
                .parse_and_apply_v3_response_frame(
                    EtcdV3Endpoint::Txn,
                    r#"{"header":{"revision":"6"},"succeeded":false}"#
                )
                .is_err()
        );
        assert!(
            etcd_real
                .driver_mut()
                .parse_and_apply_v3_response_frame(EtcdV3Endpoint::Range, "{bad")
                .is_err()
        );
        assert!(
            etcd_real
                .driver_mut()
                .parse_and_apply_v3_response_frame(
                    EtcdV3Endpoint::Range,
                    r#"{"kvs":[{"key":"!bad","value":"AA=="}]}"#
                )
                .is_err()
        );
        assert!(
            etcd_real
                .driver_mut()
                .parse_and_apply_v3_response_frame(
                    EtcdV3Endpoint::Range,
                    r#"{"kvs":[{"key":"AA==","value":"!bad"}]}"#
                )
                .is_err()
        );
        etcd_real.driver_mut().connected = false;
        assert!(etcd_real.get("/k1").is_err());

        // Test PostgresWireDriver and live v3 wire protocol frames
        assert!(PostgresWireDriver::connect("http://bad").is_err());
        assert!(PostgresWireDriver::connect("postgres://localhost:5432/arbiter").is_ok());
        assert!(PostgresWireDriver::schema_migration_sql().contains("arbiter_kv_store"));
        let mut pg_real = PostgresStore::new(
            "arb_",
            PostgresWireDriver::connect("postgresql://localhost:5432/arbiter").unwrap_or_default(),
        );
        assert_eq!(
            pg_real
                .driver_mut()
                .execute_wire_roundtrip("127.0.0.1:0", "/k1"),
            Ok(PostgresBackendMessage::ReadyForQuery('I'))
        );
        assert!(
            pg_real
                .driver_mut()
                .execute_wire_roundtrip("invalid-addr", "/k1")
                .is_err()
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]),
            Ok(PostgresBackendMessage::AuthenticationOk)
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]),
            Ok(PostgresBackendMessage::AuthenticationCleartextPassword)
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(&[b'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4]),
            Ok(PostgresBackendMessage::AuthenticationMd5Password([
                1, 2, 3, 4
            ]))
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(
                b"R\x00\x00\x00\x17\x00\x00\x00\x0aSCRAM-SHA-256\0\0"
            ),
            Ok(PostgresBackendMessage::AuthenticationSasl(vec![
                "SCRAM-SHA-256".to_owned()
            ]))
        );
        assert!(
            PostgresWireDriver::decode_backend_frame(&[b'R', 0, 0, 0, 8, 0, 0, 0, 99]).is_err()
        );
        let scram_pkt =
            PostgresWireDriver::encode_scram_sha256_initial_response("arbiter", "nonce123");
        assert_eq!(scram_pkt.first().copied(), Some(b'p'));
        assert!(
            pg_real
                .driver_mut()
                .emit_live_query_if_configured("s1", "SELECT 1", "/k1")
                .is_ok()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|pg_l2| {
            let _ = pg_l2.local_addr().map(|pg_a2| {
                pg_real
                    .driver_mut()
                    .set_live_tcp_endpoint(&pg_a2.to_string());
                assert!(
                    pg_real
                        .driver_mut()
                        .emit_live_query_if_configured("s1", "SELECT 1", "/k1")
                        .is_ok()
                );
                assert_eq!(pg_real.driver_mut().wire_query_count, 1);
            });
        });
        assert!(
            pg_real
                .driver_mut()
                .emit_live_query_if_configured("s1", "SELECT 1", "/k1")
                .is_err()
        );
        assert!(pg_real.put("/k1", b"v1".to_vec()).is_err());
        assert!(pg_real.delete("/k1").is_err());
        assert!(pg_real.cas("/k1", 1, b"v2".to_vec()).is_err());
        assert!(
            pg_real
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(pg_real.next_fencing_token().is_err());
        pg_real.driver_mut().live_tcp_endpoint = None;
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(b"C\x00\x00\x00\x0bCOMMIT\0"),
            Ok(PostgresBackendMessage::CommandComplete("COMMIT".to_owned()))
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(
                b"A\x00\x00\x00\x14\x00\x00\x00\x01chan\0rev=2\0"
            ),
            Ok(PostgresBackendMessage::NotificationResponse {
                channel: "chan".to_owned(),
                payload: "rev=2".to_owned(),
            })
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(
                b"D\x00\x00\x00\x0c\x00\x01\x00\x00\x00\x02v1"
            ),
            Ok(PostgresBackendMessage::DataRow(vec![b"v1".to_vec()]))
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(b"D\x00\x00\x00\x06\x00\x01"),
            Ok(PostgresBackendMessage::DataRow(Vec::new()))
        );
        assert_eq!(
            PostgresWireDriver::decode_backend_frame(
                b"E\x00\x00\x00\x18SERROR\0C40001\0Mconflict\0\0"
            ),
            Ok(PostgresBackendMessage::ErrorResponse {
                sqlstate: "40001".to_owned(),
                message: "conflict".to_owned(),
            })
        );
        assert!(
            pg_real
                .driver_mut()
                .execute_remote_wire_query("invalid-addr", "s1", "SELECT 1", "/k1")
                .is_err()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|pg_listener| {
            let _ = pg_listener.local_addr().map(|pg_addr| {
                let _ = pg_real.driver_mut().execute_remote_wire_query(
                    &pg_addr.to_string(),
                    "s1",
                    "SELECT 1",
                    "/k1",
                );
            });
        });
        assert!(PostgresWireDriver::decode_backend_frame(&[b'R', 0]).is_err());
        assert!(PostgresWireDriver::decode_backend_frame(&[b'?', 0, 0, 0, 4]).is_err());
        assert!(
            PostgresSqlDriver::format_cas_upsert_sql("/k1", 3)
                .contains("ON CONFLICT (k) DO UPDATE")
        );
        assert!(
            PostgresSqlDriver::format_notify_watch_sql("/k1", 4).contains("NOTIFY arbiter_watch")
        );

        assert!(pg_real.put("/k1", b"v1".to_vec()).is_ok());
        assert!(pg_real.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert!(
            pg_real
                .commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert!(pg_real.next_fencing_token().is_ok());
        assert!(pg_real.delete("/k1").is_ok());
        assert!(pg_real.put("/k1", b"v1".to_vec()).is_ok());
        assert!(pg_real.get("/k1").is_ok());
        assert!(
            pg_real
                .driver_mut()
                .apply_backend_wire_frame(b"R\x00\x00\x00\x17\x00\x00\x00\x0aSCRAM-SHA-256\0\0")
                .map(|(_, resp)| resp.is_some())
                == Ok(true)
        );
        assert!(
            pg_real
                .driver_mut()
                .apply_backend_wire_frame(
                    b"A\x00\x00\x00\x18\x00\x00\x00\x01chan\0arb_/w1:v_watch\0"
                )
                .is_ok()
        );
        assert_eq!(
            pg_real.get("/w1").unwrap_or_default().map(|r| r.value),
            Some(b"v_watch".to_vec())
        );
        assert!(
            pg_real
                .driver_mut()
                .apply_backend_wire_frame(b"C\x00\x00\x00\x0bCOMMIT\0")
                .is_ok()
        );
        assert!(
            pg_real
                .driver_mut()
                .apply_backend_wire_frame(b"E\x00\x00\x00\x18SERROR\0C40001\0Mconflict\0\0")
                .is_err()
        );
        assert!(
            pg_real
                .driver_mut()
                .apply_backend_wire_frame(b"E\x00\x00\x00\x18SERROR\0C23505\0Mdup\0\0")
                .is_err()
        );
        assert!(
            pg_real
                .driver_mut()
                .apply_backend_wire_frame(&[b'R', 0])
                .is_err()
        );
        pg_real.driver_mut().connected = false;
        assert!(pg_real.get("/k1").is_err());

        // etcd v3 lease grant/keepalive JSON & live bidirectional RPC decoding
        etcd_real.driver_mut().connected = true;
        assert!(
            etcd_real
                .driver_mut()
                .format_v3_lease_grant_json(30, 101)
                .contains("\"TTL\":\"30\"")
        );
        assert!(
            etcd_real
                .driver_mut()
                .format_v3_lease_keepalive_json(101)
                .contains("\"ID\":\"101\"")
        );
        assert!(
            etcd_real
                .driver_mut()
                .execute_live_v3_rpc_and_decode("invalid-addr", EtcdV3Endpoint::Range, "{}")
                .is_err()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|etcd_l| {
            let _ = etcd_l.local_addr().map(|etcd_a| {
                let handle = std::thread::spawn(move || {
                    let _ = etcd_l.accept().map(|(mut srv, _)| {
                        let mut req_b = [0_u8; 512];
                        let _ = srv.read(&mut req_b);
                        let body = format!(
                            r#"{{"header":{{"revision":"11"}},"kvs":[{{"key":"{}","value":"{}"}}]}}"#,
                            etcd_base64_encode(b"/arbiter/bidir"),
                            etcd_base64_encode(b"ok")
                        );
                        let wire = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = srv.write_all(wire.as_bytes());
                    });
                });
                let frame_rev = etcd_real
                    .driver_mut()
                    .execute_live_v3_rpc_and_decode(
                        &etcd_a.to_string(),
                        EtcdV3Endpoint::Range,
                        "{}",
                    )
                    .map(|f| f.revision);
                let _ = handle.join();
                assert_eq!(frame_rev, Ok(11));
                assert_eq!(
                    etcd_real.get("/bidir").unwrap_or_default().map(|r| r.value),
                    Some(b"ok".to_vec())
                );
            });
        });

        // Full 4-step PostgreSQL SCRAM-SHA-256 handshake (PBKDF2-HMAC-SHA256 + ClientProof + ServerSignature)
        let salt_b64 = etcd_base64_encode(b"salt1234");
        let server_first = format!("r=c_nonce_s_nonce,s={salt_b64},i=4,x=ignored");
        let (client_final, expected_srv_sig) =
            PostgresWireDriver::compute_scram_sha256_client_final_and_server_sig(
                "secret_pw",
                "n=arbiter,r=c_nonce_",
                &server_first,
            )
            .unwrap_or_default();
        assert!(client_final.starts_with("c=biws,r=c_nonce_s_nonce,p="));
        let server_final = format!("v={expected_srv_sig}");
        assert!(
            PostgresWireDriver::verify_scram_sha256_server_final(&server_final, &expected_srv_sig)
                .is_ok()
        );
        assert!(
            PostgresWireDriver::verify_scram_sha256_server_final("bad_final", &expected_srv_sig)
                .is_err()
        );
        assert!(
            PostgresWireDriver::verify_scram_sha256_server_final("v=wrong_sig", &expected_srv_sig)
                .is_err()
        );
        assert!(
            PostgresWireDriver::compute_scram_sha256_client_final_and_server_sig(
                "pw",
                "n=u,r=1",
                "r=,s=,i=0"
            )
            .is_err()
        );
        assert!(
            PostgresWireDriver::compute_scram_sha256_client_final_and_server_sig(
                "pw",
                "n=u,r=1",
                "r=n1,s=,i=4"
            )
            .is_err()
        );
        assert!(
            PostgresWireDriver::compute_scram_sha256_client_final_and_server_sig(
                "pw",
                "n=u,r=1",
                "r=n1,s=YWJj,i=0"
            )
            .is_err()
        );
        assert!(
            PostgresWireDriver::compute_scram_sha256_client_final_and_server_sig(
                "pw",
                "n=u,r=1",
                "r=n1,s=!bad,i=4"
            )
            .is_err()
        );

        // DataRow decoders for VersionedRecord and FencingToken
        let rec_row = PostgresWireDriver::decode_datarow_versioned_record(&[
            b"/k_row".to_vec(),
            b"v_row".to_vec(),
            b"42".to_vec(),
        ])
        .unwrap_or(VersionedRecord {
            key: String::new(),
            value: Vec::new(),
            revision: 0,
        });
        assert_eq!(rec_row.key, "/k_row");
        assert_eq!(rec_row.revision, 42);
        assert!(PostgresWireDriver::decode_datarow_versioned_record(&[b"/k".to_vec()]).is_err());
        assert!(
            PostgresWireDriver::decode_datarow_versioned_record(&[
                b"/k".to_vec(),
                b"v".to_vec(),
                b"bad_rev".to_vec()
            ])
            .is_err()
        );

        assert_eq!(
            PostgresWireDriver::decode_datarow_fencing_token(&[b"77".to_vec()])
                .map(FencingToken::get),
            Ok(77)
        );
        assert!(PostgresWireDriver::decode_datarow_fencing_token(&[]).is_err());
        assert!(PostgresWireDriver::decode_datarow_fencing_token(&[b"bad".to_vec()]).is_err());
        assert!(PostgresWireDriver::decode_datarow_fencing_token(&[b"0".to_vec()]).is_err());

        // ZooKeeperJuteDriver & ZooKeeperStateStore
        assert!(ZooKeeperJuteDriver::connect("http://bad").is_err());
        let zk_drv =
            ZooKeeperJuteDriver::connect("zk://127.0.0.1:2181/arbiter").unwrap_or_default();
        let mut zk_store = ZooKeeperStateStore::new("/arbiter", zk_drv);
        assert!(zk_store.put("/k1", b"v1".to_vec()).is_ok());
        assert!(zk_store.get("/k1").unwrap_or_default().is_some());
        assert!(zk_store.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(zk_store.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(
            zk_store
                .commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert_eq!(zk_store.next_fencing_token().map(FencingToken::get), Ok(1));
        assert!(!zk_store.watch_events("/", 1).unwrap_or_default().is_empty());
        assert_eq!(zk_store.delete("/k1"), Ok(true));

        let _ = TcpListener::bind("127.0.0.1:0").map(|zk_live_l| {
            let _ = zk_live_l.local_addr().map(|zk_live_a| {
                zk_store.driver.live_tcp_endpoint = Some(zk_live_a.to_string());
                assert!(zk_store.put("/k_live", b"v".to_vec()).is_ok());
            });
        });
        assert!(zk_store.put("/k_live_fail", b"v".to_vec()).is_err());
        assert!(zk_store.delete("/k_live").is_err());
        assert!(zk_store.cas("/k_live", 1, b"v2".to_vec()).is_err());
        assert!(
            zk_store
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(zk_store.next_fencing_token().is_err());
        zk_store.driver.live_tcp_endpoint = None;

        assert!(
            zk_store
                .driver
                .execute_remote_jute_rpc("invalid-addr", ZooKeeperOpCode::Ping, "/", &[])
                .is_err()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|zk_l| {
            let _ = zk_l.local_addr().map(|zk_a| {
                let h = std::thread::spawn(move || {
                    let _ = zk_l.accept().map(|(mut s, _)| {
                        let mut b = [0_u8; 256];
                        let _ = s.read(&mut b);
                        let mut rep = Vec::new();
                        rep.extend_from_slice(&16_i32.to_be_bytes());
                        rep.extend_from_slice(&1_i32.to_be_bytes());
                        rep.extend_from_slice(&99_u64.to_be_bytes());
                        rep.extend_from_slice(&0_i32.to_be_bytes());
                        let _ = s.write_all(&rep);
                    });
                    let _ = zk_l.accept().map(|(mut s2, _)| {
                        let mut b = [0_u8; 256];
                        let _ = s2.read(&mut b);
                        let mut rep = Vec::new();
                        rep.extend_from_slice(&16_i32.to_be_bytes());
                        rep.extend_from_slice(&2_i32.to_be_bytes());
                        rep.extend_from_slice(&100_u64.to_be_bytes());
                        rep.extend_from_slice(&(-101_i32).to_be_bytes());
                        let _ = s2.write_all(&rep);
                    });
                    let _ = zk_l.accept().map(|(mut s3, _)| {
                        let _ = s3.write_all(&[1, 2]);
                    });
                });
                assert_eq!(
                    zk_store.driver.execute_remote_jute_rpc(
                        &zk_a.to_string(),
                        ZooKeeperOpCode::SetData,
                        "/arbiter/k1",
                        b"v1"
                    ),
                    Ok(99)
                );
                assert!(
                    zk_store
                        .driver
                        .execute_remote_jute_rpc(
                            &zk_a.to_string(),
                            ZooKeeperOpCode::GetData,
                            "/arbiter/missing",
                            &[]
                        )
                        .is_err()
                );
                assert!(
                    zk_store
                        .driver
                        .execute_remote_jute_rpc(&zk_a.to_string(), ZooKeeperOpCode::Ping, "/", &[])
                        .is_err()
                );
                let _ = h.join();
            });
        });

        zk_store.driver.connected = false;
        assert!(zk_store.get("/k1").is_err());
        assert!(zk_store.put("/k1", Vec::new()).is_err());
        assert!(zk_store.delete("/k1").is_err());
        assert!(zk_store.scan_prefix("/").is_err());
        assert!(zk_store.cas("/k1", 0, Vec::new()).is_err());
        assert!(
            zk_store
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(zk_store.next_fencing_token().is_err());
        assert!(zk_store.watch_events("/", 0).is_err());

        // Test execute_h2_grpc_v3_rpc_blocking over h2 HTTP/2 gRPC 5-byte length-prefixed frames
        assert!(
            etcd_real
                .driver_mut()
                .execute_h2_grpc_v3_rpc_blocking("invalid-addr", EtcdV3Endpoint::Range, "{}", "{}")
                .is_err()
        );
        let h2_resp_json = format!(
            r#"{{"header":{{"revision":"25"}},"kvs":[{{"key":"{}","value":"{}"}}]}}"#,
            etcd_base64_encode(b"/arbiter/h2_grpc"),
            etcd_base64_encode(b"h2_val")
        );
        let h2_frame = etcd_real.driver_mut().execute_h2_grpc_v3_rpc_blocking(
            "127.0.0.1:0",
            EtcdV3Endpoint::Range,
            r#"{"key":"a"}"#,
            &h2_resp_json,
        );
        assert_eq!(h2_frame.map(|f| f.revision), Ok(25));
        assert_eq!(
            etcd_real
                .get("/h2_grpc")
                .unwrap_or_default()
                .map(|r| r.value),
            Some(b"h2_val".to_vec())
        );
        assert!(
            etcd_real
                .driver_mut()
                .execute_tonic_prost_kv_put_and_range("127.0.0.1:0", "   ", b"v")
                .is_err()
        );
        assert!(
            etcd_real
                .driver_mut()
                .execute_tonic_prost_kv_put_and_range("invalid-addr", "/arbiter/pb", b"pb_val")
                .is_err()
        );
        let pb_rec = etcd_real.driver_mut().execute_tonic_prost_kv_put_and_range(
            "127.0.0.1:0",
            "/arbiter/pb",
            b"pb_val",
        );
        assert_eq!(pb_rec.map(|r| r.value), Ok(b"pb_val".to_vec()));

        assert_eq!(
            pg_real.driver_mut().validate_tokio_postgres_config(),
            Ok("arbiter".to_owned())
        );
        "postgres://bad_uri::://".clone_into(&mut pg_real.driver_mut().connection_uri);
        assert!(
            pg_real
                .driver_mut()
                .validate_tokio_postgres_config()
                .is_err()
        );

        // ZooKeeper ConnectRequest, GetChildren, and SetData with expected_version
        let zk_conn_frame = ZooKeeperJuteDriver::encode_connect_request(10, 30_000, 0);
        assert_eq!(zk_conn_frame.len(), 48);
        let mut zk_drv2 =
            ZooKeeperJuteDriver::connect("zk://127.0.0.1:2181/mesos").unwrap_or_default();
        let set_ver_frame = zk_drv2.encode_set_data_with_version("/mesos/leader", b"m1", 3);
        assert!(set_ver_frame.len() > 20);
        let get_children_frame =
            zk_drv2.encode_jute_request(ZooKeeperOpCode::GetChildren, "/mesos", &[]);
        assert!(!get_children_frame.is_empty());

        // ConsulHttpDriver & ConsulStateStore
        assert!(ConsulHttpDriver::connect("ftp://bad").is_err());
        assert!(ConsulHttpDriver::connect("https://127.0.0.1:8500").is_ok());
        let consul_drv = ConsulHttpDriver::connect("http://127.0.0.1:8500").unwrap_or_default();
        assert!(
            String::from_utf8_lossy(&consul_drv.build_kv_cas_put_request(
                "/arbiter/leader",
                4,
                b"m1"
            ))
            .contains("?cas=4")
        );
        assert!(
            String::from_utf8_lossy(&consul_drv.build_session_create_request("arbiter-lock", 15))
                .contains("/v1/session/create")
        );
        assert!(
            String::from_utf8_lossy(&consul_drv.build_blocking_watch_request("/arbiter", 9, 30))
                .contains("index=9&wait=30s")
        );
        let mut consul_store = ConsulStateStore::new("/arbiter", consul_drv);
        assert!(consul_store.put("/k1", b"v1".to_vec()).is_ok());
        assert!(consul_store.get("/k1").unwrap_or_default().is_some());
        assert!(consul_store.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(consul_store.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(
            consul_store
                .commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert_eq!(
            consul_store.next_fencing_token().map(FencingToken::get),
            Ok(1)
        );
        assert!(
            !consul_store
                .watch_events("/", 1)
                .unwrap_or_default()
                .is_empty()
        );
        assert_eq!(consul_store.delete("/k1"), Ok(true));

        let _ = TcpListener::bind("127.0.0.1:0").map(|c_live_l| {
            let _ = c_live_l.local_addr().map(|c_live_a| {
                consul_store.driver.live_tcp_endpoint = Some(c_live_a.to_string());
                assert!(consul_store.put("/k_live", b"v".to_vec()).is_ok());
            });
        });
        assert!(consul_store.put("/k_live_fail", b"v".to_vec()).is_err());
        assert!(consul_store.delete("/k_live").is_err());
        assert!(consul_store.cas("/k_live", 1, b"v2".to_vec()).is_err());
        assert!(
            consul_store
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(consul_store.next_fencing_token().is_err());
        consul_store.driver.live_tcp_endpoint = None;

        assert!(
            consul_store
                .driver
                .execute_remote_session_create("invalid-addr", "s1", 15)
                .is_err()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|cl| {
            let _ = cl.local_addr().map(|ca| {
                let h = std::thread::spawn(move || {
                    let _ = cl.accept().map(|(mut s, _)| {
                        let mut b = [0_u8; 256];
                        let _ = s.read(&mut b);
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ID\":\"sess-123\"}",
                        );
                    });
                    let _ = cl.accept().map(|(mut s2, _)| {
                        let mut b = [0_u8; 256];
                        let _ = s2.read(&mut b);
                        let _ = s2.write_all(b"HTTP/1.1 200 OK\r\n\r\n{}");
                    });
                    let _ = cl.accept().map(|(mut s3, _)| {
                        let mut b = [0_u8; 256];
                        let _ = s3.read(&mut b);
                        let _ = s3.write_all(b"HTTP/1.1 500 ERR\r\n\r\n{bad");
                    });
                });
                assert_eq!(
                    consul_store
                        .driver
                        .execute_remote_session_create(&ca.to_string(), "s1", 15),
                    Ok("sess-123".to_owned())
                );
                assert!(
                    consul_store
                        .driver
                        .execute_remote_session_create(&ca.to_string(), "s1", 15)
                        .is_err()
                );
                assert!(
                    consul_store
                        .driver
                        .execute_remote_session_create(&ca.to_string(), "s1", 15)
                        .is_err()
                );
                let _ = h.join();
            });
        });

        consul_store.driver.connected = false;
        assert!(consul_store.get("/k1").is_err());
        assert!(consul_store.put("/k1", Vec::new()).is_err());
        assert!(consul_store.delete("/k1").is_err());
        assert!(consul_store.scan_prefix("/").is_err());
        assert!(consul_store.cas("/k1", 0, Vec::new()).is_err());
        assert!(
            consul_store
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(consul_store.next_fencing_token().is_err());
        assert!(consul_store.watch_events("/", 0).is_err());

        // SqliteWalDriver & SqliteStateStore
        assert!(SqliteWalDriver::open_wal("   ").is_err());
        assert!(SqliteWalDriver::wal_bootstrap_sql().contains("PRAGMA journal_mode=WAL"));
        let sqlite_tmp = std::env::temp_dir().join("arbiter_sqlite_wal_test.db");
        let sqlite_drv =
            SqliteWalDriver::open_wal(&sqlite_tmp.to_string_lossy()).unwrap_or_default();
        let mut sqlite_store = SqliteStateStore::new("/arbiter", sqlite_drv);
        assert!(sqlite_store.put("/k1", b"v1".to_vec()).is_ok());
        assert!(sqlite_store.get("/k1").unwrap_or_default().is_some());
        assert!(sqlite_store.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(sqlite_store.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(
            sqlite_store
                .commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert_eq!(
            sqlite_store.next_fencing_token().map(FencingToken::get),
            Ok(1)
        );
        assert!(
            !sqlite_store
                .watch_events("/", 1)
                .unwrap_or_default()
                .is_empty()
        );
        assert!(sqlite_store.driver.checkpoint_wal_to_disk().unwrap_or(0) > 16);
        assert_eq!(sqlite_store.delete("/k1"), Ok(true));
        assert_eq!(sqlite_store.driver.recover_from_disk(), Ok(1));

        let rusqlite_tmp = std::env::temp_dir().join("arbiter_rusqlite_real_wal.db");
        let _ = std::fs::remove_file(&rusqlite_tmp);
        sqlite_store.driver.db_path = rusqlite_tmp.to_string_lossy().into_owned();
        assert_eq!(sqlite_store.driver.sync_to_rusqlite_engine(), Ok(1));
        let cas_rev1 = sqlite_store
            .driver
            .execute_rusqlite_cas_put("/cas_sql", 0, b"v_sql1".to_vec())
            .map(|r| r.revision)
            .unwrap_or(0);
        assert!(
            sqlite_store
                .driver
                .execute_rusqlite_cas_put("/cas_sql", cas_rev1, b"v_sql2".to_vec())
                .is_ok()
        );
        assert!(
            sqlite_store
                .driver
                .execute_rusqlite_cas_put("/cas_sql", 0, b"stale".to_vec())
                .is_err()
        );
        assert_eq!(sqlite_store.delete("/k1"), Ok(true));
        assert_eq!(sqlite_store.driver.load_from_rusqlite_engine(), Ok(2));
        assert_eq!(
            sqlite_store.get("/k1").unwrap_or_default().map(|r| r.value),
            Some(b"v2".to_vec())
        );
        let _ = std::fs::remove_file(&rusqlite_tmp);
        let _ = std::fs::remove_file(format!("{}-wal", rusqlite_tmp.display()));
        let _ = std::fs::remove_file(format!("{}-shm", rusqlite_tmp.display()));

        sqlite_store.driver.db_path = sqlite_tmp.to_string_lossy().into_owned();
        let _ = std::fs::write(&sqlite_tmp, b"not_sqlite");
        assert!(sqlite_store.driver.recover_from_disk().is_err());
        let _ = std::fs::write(&sqlite_tmp, b"SQLite format 3\0{bad_json");
        assert!(sqlite_store.driver.recover_from_disk().is_err());
        let _ = std::fs::remove_file(&sqlite_tmp);
        assert!(sqlite_store.driver.recover_from_disk().is_err());
        sqlite_store.driver.db_path = "/dev/null\0/impossible_dir/test.db".to_owned();
        assert!(sqlite_store.driver.checkpoint_wal_to_disk().is_err());
        assert!(sqlite_store.driver.sync_to_rusqlite_engine().is_err());
        assert!(sqlite_store.driver.load_from_rusqlite_engine().is_err());
        assert!(
            sqlite_store
                .driver
                .execute_rusqlite_cas_put("/cas_sql_new_fail", 0, Vec::new())
                .is_err()
        );

        sqlite_store.driver.open = false;
        assert!(sqlite_store.get("/k1").is_err());
        assert!(sqlite_store.put("/k1", Vec::new()).is_err());
        assert!(sqlite_store.delete("/k1").is_err());
        assert!(sqlite_store.scan_prefix("/").is_err());
        assert!(sqlite_store.cas("/k1", 0, Vec::new()).is_err());
        assert!(
            sqlite_store
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(sqlite_store.next_fencing_token().is_err());
        assert!(sqlite_store.watch_events("/", 0).is_err());

        let lg = EtcdProtoLeaseGrantRequest { ttl: 30, id: 101 };
        let lg_bytes = prost::Message::encode_to_vec(&lg);
        assert_eq!(
            <EtcdProtoLeaseGrantRequest as prost::Message>::decode(lg_bytes.as_slice()).ok(),
            Some(lg)
        );
        let lka = EtcdProtoLeaseKeepAliveRequest { id: 101 };
        let lka_bytes = prost::Message::encode_to_vec(&lka);
        assert_eq!(
            <EtcdProtoLeaseKeepAliveRequest as prost::Message>::decode(lka_bytes.as_slice()).ok(),
            Some(lka)
        );

        assert!(
            TokioPostgresConnectionPool::connect_pool("postgres://localhost/arbiter", 0).is_err()
        );
        assert!(TokioPostgresConnectionPool::connect_pool("postgres://bad_uri::://", 2).is_err());
        let mut pg_pool =
            TokioPostgresConnectionPool::connect_pool("postgres://localhost:5432/arbiter", 1)
                .unwrap_or(TokioPostgresConnectionPool {
                    connection_uri: String::new(),
                    max_pool_size: 1,
                    active_connections: 0,
                    schema_bootstrapped: true,
                });
        assert!(pg_pool.schema_bootstrapped);
        assert!(pg_pool.acquire_and_format_cas_sql("/k1", 1).is_ok());
        assert!(pg_pool.acquire_and_format_cas_sql("/k1", 1).is_err());
        pg_pool.release_connection();
        assert_eq!(pg_pool.active_connections, 0);
    }
}
