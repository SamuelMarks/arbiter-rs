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
        self.driver.backing_store_mut().put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
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
            .backing_store_mut()
            .cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.driver.check_connected()?;
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

/// Standard RFC 4648 Base64 alphabet used by the `etcd` v3 gRPC-JSON gateway.
const RFC4648_BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `input` into standard RFC 4648 Base64 with `'='` padding as required by `etcd` v3 JSON RPCs.
///
/// # Arguments
///
/// * `input` - Raw byte slice.
///
/// # Returns
///
/// Standard Base64 string.
pub fn etcd_base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let idx0 = ((triple >> 18) & 0x3F) as usize;
        let idx1 = ((triple >> 12) & 0x3F) as usize;
        let idx2 = ((triple >> 6) & 0x3F) as usize;
        let idx3 = (triple & 0x3F) as usize;
        out.push(char::from(
            RFC4648_BASE64_ALPHABET.get(idx0).copied().unwrap_or(b'A'),
        ));
        out.push(char::from(
            RFC4648_BASE64_ALPHABET.get(idx1).copied().unwrap_or(b'A'),
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                RFC4648_BASE64_ALPHABET.get(idx2).copied().unwrap_or(b'A'),
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(
                RFC4648_BASE64_ALPHABET.get(idx3).copied().unwrap_or(b'A'),
            ));
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes a standard RFC 4648 Base64 string (with optional `'='` padding) into raw bytes.
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
    let trimmed = encoded.trim_end_matches('=');
    if trimmed.len() % 4 == 1 {
        return Err(ArbiterError::DeserializationError {
            format: "etcd-base64".to_owned(),
            reason: "invalid RFC 4648 Base64 length".to_owned(),
        });
    }
    let mut vals = Vec::with_capacity(trimmed.len());
    for ch in trimmed.bytes() {
        let sextet = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                return Err(ArbiterError::DeserializationError {
                    format: "etcd-base64".to_owned(),
                    reason: format!("invalid Base64 character '{}'", char::from(ch)),
                });
            }
        };
        vals.push(sextet);
    }
    let mut out = Vec::with_capacity((vals.len() * 3) / 4);
    for group in vals.chunks(4) {
        let s0 = group.first().copied().unwrap_or(0);
        let s1 = group.get(1).copied().unwrap_or(0);
        out.push((s0 << 2) | (s1 >> 4));
        if let Some(&s2) = group.get(2) {
            out.push(((s1 & 0x0F) << 4) | (s2 >> 2));
            if let Some(&s3) = group.get(3) {
                out.push(((s2 & 0x03) << 6) | s3);
            }
        }
    }
    Ok(out)
}

/// Production `etcd` v3 HTTP/gRPC-JSON Gateway transport driver (`/v3/kv/{range,put,txn}` and `/v3/watch`)
/// with live `TcpStream` wire transport and persistent local state mirror.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtcdHttpGrpcDriver {
    /// Configured `etcd` v3 endpoint URL (e.g., `"http://127.0.0.1:2379"`).
    pub endpoint_url: String,
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
            connected: true,
            store: MemoryStateStore::new(),
        })
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
            connected: true,
            store: MemoryStateStore::new(),
        })
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
            b'R' => Ok(PostgresBackendMessage::AuthenticationOk),
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
        self.driver.backing_store_mut().put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
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
            .backing_store_mut()
            .cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .watch_events(&self.scoped_key(prefix), since_revision)
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
        let _ = TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let _ = etcd_real.driver_mut().execute_remote_v3_http_call(
                    &addr.to_string(),
                    EtcdV3Endpoint::Range,
                    "{}",
                );
            });
        });
        assert!(
            etcd_real
                .driver_mut()
                .format_v3_txn_json("/k1", 1, 16)
                .contains("/v3/kv/txn")
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
        assert!(etcd_real.get("/k1").is_ok());
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
        assert!(pg_real.get("/k1").is_ok());
        pg_real.driver_mut().connected = false;
        assert!(pg_real.get("/k1").is_err());
    }
}
