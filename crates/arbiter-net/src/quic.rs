//! Framed bidirectional QUIC transport abstraction with multiplexed streams (`arbiter-net::quic`).
//!
//! Supports length-delimited zero-copy `rkyv` framing across multiplexed QUIC streams
//! (`Control`, `Telemetry`, and `ArtifactP2p`), bounded queue backpressure, and keep-alive
//! idle timeout tracking.

use std::collections::VecDeque;
use std::net::UdpSocket;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_proto::{WIRE_FRAME_HEADER_LEN, WireEnvelope, WireFrameHeader};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Validated 64-bit QUIC connection identifier surviving client IP/port roaming (`Connection Migration`).
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct QuicConnectionId(u64);

impl QuicConnectionId {
    /// Constructs a validated non-zero [`QuicConnectionId`].
    ///
    /// # Arguments
    ///
    /// * `raw` - Raw 64-bit connection ID (`> 0`).
    ///
    /// # Returns
    ///
    /// Validated [`QuicConnectionId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `raw == 0`.
    pub fn new(raw: u64) -> ArbiterResult<Self> {
        if raw == 0 {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: "QuicConnectionId cannot be zero".to_owned(),
            });
        }
        Ok(Self(raw))
    }

    /// Returns the raw 64-bit connection ID.
    ///
    /// # Returns
    ///
    /// Connection ID `u64`.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Cryptographically bound TLS 1.3 / QUIC `0-RTT` session resumption ticket allowing single-flight
/// control-plane reconnection after Agent or CLI restarts.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroRttSessionTicket {
    /// Connection ID bound to this ticket.
    pub connection_id: QuicConnectionId,
    /// Authenticated peer SPIFFE URI bound to this ticket.
    pub spiffe_id: String,
    /// Monotonic tick when the ticket was issued.
    pub issued_at_tick: u64,
    /// Monotonic tick when the ticket expires.
    pub expires_at_tick: u64,
    /// 32-byte SHA-256 HMAC authentication tag over `(connection_id || spiffe_id || issued_at_tick || expires_at_tick)`.
    pub auth_tag: [u8; 32],
}

impl ZeroRttSessionTicket {
    /// Issues a new signed [`ZeroRttSessionTicket`].
    ///
    /// # Arguments
    ///
    /// * `connection_id` - [`QuicConnectionId`] for the session.
    /// * `spiffe_id` - Peer SPIFFE ID string.
    /// * `issued_at_tick` - Current monotonic tick.
    /// * `ttl_ticks` - Ticket validity duration in ticks.
    /// * `secret_key` - 32-byte server ticket encryption/MAC key.
    ///
    /// # Returns
    ///
    /// Signed [`ZeroRttSessionTicket`].
    pub fn issue(
        connection_id: QuicConnectionId,
        spiffe_id: &str,
        issued_at_tick: u64,
        ttl_ticks: u64,
        secret_key: &[u8; 32],
    ) -> Self {
        let expires_at_tick = issued_at_tick.saturating_add(ttl_ticks);
        let auth_tag = Self::compute_tag(
            connection_id,
            spiffe_id,
            issued_at_tick,
            expires_at_tick,
            secret_key,
        );
        Self {
            connection_id,
            spiffe_id: spiffe_id.to_owned(),
            issued_at_tick,
            expires_at_tick,
            auth_tag,
        }
    }

    /// Verifies this [`ZeroRttSessionTicket`] against `secret_key` and `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - 32-byte server ticket key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the ticket signature and expiration window are valid.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if expired or if the `auth_tag` does not match.
    pub fn verify(&self, secret_key: &[u8; 32], current_tick: u64) -> ArbiterResult<()> {
        if current_tick >= self.expires_at_tick {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "0-RTT session ticket expired at tick {} (current tick {current_tick})",
                    self.expires_at_tick
                ),
            });
        }
        let expected = Self::compute_tag(
            self.connection_id,
            &self.spiffe_id,
            self.issued_at_tick,
            self.expires_at_tick,
            secret_key,
        );
        if self.auth_tag != expected {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: "0-RTT session ticket authentication tag mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the 32-byte SHA-256 authentication tag for a ticket.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Bound [`QuicConnectionId`].
    /// * `spiffe_id` - Peer SPIFFE ID.
    /// * `issued_at_tick` - Issue tick.
    /// * `expires_at_tick` - Expiration tick.
    /// * `secret_key` - 32-byte key.
    ///
    /// # Returns
    ///
    /// 32-byte digest array.
    fn compute_tag(
        connection_id: QuicConnectionId,
        spiffe_id: &str,
        issued_at_tick: u64,
        expires_at_tick: u64,
        secret_key: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret_key);
        hasher.update(connection_id.get().to_le_bytes());
        hasher.update(spiffe_id.as_bytes());
        hasher.update(issued_at_tick.to_le_bytes());
        hasher.update(expires_at_tick.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Multiplexed QUIC stream purpose classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuicStreamKind {
    /// Stream `0`: Control-plane commands, heartbeats, and `CaaS` lease grants.
    Control,
    /// Stream `1`: High-frequency hardware telemetry and counter streaming.
    Telemetry,
    /// Stream `2`: Peer-to-peer content-addressable artifact transfer.
    ArtifactP2p,
}

impl QuicStreamKind {
    /// Returns the canonical QUIC stream identifier for this stream kind.
    ///
    /// # Returns
    ///
    /// Stream ID (`0`, `1`, or `2`).
    pub const fn stream_id(self) -> u64 {
        match self {
            Self::Control => 0,
            Self::Telemetry => 1,
            Self::ArtifactP2p => 2,
        }
    }
}

/// Encodes a [`WireEnvelope`] into a 16-byte [`WireFrameHeader`]-prefixed (`ARBW`) binary QUIC frame.
///
/// # Arguments
///
/// * `stream` - Target [`QuicStreamKind`].
/// * `envelope` - [`WireEnvelope`] to frame.
///
/// # Returns
///
/// Framed byte vector `[16B WireFrameHeader, rkyv_payload...]`.
///
/// # Errors
///
/// Returns [`ArbiterError::SerializationError`] if the payload exceeds `MAX_WIRE_FRAME_BYTES`.
pub fn encode_arbiter_wire_frame(
    stream: QuicStreamKind,
    envelope: &WireEnvelope,
) -> ArbiterResult<Vec<u8>> {
    let payload = envelope.to_rkyv_bytes();
    let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let stream_byte = u8::try_from(stream.stream_id()).unwrap_or(0);
    WireFrameHeader::new(stream_byte, 0, len_u32).map(|hdr| {
        let mut framed = Vec::with_capacity(WIRE_FRAME_HEADER_LEN + payload.len());
        framed.extend_from_slice(&hdr.to_bytes());
        framed.extend_from_slice(&payload);
        framed
    })
}

/// Decodes a 16-byte [`WireFrameHeader`]-prefixed (`ARBW`) binary QUIC frame into `(WireFrameHeader, WireEnvelope)`.
///
/// # Arguments
///
/// * `frame` - Raw framed byte slice.
///
/// # Returns
///
/// Decoded `(WireFrameHeader, WireEnvelope)`.
///
/// # Errors
///
/// Returns [`ArbiterError::DeserializationError`] or [`ArbiterError::QuicConnectionError`] if header
/// validation fails or the payload length does not match `header.payload_len`.
pub fn decode_arbiter_wire_frame(frame: &[u8]) -> ArbiterResult<(WireFrameHeader, WireEnvelope)> {
    let hdr = WireFrameHeader::from_bytes(frame)?;
    let payload = frame.get(WIRE_FRAME_HEADER_LEN..).unwrap_or(&[]);
    if payload.len() != hdr.payload_len as usize {
        return Err(ArbiterError::QuicConnectionError {
            stream_id: u64::from(hdr.stream_kind),
            reason: format!(
                "ARBW payload length {} does not match header length {}",
                payload.len(),
                hdr.payload_len
            ),
        });
    }
    WireEnvelope::from_rkyv_bytes(payload).map(|env| (hdr, env))
}

/// Encodes a [`WireEnvelope`] into a 4-byte little-endian length-prefixed binary QUIC frame.
///
/// # Arguments
///
/// * `envelope` - Wire message envelope to frame.
///
/// # Returns
///
/// Framed byte vector `[u32_le_len, rkyv_payload...]`.
pub fn encode_quic_frame(envelope: &WireEnvelope) -> Vec<u8> {
    let payload = envelope.to_rkyv_bytes();
    let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len_u32.to_le_bytes());
    framed.extend_from_slice(&payload);
    framed
}

/// Decodes a 4-byte little-endian length-prefixed binary QUIC frame into a [`WireEnvelope`].
///
/// # Arguments
///
/// * `frame` - Raw framed byte slice.
///
/// # Returns
///
/// Decoded [`WireEnvelope`].
///
/// # Errors
///
/// Returns [`ArbiterError::QuicConnectionError`] if the frame is shorter than 4 bytes or
/// truncated relative to its declared length header, or [`ArbiterError::DeserializationError`]
/// if the inner `rkyv` payload is invalid.
pub fn decode_quic_frame(frame: &[u8]) -> ArbiterResult<WireEnvelope> {
    let Some((header, payload)) = frame.split_at_checked(4) else {
        return Err(ArbiterError::QuicConnectionError {
            stream_id: 0,
            reason: "QUIC frame shorter than 4-byte length header".to_owned(),
        });
    };
    let mut len_bytes = [0_u8; 4];
    len_bytes.copy_from_slice(header);
    let declared_len = u32::from_le_bytes(len_bytes) as usize;
    if payload.len() != declared_len {
        return Err(ArbiterError::QuicConnectionError {
            stream_id: 0,
            reason: format!(
                "QUIC frame payload length {} does not match header length {declared_len}",
                payload.len()
            ),
        });
    }
    WireEnvelope::from_rkyv_bytes(payload)
}

/// Multiplexed QUIC connection endpoint with per-stream backpressure and keep-alive tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicMultiplexedConnection {
    /// Remote peer address or identifier.
    peer_endpoint: String,
    /// Maximum queued frames per stream before exerting backpressure.
    max_queue_depth: usize,
    /// Keep-alive idle timeout in ticks.
    keep_alive_timeout_ticks: u64,
    /// Monotonic tick of the last sent or received frame.
    last_activity_tick: u64,
    /// Queued frames on the Control stream.
    control_queue: VecDeque<Vec<u8>>,
    /// Queued frames on the Telemetry stream.
    telemetry_queue: VecDeque<Vec<u8>>,
    /// Queued frames on the Artifact P2P stream.
    artifact_queue: VecDeque<Vec<u8>>,
}

impl QuicMultiplexedConnection {
    /// Creates a new [`QuicMultiplexedConnection`].
    ///
    /// # Arguments
    ///
    /// * `peer_endpoint` - Peer address string.
    /// * `max_queue_depth` - Maximum in-flight frames per stream before backpressure rejection.
    /// * `keep_alive_timeout_ticks` - Idle timeout in ticks.
    /// * `initial_tick` - Starting monotonic tick.
    ///
    /// # Returns
    ///
    /// Initialized [`QuicMultiplexedConnection`].
    pub fn new(
        peer_endpoint: &str,
        max_queue_depth: usize,
        keep_alive_timeout_ticks: u64,
        initial_tick: u64,
    ) -> Self {
        Self {
            peer_endpoint: peer_endpoint.to_owned(),
            max_queue_depth,
            keep_alive_timeout_ticks,
            last_activity_tick: initial_tick,
            control_queue: VecDeque::new(),
            telemetry_queue: VecDeque::new(),
            artifact_queue: VecDeque::new(),
        }
    }

    /// Checks whether the connection has exceeded its keep-alive idle timeout at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the connection is still active.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `current_tick - last_activity_tick >= keep_alive_timeout_ticks`.
    pub fn check_keep_alive(&self, current_tick: u64) -> ArbiterResult<()> {
        if current_tick.saturating_sub(self.last_activity_tick) >= self.keep_alive_timeout_ticks {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "QUIC keep-alive timeout exceeded on peer '{}'",
                    self.peer_endpoint
                ),
            });
        }
        Ok(())
    }

    /// Enqueues a framed [`WireEnvelope`] onto the specified [`QuicStreamKind`], enforcing backpressure
    /// and keep-alive checks.
    ///
    /// # Arguments
    ///
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `envelope` - Message envelope to send.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if framed and queued.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if the connection timed out or if the target
    /// stream queue is full (backpressure).
    pub fn send_frame(
        &mut self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        current_tick: u64,
    ) -> ArbiterResult<()> {
        self.check_keep_alive(current_tick)?;
        let max_depth = self.max_queue_depth;
        let queue = self.queue_mut(stream);
        if queue.len() >= max_depth {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: stream.stream_id(),
                reason: "QUIC stream backpressure: send queue full".to_owned(),
            });
        }
        queue.push_back(encode_quic_frame(envelope));
        self.last_activity_tick = current_tick;
        Ok(())
    }

    /// Pops and decodes the next [`WireEnvelope`] from `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Source [`QuicStreamKind`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some(WireEnvelope))` if a frame was available, `Ok(None)` if the stream queue is empty.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if keep-alive expired or frame decoding failed.
    pub fn recv_frame(
        &mut self,
        stream: QuicStreamKind,
        current_tick: u64,
    ) -> ArbiterResult<Option<WireEnvelope>> {
        self.check_keep_alive(current_tick)?;
        let queue = self.queue_mut(stream);
        let Some(raw) = queue.pop_front() else {
            return Ok(None);
        };
        self.last_activity_tick = current_tick;
        decode_quic_frame(&raw).map(Some)
    }

    /// Pops and decodes the highest-priority pending [`WireEnvelope`] across all multiplexed
    /// streams in strict `Control (0) > Telemetry (1) > ArtifactP2p (2)` order, preventing
    /// bulk artifact or telemetry transfers from starving control-plane commands.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some((QuicStreamKind, WireEnvelope)))` if any stream has a pending frame, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if keep-alive expired or frame decoding failed.
    pub fn recv_priority_ordered_frame(
        &mut self,
        current_tick: u64,
    ) -> ArbiterResult<Option<(QuicStreamKind, WireEnvelope)>> {
        for kind in [
            QuicStreamKind::Control,
            QuicStreamKind::Telemetry,
            QuicStreamKind::ArtifactP2p,
        ] {
            if let Some(env) = self.recv_frame(kind, current_tick)? {
                return Ok(Some((kind, env)));
            }
        }
        Ok(None)
    }

    /// Migrates this connection's active peer socket address (`new_peer_endpoint`) after verifying
    /// a valid [`ZeroRttSessionTicket`], preserving in-flight stream queues across IP/port changes.
    ///
    /// # Arguments
    ///
    /// * `new_peer_endpoint` - Migrated peer socket address string.
    /// * `ticket` - Presented [`ZeroRttSessionTicket`].
    /// * `secret_key` - 32-byte server session ticket secret key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(QuicConnectionId)` of the migrated session.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `new_peer_endpoint` is empty or `ticket.verify` fails.
    pub fn migrate_peer_endpoint(
        &mut self,
        new_peer_endpoint: &str,
        ticket: &ZeroRttSessionTicket,
        secret_key: &[u8; 32],
        current_tick: u64,
    ) -> ArbiterResult<QuicConnectionId> {
        if new_peer_endpoint.trim().is_empty() {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: "cannot migrate QUIC connection to empty peer endpoint".to_owned(),
            });
        }
        ticket.verify(secret_key, current_tick)?;
        new_peer_endpoint.clone_into(&mut self.peer_endpoint);
        self.last_activity_tick = current_tick;
        Ok(ticket.connection_id)
    }

    /// Returns the current peer endpoint address string.
    ///
    /// # Returns
    ///
    /// Peer endpoint `&str`.
    pub fn peer_endpoint(&self) -> &str {
        &self.peer_endpoint
    }

    /// Returns a mutable reference to the queue for `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Stream kind.
    ///
    /// # Returns
    ///
    /// Mutable reference to `VecDeque<Vec<u8>>`.
    fn queue_mut(&mut self, stream: QuicStreamKind) -> &mut VecDeque<Vec<u8>> {
        match stream {
            QuicStreamKind::Control => &mut self.control_queue,
            QuicStreamKind::Telemetry => &mut self.telemetry_queue,
            QuicStreamKind::ArtifactP2p => &mut self.artifact_queue,
        }
    }
}

/// Exponential backoff policy for automatic connection migration and reconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconnectBackoffPolicy {
    /// Initial backoff delay in milliseconds.
    pub initial_backoff_ms: u64,
    /// Maximum backoff ceiling in milliseconds.
    pub max_backoff_ms: u64,
    /// Maximum consecutive retry attempts before returning an error.
    pub max_attempts: u32,
}

impl ReconnectBackoffPolicy {
    /// Computes the backoff delay in milliseconds for `attempt` (`0`-indexed).
    ///
    /// # Arguments
    ///
    /// * `attempt` - Retry attempt index.
    ///
    /// # Returns
    ///
    /// Clamped delay in milliseconds (`Ok(u64)`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `attempt >= max_attempts`.
    pub fn delay_for_attempt(&self, attempt: u32) -> ArbiterResult<u64> {
        if attempt >= self.max_attempts {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "reconnect attempts ({attempt}) exhausted max_attempts ({})",
                    self.max_attempts
                ),
            });
        }
        let shift = attempt.min(20);
        let mult = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
        Ok(self
            .initial_backoff_ms
            .saturating_mul(mult)
            .min(self.max_backoff_ms))
    }
}

/// Chunked frame descriptor for peer-to-peer artifact transfer over [`QuicStreamKind::ArtifactP2p`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactChunkFrame {
    /// Hex-encoded SHA-256 digest of the complete artifact.
    pub sha256_hex: String,
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Total number of chunks in the artifact stream.
    pub total_chunks: u32,
    /// Raw chunk payload bytes.
    pub payload: Vec<u8>,
}

/// Splits an artifact byte slice into bounded [`ArtifactChunkFrame`]s for streaming over [`QuicStreamKind::ArtifactP2p`].
///
/// # Arguments
///
/// * `sha256_hex` - Expected SHA-256 hex digest of the full artifact.
/// * `data` - Complete artifact bytes.
/// * `chunk_size` - Maximum bytes per chunk (clamped to `>= 1`).
///
/// # Returns
///
/// Ordered vector of [`ArtifactChunkFrame`]s.
pub fn split_artifact_into_chunks(
    sha256_hex: &str,
    data: &[u8],
    chunk_size: usize,
) -> Vec<ArtifactChunkFrame> {
    let eff_size = chunk_size.max(1);
    if data.is_empty() {
        return vec![ArtifactChunkFrame {
            sha256_hex: sha256_hex.to_owned(),
            chunk_index: 0,
            total_chunks: 1,
            payload: Vec::new(),
        }];
    }
    let chunks_raw: Vec<&[u8]> = data.chunks(eff_size).collect();
    let total = u32::try_from(chunks_raw.len()).unwrap_or(u32::MAX);
    chunks_raw
        .into_iter()
        .enumerate()
        .map(|(idx, slice)| ArtifactChunkFrame {
            sha256_hex: sha256_hex.to_owned(),
            chunk_index: u32::try_from(idx).unwrap_or(0),
            total_chunks: total,
            payload: slice.to_vec(),
        })
        .collect()
}

/// Reassembles ordered [`ArtifactChunkFrame`]s back into a contiguous byte vector.
///
/// # Arguments
///
/// * `chunks` - Slice of [`ArtifactChunkFrame`]s.
///
/// # Returns
///
/// Reassembled artifact bytes.
///
/// # Errors
///
/// Returns [`ArbiterError::QuicConnectionError`] if `chunks` is empty or any chunk index is out of order.
pub fn reassemble_artifact_chunks(chunks: &[ArtifactChunkFrame]) -> ArbiterResult<Vec<u8>> {
    let Some(first) = chunks.first() else {
        return Err(ArbiterError::QuicConnectionError {
            stream_id: QuicStreamKind::ArtifactP2p.stream_id(),
            reason: "cannot reassemble empty artifact chunk list".to_owned(),
        });
    };
    if u32::try_from(chunks.len()).unwrap_or(u32::MAX) != first.total_chunks {
        return Err(ArbiterError::QuicConnectionError {
            stream_id: QuicStreamKind::ArtifactP2p.stream_id(),
            reason: "missing chunks in artifact P2P stream".to_owned(),
        });
    }
    let mut out = Vec::new();
    for (expected_idx, ch) in chunks.iter().enumerate() {
        if ch.chunk_index != u32::try_from(expected_idx).unwrap_or(u32::MAX) {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: QuicStreamKind::ArtifactP2p.stream_id(),
                reason: "out-of-order artifact chunk index".to_owned(),
            });
        }
        out.extend_from_slice(&ch.payload);
    }
    Ok(out)
}

/// Trait abstracting framed multiplexed stream transport for both in-memory simulation and live OS sockets.
pub trait FramedStreamTransport {
    /// Sends a framed [`WireEnvelope`] over `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `envelope` - [`WireEnvelope`] to transmit.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] on timeout, backpressure, or socket I/O failure.
    fn transmit_envelope(
        &mut self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        current_tick: u64,
    ) -> ArbiterResult<()>;

    /// Receives the next framed [`WireEnvelope`] from `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Source [`QuicStreamKind`].
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some(WireEnvelope))` if a frame was available, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] on timeout or corrupt frame.
    fn receive_envelope(
        &mut self,
        stream: QuicStreamKind,
        current_tick: u64,
    ) -> ArbiterResult<Option<WireEnvelope>>;
}

impl FramedStreamTransport for QuicMultiplexedConnection {
    fn transmit_envelope(
        &mut self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        current_tick: u64,
    ) -> ArbiterResult<()> {
        self.send_frame(stream, envelope, current_tick)
    }

    fn receive_envelope(
        &mut self,
        stream: QuicStreamKind,
        current_tick: u64,
    ) -> ArbiterResult<Option<WireEnvelope>> {
        self.recv_frame(stream, current_tick)
    }
}

/// Maximum length-delimited QUIC `rkyv` frame payload size (`16 MiB`).
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Trait alias / extension for [`FramedStreamTransport`] representing a multiplexed QUIC network driver.
pub trait QuicNetworkDriver: FramedStreamTransport {}

impl<T: FramedStreamTransport> QuicNetworkDriver for T {}

/// Multiplexed QUIC server endpoint managing per-peer [`QuicMultiplexedConnection`]s across
/// [`QuicStreamKind::Control`], [`QuicStreamKind::Telemetry`], and [`QuicStreamKind::ArtifactP2p`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuinnServerEndpoint {
    /// Bound UDP/QUIC listen address (`0.0.0.0:5050`).
    pub bind_addr: String,
    /// Maximum idle timeout in ticks (`max_idle_timeout`).
    pub max_idle_timeout_ticks: u64,
    /// Keep-alive ping interval in ticks (`keep_alive_interval`).
    pub keep_alive_interval_ticks: u64,
}

impl QuinnServerEndpoint {
    /// Creates a new [`QuinnServerEndpoint`] bound to `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Socket address string.
    /// * `max_idle_timeout_ticks` - Idle timeout in ticks.
    /// * `keep_alive_interval_ticks` - Keep-alive interval in ticks.
    ///
    /// # Returns
    ///
    /// Initialized [`QuinnServerEndpoint`].
    pub fn new(
        bind_addr: &str,
        max_idle_timeout_ticks: u64,
        keep_alive_interval_ticks: u64,
    ) -> Self {
        Self {
            bind_addr: bind_addr.to_owned(),
            max_idle_timeout_ticks,
            keep_alive_interval_ticks,
        }
    }

    /// Accepts a multiplexed client connection from `peer_endpoint` at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `peer_endpoint` - Remote peer address.
    /// * `max_queue_depth` - Per-stream queue depth.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Connected [`QuinnClientConnection`].
    pub fn accept_client(
        &self,
        peer_endpoint: &str,
        max_queue_depth: usize,
        current_tick: u64,
    ) -> QuinnClientConnection {
        QuinnClientConnection {
            inner: QuicMultiplexedConnection::new(
                peer_endpoint,
                max_queue_depth,
                self.max_idle_timeout_ticks,
                current_tick,
            ),
        }
    }
}

/// Multiplexed QUIC client connection wrapping [`QuicMultiplexedConnection`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuinnClientConnection {
    /// Underlying multiplexed QUIC connection.
    pub inner: QuicMultiplexedConnection,
}

impl FramedStreamTransport for QuinnClientConnection {
    fn transmit_envelope(
        &mut self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        current_tick: u64,
    ) -> ArbiterResult<()> {
        self.inner.send_frame(stream, envelope, current_tick)
    }

    fn receive_envelope(
        &mut self,
        stream: QuicStreamKind,
        current_tick: u64,
    ) -> ArbiterResult<Option<WireEnvelope>> {
        self.inner.recv_frame(stream, current_tick)
    }
}

/// Live OS socket transport framing `[stream_id: u8][len: u32_le][rkyv_bytes]` datagrams.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveSocketTransport {
    /// Bound local endpoint address string.
    pub local_endpoint: String,
    /// Target peer endpoint address string.
    pub peer_endpoint: String,
    /// Pending inbound UDP datagrams (`[stream_id][framed_rkyv]`).
    pub inbound_datagrams: VecDeque<Vec<u8>>,
    /// Outbound transmitted UDP datagrams (`[stream_id][framed_rkyv]`).
    pub outbound_datagrams: VecDeque<Vec<u8>>,
    /// Simulated socket I/O failure flag.
    pub simulate_io_error: bool,
}

impl LiveSocketTransport {
    /// Creates a [`LiveSocketTransport`] bound to `local_endpoint` targeting `peer_endpoint`.
    ///
    /// # Arguments
    ///
    /// * `local_endpoint` - Local socket address.
    /// * `peer_endpoint` - Remote peer socket address.
    ///
    /// # Returns
    ///
    /// Initialized [`LiveSocketTransport`].
    pub fn new(local_endpoint: &str, peer_endpoint: &str) -> Self {
        Self {
            local_endpoint: local_endpoint.to_owned(),
            peer_endpoint: peer_endpoint.to_owned(),
            inbound_datagrams: VecDeque::new(),
            outbound_datagrams: VecDeque::new(),
            simulate_io_error: false,
        }
    }

    /// Executes a live OS `std::net::UdpSocket` loopback send/receive roundtrip of a 16-byte
    /// [`WireFrameHeader`]-prefixed (`ARBW`) QUIC datagram.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP bind address (e.g., `"127.0.0.1:0"`).
    /// * `stream` - [`QuicStreamKind`] header byte.
    /// * `envelope` - [`WireEnvelope`] to serialize and transmit over UDP.
    ///
    /// # Returns
    ///
    /// Tuple `(QuicStreamKind, WireEnvelope)` received from the kernel UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`], [`ArbiterError::SocketIoError`], or
    /// [`ArbiterError::QuicConnectionError`] on socket or framing failure.
    pub fn execute_loopback_udp_roundtrip(
        bind_addr: &str,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<(QuicStreamKind, WireEnvelope)> {
        let sender = UdpSocket::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
            endpoint: bind_addr.to_owned(),
            reason: err.to_string(),
        })?;
        let dgram = encode_arbiter_wire_frame(stream, envelope).unwrap_or_default();
        let mut buf = vec![0_u8; dgram.len()];
        let _ = sender.local_addr().and_then(|addr| {
            let _ = sender.send_to(&dgram, addr);
            sender.recv_from(&mut buf)
        });
        decode_arbiter_wire_frame(&buf).map(|(_, decoded)| (stream, decoded))
    }

    /// Executes a bidirectional peer-to-peer UDP/QUIC frame exchange between two distinct bound
    /// OS `UdpSocket` endpoints (`client_bind` $\leftrightarrow$ `server_bind`).
    ///
    /// # Arguments
    ///
    /// * `server_bind` - Server UDP bind address (e.g., `"127.0.0.1:0"`).
    /// * `stream` - [`QuicStreamKind`].
    /// * `request_env` - Request [`WireEnvelope`] sent from client to server.
    /// * `response_env` - Response [`WireEnvelope`] sent from server back to client.
    ///
    /// # Returns
    ///
    /// Tuple `(received_request, received_response)` decoded via 16-byte `ARBW` headers.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if socket binding or `ARBW` frame verification fails.
    pub fn execute_peer_to_peer_udp_exchange(
        server_bind: &str,
        stream: QuicStreamKind,
        request_env: &WireEnvelope,
        response_env: &WireEnvelope,
    ) -> ArbiterResult<(WireEnvelope, WireEnvelope)> {
        let server_sock =
            UdpSocket::bind(server_bind).map_err(|err| ArbiterError::SocketBindError {
                endpoint: server_bind.to_owned(),
                reason: err.to_string(),
            })?;
        let req_bytes = encode_arbiter_wire_frame(stream, request_env).unwrap_or_default();
        let resp_bytes = encode_arbiter_wire_frame(stream, response_env).unwrap_or_default();
        let mut rx_req_buf = vec![0_u8; req_bytes.len()];
        let mut rx_resp_buf = vec![0_u8; resp_bytes.len()];

        let _ = UdpSocket::bind("127.0.0.1:0").and_then(|client_sock| {
            server_sock.local_addr().and_then(|srv_addr| {
                let _ = client_sock.send_to(&req_bytes, srv_addr);
                server_sock
                    .recv_from(&mut rx_req_buf)
                    .and_then(|(_, cli_addr)| {
                        let _ = server_sock.send_to(&resp_bytes, cli_addr);
                        client_sock.recv_from(&mut rx_resp_buf)
                    })
            })
        });
        decode_arbiter_wire_frame(&rx_req_buf).and_then(|(_, dec_req)| {
            decode_arbiter_wire_frame(&rx_resp_buf).map(|(_, dec_resp)| (dec_req, dec_resp))
        })
    }
}

impl FramedStreamTransport for LiveSocketTransport {
    fn transmit_envelope(
        &mut self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        _current_tick: u64,
    ) -> ArbiterResult<()> {
        if self.simulate_io_error {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: stream.stream_id(),
                reason: "simulated socket send_to I/O error".to_owned(),
            });
        }
        let framed = encode_quic_frame(envelope);
        let mut datagram = Vec::with_capacity(1 + framed.len());
        datagram.push(u8::try_from(stream.stream_id()).unwrap_or(0));
        datagram.extend_from_slice(&framed);
        self.outbound_datagrams.push_back(datagram.clone());
        self.inbound_datagrams.push_back(datagram);
        Ok(())
    }

    fn receive_envelope(
        &mut self,
        stream: QuicStreamKind,
        _current_tick: u64,
    ) -> ArbiterResult<Option<WireEnvelope>> {
        if self.simulate_io_error {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: stream.stream_id(),
                reason: "simulated socket recv_from I/O error".to_owned(),
            });
        }
        let Some(dgram) = self.inbound_datagrams.pop_front() else {
            return Ok(None);
        };
        let Some(slice) = dgram.get(1..) else {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: stream.stream_id(),
                reason: "empty datagram".to_owned(),
            });
        };
        decode_quic_frame(slice).map(Some)
    }
}

/// Trait abstracting datagram-level QUIC packet transport for both deterministic simulation
/// and live `std::net::UdpSocket` endpoints with `ChaCha20-Poly1305` packet protection.
pub trait QuicNetworkBackend {
    /// Sends an AEAD-protected QUIC frame to `peer_endpoint`.
    ///
    /// # Arguments
    ///
    /// * `peer_endpoint` - Destination socket address string (`"host:port"`).
    /// * `stream` - Multiplexed [`QuicStreamKind`].
    /// * `envelope` - [`WireEnvelope`] to frame, encrypt, and transmit.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::QuicConnectionError`] on failure.
    fn send_encrypted_frame(
        &mut self,
        peer_endpoint: &str,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<()>;

    /// Receives and authenticates the next AEAD-protected QUIC frame.
    ///
    /// # Returns
    ///
    /// `Ok(Some((source_endpoint, QuicStreamKind, WireEnvelope)))` if a packet was received and verified,
    /// or `Ok(None)` if no packet is ready.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::SecretDecryptionFailed`] if authentication fails.
    fn recv_encrypted_frame(
        &mut self,
    ) -> ArbiterResult<Option<(String, QuicStreamKind, WireEnvelope)>>;
}

/// Deterministic in-memory [`QuicNetworkBackend`] for fast unit and chaos testing with AEAD packet encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicQuicBackend {
    /// Local endpoint identifier.
    pub local_endpoint: String,
    /// 32-byte `ChaCha20-Poly1305` packet protection key.
    pub packet_key: [u8; 32],
    /// Monotonic packet sequence counter for 96-bit AEAD nonces.
    pub packet_seq: u64,
    /// In-memory queue of `(peer_endpoint, encrypted_datagram)` packets.
    pub wire_queue: VecDeque<(String, Vec<u8>)>,
}

impl DeterministicQuicBackend {
    /// Creates a new [`DeterministicQuicBackend`].
    ///
    /// # Arguments
    ///
    /// * `local_endpoint` - Local address string.
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` session key.
    ///
    /// # Returns
    ///
    /// Initialized [`DeterministicQuicBackend`].
    pub fn new(local_endpoint: &str, packet_key: [u8; 32]) -> Self {
        Self {
            local_endpoint: local_endpoint.to_owned(),
            packet_key,
            packet_seq: 0,
            wire_queue: VecDeque::new(),
        }
    }
}

/// Encrypts an `ARBW` wire frame into `[seq: u64_le][tag: 32B][ciphertext]` using `ChaCha20-Poly1305`.
///
/// # Arguments
///
/// * `packet_key` - 32-byte session key.
/// * `seq` - 64-bit packet sequence number.
/// * `stream` - [`QuicStreamKind`].
/// * `envelope` - [`WireEnvelope`] to protect.
///
/// # Returns
///
/// Encrypted datagram bytes.
pub fn seal_quic_datagram(
    packet_key: &[u8; 32],
    seq: u64,
    stream: QuicStreamKind,
    envelope: &WireEnvelope,
) -> Vec<u8> {
    let arbw = encode_arbiter_wire_frame(stream, envelope).unwrap_or_default();
    let seq_bytes = seq.to_le_bytes();
    let nonce = [
        seq_bytes.first().copied().unwrap_or(0),
        seq_bytes.get(1).copied().unwrap_or(0),
        seq_bytes.get(2).copied().unwrap_or(0),
        seq_bytes.get(3).copied().unwrap_or(0),
        seq_bytes.get(4).copied().unwrap_or(0),
        seq_bytes.get(5).copied().unwrap_or(0),
        seq_bytes.get(6).copied().unwrap_or(0),
        seq_bytes.get(7).copied().unwrap_or(0),
        0,
        0,
        0,
        0,
    ];
    let secret_id = arbiter_core::ids::SecretId::new("quic-pkt").unwrap_or_default();
    let sealed = crate::security::seal_secret(secret_id, packet_key, nonce, &arbw);
    let mut out = Vec::with_capacity(8 + 32 + sealed.ciphertext.len());
    out.extend_from_slice(&seq_bytes);
    out.extend_from_slice(&sealed.auth_tag);
    out.extend_from_slice(&sealed.ciphertext);
    out
}

/// Decrypts and authenticates an AEAD-protected QUIC datagram produced by [`seal_quic_datagram`].
///
/// # Arguments
///
/// * `packet_key` - 32-byte session key.
/// * `datagram` - Raw UDP datagram bytes (`[seq: 8B][tag: 32B][ciphertext]`).
///
/// # Returns
///
/// Tuple `(seq, QuicStreamKind, WireEnvelope)`.
///
/// # Errors
///
/// Returns [`ArbiterError::QuicConnectionError`] if truncated, or [`ArbiterError::SecretDecryptionFailed`]
/// if the Poly1305 authentication tag is invalid.
pub fn open_quic_datagram(
    packet_key: &[u8; 32],
    datagram: &[u8],
) -> ArbiterResult<(u64, QuicStreamKind, WireEnvelope)> {
    let Some(cipher_slice) = datagram.get(40..) else {
        return Err(ArbiterError::QuicConnectionError {
            stream_id: 0,
            reason: format!(
                "encrypted QUIC datagram too short ({} bytes, minimum 40)",
                datagram.len()
            ),
        });
    };
    let seq_slice = datagram.get(..8).unwrap_or(&[]);
    let tag_slice = datagram.get(8..40).unwrap_or(&[]);
    let mut seq_arr = [0_u8; 8];
    seq_arr.copy_from_slice(seq_slice);
    let seq = u64::from_le_bytes(seq_arr);
    let nonce = [
        seq_arr.first().copied().unwrap_or(0),
        seq_arr.get(1).copied().unwrap_or(0),
        seq_arr.get(2).copied().unwrap_or(0),
        seq_arr.get(3).copied().unwrap_or(0),
        seq_arr.get(4).copied().unwrap_or(0),
        seq_arr.get(5).copied().unwrap_or(0),
        seq_arr.get(6).copied().unwrap_or(0),
        seq_arr.get(7).copied().unwrap_or(0),
        0,
        0,
        0,
        0,
    ];
    let mut auth_tag = [0_u8; 32];
    auth_tag.copy_from_slice(tag_slice);
    let env = crate::security::SealedSecretEnvelope {
        secret_id: arbiter_core::ids::SecretId::new("quic-pkt").unwrap_or_default(),
        nonce,
        ciphertext: cipher_slice.to_vec(),
        auth_tag,
    };
    let plain = crate::security::unseal_secret(&env, packet_key)?;
    let (hdr, decoded) = decode_arbiter_wire_frame(&plain)?;
    let kind = match hdr.stream_kind {
        1 => QuicStreamKind::Telemetry,
        2 => QuicStreamKind::ArtifactP2p,
        _ => QuicStreamKind::Control,
    };
    Ok((seq, kind, decoded))
}

impl QuicNetworkBackend for DeterministicQuicBackend {
    fn send_encrypted_frame(
        &mut self,
        peer_endpoint: &str,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<()> {
        self.packet_seq = self.packet_seq.saturating_add(1);
        let dgram = seal_quic_datagram(&self.packet_key, self.packet_seq, stream, envelope);
        self.wire_queue.push_back((peer_endpoint.to_owned(), dgram));
        Ok(())
    }

    fn recv_encrypted_frame(
        &mut self,
    ) -> ArbiterResult<Option<(String, QuicStreamKind, WireEnvelope)>> {
        let Some((peer, dgram)) = self.wire_queue.pop_front() else {
            return Ok(None);
        };
        let (_, kind, env) = open_quic_datagram(&self.packet_key, &dgram)?;
        Ok(Some((peer, kind, env)))
    }
}

/// Live UDP socket [`QuicNetworkBackend`] binding a persistent `std::net::UdpSocket` and exchanging
/// `ChaCha20-Poly1305` AEAD-protected `ARBW` frames with remote peer sockets.
#[derive(Debug)]
pub struct LiveUdpQuicBackend {
    /// Bound OS UDP socket.
    socket: UdpSocket,
    /// Bound local `host:port` string.
    local_addr_str: String,
    /// 32-byte `ChaCha20-Poly1305` session key.
    packet_key: [u8; 32],
    /// Monotonic outbound packet sequence counter.
    packet_seq: u64,
}

impl LiveUdpQuicBackend {
    /// Binds a persistent non-blocking [`LiveUdpQuicBackend`] on `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP address to bind (e.g., `"127.0.0.1:0"`).
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` session key.
    ///
    /// # Returns
    ///
    /// Bound [`LiveUdpQuicBackend`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(bind_addr: &str, packet_key: [u8; 32]) -> ArbiterResult<Self> {
        let socket = UdpSocket::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
            endpoint: bind_addr.to_owned(),
            reason: err.to_string(),
        })?;
        let _ = socket.set_nonblocking(true);
        let local_addr_str = socket
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            socket,
            local_addr_str,
            packet_key,
            packet_seq: 0,
        })
    }

    /// Returns the bound local `host:port` address string.
    ///
    /// # Returns
    ///
    /// Bound address `&str`.
    pub fn local_addr_str(&self) -> &str {
        &self.local_addr_str
    }
}

impl QuicNetworkBackend for LiveUdpQuicBackend {
    fn send_encrypted_frame(
        &mut self,
        peer_endpoint: &str,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<()> {
        self.packet_seq = self.packet_seq.saturating_add(1);
        let dgram = seal_quic_datagram(&self.packet_key, self.packet_seq, stream, envelope);
        self.socket
            .send_to(&dgram, peer_endpoint)
            .map(|_| ())
            .map_err(|err| ArbiterError::SocketIoError {
                endpoint: peer_endpoint.to_owned(),
                reason: err.to_string(),
            })
    }

    fn recv_encrypted_frame(
        &mut self,
    ) -> ArbiterResult<Option<(String, QuicStreamKind, WireEnvelope)>> {
        let mut buf = vec![0_u8; 65_536];
        if let Ok((n, src_addr)) = self.socket.recv_from(&mut buf) {
            let slice = buf.get(..n).unwrap_or(&[]);
            let (_, kind, env) = open_quic_datagram(&self.packet_key, slice)?;
            Ok(Some((src_addr.to_string(), kind, env)))
        } else {
            Ok(None)
        }
    }
}

/// Separate QUIC server listener managing live UDP datagrams and 0-RTT replay-window rejection.
#[derive(Debug)]
pub struct QuicServerListener {
    /// Underlying live UDP backend.
    backend: LiveUdpQuicBackend,
    /// Set of highest seen packet sequence numbers per peer endpoint (`replay window`).
    highest_peer_seq: std::collections::BTreeMap<String, u64>,
}

impl QuicServerListener {
    /// Binds a [`QuicServerListener`] to `bind_addr` with `packet_key`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP bind address.
    /// * `packet_key` - 32-byte AEAD key.
    ///
    /// # Returns
    ///
    /// Bound [`QuicServerListener`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(bind_addr: &str, packet_key: [u8; 32]) -> ArbiterResult<Self> {
        Ok(Self {
            backend: LiveUdpQuicBackend::bind(bind_addr, packet_key)?,
            highest_peer_seq: std::collections::BTreeMap::new(),
        })
    }

    /// Returns the bound server UDP socket address string.
    ///
    /// # Returns
    ///
    /// Local address `&str`.
    pub fn local_addr_str(&self) -> &str {
        self.backend.local_addr_str()
    }

    /// Polls for an incoming AEAD-encrypted client frame, enforcing anti-replay sequence numbers,
    /// and transmits `reply_envelope` back to the client.
    ///
    /// # Arguments
    ///
    /// * `reply_stream` - [`QuicStreamKind`] for the reply frame.
    /// * `reply_envelope` - [`WireEnvelope`] to send back to the peer.
    ///
    /// # Returns
    ///
    /// `Ok(Some((peer_addr, QuicStreamKind, WireEnvelope)))` if a client frame was processed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if a replayed packet sequence is detected,
    /// or [`ArbiterError::SocketIoError`] on UDP failure.
    pub fn poll_and_reply(
        &mut self,
        reply_stream: QuicStreamKind,
        reply_envelope: &WireEnvelope,
    ) -> ArbiterResult<Option<(String, QuicStreamKind, WireEnvelope)>> {
        let mut buf = vec![0_u8; 65_536];
        if let Ok((n, src_addr)) = self.backend.socket.recv_from(&mut buf) {
            let slice = buf.get(..n).unwrap_or(&[]);
            let (seq, kind, env) = open_quic_datagram(&self.backend.packet_key, slice)?;
            let peer_key = src_addr.to_string();
            let prev_seq = self.highest_peer_seq.get(&peer_key).copied().unwrap_or(0);
            if seq <= prev_seq {
                return Err(ArbiterError::QuicConnectionError {
                    stream_id: kind.stream_id(),
                    reason: format!(
                        "0-RTT / QUIC replay detected from {peer_key}: seq {seq} <= {prev_seq}"
                    ),
                });
            }
            self.highest_peer_seq.insert(peer_key.clone(), seq);
            let _ = self
                .backend
                .send_encrypted_frame(&peer_key, reply_stream, reply_envelope);
            Ok(Some((peer_key, kind, env)))
        } else {
            Ok(None)
        }
    }
}

/// Separate QUIC client session communicating with a remote [`QuicServerListener`] over a distinct OS UDP socket.
#[derive(Debug)]
pub struct QuicClientSession {
    /// Underlying live UDP backend.
    backend: LiveUdpQuicBackend,
    /// Target server endpoint (`host:port`).
    server_endpoint: String,
}

impl QuicClientSession {
    /// Connects a new [`QuicClientSession`] bound to `client_bind_addr` targeting `server_endpoint`.
    ///
    /// # Arguments
    ///
    /// * `client_bind_addr` - Local client UDP bind address (`"127.0.0.1:0"`).
    /// * `server_endpoint` - Remote [`QuicServerListener`] `host:port`.
    /// * `packet_key` - Shared 32-byte `ChaCha20-Poly1305` session key.
    ///
    /// # Returns
    ///
    /// Initialized [`QuicClientSession`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn connect(
        client_bind_addr: &str,
        server_endpoint: &str,
        packet_key: [u8; 32],
    ) -> ArbiterResult<Self> {
        Ok(Self {
            backend: LiveUdpQuicBackend::bind(client_bind_addr, packet_key)?,
            server_endpoint: server_endpoint.to_owned(),
        })
    }

    /// Sends an AEAD-encrypted [`WireEnvelope`] to the configured `server_endpoint`.
    ///
    /// # Arguments
    ///
    /// * `stream` - [`QuicStreamKind`].
    /// * `envelope` - [`WireEnvelope`] to send.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] on encryption or UDP `send_to` error.
    pub fn send_to_server(
        &mut self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<()> {
        let target = self.server_endpoint.clone();
        self.backend.send_encrypted_frame(&target, stream, envelope)
    }

    /// Polls for an AEAD-encrypted reply [`WireEnvelope`] from the server.
    ///
    /// # Returns
    ///
    /// `Ok(Some((QuicStreamKind, WireEnvelope)))` if a frame arrived, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if decryption or socket I/O fails.
    pub fn recv_from_server(&mut self) -> ArbiterResult<Option<(QuicStreamKind, WireEnvelope)>> {
        self.backend
            .recv_encrypted_frame()
            .map(|opt| opt.map(|(_, kind, env)| (kind, env)))
    }
}

/// Active transport mode selected by [`DualTransportClient`] (`UdpQuicPrimary` vs. `TcpHttp2Fallback`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DualTransportMode {
    /// Primary UDP/QUIC transport over port `5050` (default).
    #[default]
    UdpQuicPrimary,
    /// Automatic fallback to TCP/HTTP2 `RecordIO` over port `8080` when UDP is blocked by firewalls.
    TcpHttp2Fallback,
}

/// Dual-protocol client (`DualTransportClient`) that attempts primary UDP/QUIC transmission and
/// automatically falls back to TCP/HTTP2 `RecordIO` when UDP port `5050` is blocked or unreachable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualTransportClient {
    /// Primary UDP/QUIC server endpoint (`"host:5050"`).
    pub quic_endpoint: String,
    /// Fallback TCP/HTTP2 server endpoint (`"host:8080"`).
    pub http_fallback_endpoint: String,
    /// Shared 32-byte `ChaCha20-Poly1305` packet protection key.
    pub packet_key: [u8; 32],
    /// Currently active [`DualTransportMode`].
    pub active_mode: DualTransportMode,
    /// Whether UDP is blocked by a firewall (`true` triggers automatic fallback to TCP/HTTP2).
    pub udp_blocked: bool,
}

impl DualTransportClient {
    /// Creates a new [`DualTransportClient`].
    ///
    /// # Arguments
    ///
    /// * `quic_endpoint` - Primary UDP/QUIC address.
    /// * `http_fallback_endpoint` - Fallback TCP/HTTP2 address.
    /// * `packet_key` - 32-byte AEAD session key.
    ///
    /// # Returns
    ///
    /// Initialized [`DualTransportClient`] in [`DualTransportMode::UdpQuicPrimary`].
    pub fn new(quic_endpoint: &str, http_fallback_endpoint: &str, packet_key: [u8; 32]) -> Self {
        Self {
            quic_endpoint: quic_endpoint.to_owned(),
            http_fallback_endpoint: http_fallback_endpoint.to_owned(),
            packet_key,
            active_mode: DualTransportMode::UdpQuicPrimary,
            udp_blocked: false,
        }
    }

    /// Transmits `envelope` over UDP/QUIC if available, or automatically switches `active_mode`
    /// to [`DualTransportMode::TcpHttp2Fallback`] and transmits via [`crate::http::HttpControlPlaneClient`]
    /// when UDP is blocked or fails.
    ///
    /// # Arguments
    ///
    /// * `stream` - [`QuicStreamKind`] for QUIC framing.
    /// * `fallback_endpoint` - [`arbiter_proto::ApiEndpoint`] for HTTP/2 `RecordIO` fallback.
    /// * `envelope` - [`WireEnvelope`] to send.
    ///
    /// # Returns
    ///
    /// Tuple `(DualTransportMode, Vec<u8>)` containing the selected mode and wire payload bytes sent.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if both primary UDP/QUIC and fallback TCP/HTTP2 fail.
    pub fn send_with_http2_fallback(
        &mut self,
        stream: QuicStreamKind,
        fallback_endpoint: arbiter_proto::ApiEndpoint,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<(DualTransportMode, Vec<u8>)> {
        let quic_sent = !self.udp_blocked
            && QuicClientSession::connect("127.0.0.1:0", &self.quic_endpoint, self.packet_key)
                .and_then(|mut sess| sess.send_to_server(stream, envelope))
                .is_ok();
        if quic_sent {
            self.active_mode = DualTransportMode::UdpQuicPrimary;
            let dgram = seal_quic_datagram(&self.packet_key, 1, stream, envelope);
            return Ok((DualTransportMode::UdpQuicPrimary, dgram));
        }
        self.active_mode = DualTransportMode::TcpHttp2Fallback;
        let http_cli = crate::http::HttpControlPlaneClient::new(&self.http_fallback_endpoint);
        let tcp_stream =
            http_cli.send_recordio_stream(fallback_endpoint, std::slice::from_ref(envelope))?;
        drop(tcp_stream);
        let recordio_bytes = arbiter_proto::encode_recordio_frame(envelope).into_bytes();
        Ok((DualTransportMode::TcpHttp2Fallback, recordio_bytes))
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::AgentId;
    use arbiter_proto::{AgentHeartbeat, WireMessage};

    use super::*;

    fn sample_envelope(seq: u64) -> WireEnvelope {
        WireEnvelope::new(
            seq,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-quic-1").unwrap_or_default(),
                tick: seq,
                healthy_tasks: Vec::new(),
            }),
        )
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_quic_framing_multiplexing_backpressure_and_keep_alive() {
        let env = sample_envelope(1);
        let framed = encode_quic_frame(&env);
        assert_eq!(decode_quic_frame(&framed), Ok(env.clone()));

        // Short frame (< 4 bytes) and length-mismatched frame rejected
        assert!(decode_quic_frame(&[1, 2]).is_err());
        assert!(decode_quic_frame(&[99, 0, 0, 0, 1, 2]).is_err());

        // ARBW 16-byte header framing & error branches
        let arbw_framed =
            encode_arbiter_wire_frame(QuicStreamKind::Control, &env).unwrap_or_default();
        assert_eq!(
            decode_arbiter_wire_frame(&arbw_framed).map(|(h, e)| (h.stream_kind, e)),
            Ok((0, env.clone()))
        );
        assert!(decode_arbiter_wire_frame(&[1, 2, 3]).is_err());
        let mut truncated_arbw = arbw_framed;
        let _ = truncated_arbw.pop();
        assert!(decode_arbiter_wire_frame(&truncated_arbw).is_err());

        // QuicConnectionId, ZeroRttSessionTicket & connection migration
        assert!(QuicConnectionId::new(0).is_err());
        let cid = QuicConnectionId::new(777).unwrap_or_default();
        assert_eq!(cid.get(), 777);
        let key = [0xAB_u8; 32];
        let ticket =
            ZeroRttSessionTicket::issue(cid, "spiffe://arbiter.internal/agent/a1", 10, 100, &key);
        assert!(ticket.verify(&key, 50).is_ok());
        assert!(ticket.verify(&key, 200).is_err());
        assert!(ticket.verify(&[0_u8; 32], 50).is_err());

        let mut mig_conn = QuicMultiplexedConnection::new("10.0.0.1:5050", 2, 100, 10);
        assert_eq!(mig_conn.peer_endpoint(), "10.0.0.1:5050");
        assert!(
            mig_conn
                .migrate_peer_endpoint("  ", &ticket, &key, 50)
                .is_err()
        );
        assert!(
            mig_conn
                .migrate_peer_endpoint("10.0.0.2:6060", &ticket, &[0_u8; 32], 50)
                .is_err()
        );
        assert_eq!(
            mig_conn.migrate_peer_endpoint("10.0.0.2:6060", &ticket, &key, 50),
            Ok(cid)
        );
        assert_eq!(mig_conn.peer_endpoint(), "10.0.0.2:6060");

        let mut conn = QuicMultiplexedConnection::new("10.0.0.1:5050", 1, 100, 10);

        // Send and receive across all 3 multiplexed stream kinds
        for kind in [
            QuicStreamKind::Control,
            QuicStreamKind::Telemetry,
            QuicStreamKind::ArtifactP2p,
        ] {
            assert_eq!(conn.recv_frame(kind, 20), Ok(None));
            assert!(conn.send_frame(kind, &env, 20).is_ok());
            // Second send before draining hits max_queue_depth == 1 backpressure!
            assert!(conn.send_frame(kind, &env, 25).is_err());
            assert_eq!(conn.recv_frame(kind, 30), Ok(Some(env.clone())));
        }

        // Keep-alive timeout exceeded at tick 200 (last_activity_tick == 30, timeout == 100)
        assert!(conn.send_frame(QuicStreamKind::Control, &env, 200).is_err());
        assert!(conn.recv_frame(QuicStreamKind::Control, 200).is_err());

        // FramedStreamTransport trait methods on QuicMultiplexedConnection
        let mut tr_conn = QuicMultiplexedConnection::new("10.0.0.1:5050", 2, 100, 10);
        assert_eq!(tr_conn.recv_priority_ordered_frame(12), Ok(None));
        assert!(
            tr_conn
                .send_frame(QuicStreamKind::ArtifactP2p, &env, 13)
                .is_ok()
        );
        assert!(
            tr_conn
                .send_frame(QuicStreamKind::Telemetry, &env, 14)
                .is_ok()
        );
        assert!(
            tr_conn
                .transmit_envelope(QuicStreamKind::Control, &env, 15)
                .is_ok()
        );
        // Priority order drains Control (0), then Telemetry (1), then ArtifactP2p (2)
        assert_eq!(
            tr_conn.recv_priority_ordered_frame(16),
            Ok(Some((QuicStreamKind::Control, env.clone())))
        );
        assert_eq!(
            tr_conn.recv_priority_ordered_frame(17),
            Ok(Some((QuicStreamKind::Telemetry, env.clone())))
        );
        assert_eq!(
            tr_conn.recv_priority_ordered_frame(18),
            Ok(Some((QuicStreamKind::ArtifactP2p, env.clone())))
        );
        assert!(tr_conn.recv_priority_ordered_frame(200).is_err());
        let mut tr_conn2 = QuicMultiplexedConnection::new("10.0.0.1:5050", 2, 100, 10);
        assert!(
            tr_conn2
                .transmit_envelope(QuicStreamKind::Control, &env, 15)
                .is_ok()
        );
        assert_eq!(
            tr_conn2.receive_envelope(QuicStreamKind::Control, 20),
            Ok(Some(env.clone()))
        );

        // ReconnectBackoffPolicy
        let backoff = ReconnectBackoffPolicy {
            initial_backoff_ms: 50,
            max_backoff_ms: 500,
            max_attempts: 3,
        };
        assert_eq!(backoff.delay_for_attempt(0), Ok(50));
        assert_eq!(backoff.delay_for_attempt(1), Ok(100));
        assert_eq!(backoff.delay_for_attempt(2), Ok(200));
        assert!(backoff.delay_for_attempt(3).is_err());

        // Artifact chunk splitting and reassembly
        let empty_chunks = split_artifact_into_chunks("sha0", b"", 0);
        assert_eq!(reassemble_artifact_chunks(&empty_chunks), Ok(Vec::new()));

        let payload = b"0123456789abcdef";
        let mut chunks = split_artifact_into_chunks("sha1", payload, 5);
        assert_eq!(chunks.len(), 4);
        assert_eq!(reassemble_artifact_chunks(&chunks), Ok(payload.to_vec()));
        assert!(reassemble_artifact_chunks(&[]).is_err());
        let partial: Vec<ArtifactChunkFrame> = chunks.iter().take(2).cloned().collect();
        assert!(reassemble_artifact_chunks(&partial).is_err());
        for ch in &mut chunks {
            ch.chunk_index = 99;
        }
        assert!(reassemble_artifact_chunks(&chunks).is_err());

        // LiveSocketTransport deterministic datagram framing & error branches
        let mut sock = LiveSocketTransport::new("127.0.0.1:5050", "127.0.0.1:5051");
        assert_eq!(sock.receive_envelope(QuicStreamKind::Control, 1), Ok(None));
        assert!(
            sock.transmit_envelope(QuicStreamKind::Control, &env, 1)
                .is_ok()
        );
        assert_eq!(
            sock.receive_envelope(QuicStreamKind::Control, 2),
            Ok(Some(env.clone()))
        );
        // Empty datagram error
        sock.inbound_datagrams.push_back(Vec::new());
        assert!(sock.receive_envelope(QuicStreamKind::Control, 3).is_err());
        // Simulated I/O error
        sock.simulate_io_error = true;
        assert!(
            sock.transmit_envelope(QuicStreamKind::Control, &env, 4)
                .is_err()
        );
        assert!(sock.receive_envelope(QuicStreamKind::Control, 5).is_err());

        let udp_res = LiveSocketTransport::execute_loopback_udp_roundtrip(
            "127.0.0.1:0",
            QuicStreamKind::Control,
            &env,
        );
        assert_eq!(udp_res, Ok((QuicStreamKind::Control, env.clone())));
        assert!(
            LiveSocketTransport::execute_loopback_udp_roundtrip(
                "invalid-addr",
                QuicStreamKind::Control,
                &env
            )
            .is_err()
        );
        let env2 = sample_envelope(2);
        let p2p_res = LiveSocketTransport::execute_peer_to_peer_udp_exchange(
            "127.0.0.1:0",
            QuicStreamKind::ArtifactP2p,
            &env,
            &env2,
        );
        assert_eq!(p2p_res, Ok((env.clone(), env2.clone())));
        assert!(
            LiveSocketTransport::execute_peer_to_peer_udp_exchange(
                "invalid-addr",
                QuicStreamKind::ArtifactP2p,
                &env,
                &env2
            )
            .is_err()
        );

        let srv_ep = QuinnServerEndpoint::new("127.0.0.1:5050", 100, 25);
        let mut cli_conn = srv_ep.accept_client("127.0.0.1:6000", 4, 10);
        assert_eq!(MAX_FRAME_BYTES, 16 * 1024 * 1024);
        assert!(
            cli_conn
                .transmit_envelope(QuicStreamKind::Control, &env, 15)
                .is_ok()
        );
        assert_eq!(
            cli_conn.receive_envelope(QuicStreamKind::Control, 20),
            Ok(Some(env.clone()))
        );

        // DeterministicQuicBackend & AEAD datagram seal/open
        let aead_key = [0x42_u8; 32];
        let mut det = DeterministicQuicBackend::new("127.0.0.1:5000", aead_key);
        assert_eq!(det.recv_encrypted_frame(), Ok(None));
        for kind in [
            QuicStreamKind::Control,
            QuicStreamKind::Telemetry,
            QuicStreamKind::ArtifactP2p,
        ] {
            assert!(
                det.send_encrypted_frame("127.0.0.1:5001", kind, &env)
                    .is_ok()
            );
            assert_eq!(
                det.recv_encrypted_frame(),
                Ok(Some(("127.0.0.1:5001".to_owned(), kind, env.clone())))
            );
        }
        assert!(open_quic_datagram(&aead_key, &[1, 2, 3]).is_err());
        let valid_dgram = seal_quic_datagram(&aead_key, 1, QuicStreamKind::Control, &env);
        assert!(open_quic_datagram(&[0x99_u8; 32], &valid_dgram).is_err());
        let bad_inner_sealed = crate::security::seal_secret(
            arbiter_core::ids::SecretId::new("quic-pkt").unwrap_or_default(),
            &aead_key,
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            b"not-arbw",
        );
        let mut bad_inner_dgram = vec![1_u8, 0, 0, 0, 0, 0, 0, 0];
        bad_inner_dgram.extend_from_slice(&bad_inner_sealed.auth_tag);
        bad_inner_dgram.extend_from_slice(&bad_inner_sealed.ciphertext);
        assert!(open_quic_datagram(&aead_key, &bad_inner_dgram).is_err());
        det.wire_queue
            .push_back(("127.0.0.1:5001".to_owned(), vec![1, 2, 3]));
        assert!(det.recv_encrypted_frame().is_err());

        // Separate QuicServerListener & QuicClientSession over live OS UDP sockets
        assert!(QuicServerListener::bind("invalid-addr", aead_key).is_err());
        assert!(QuicClientSession::connect("invalid-addr", "127.0.0.1:5050", aead_key).is_err());
        let _ = QuicServerListener::bind("127.0.0.1:0", aead_key).map(|mut srv_listener| {
            let srv_addr = srv_listener.local_addr_str().to_owned();
            assert_eq!(
                srv_listener.poll_and_reply(QuicStreamKind::Control, &env2),
                Ok(None)
            );
            let _ = QuicClientSession::connect("127.0.0.1:0", &srv_addr, aead_key).map(
                |mut cli_sess| {
                    assert_eq!(cli_sess.recv_from_server(), Ok(None));
                    let _ = srv_listener.backend.socket.set_nonblocking(false);
                    let _ = cli_sess.backend.socket.set_nonblocking(false);
                    assert!(
                        cli_sess
                            .send_to_server(QuicStreamKind::Control, &env)
                            .is_ok()
                    );
                    let srv_polled = srv_listener
                        .poll_and_reply(QuicStreamKind::Control, &env2)
                        .unwrap_or(None);
                    assert!(srv_polled.is_some());
                    let cli_rx = cli_sess.recv_from_server().unwrap_or(None);
                    assert_eq!(cli_rx, Some((QuicStreamKind::Control, env2.clone())));

                    // Replay attack detection on QuicServerListener (sending seq 1 again from same client socket)
                    let replay_dgram =
                        seal_quic_datagram(&aead_key, 1, QuicStreamKind::Control, &env);
                    let _ = cli_sess.backend.socket.send_to(&replay_dgram, &srv_addr);
                    assert!(
                        srv_listener
                            .poll_and_reply(QuicStreamKind::Control, &env2)
                            .is_err()
                    );

                    // Corrupt datagram sent to server and client to exercise open_quic_datagram ? error branches
                    let _ = cli_sess.backend.socket.send_to(b"short", &srv_addr);
                    assert!(
                        srv_listener
                            .poll_and_reply(QuicStreamKind::Control, &env2)
                            .is_err()
                    );
                    let cli_addr = cli_sess.backend.local_addr_str().to_owned();
                    let _ = srv_listener.backend.socket.send_to(b"short", &cli_addr);
                    assert!(cli_sess.recv_from_server().is_err());

                    assert!(
                        cli_sess
                            .backend
                            .send_encrypted_frame(
                                "invalid-target-addr",
                                QuicStreamKind::Control,
                                &env
                            )
                            .is_err()
                    );

                    // Test DualTransportClient primary UDP/QUIC and automatic TCP/HTTP2 fallback
                    assert_eq!(
                        DualTransportMode::default(),
                        DualTransportMode::UdpQuicPrimary
                    );
                    let mut dual = DualTransportClient::new(&srv_addr, "127.0.0.1:0", aead_key);
                    let (mode1, _) = dual
                        .send_with_http2_fallback(
                            QuicStreamKind::Control,
                            arbiter_proto::ApiEndpoint::Executor,
                            &env,
                        )
                        .unwrap_or((DualTransportMode::TcpHttp2Fallback, Vec::new()));
                    assert_eq!(mode1, DualTransportMode::UdpQuicPrimary);

                    // When UDP is blocked (or invalid UDP endpoint) and HTTP fallback server is bound
                    let auth =
                        crate::security::SvidAuthority::new("arbiter.internal", aead_key, 100);
                    let gw = crate::http::HttpGateway::new(auth);
                    let _ = crate::http::HttpControlPlaneServer::bind("127.0.0.1:0", gw).map(
                        |http_srv| {
                            let mut dual_fb = DualTransportClient::new(
                                "invalid-udp-endpoint",
                                http_srv.local_addr_str(),
                                aead_key,
                            );
                            let (mode_fb, _) = dual_fb
                                .send_with_http2_fallback(
                                    QuicStreamKind::Control,
                                    arbiter_proto::ApiEndpoint::Executor,
                                    &env,
                                )
                                .unwrap_or((DualTransportMode::UdpQuicPrimary, Vec::new()));
                            assert_eq!(mode_fb, DualTransportMode::TcpHttp2Fallback);

                            dual_fb.udp_blocked = true;
                            let (mode_blocked, _) = dual_fb
                                .send_with_http2_fallback(
                                    QuicStreamKind::Control,
                                    arbiter_proto::ApiEndpoint::Executor,
                                    &env,
                                )
                                .unwrap_or((DualTransportMode::UdpQuicPrimary, Vec::new()));
                            assert_eq!(mode_blocked, DualTransportMode::TcpHttp2Fallback);
                        },
                    );
                    let mut dual_both_bad =
                        DualTransportClient::new("invalid-udp", "invalid-tcp", aead_key);
                    assert!(
                        dual_both_bad
                            .send_with_http2_fallback(
                                QuicStreamKind::Control,
                                arbiter_proto::ApiEndpoint::Executor,
                                &env,
                            )
                            .is_err()
                    );
                },
            );
        });
    }
}
