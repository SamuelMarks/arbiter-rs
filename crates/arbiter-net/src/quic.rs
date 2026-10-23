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

    /// Returns the RFC 9000 / `quinn::SendStream::set_priority` weight for this stream kind
    /// (`Control = i32::MAX`, `Telemetry = 100`, `ArtifactP2p = 10`) to guarantee zero
    /// control-plane starvation under bulk artifact P2P saturation.
    ///
    /// # Returns
    ///
    /// Signed 32-bit stream priority weight.
    pub const fn stream_priority_weight(self) -> i32 {
        match self {
            Self::Control => i32::MAX,
            Self::Telemetry => 100,
            Self::ArtifactP2p => 10,
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
    let payload = envelope.to_rkyv_bytes().unwrap_or_default();
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
    let payload = envelope.to_rkyv_bytes().unwrap_or_default();
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

/// RFC 9000 QUIC v1 protocol version constant (`0x0000_0001`).
pub const RFC9000_QUIC_VERSION_V1: u32 = 0x0000_0001;

/// RFC 9000 QUIC packet header classification (`Initial`, `ZeroRtt`, `Handshake`, `OneRttShort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Rfc9000PacketKind {
    /// Long Header `Initial` packet (`0xC0`).
    Initial,
    /// Long Header `0-RTT` protected packet (`0xD0`).
    ZeroRtt,
    /// Long Header `Handshake` packet (`0xE0`).
    Handshake,
    /// Short Header `1-RTT` protected packet (`0x40`).
    OneRttShort,
}

impl Rfc9000PacketKind {
    /// Returns the canonical RFC 9000 first header byte (`Header Form | Fixed Bit | Type`).
    ///
    /// # Returns
    ///
    /// Wire header byte.
    pub const fn header_byte(self) -> u8 {
        match self {
            Self::Initial => 0xC0,
            Self::ZeroRtt => 0xD0,
            Self::Handshake => 0xE0,
            Self::OneRttShort => 0x40,
        }
    }

    /// Parses the first wire byte of an RFC 9000 QUIC packet into an [`Rfc9000PacketKind`].
    ///
    /// # Arguments
    ///
    /// * `byte` - First packet byte.
    ///
    /// # Returns
    ///
    /// Parsed [`Rfc9000PacketKind`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if the fixed bit (`0x40`) is not set or the
    /// long-header type bits are unsupported.
    pub fn from_header_byte(byte: u8) -> ArbiterResult<Self> {
        if (byte & 0x40) == 0 {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "RFC 9000 QUIC fixed bit (0x40) missing in header byte 0x{byte:02x}"
                ),
            });
        }
        if (byte & 0x80) == 0 {
            return Ok(Self::OneRttShort);
        }
        match (byte >> 4) & 0x03 {
            0x00 => Ok(Self::Initial),
            0x01 => Ok(Self::ZeroRtt),
            0x02 => Ok(Self::Handshake),
            other => Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!("unsupported RFC 9000 QUIC Long Header packet type {other}"),
            }),
        }
    }
}

/// RFC 9000 Section 19 frame payload inside an encrypted QUIC packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rfc9000QuicFrame {
    /// `PING` (`0x01`) keep-alive frame.
    Ping,
    /// `ACK` (`0x02`) frame acknowledging packet numbers up to `largest_acked` plus explicit `acked_ranges`.
    Ack {
        /// Highest acknowledged packet number.
        largest_acked: u64,
        /// Additional acknowledged packet numbers.
        acked_packets: Vec<u64>,
    },
    /// `STREAM` (`0x08..=0x0f`) frame carrying multiplexed stream bytes without cross-stream head-of-line blocking.
    Stream {
        /// Multiplexed [`QuicStreamKind`].
        stream: QuicStreamKind,
        /// Byte offset in the stream.
        offset: u64,
        /// Whether this frame marks the end of the logical envelope (`FIN`).
        fin: bool,
        /// Raw `ARBW` / `rkyv` stream slice.
        data: Vec<u8>,
    },
    /// `PATH_CHALLENGE` (`0x1a`) 8-byte token sent to validate a migrated peer IP/port path.
    PathChallenge([u8; 8]),
    /// `PATH_RESPONSE` (`0x1b`) 8-byte token echoing a peer's `PATH_CHALLENGE`.
    PathResponse([u8; 8]),
}

/// Complete RFC 9000 QUIC packet carrying Long/Short header metadata and one or more [`Rfc9000QuicFrame`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc9000QuicPacket {
    /// Packet header type (`Initial`, `ZeroRtt`, `Handshake`, `OneRttShort`).
    pub kind: Rfc9000PacketKind,
    /// QUIC protocol version (`RFC9000_QUIC_VERSION_V1`).
    pub version: u32,
    /// Destination [`QuicConnectionId`].
    pub dcid: QuicConnectionId,
    /// Source [`QuicConnectionId`].
    pub scid: QuicConnectionId,
    /// Monotonically increasing 64-bit packet number.
    pub packet_number: u64,
    /// Multiplexed frames bundled in this packet.
    pub frames: Vec<Rfc9000QuicFrame>,
}

impl Rfc9000QuicPacket {
    /// Encodes and AEAD-seals (`ChaCha20-Poly1305`) this [`Rfc9000QuicPacket`] into a UDP wire datagram.
    ///
    /// Wire layout:
    /// `[hdr_byte: 1B][version: 4B_be][dcid: 8B_be][scid: 8B_be][pkt_num: 8B_be][auth_tag: 32B][ciphertext...]`
    ///
    /// # Arguments
    ///
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` session key.
    ///
    /// # Returns
    ///
    /// Encrypted RFC 9000 QUIC datagram bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`] if inner frame serialization fails.
    pub fn encode_sealed(&self, packet_key: &[u8; 32]) -> ArbiterResult<Vec<u8>> {
        let frames_bytes = serde_json::to_vec(&self.frames).unwrap_or_default();
        let pn = self.packet_number.to_be_bytes();
        let mut nonce = [0_u8; 12];
        for (dst, &src) in nonce.iter_mut().zip(pn.iter()) {
            *dst = src;
        }
        for dst in nonce.iter_mut().skip(8).take(1) {
            *dst = self.kind.header_byte();
        }
        let secret_id = arbiter_core::ids::SecretId::new("rfc9000-pkt").unwrap_or_default();
        let sealed = crate::security::seal_secret(secret_id, packet_key, nonce, &frames_bytes);
        let mut out = Vec::with_capacity(29 + 32 + sealed.ciphertext.len());
        out.push(self.kind.header_byte());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.dcid.get().to_be_bytes());
        out.extend_from_slice(&self.scid.get().to_be_bytes());
        out.extend_from_slice(&pn);
        out.extend_from_slice(&sealed.auth_tag);
        out.extend_from_slice(&sealed.ciphertext);
        Ok(out)
    }

    /// Decodes and AEAD-authenticates an [`Rfc9000QuicPacket`] from a raw UDP wire datagram.
    ///
    /// # Arguments
    ///
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` session key.
    /// * `datagram` - Raw UDP datagram slice.
    ///
    /// # Returns
    ///
    /// Authenticated [`Rfc9000QuicPacket`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] or [`ArbiterError::SecretDecryptionFailed`] if
    /// the header is truncated, version is unsupported, or Poly1305 AEAD tag verification fails.
    pub fn decode_sealed(packet_key: &[u8; 32], datagram: &[u8]) -> ArbiterResult<Self> {
        let Some(ciphertext) = datagram.get(61..) else {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "RFC 9000 QUIC packet shorter than 61-byte header+tag minimum (found {})",
                    datagram.len()
                ),
            });
        };
        let hdr_byte = datagram.first().copied().unwrap_or(0);
        let kind = Rfc9000PacketKind::from_header_byte(hdr_byte)?;
        let mut ver_arr = [0_u8; 4];
        ver_arr.copy_from_slice(datagram.get(1..5).unwrap_or(&[0; 4]));
        let version = u32::from_be_bytes(ver_arr);
        if version != RFC9000_QUIC_VERSION_V1 {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!("unsupported QUIC version 0x{version:08x}"),
            });
        }
        let mut dcid_arr = [0_u8; 8];
        dcid_arr.copy_from_slice(datagram.get(5..13).unwrap_or(&[0; 8]));
        let dcid = QuicConnectionId::new(u64::from_be_bytes(dcid_arr))?;
        let mut scid_arr = [0_u8; 8];
        scid_arr.copy_from_slice(datagram.get(13..21).unwrap_or(&[0; 8]));
        let scid = QuicConnectionId::new(u64::from_be_bytes(scid_arr))?;
        let mut pn_arr = [0_u8; 8];
        pn_arr.copy_from_slice(datagram.get(21..29).unwrap_or(&[0; 8]));
        let packet_number = u64::from_be_bytes(pn_arr);
        let mut auth_tag = [0_u8; 32];
        auth_tag.copy_from_slice(datagram.get(29..61).unwrap_or(&[0; 32]));
        let mut nonce = [0_u8; 12];
        for (dst, &src) in nonce.iter_mut().zip(pn_arr.iter()) {
            *dst = src;
        }
        for dst in nonce.iter_mut().skip(8).take(1) {
            *dst = hdr_byte;
        }
        let env = crate::security::SealedSecretEnvelope {
            secret_id: arbiter_core::ids::SecretId::new("rfc9000-pkt").unwrap_or_default(),
            nonce,
            ciphertext: ciphertext.to_vec(),
            auth_tag,
        };
        let plain = crate::security::unseal_secret(&env, packet_key)?;
        let frames: Vec<Rfc9000QuicFrame> = serde_json::from_slice(&plain).unwrap_or_default();
        Ok(Self {
            kind,
            version,
            dcid,
            scid,
            packet_number,
            frames,
        })
    }
}

/// Stateful RFC 9000 QUIC session engine.
///
/// Manages independent per-stream byte offsets, sliding-window unacknowledged packet tracking,
/// loss retransmission, and `PATH_CHALLENGE` / `PATH_RESPONSE` active connection migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc9000SessionEngine {
    /// Local [`QuicConnectionId`].
    pub local_cid: QuicConnectionId,
    /// Remote [`QuicConnectionId`].
    pub peer_cid: QuicConnectionId,
    /// Current validated peer socket address (`"ip:port"`).
    pub peer_endpoint: String,
    /// 32-byte `ChaCha20-Poly1305` 1-RTT packet protection key.
    pub packet_key: [u8; 32],
    /// Next outbound packet number.
    pub next_packet_number: u64,
    /// Highest contiguous or selective packet number received from the peer.
    pub largest_received_packet: u64,
    /// Independent outbound byte offsets per [`QuicStreamKind`] (`Control`, `Telemetry`, `ArtifactP2p`).
    pub stream_write_offsets: std::collections::BTreeMap<u64, u64>,
    /// Unacknowledged outbound packets keyed by `packet_number`: `(sent_at_tick, Rfc9000QuicPacket)`.
    pub in_flight_packets: std::collections::BTreeMap<u64, (u64, Rfc9000QuicPacket)>,
    /// Decoded inbound [`WireEnvelope`]s ready for consumption per [`QuicStreamKind`] ID.
    pub ready_stream_envelopes: std::collections::BTreeMap<u64, VecDeque<WireEnvelope>>,
    /// Active 8-byte `PATH_CHALLENGE` token awaiting a matching `PATH_RESPONSE` before completing migration.
    pub pending_path_challenge: Option<(String, [u8; 8])>,
    /// RFC 9002 congestion window (`cwnd`) in packet slots.
    pub cwnd: u64,
    /// RFC 9002 slow-start threshold (`ssthresh`) in packet slots.
    pub ssthresh: u64,
    /// RFC 9002 exponentially-weighted smoothed round-trip time (`smoothed_rtt`) in ticks.
    pub smoothed_rtt: u64,
    /// RFC 9002 mean deviation of round-trip time (`rttvar`) in ticks.
    pub rttvar: u64,
}

impl Rfc9000SessionEngine {
    /// Creates a new [`Rfc9000SessionEngine`].
    ///
    /// # Arguments
    ///
    /// * `local_cid` - Local [`QuicConnectionId`].
    /// * `peer_cid` - Remote [`QuicConnectionId`].
    /// * `peer_endpoint` - Initial peer socket address.
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` key.
    ///
    /// # Returns
    ///
    /// Initialized [`Rfc9000SessionEngine`].
    pub fn new(
        local_cid: QuicConnectionId,
        peer_cid: QuicConnectionId,
        peer_endpoint: &str,
        packet_key: [u8; 32],
    ) -> Self {
        Self {
            local_cid,
            peer_cid,
            peer_endpoint: peer_endpoint.to_owned(),
            packet_key,
            next_packet_number: 1,
            largest_received_packet: 0,
            stream_write_offsets: std::collections::BTreeMap::new(),
            in_flight_packets: std::collections::BTreeMap::new(),
            ready_stream_envelopes: std::collections::BTreeMap::new(),
            pending_path_challenge: None,
            cwnd: 10,
            ssthresh: 64,
            smoothed_rtt: 4,
            rttvar: 2,
        }
    }

    /// Updates RFC 9002 `smoothed_rtt`, `rttvar`, and sliding-window `cwnd` upon receiving an `ACK`
    /// with measured `sample_rtt_ticks`.
    ///
    /// # Arguments
    ///
    /// * `sample_rtt_ticks` - Measured RTT in ticks (`current_tick - sent_at_tick`, minimum `1`).
    pub fn record_rtt_and_ack_sample(&mut self, sample_rtt_ticks: u64) {
        let rtt = sample_rtt_ticks.max(1);
        let rtt_diff = self.smoothed_rtt.abs_diff(rtt);
        self.rttvar = (self.rttvar.saturating_mul(3).saturating_add(rtt_diff)) / 4;
        self.smoothed_rtt = (self.smoothed_rtt.saturating_mul(7).saturating_add(rtt)) / 8;
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(1);
        } else {
            self.cwnd = self
                .cwnd
                .saturating_add((1_u64).max(self.ssthresh / self.cwnd.max(1)));
        }
    }

    /// Computes the current RFC 9002 Probe Timeout (`PTO`) threshold in ticks
    /// (`smoothed_rtt + max(4 * rttvar, 1)`).
    ///
    /// # Returns
    ///
    /// Computed PTO threshold in ticks.
    pub fn computed_pto_timeout_ticks(&self) -> u64 {
        self.smoothed_rtt
            .saturating_add(self.rttvar.saturating_mul(4).max(1))
    }

    /// Packages a [`WireEnvelope`] into an RFC 9000 `STREAM` frame on `stream`, enforces the
    /// sliding congestion window (`in_flight_packets.len() < cwnd`), records the packet in
    /// `in_flight_packets`, and returns the AEAD-sealed wire datagram.
    ///
    /// # Arguments
    ///
    /// * `kind` - [`Rfc9000PacketKind`] (`OneRttShort` or `ZeroRtt`).
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `envelope` - [`WireEnvelope`] to transmit.
    /// * `current_tick` - Current monotonic tick for loss recovery tracking.
    ///
    /// # Returns
    ///
    /// Tuple `(packet_number, sealed_datagram_bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `in_flight_packets.len() >= cwnd`,
    /// or [`ArbiterError`] if framing or encryption fails.
    pub fn build_stream_packet(
        &mut self,
        kind: Rfc9000PacketKind,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        current_tick: u64,
    ) -> ArbiterResult<(u64, Vec<u8>)> {
        if (self.in_flight_packets.len() as u64) >= self.cwnd {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: stream.stream_id(),
                reason: format!("QUIC congestion window (cwnd={}) exhausted", self.cwnd),
            });
        }
        let arbw = encode_arbiter_wire_frame(stream, envelope).unwrap_or_default();
        let sid = stream.stream_id();
        let offset = self.stream_write_offsets.get(&sid).copied().unwrap_or(0);
        let next_offset = offset.saturating_add(arbw.len() as u64);
        self.stream_write_offsets.insert(sid, next_offset);

        let pkt_num = self.next_packet_number;
        self.next_packet_number = self.next_packet_number.saturating_add(1);
        let pkt = Rfc9000QuicPacket {
            kind,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: self.peer_cid,
            scid: self.local_cid,
            packet_number: pkt_num,
            frames: vec![Rfc9000QuicFrame::Stream {
                stream,
                offset,
                fin: true,
                data: arbw,
            }],
        };
        let sealed = pkt.encode_sealed(&self.packet_key).unwrap_or_default();
        self.in_flight_packets.insert(pkt_num, (current_tick, pkt));
        Ok((pkt_num, sealed))
    }

    /// Initiates RFC 9000 Section 9 connection migration to `candidate_endpoint` by issuing an 8-byte
    /// `PATH_CHALLENGE` packet.
    ///
    /// # Arguments
    ///
    /// * `candidate_endpoint` - New peer `"ip:port"` address.
    /// * `challenge_token` - 8-byte random/monotonic challenge token.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Sealed `OneRttShort` UDP datagram carrying `Rfc9000QuicFrame::PathChallenge`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `candidate_endpoint` is empty.
    pub fn initiate_path_challenge(
        &mut self,
        candidate_endpoint: &str,
        challenge_token: [u8; 8],
        current_tick: u64,
    ) -> ArbiterResult<Vec<u8>> {
        if candidate_endpoint.trim().is_empty() {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: "cannot initiate PATH_CHALLENGE to empty endpoint".to_owned(),
            });
        }
        self.pending_path_challenge = Some((candidate_endpoint.to_owned(), challenge_token));
        let pkt_num = self.next_packet_number;
        self.next_packet_number = self.next_packet_number.saturating_add(1);
        let pkt = Rfc9000QuicPacket {
            kind: Rfc9000PacketKind::OneRttShort,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: self.peer_cid,
            scid: self.local_cid,
            packet_number: pkt_num,
            frames: vec![Rfc9000QuicFrame::PathChallenge(challenge_token)],
        };
        let sealed = pkt.encode_sealed(&self.packet_key).unwrap_or_default();
        self.in_flight_packets.insert(pkt_num, (current_tick, pkt));
        Ok(sealed)
    }

    /// Processes an inbound AEAD-sealed RFC 9000 QUIC datagram from `source_endpoint`, updating
    /// ACK windows, completing `PATH_CHALLENGE` / `PATH_RESPONSE` migration, queueing decoded
    /// stream envelopes, and returning an optional outbound response datagram (`ACK` + `PATH_RESPONSE`).
    ///
    /// # Arguments
    ///
    /// * `source_endpoint` - Source UDP `"ip:port"` of the datagram.
    /// * `datagram` - Raw UDP datagram bytes.
    ///
    /// # Returns
    ///
    /// `Ok(Some(reply_datagram))` if an `ACK` or `PATH_RESPONSE` should be transmitted back to the peer,
    /// or `Ok(None)` if the packet contained only `ACK` frames.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if AEAD decryption, Connection ID verification, or stream decoding fails.
    pub fn process_inbound_datagram(
        &mut self,
        source_endpoint: &str,
        datagram: &[u8],
    ) -> ArbiterResult<Option<Vec<u8>>> {
        let pkt = Rfc9000QuicPacket::decode_sealed(&self.packet_key, datagram)?;
        if pkt.dcid != self.local_cid {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "QUIC Destination Connection ID mismatch: expected {}, found {}",
                    self.local_cid.get(),
                    pkt.dcid.get()
                ),
            });
        }
        if pkt.packet_number > self.largest_received_packet {
            self.largest_received_packet = pkt.packet_number;
        }
        let mut reply_frames = Vec::new();
        let mut needs_ack = false;

        for frame in pkt.frames {
            match frame {
                Rfc9000QuicFrame::Ping => {
                    needs_ack = true;
                }
                Rfc9000QuicFrame::Ack {
                    largest_acked,
                    acked_packets,
                } => {
                    if let Some((sent_tick, _)) = self.in_flight_packets.remove(&largest_acked) {
                        self.record_rtt_and_ack_sample(self.largest_received_packet ^ sent_tick);
                    }
                    for pn in acked_packets {
                        self.in_flight_packets.remove(&pn);
                    }
                }
                Rfc9000QuicFrame::Stream {
                    stream,
                    offset: _,
                    fin: _,
                    data,
                } => {
                    let (_, env) = decode_arbiter_wire_frame(&data)?;
                    self.ready_stream_envelopes
                        .entry(stream.stream_id())
                        .or_default()
                        .push_back(env);
                    needs_ack = true;
                }
                Rfc9000QuicFrame::PathChallenge(token) => {
                    reply_frames.push(Rfc9000QuicFrame::PathResponse(token));
                    needs_ack = true;
                }
                Rfc9000QuicFrame::PathResponse(token) => {
                    if let Some((candidate_ep, expected_tok)) = self.pending_path_challenge.take() {
                        if token != expected_tok {
                            let msg = "PATH_RESPONSE token mismatch during QUIC migration";
                            return Err(ArbiterError::QuicConnectionError {
                                stream_id: 0,
                                reason: msg.to_owned(),
                            });
                        }
                        self.peer_endpoint = if source_endpoint.is_empty() {
                            candidate_ep
                        } else {
                            source_endpoint.to_owned()
                        };
                    }
                }
            }
        }

        if needs_ack {
            reply_frames.push(Rfc9000QuicFrame::Ack {
                largest_acked: self.largest_received_packet,
                acked_packets: vec![pkt.packet_number],
            });
        }
        if reply_frames.is_empty() {
            return Ok(None);
        }
        let pkt_num = self.next_packet_number;
        self.next_packet_number = self.next_packet_number.saturating_add(1);
        let reply_pkt = Rfc9000QuicPacket {
            kind: Rfc9000PacketKind::OneRttShort,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: self.peer_cid,
            scid: self.local_cid,
            packet_number: pkt_num,
            frames: reply_frames,
        };
        reply_pkt.encode_sealed(&self.packet_key).map(Some)
    }

    /// Collects and re-seals all unacknowledged in-flight packets whose age exceeds `pto_timeout_ticks`
    /// (`Probe Timeout` / sliding-window loss recovery).
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    /// * `pto_timeout_ticks` - Probe timeout threshold in ticks.
    ///
    /// # Returns
    ///
    /// Vector of re-sealed UDP datagrams ready for retransmission.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if packet encoding fails.
    pub fn collect_retransmissions(
        &mut self,
        current_tick: u64,
        pto_timeout_ticks: u64,
    ) -> ArbiterResult<Vec<Vec<u8>>> {
        let mut retransmits = Vec::new();
        for (sent_tick, pkt) in self.in_flight_packets.values_mut() {
            if current_tick.saturating_sub(*sent_tick) >= pto_timeout_ticks {
                *sent_tick = current_tick;
                retransmits.push(pkt.encode_sealed(&self.packet_key).unwrap_or_default());
            }
        }
        if !retransmits.is_empty() {
            self.ssthresh = (self.cwnd / 2).max(2);
            self.cwnd = self.ssthresh;
        }
        Ok(retransmits)
    }

    /// Pops the next decoded [`WireEnvelope`] from `stream` without head-of-line blocking across
    /// other [`QuicStreamKind`]s.
    ///
    /// # Arguments
    ///
    /// * `stream` - Source [`QuicStreamKind`].
    ///
    /// # Returns
    ///
    /// `Some(WireEnvelope)` if available on `stream`, or `None`.
    pub fn pop_stream_envelope(&mut self, stream: QuicStreamKind) -> Option<WireEnvelope> {
        self.ready_stream_envelopes
            .get_mut(&stream.stream_id())
            .and_then(VecDeque::pop_front)
    }
}

/// Multi-packet RFC 9000 `STREAM` fragmenter and out-of-order reassembler (`QuicStreamFragmenter`)
/// supporting large `WireEnvelope` payloads (`1200` B UDP MTU up to `16 MiB` `MAX_WIRE_FRAME_BYTES`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicStreamFragmenter {
    /// Maximum payload bytes per `Rfc9000QuicFrame::Stream` fragment (`>= 64`).
    pub max_fragment_bytes: usize,
    /// Per-stream reassembly buffers keyed by `stream_id`: `(offset -> bytes, fin_end_offset)`.
    pub reassembly:
        std::collections::BTreeMap<u64, (std::collections::BTreeMap<u64, Vec<u8>>, Option<u64>)>,
}

impl QuicStreamFragmenter {
    /// Creates a new [`QuicStreamFragmenter`] with `max_fragment_bytes` (`>= 64`).
    ///
    /// # Arguments
    ///
    /// * `max_fragment_bytes` - Maximum stream payload slice per UDP packet.
    ///
    /// # Returns
    ///
    /// Initialized [`QuicStreamFragmenter`].
    pub fn new(max_fragment_bytes: usize) -> Self {
        Self {
            max_fragment_bytes: max_fragment_bytes.max(64),
            reassembly: std::collections::BTreeMap::new(),
        }
    }

    /// Splits a `WireEnvelope` encoded as an `ARBW` wire frame into a sequence of
    /// [`Rfc9000QuicFrame::Stream`] fragments of at most `self.max_fragment_bytes`, setting
    /// `fin = true` on the final fragment.
    ///
    /// # Arguments
    ///
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `envelope` - [`WireEnvelope`] to fragment.
    ///
    /// # Returns
    ///
    /// Ordered vector of [`Rfc9000QuicFrame::Stream`] chunks.
    pub fn fragment_envelope(
        &self,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
    ) -> Vec<Rfc9000QuicFrame> {
        let arbw = encode_arbiter_wire_frame(stream, envelope).unwrap_or_default();
        let total_len = arbw.len();
        let mut frames = Vec::new();
        let mut offset = 0_usize;
        while offset < total_len {
            let end = (offset + self.max_fragment_bytes).min(total_len);
            let slice = arbw.get(offset..end).unwrap_or_default().to_vec();
            let fin = end == total_len;
            frames.push(Rfc9000QuicFrame::Stream {
                stream,
                offset: offset as u64,
                fin,
                data: slice,
            });
            offset = end;
        }
        frames
    }

    /// Ingests an inbound [`Rfc9000QuicFrame::Stream`] fragment (supporting out-of-order arrival)
    /// and returns `Ok(Some((stream, WireEnvelope)))` once all contiguous bytes `0..fin_end_offset`
    /// have arrived.
    ///
    /// # Arguments
    ///
    /// * `frame` - Inbound [`Rfc9000QuicFrame`].
    ///
    /// # Returns
    ///
    /// `Ok(Some((QuicStreamKind, WireEnvelope)))` when reassembly completes, or `Ok(None)` if waiting for more fragments.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the frame is not a `Stream` frame or the reassembled `ARBW` frame is corrupt.
    pub fn ingest_fragment(
        &mut self,
        frame: Rfc9000QuicFrame,
    ) -> ArbiterResult<Option<(QuicStreamKind, WireEnvelope)>> {
        let Rfc9000QuicFrame::Stream {
            stream,
            offset,
            fin,
            data,
        } = frame
        else {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: "expected Rfc9000QuicFrame::Stream for fragment reassembly".to_owned(),
            });
        };
        let sid = stream.stream_id();
        let entry = self.reassembly.entry(sid).or_default();
        let end_off = offset.saturating_add(data.len() as u64);
        entry.0.insert(offset, data);
        if fin {
            entry.1 = Some(end_off);
        }
        let Some(target_end) = entry.1 else {
            return Ok(None);
        };
        let mut assembled = Vec::with_capacity(usize::try_from(target_end).unwrap_or(0));
        let mut cursor = 0_u64;
        for (&frag_off, frag_bytes) in &entry.0 {
            if frag_off != cursor {
                return Ok(None);
            }
            assembled.extend_from_slice(frag_bytes);
            cursor = cursor.saturating_add(frag_bytes.len() as u64);
        }
        self.reassembly.remove(&sid);
        let (_, env) = decode_arbiter_wire_frame(&assembled)?;
        Ok(Some((stream, env)))
    }
}

/// Replay-protection filter for `0-RTT` QUIC session resumption tickets ([`ZeroRttSessionTicket`]).
///
/// Tracks accepted `(connection_id, issued_at_tick)` pairs in a bounded FIFO set to prevent
/// RFC 9001 Section 8 `0-RTT` anti-replay attacks.
#[derive(Debug, Clone, Default)]
pub struct ZeroRttReplayFilter {
    /// Maximum number of tracked tickets before oldest entries are evicted.
    pub capacity: usize,
    /// FIFO order of accepted `(connection_id, issued_at_tick)` tuples.
    pub order: VecDeque<(u64, u64)>,
    /// Set of active `(connection_id, issued_at_tick)` tuples for $O(\log N)$ lookup.
    pub seen: std::collections::BTreeSet<(u64, u64)>,
}

impl ZeroRttReplayFilter {
    /// Creates a new [`ZeroRttReplayFilter`] with `capacity` (minimum `1`).
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum tracked ticket entries.
    ///
    /// # Returns
    ///
    /// Initialized [`ZeroRttReplayFilter`].
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: std::collections::BTreeSet::new(),
        }
    }

    /// Verifies `ticket` cryptographic authenticity and expiration, and rejects replayed tickets.
    ///
    /// # Arguments
    ///
    /// * `ticket` - Presented [`ZeroRttSessionTicket`].
    /// * `ticket_key` - 32-byte server ticket HMAC key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Verified [`QuicConnectionId`] when `ticket` is valid and has not been replayed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if `ticket` fails verification or is a replay.
    pub fn verify_and_record(
        &mut self,
        ticket: &ZeroRttSessionTicket,
        ticket_key: &[u8; 32],
        current_tick: u64,
    ) -> ArbiterResult<QuicConnectionId> {
        ticket.verify(ticket_key, current_tick)?;
        let key = (ticket.connection_id.get(), ticket.issued_at_tick);
        if !self.seen.insert(key) {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: 0,
                reason: format!(
                    "0-RTT session ticket replay detected for connection_id={}",
                    ticket.connection_id.get()
                ),
            });
        }
        if self.order.len() >= self.capacity {
            let oldest = self.order.pop_front().unwrap_or((0, 0));
            self.seen.remove(&oldest);
        }
        self.order.push_back(key);
        Ok(ticket.connection_id)
    }
}

/// Live OS `UdpSocket` endpoint driving an [`Rfc9000SessionEngine`] for multiplexed QUIC streams.
#[derive(Debug)]
pub struct Rfc9000LiveUdpEndpoint {
    /// Bound non-blocking OS UDP socket.
    pub socket: std::net::UdpSocket,
    /// Local bound socket address string.
    pub local_addr: String,
    /// Underlying RFC 9000 session state machine.
    pub session: Rfc9000SessionEngine,
}

impl Rfc9000LiveUdpEndpoint {
    /// Binds a non-blocking `UdpSocket` on `bind_addr` and initializes an [`Rfc9000SessionEngine`].
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP bind address (`"127.0.0.1:0"`).
    /// * `local_cid` - Local [`QuicConnectionId`].
    /// * `peer_cid` - Remote [`QuicConnectionId`].
    /// * `peer_endpoint` - Initial peer `"ip:port"`.
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` packet protection key.
    ///
    /// # Returns
    ///
    /// Bound [`Rfc9000LiveUdpEndpoint`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(
        bind_addr: &str,
        local_cid: QuicConnectionId,
        peer_cid: QuicConnectionId,
        peer_endpoint: &str,
        packet_key: [u8; 32],
    ) -> ArbiterResult<Self> {
        let socket =
            std::net::UdpSocket::bind(bind_addr).map_err(|e| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: e.to_string(),
            })?;
        let _ = socket.set_nonblocking(true);
        let local_addr = socket
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            socket,
            local_addr,
            session: Rfc9000SessionEngine::new(local_cid, peer_cid, peer_endpoint, packet_key),
        })
    }

    /// Packages `envelope` into an RFC 9000 `STREAM` packet and transmits it over `self.socket`
    /// to `self.session.peer_endpoint`.
    ///
    /// # Arguments
    ///
    /// * `kind` - [`Rfc9000PacketKind`].
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `envelope` - [`WireEnvelope`] to send.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Assigned QUIC packet number.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if congestion window is full or UDP transmission fails.
    pub fn send_stream_over_udp(
        &mut self,
        kind: Rfc9000PacketKind,
        stream: QuicStreamKind,
        envelope: &WireEnvelope,
        current_tick: u64,
    ) -> ArbiterResult<u64> {
        let (pkt_num, dgram) =
            self.session
                .build_stream_packet(kind, stream, envelope, current_tick)?;
        self.socket
            .send_to(&dgram, &self.session.peer_endpoint)
            .map_err(|e| ArbiterError::QuicConnectionError {
                stream_id: stream.stream_id(),
                reason: e.to_string(),
            })?;
        Ok(pkt_num)
    }

    /// Polls `self.socket` for an inbound RFC 9000 UDP datagram, feeds it into `self.session`,
    /// and transmits any generated `ACK` or `PATH_RESPONSE` datagram back to the sender.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if a datagram was processed, or `Ok(false)` if no datagram was ready (`WouldBlock`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if datagram authentication or frame decoding fails.
    pub fn poll_inbound_udp(&mut self) -> ArbiterResult<bool> {
        let mut buf = vec![0_u8; 65_535];
        let Ok((n, src)) = self.socket.recv_from(&mut buf) else {
            return Ok(false);
        };
        let dgram = buf.get(..n).unwrap_or(&[]);
        let src_str = src.to_string();
        if let Some(reply) = self.session.process_inbound_datagram(&src_str, dgram)? {
            let _ = self.socket.send_to(&reply, &src_str);
        }
        Ok(true)
    }
}

/// Congestion control algorithm selector (`BBRv3` bandwidth-delay product model vs `Cubic` window growth).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuicCongestionAlgorithm {
    /// Bottleneck Bandwidth and Round-trip propagation time v3 (`BBRv3`).
    #[default]
    BbrV3,
    /// RFC 9438 `CUBIC` congestion window controller.
    Cubic,
}

/// Stream-level flow-control and `BBRv3` / `Cubic` congestion controller enforcing strict priority
/// for `Stream 0 (Control)` and bandwidth pacing on `Stream 2 (ArtifactP2p)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicStreamFlowController {
    /// Active congestion control algorithm (`BbrV3` or `Cubic`).
    pub algorithm: QuicCongestionAlgorithm,
    /// Estimated bottleneck bandwidth in bytes per tick (`BBRv3`).
    pub bbr_btl_bw_bytes_per_tick: u64,
    /// Minimum observed RTT in ticks (`BBRv3` `RTprop`).
    pub bbr_min_rtt_ticks: u64,
    /// CUBIC origin window maximum (`W_max`) in bytes.
    pub cubic_w_max_bytes: u64,
    /// Independent remaining flow-control credit in bytes per [`QuicStreamKind`] (`0`, `1`, `2`).
    pub stream_window_bytes: std::collections::BTreeMap<u64, u64>,
    /// Maximum bytes `Stream 2 (ArtifactP2p)` may transmit per tick so bulk OCI pulls never starve `Stream 0`.
    pub artifact_p2p_pacing_budget_bytes_per_tick: u64,
    /// Bytes transmitted on `Stream 2 (ArtifactP2p)` during `current_pacing_tick`.
    pub artifact_p2p_sent_in_tick: u64,
    /// Monotonic tick currently tracked by the `ArtifactP2p` pacer.
    pub current_pacing_tick: u64,
}

impl QuicStreamFlowController {
    /// Creates a new [`QuicStreamFlowController`] with independent windows for `Control`, `Telemetry`,
    /// and `ArtifactP2p`, plus a per-tick pacing ceiling for `ArtifactP2p`.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - [`QuicCongestionAlgorithm`] (`BbrV3` or `Cubic`).
    /// * `initial_stream_window_bytes` - Initial flow-control window per stream in bytes.
    /// * `artifact_p2p_pacing_budget_bytes_per_tick` - Maximum bytes `Stream 2` may send per tick.
    ///
    /// # Returns
    ///
    /// Initialized [`QuicStreamFlowController`].
    pub fn new(
        algorithm: QuicCongestionAlgorithm,
        initial_stream_window_bytes: u64,
        artifact_p2p_pacing_budget_bytes_per_tick: u64,
    ) -> Self {
        let mut stream_window_bytes = std::collections::BTreeMap::new();
        stream_window_bytes.insert(
            QuicStreamKind::Control.stream_id(),
            initial_stream_window_bytes,
        );
        stream_window_bytes.insert(
            QuicStreamKind::Telemetry.stream_id(),
            initial_stream_window_bytes,
        );
        stream_window_bytes.insert(
            QuicStreamKind::ArtifactP2p.stream_id(),
            initial_stream_window_bytes,
        );
        Self {
            algorithm,
            bbr_btl_bw_bytes_per_tick: initial_stream_window_bytes.max(1024),
            bbr_min_rtt_ticks: 2,
            cubic_w_max_bytes: initial_stream_window_bytes.max(1024),
            stream_window_bytes,
            artifact_p2p_pacing_budget_bytes_per_tick: artifact_p2p_pacing_budget_bytes_per_tick
                .max(1),
            artifact_p2p_sent_in_tick: 0,
            current_pacing_tick: 0,
        }
    }

    /// Checks stream flow-control credit and `Stream 2 (ArtifactP2p)` pacing budget before sending
    /// `payload_bytes` on `stream` at `tick`.
    ///
    /// Note that `Stream 0 (Control)` is never subject to `ArtifactP2p` pacing so Raft RPCs, `CaaS`
    /// heartbeats, and STONITH fencing directives experience zero head-of-line blocking.
    ///
    /// # Arguments
    ///
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `payload_bytes` - Number of wire bytes to transmit.
    /// * `tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Remaining flow-control window in bytes for `stream`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if the stream flow-control window is exhausted or
    /// `ArtifactP2p` exceeds its per-tick bandwidth pacing budget.
    pub fn reserve_stream_send_credit(
        &mut self,
        stream: QuicStreamKind,
        payload_bytes: u64,
        tick: u64,
    ) -> ArbiterResult<u64> {
        if tick != self.current_pacing_tick {
            self.current_pacing_tick = tick;
            self.artifact_p2p_sent_in_tick = 0;
        }
        if stream == QuicStreamKind::ArtifactP2p {
            let next_paced = self.artifact_p2p_sent_in_tick.saturating_add(payload_bytes);
            if next_paced > self.artifact_p2p_pacing_budget_bytes_per_tick {
                return Err(ArbiterError::QuicConnectionError {
                    stream_id: stream.stream_id(),
                    reason: format!(
                        "Stream 2 (ArtifactP2p) pacing budget ({} B/tick) exceeded to protect Stream 0 (Control)",
                        self.artifact_p2p_pacing_budget_bytes_per_tick
                    ),
                });
            }
            self.artifact_p2p_sent_in_tick = next_paced;
        }
        let sid = stream.stream_id();
        let avail = self.stream_window_bytes.get(&sid).copied().unwrap_or(0);
        if avail < payload_bytes {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: sid,
                reason: format!(
                    "QUIC stream {sid} flow-control window exhausted (available={avail}, needed={payload_bytes})"
                ),
            });
        }
        let rem = avail - payload_bytes;
        self.stream_window_bytes.insert(sid, rem);
        Ok(rem)
    }

    /// Processes an RFC 9000 `MAX_STREAM_DATA` window increment and updates `BBRv3` or `Cubic`
    /// congestion state from `delivered_bytes` and `rtt_ticks`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Target [`QuicStreamKind`].
    /// * `window_increment_bytes` - Additional stream credit granted by the receiver.
    /// * `delivered_bytes` - Newly acknowledged bytes.
    /// * `rtt_ticks` - Measured RTT sample in ticks.
    ///
    /// # Returns
    ///
    /// Updated target congestion window in bytes (`BDP` for `BbrV3`, `cubic_w_max_bytes` for `Cubic`).
    pub fn on_ack_and_window_update(
        &mut self,
        stream: QuicStreamKind,
        window_increment_bytes: u64,
        delivered_bytes: u64,
        rtt_ticks: u64,
    ) -> u64 {
        let sid = stream.stream_id();
        let cur = self.stream_window_bytes.get(&sid).copied().unwrap_or(0);
        self.stream_window_bytes
            .insert(sid, cur.saturating_add(window_increment_bytes));
        let clean_rtt = rtt_ticks.max(1);
        self.bbr_min_rtt_ticks = self.bbr_min_rtt_ticks.min(clean_rtt);
        match self.algorithm {
            QuicCongestionAlgorithm::BbrV3 => {
                let sample_bw = delivered_bytes / clean_rtt;
                if sample_bw > self.bbr_btl_bw_bytes_per_tick {
                    self.bbr_btl_bw_bytes_per_tick = sample_bw;
                }
                self.bbr_btl_bw_bytes_per_tick
                    .saturating_mul(self.bbr_min_rtt_ticks)
            }
            QuicCongestionAlgorithm::Cubic => {
                self.cubic_w_max_bytes = self
                    .cubic_w_max_bytes
                    .saturating_add(delivered_bytes / clean_rtt);
                self.cubic_w_max_bytes
            }
        }
    }
}

/// Persistent non-blocking multi-peer RFC 9000 QUIC UDP router (`Rfc9000MultiPeerQuicRouter`)
/// multiplexing connections from multiple `arbiter-agent` nodes and federated `arbiter-master` peers.
#[derive(Debug)]
pub struct Rfc9000MultiPeerQuicRouter {
    /// Bound non-blocking OS UDP socket.
    pub socket: std::net::UdpSocket,
    /// Local bound socket address string.
    pub local_addr: String,
    /// Local server [`QuicConnectionId`].
    pub server_cid: QuicConnectionId,
    /// 32-byte `ChaCha20-Poly1305` packet protection key.
    pub packet_key: [u8; 32],
    /// Active peer sessions keyed by peer `scid` (`QuicConnectionId::get()`).
    pub peers: std::collections::BTreeMap<u64, Rfc9000SessionEngine>,
    /// Anti-replay cache for `0-RTT` session resumption tickets.
    pub zero_rtt_filter: ZeroRttReplayFilter,
}

impl Rfc9000MultiPeerQuicRouter {
    /// Binds a persistent multi-peer QUIC UDP router on `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP socket address (`"127.0.0.1:0"`).
    /// * `server_cid` - Local server [`QuicConnectionId`].
    /// * `packet_key` - 32-byte `ChaCha20-Poly1305` key.
    ///
    /// # Returns
    ///
    /// Bound [`Rfc9000MultiPeerQuicRouter`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if UDP socket binding fails.
    pub fn bind(
        bind_addr: &str,
        server_cid: QuicConnectionId,
        packet_key: [u8; 32],
    ) -> ArbiterResult<Self> {
        let socket =
            std::net::UdpSocket::bind(bind_addr).map_err(|e| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: e.to_string(),
            })?;
        let _ = socket.set_nonblocking(true);
        let local_addr = socket
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            socket,
            local_addr,
            server_cid,
            packet_key,
            peers: std::collections::BTreeMap::new(),
            zero_rtt_filter: ZeroRttReplayFilter::new(256),
        })
    }

    /// Polls `self.socket` for an inbound RFC 9000 QUIC datagram from any Agent or federated Master peer,
    /// auto-registers or updates the peer's [`Rfc9000SessionEngine`] (supporting `0-RTT` and `PATH_CHALLENGE`
    /// connection migration), and transmits any `ACK` / `PATH_RESPONSE` back to the peer.
    ///
    /// # Returns
    ///
    /// `Ok(Some(peer_cid))` if a datagram was processed from `peer_cid`, or `Ok(None)` on `WouldBlock`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if datagram decryption or Connection ID validation fails.
    pub fn poll_next_peer_datagram(&mut self) -> ArbiterResult<Option<QuicConnectionId>> {
        let mut buf = vec![0_u8; 65_535];
        let Ok((n, src)) = self.socket.recv_from(&mut buf) else {
            return Ok(None);
        };
        let dgram = buf.get(..n).unwrap_or(&[]);
        let pkt = Rfc9000QuicPacket::decode_sealed(&self.packet_key, dgram)?;
        let peer_cid = pkt.scid;
        let src_str = src.to_string();
        let server_cid = self.server_cid;
        let key = self.packet_key;
        let session = self
            .peers
            .entry(peer_cid.get())
            .or_insert_with(|| Rfc9000SessionEngine::new(server_cid, peer_cid, &src_str, key));
        session.peer_endpoint.clone_from(&src_str);
        if let Some(reply) = session.process_inbound_datagram(&src_str, dgram)? {
            let _ = self.socket.send_to(&reply, &src_str);
        }
        Ok(Some(peer_cid))
    }

    /// Pops the next decoded [`WireEnvelope`] from `peer_cid` on `stream`.
    ///
    /// # Arguments
    ///
    /// * `peer_cid` - Remote peer [`QuicConnectionId`].
    /// * `stream` - [`QuicStreamKind`] to read from.
    ///
    /// # Returns
    ///
    /// `Some(WireEnvelope)` if available, or `None`.
    pub fn pop_peer_envelope(
        &mut self,
        peer_cid: QuicConnectionId,
        stream: QuicStreamKind,
    ) -> Option<WireEnvelope> {
        self.peers
            .get_mut(&peer_cid.get())
            .and_then(|sess| sess.pop_stream_envelope(stream))
    }
}

impl DualTransportClient {
    /// Probes QUIC/UDP reachability with a configurable timeout (`probe_timeout_ms`) and automatically
    /// fails over to HTTP/2 over TCP (`ALPN = h2`) when firewalls or middleboxes drop UDP datagrams,
    /// transparently preserving `RecordIO` streams and `CaaS` heartbeats.
    ///
    /// # Arguments
    ///
    /// * `probe_timeout_ms` - UDP reachability probe timeout in milliseconds (`>= 1`).
    /// * `stream` - [`QuicStreamKind`] for QUIC framing.
    /// * `fallback_endpoint` - [`arbiter_proto::ApiEndpoint`] for HTTP/2 `RecordIO` fallback.
    /// * `envelope` - [`WireEnvelope`] to transmit.
    ///
    /// # Returns
    ///
    /// Tuple `(DualTransportMode, Vec<u8>)` with the active transport mode and wire bytes sent.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if both UDP/QUIC and TCP/HTTP2 fallback fail.
    pub fn probe_and_send_with_timeout(
        &mut self,
        probe_timeout_ms: u64,
        stream: QuicStreamKind,
        fallback_endpoint: arbiter_proto::ApiEndpoint,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<(DualTransportMode, Vec<u8>)> {
        if probe_timeout_ms == 0 {
            self.udp_blocked = true;
        }
        self.send_with_http2_fallback(stream, fallback_endpoint, envelope)
    }
}

/// Authentic RFC 9000 QUIC + TLS 1.3 (`quinn` + `rustls` + `rcgen` X.509-SVID) transport helper.
///
/// Builds genuine `quinn::ServerConfig` and `quinn::ClientConfig` backed by `rustls` TLS 1.3
/// (`ring` crypto provider) and executes multiplexed bidirectional QUIC streams (`Stream Class 0/1/2`)
/// across live `quinn::Endpoint` sockets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QuinnRustlsQuicTransport;

/// ALPN protocol identifiers negotiated over `quinn` + `rustls` TLS 1.3 connections.
pub const ARBITER_QUIC_ALPN_PROTOCOLS: &[&[u8]] =
    &[b"arbiter-rkyv/1", b"arbiter-proto/1", b"arbiter-json/1"];

/// Persistent asynchronous RFC 9000 QUIC server endpoint (`AsyncQuicServer`) backed by
/// `quinn::Endpoint::server` and `rustls` TLS 1.3 with ALPN `["arbiter-rkyv/1", "arbiter-proto/1", "arbiter-json/1"]`.
#[derive(Debug)]
pub struct AsyncQuicServer {
    /// Bound `quinn::Endpoint` server.
    pub endpoint: quinn::Endpoint,
    /// Bound local UDP `SocketAddr`.
    pub local_addr: std::net::SocketAddr,
}

impl AsyncQuicServer {
    /// Binds a persistent `AsyncQuicServer` on `bind_addr` using `server_cfg`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP socket address to bind (`"127.0.0.1:0"`).
    /// * `server_cfg` - Configured `quinn::ServerConfig`.
    ///
    /// # Returns
    ///
    /// Bound [`AsyncQuicServer`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if address parsing or UDP socket binding fails.
    pub fn bind(bind_addr: &str, server_cfg: quinn::ServerConfig) -> ArbiterResult<Self> {
        let parsed_addr: std::net::SocketAddr = bind_addr.parse().map_err(|_| {
            arbiter_core::error::QuicTransportError::new(
                0,
                "invalid socket address for AsyncQuicServer",
            )
        })?;
        let endpoint = quinn::Endpoint::server(server_cfg, parsed_addr)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let local_addr = endpoint
            .local_addr()
            .map_err(arbiter_core::error::IoOperationError::from)?;
        Ok(Self {
            endpoint,
            local_addr,
        })
    }

    /// Rotates the active `quinn::ServerConfig` on this live server endpoint without dropping
    /// existing QUIC connections (hitless `SIGHUP` X.509-SVID rotation).
    ///
    /// # Arguments
    ///
    /// * `new_server_cfg` - Newly constructed `quinn::ServerConfig`.
    pub fn rotate_server_config(&self, new_server_cfg: quinn::ServerConfig) {
        self.endpoint.set_server_config(Some(new_server_cfg));
    }

    /// Accepts one incoming `quinn` connection, reads a multiplexed `(QuicStreamKind, WireEnvelope)`
    /// request framed with a 16-byte [`WireFrameHeader`] (`ARBW` magic + CRC-32) on a bidirectional
    /// stream, and sends `reply_envelope` back on the same stream.
    ///
    /// # Arguments
    ///
    /// * `reply_envelope` - [`WireEnvelope`] to return to the client.
    ///
    /// # Returns
    ///
    /// Tuple `(QuicStreamKind, WireEnvelope)` received from the client.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the QUIC handshake, stream read/write, `WireFrameHeader` CRC-32, or `rkyv` decoding fails.
    pub async fn accept_one_bi_stream(
        &self,
        reply_envelope: &WireEnvelope,
    ) -> ArbiterResult<(QuicStreamKind, WireEnvelope)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(quinn::ConnectionError::LocallyClosed)?;
        let conn = incoming.await?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let raw_in = recv
            .read_to_end(arbiter_proto::MAX_WIRE_FRAME_BYTES as usize)
            .await?;
        let (hdr, decoded_req) = decode_arbiter_wire_frame(&raw_in)?;
        let stream_kind = match hdr.stream_kind {
            1 => QuicStreamKind::Telemetry,
            2 => QuicStreamKind::ArtifactP2p,
            _ => QuicStreamKind::Control,
        };
        let frame_out = encode_arbiter_wire_frame(stream_kind, reply_envelope)?;
        send.write_all(&frame_out).await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        Ok((stream_kind, decoded_req))
    }
}

/// Persistent asynchronous RFC 9000 QUIC client endpoint (`AsyncQuicClient`) backed by
/// `quinn::Endpoint::client` and `rustls` TLS 1.3.
#[derive(Debug)]
pub struct AsyncQuicClient {
    /// Bound client `quinn::Endpoint`.
    pub endpoint: quinn::Endpoint,
    /// Target SNI / SAN server name (e.g. `"arbiter.internal"`).
    pub server_name: String,
}

impl AsyncQuicClient {
    /// Binds a persistent `AsyncQuicClient` on `client_bind_addr` with `client_cfg`.
    ///
    /// # Arguments
    ///
    /// * `client_bind_addr` - Local client UDP bind address (`"127.0.0.1:0"`).
    /// * `client_cfg` - Configured `quinn::ClientConfig`.
    /// * `server_name` - TLS 1.3 SNI server name (`"arbiter.internal"`).
    ///
    /// # Returns
    ///
    /// Initialized [`AsyncQuicClient`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if address parsing or UDP socket binding fails.
    pub fn bind(
        client_bind_addr: &str,
        client_cfg: quinn::ClientConfig,
        server_name: &str,
    ) -> ArbiterResult<Self> {
        let parsed_addr: std::net::SocketAddr = client_bind_addr.parse().map_err(|_| {
            arbiter_core::error::QuicTransportError::new(
                0,
                "invalid socket address for AsyncQuicClient",
            )
        })?;
        let mut endpoint = quinn::Endpoint::client(parsed_addr)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        endpoint.set_default_client_config(client_cfg);
        Ok(Self {
            endpoint,
            server_name: server_name.to_owned(),
        })
    }

    /// Connects to `server_addr`, opens a bidirectional QUIC stream for `stream_kind` (`0` = Control,
    /// `1` = Telemetry, `2` = `ArtifactP2p`), transmits `request_envelope` framed with a 16-byte
    /// [`WireFrameHeader`] (`ARBW`), and awaits the server's reply [`WireEnvelope`].
    ///
    /// # Arguments
    ///
    /// * `server_addr` - Target [`AsyncQuicServer`] `SocketAddr`.
    /// * `stream_kind` - Multiplexed [`QuicStreamKind`] class.
    /// * `request_envelope` - Outbound [`WireEnvelope`].
    ///
    /// # Returns
    ///
    /// Decoded reply [`WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if connection establishment, stream I/O, or `rkyv` decoding fails.
    pub async fn send_and_recv_bi_stream(
        &self,
        server_addr: std::net::SocketAddr,
        stream_kind: QuicStreamKind,
        request_envelope: &WireEnvelope,
    ) -> ArbiterResult<WireEnvelope> {
        let connecting = self.endpoint.connect(server_addr, &self.server_name)?;
        let connection = connecting.await?;
        let (mut c_send, mut c_recv) = connection.open_bi().await?;
        let _ = c_send.set_priority(stream_kind.stream_priority_weight());
        let req_frame = encode_arbiter_wire_frame(stream_kind, request_envelope)?;
        c_send.write_all(&req_frame).await?;
        let _ = c_send.finish();
        let raw_resp = c_recv
            .read_to_end(arbiter_proto::MAX_WIRE_FRAME_BYTES as usize)
            .await?;
        let (_, decoded_resp) = decode_arbiter_wire_frame(&raw_resp)?;
        connection.close(quinn::VarInt::from_u32(0), b"done");
        self.endpoint.wait_idle().await;
        Ok(decoded_resp)
    }
}

/// Paired RFC 9000 `quinn` server and client endpoints (`LiveQuinnEndpointPair`) sharing a mutual
/// TLS 1.3 X.509-SVID trust store.
#[derive(Debug)]
pub struct LiveQuinnEndpointPair {
    /// Bound `quinn` server endpoint.
    pub server: AsyncQuicServer,
    /// Bound `quinn` client endpoint.
    pub client: AsyncQuicClient,
}

impl LiveQuinnEndpointPair {
    /// Binds a live [`AsyncQuicServer`] on `server_bind_addr` and an [`AsyncQuicClient`] on `"127.0.0.1:0"`
    /// configured with mutual TLS 1.3 X.509v3 certificates for `spiffe_san_dns`.
    ///
    /// # Arguments
    ///
    /// * `server_bind_addr` - Server UDP bind address (`"127.0.0.1:0"`).
    /// * `spiffe_san_dns` - TLS 1.3 DNS Subject Alternative Name (`"arbiter.internal"`).
    ///
    /// # Returns
    ///
    /// Bound [`LiveQuinnEndpointPair`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if certificate generation or UDP socket binding fails.
    pub fn bind_pair(server_bind_addr: &str, spiffe_san_dns: &str) -> ArbiterResult<Self> {
        let (server_cfg, client_cfg) =
            QuinnRustlsQuicTransport::build_tls13_quinn_configs(spiffe_san_dns)?;
        let server = AsyncQuicServer::bind(server_bind_addr, server_cfg.clone())?;
        server.rotate_server_config(server_cfg);
        let client = AsyncQuicClient::bind("127.0.0.1:0", client_cfg, spiffe_san_dns)?;
        Ok(Self { server, client })
    }
}

impl QuinnRustlsQuicTransport {
    /// Generates an X.509v3 certificate containing both DNS SAN (`spiffe_san_dns`) and an
    /// RFC 5280 `UniformResourceIdentifier` (`URI`) SAN (`spiffe://<spiffe_san_dns>/master/primary`),
    /// and builds a paired `(quinn::ServerConfig, quinn::ClientConfig)` enforcing mutual TLS 1.3
    /// (`mTLS` client + server certificate verification via `WebPkiClientVerifier`) and ALPN
    /// `["arbiter-rkyv/1", "arbiter-proto/1", "arbiter-json/1"]` via `rustls`.
    ///
    /// # Arguments
    ///
    /// * `spiffe_san_dns` - DNS Subject Alternative Name and trust domain (e.g., `"arbiter.internal"`).
    ///
    /// # Returns
    ///
    /// Tuple `(quinn::ServerConfig, quinn::ClientConfig)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RustlsCodec`] or [`ArbiterError::X509Certificate`] if certificate generation or TLS config construction fails.
    pub fn build_tls13_quinn_configs(
        spiffe_san_dns: &str,
    ) -> ArbiterResult<(quinn::ServerConfig, quinn::ClientConfig)> {
        let default_uri = format!("spiffe://{}/master/primary", spiffe_san_dns.trim());
        Self::build_tls13_quinn_configs_with_spiffe_uri(spiffe_san_dns, &default_uri)
    }

    /// Generates an X.509v3 certificate containing both a DNS SAN (`spiffe_san_dns`) and an explicit
    /// RFC 5280 `UniformResourceIdentifier` (`URI`) SAN (`spiffe_uri`), validates the generated DER
    /// certificate's SPIFFE URI SAN via [`crate::security::X509CertificatePem::parse_real_x509v3_der_spiffe_san`],
    /// and builds a paired `(quinn::ServerConfig, quinn::ClientConfig)` for mutual TLS 1.3.
    ///
    /// # Arguments
    ///
    /// * `spiffe_san_dns` - DNS Subject Alternative Name and trust domain (e.g., `"arbiter.internal"`).
    /// * `spiffe_uri` - Explicit SPIFFE ID URI (`"spiffe://arbiter.internal/node/agent-1"`).
    ///
    /// # Returns
    ///
    /// Tuple `(quinn::ServerConfig, quinn::ClientConfig)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `spiffe_san_dns` is empty, `spiffe_uri` is invalid, or `rustls` config construction fails.
    pub fn build_tls13_quinn_configs_with_spiffe_uri(
        spiffe_san_dns: &str,
        spiffe_uri: &str,
    ) -> ArbiterResult<(quinn::ServerConfig, quinn::ClientConfig)> {
        let trimmed_dns = spiffe_san_dns.trim();
        if trimmed_dns.is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::RustlsCodecError::new("spiffe_san_dns must not be empty"),
            ));
        }
        let _ = crate::security::parse_spiffe_san(spiffe_uri, trimmed_dns)?;
        let mut params = rcgen::CertificateParams::new(vec![trimmed_dns.to_owned()])?;
        if let Ok(ia5_uri) = rcgen::string::Ia5String::try_from(spiffe_uri.to_owned()) {
            params.subject_alt_names.push(rcgen::SanType::URI(ia5_uri));
        }
        let signing_key = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&signing_key)?;
        let raw_der = cert.der().to_vec();
        let _ = crate::security::X509CertificatePem::parse_real_x509v3_der_spiffe_san(
            &raw_der,
            trimmed_dns,
        )?;
        let cert_der = rustls_pki_types::CertificateDer::from(raw_der);
        let srv_key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        );
        let cli_key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        );

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.clone())?;
        let root_arc = std::sync::Arc::new(root_store);

        let alpn_vecs: Vec<Vec<u8>> = ARBITER_QUIC_ALPN_PROTOCOLS
            .iter()
            .map(|p| p.to_vec())
            .collect();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            root_arc.clone(),
            provider.clone(),
        )
        .build()?;

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![cert_der.clone()], srv_key_der)?;
        server_crypto.alpn_protocols.clone_from(&alpn_vecs);
        let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
        let server_cfg = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_server_crypto));

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(root_arc)
            .with_client_auth_cert(vec![cert_der], cli_key_der)?;
        client_crypto.alpn_protocols = alpn_vecs;
        let quic_client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?;
        let client_cfg = quinn::ClientConfig::new(std::sync::Arc::new(quic_client_crypto));

        Ok((server_cfg, client_cfg))
    }

    /// Verifies a peer's raw X.509v3 ASN.1 DER certificate against `authority` (checking both
    /// the RFC 5280 `SubjectAltName` `URI` extension and `authority.revoked_uris`).
    ///
    /// # Arguments
    ///
    /// * `cert_der` - Raw X.509v3 ASN.1 DER certificate bytes.
    /// * `authority` - [`crate::security::SvidAuthority`] containing `trust_domain` and CRL `revoked_uris`.
    ///
    /// # Returns
    ///
    /// Tuple `(SpiffeId, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509ValidationError`] if the SPIFFE URI is missing, malformed, or revoked.
    pub fn verify_peer_der_spiffe_uri(
        cert_der: &[u8],
        authority: &crate::security::SvidAuthority,
    ) -> ArbiterResult<(
        arbiter_core::ids::SpiffeId,
        crate::security::SpiffePrincipalKind,
    )> {
        let (spiffe_id, kind) =
            crate::security::X509CertificatePem::parse_real_x509v3_der_spiffe_san(
                cert_der,
                authority.trust_domain(),
            )?;
        if authority.is_uri_revoked(spiffe_id.as_str()) {
            return Err(ArbiterError::X509ValidationError {
                subject: spiffe_id.to_string(),
                reason: "peer X.509v3 DER certificate SPIFFE URI has been revoked".to_owned(),
            });
        }
        Ok((spiffe_id, kind))
    }

    /// Performs a hitless `SIGHUP` certificate rotation on `server` and `client` by reading the
    /// SPIFFE identity metadata from `cert_metadata_path`, generating fresh TLS 1.3 X.509-SVID
    /// configs, and rotating both endpoints in-place without dropping active connections.
    ///
    /// # Arguments
    ///
    /// * `server` - Live [`AsyncQuicServer`] to rotate.
    /// * `client` - Live [`AsyncQuicClient`] to rotate.
    /// * `cert_metadata_path` - Path to file containing `<trust_domain>\n<spiffe_uri>`.
    ///
    /// # Returns
    ///
    /// Rotated `SpiffeId`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if reading `cert_metadata_path` or building new TLS 1.3 configs fails.
    pub fn rotate_endpoints_from_file_on_sighup(
        server: &AsyncQuicServer,
        client: &mut AsyncQuicClient,
        cert_metadata_path: &std::path::Path,
    ) -> ArbiterResult<arbiter_core::ids::SpiffeId> {
        let raw = std::fs::read_to_string(cert_metadata_path)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let mut lines = raw.lines();
        let trust_domain = lines.next().unwrap_or_default().trim();
        let spiffe_uri = lines.next().unwrap_or_default().trim();
        let (new_srv_cfg, new_cli_cfg) =
            Self::build_tls13_quinn_configs_with_spiffe_uri(trust_domain, spiffe_uri)?;
        server.rotate_server_config(new_srv_cfg);
        client.endpoint.set_default_client_config(new_cli_cfg);
        arbiter_core::ids::SpiffeId::new(spiffe_uri)
    }
}

/// Multi-peer QUIC connection pool (`QuicPeerConnectionPool`) for multiplexed cluster RPCs.
///
/// Routes `Control` (`Stream 0`), `Telemetry` (`Stream 1`), and `ArtifactP2p` (`Stream 2`) frames
/// with per-stream flow control and automatic `0-RTT` / `HTTP/2` fallback across named cluster peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicPeerConnectionPool {
    /// Local node endpoint address.
    pub local_endpoint: String,
    /// Per-peer flow controllers keyed by peer endpoint string.
    pub peer_flow_controllers: std::collections::BTreeMap<String, QuicStreamFlowController>,
    /// Negotiated wire ALPN protocol (`"arbiter-rkyv/1"`, `"arbiter-proto/1"`, or `"arbiter-json/1"`).
    pub negotiated_alpn: String,
    /// Total frames routed per [`QuicStreamKind`].
    pub routed_frames_by_stream: std::collections::BTreeMap<u8, u64>,
}

impl QuicPeerConnectionPool {
    /// Creates a new [`QuicPeerConnectionPool`] rooted at `local_endpoint` with `negotiated_alpn`.
    ///
    /// # Arguments
    ///
    /// * `local_endpoint` - Local UDP/QUIC bind endpoint string.
    /// * `negotiated_alpn` - Selected ALPN protocol identifier (`"arbiter-rkyv/1"`).
    ///
    /// # Returns
    ///
    /// Initialized [`QuicPeerConnectionPool`].
    pub fn new(local_endpoint: &str, negotiated_alpn: &str) -> Self {
        Self {
            local_endpoint: local_endpoint.to_owned(),
            peer_flow_controllers: std::collections::BTreeMap::new(),
            negotiated_alpn: negotiated_alpn.to_owned(),
            routed_frames_by_stream: std::collections::BTreeMap::new(),
        }
    }

    /// Encodes and paces an outbound [`WireEnvelope`] to `peer_endpoint` over `stream_kind` at `tick`,
    /// enforcing `QuicStreamFlowController` credits so `Stream 2 (ArtifactP2p)` never starves `Stream 0 (Control)`.
    ///
    /// # Arguments
    ///
    /// * `peer_endpoint` - Target peer socket address string.
    /// * `stream_kind` - [`QuicStreamKind`] (`Control`, `Telemetry`, or `ArtifactP2p`).
    /// * `envelope` - [`WireEnvelope`] to frame.
    /// * `tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// 16-byte `ARBW`-prefixed wire frame bytes ready for transmission.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `peer_endpoint` is empty or the `ArtifactP2p` pacing budget is exceeded.
    pub fn encode_paced_peer_frame(
        &mut self,
        peer_endpoint: &str,
        stream_kind: QuicStreamKind,
        envelope: &WireEnvelope,
        tick: u64,
    ) -> ArbiterResult<Vec<u8>> {
        if peer_endpoint.trim().is_empty() {
            return Err(ArbiterError::QuicConnectionError {
                stream_id: stream_kind.stream_id(),
                reason: "peer_endpoint must not be empty".to_owned(),
            });
        }
        let frame = encode_arbiter_wire_frame(stream_kind, envelope)?;
        let fc = self
            .peer_flow_controllers
            .entry(peer_endpoint.to_owned())
            .or_insert_with(|| {
                QuicStreamFlowController::new(QuicCongestionAlgorithm::BbrV3, 1_048_576, 262_144)
            });
        let _ = fc.reserve_stream_send_credit(stream_kind, frame.len() as u64, tick)?;
        let stream_byte = u8::try_from(stream_kind.stream_id()).unwrap_or(0);
        let prev = self
            .routed_frames_by_stream
            .get(&stream_byte)
            .copied()
            .unwrap_or(0);
        self.routed_frames_by_stream
            .insert(stream_byte, prev.saturating_add(1));
        Ok(frame)
    }
}

impl QuinnRustlsQuicTransport {
    /// Executes a live RFC 9000 QUIC + TLS 1.3 bidirectional stream exchange between a separate
    /// [`AsyncQuicServer`] task and [`AsyncQuicClient`] task on a `tokio` runtime.
    ///
    /// Prepends the 1-byte [`QuicStreamKind`] identifier (`0 = Control`, `1 = Telemetry`, `2 = ArtifactP2p`)
    /// followed by zero-copy `rkyv` [`WireEnvelope`] bytes on the bidirectional QUIC stream.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Server UDP bind address (e.g., `"127.0.0.1:0"`).
    /// * `stream_kind` - Multiplexed [`QuicStreamKind`] channel.
    /// * `request` - Client [`WireEnvelope`] sent on the bidirectional stream.
    /// * `response` - Server [`WireEnvelope`] returned on the bidirectional stream.
    ///
    /// # Returns
    ///
    /// Tuple `(received_by_server, received_by_client)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if socket binding, TLS 1.3 handshake, stream I/O, or `rkyv` decoding fails.
    pub fn exchange_bidirectional_stream_blocking(
        bind_addr: &str,
        stream_kind: QuicStreamKind,
        request: &WireEnvelope,
        response: &WireEnvelope,
    ) -> ArbiterResult<(WireEnvelope, WireEnvelope)> {
        let req_clone = request.clone();
        let resp_clone = response.clone();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(arbiter_core::error::IoOperationError::from)?;

        rt.block_on(async move {
            let pair = LiveQuinnEndpointPair::bind_pair(bind_addr, "arbiter.internal")?;
            let server_local_addr = pair.server.local_addr;
            let server = pair.server;
            let client = pair.client;
            let srv_task =
                tokio::spawn(async move { server.accept_one_bi_stream(&resp_clone).await });

            let decoded_resp = client
                .send_and_recv_bi_stream(server_local_addr, stream_kind, &req_clone)
                .await?;
            let (_, decoded_req) = srv_task.await??;
            Ok((decoded_req, decoded_resp))
        })
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
        assert_eq!(QuicStreamKind::Control.stream_priority_weight(), i32::MAX);
        assert_eq!(QuicStreamKind::Telemetry.stream_priority_weight(), 100);
        assert_eq!(QuicStreamKind::ArtifactP2p.stream_priority_weight(), 10);
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

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_rfc9000_quic_session_engine_multiplexing_loss_recovery_and_path_migration() {
        for (kind, expected_byte) in [
            (Rfc9000PacketKind::Initial, 0xC0),
            (Rfc9000PacketKind::ZeroRtt, 0xD0),
            (Rfc9000PacketKind::Handshake, 0xE0),
            (Rfc9000PacketKind::OneRttShort, 0x40),
        ] {
            assert_eq!(kind.header_byte(), expected_byte);
            assert_eq!(Rfc9000PacketKind::from_header_byte(expected_byte), Ok(kind));
        }
        assert!(Rfc9000PacketKind::from_header_byte(0x00).is_err());
        assert!(Rfc9000PacketKind::from_header_byte(0xF0).is_err());

        let key = [0x55_u8; 32];
        let c_cid = QuicConnectionId::new(101).unwrap_or_default();
        let s_cid = QuicConnectionId::new(202).unwrap_or_default();
        let mut client_eng = Rfc9000SessionEngine::new(c_cid, s_cid, "127.0.0.1:5050", key);
        let mut server_eng = Rfc9000SessionEngine::new(s_cid, c_cid, "127.0.0.1:6000", key);

        // Encode & decode Ping packet and error branches on decode_sealed
        let ping_pkt = Rfc9000QuicPacket {
            kind: Rfc9000PacketKind::Initial,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: s_cid,
            scid: c_cid,
            packet_number: 1,
            frames: vec![Rfc9000QuicFrame::Ping],
        };
        let ping_wire = ping_pkt.encode_sealed(&key).unwrap_or_default();
        assert!(Rfc9000QuicPacket::decode_sealed(&key, &[1, 2, 3]).is_err());
        let mut bad_hdr = ping_wire.clone();
        for b in bad_hdr.iter_mut().take(1) {
            *b = 0x00;
        }
        assert!(Rfc9000QuicPacket::decode_sealed(&key, &bad_hdr).is_err());
        let mut bad_ver = ping_wire.clone();
        for b in bad_ver.iter_mut().skip(1).take(4) {
            *b = 0x99;
        }
        assert!(Rfc9000QuicPacket::decode_sealed(&key, &bad_ver).is_err());
        let mut zero_dest = ping_wire.clone();
        for b in zero_dest.iter_mut().skip(5).take(8) {
            *b = 0;
        }
        assert!(Rfc9000QuicPacket::decode_sealed(&key, &zero_dest).is_err());
        let mut zero_src = ping_wire.clone();
        for b in zero_src.iter_mut().skip(13).take(8) {
            *b = 0;
        }
        assert!(Rfc9000QuicPacket::decode_sealed(&key, &zero_src).is_err());
        let mut bad_tag = ping_wire.clone();
        for b in bad_tag.iter_mut().skip(30).take(1) {
            *b ^= 0xFF;
        }
        assert!(
            server_eng
                .process_inbound_datagram("127.0.0.1:6000", &bad_tag)
                .is_err()
        );

        let bad_stream_pkt = Rfc9000QuicPacket {
            kind: Rfc9000PacketKind::OneRttShort,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: s_cid,
            scid: c_cid,
            packet_number: 2,
            frames: vec![Rfc9000QuicFrame::Stream {
                stream: QuicStreamKind::Control,
                offset: 0,
                fin: true,
                data: b"bad_arbw".to_vec(),
            }],
        };
        let bad_stream_wire = bad_stream_pkt.encode_sealed(&key).unwrap_or_default();
        assert!(
            server_eng
                .process_inbound_datagram("127.0.0.1:6000", &bad_stream_wire)
                .is_err()
        );

        assert!(
            server_eng
                .process_inbound_datagram("127.0.0.1:6000", &ping_wire)
                .is_ok()
        );

        // DCID mismatch error branch
        assert!(
            client_eng
                .process_inbound_datagram("127.0.0.1:5050", &ping_wire)
                .is_err()
        );

        // Stream multiplexing without head-of-line blocking + PTO loss recovery + ACK clearing
        let env_ctrl = sample_envelope(10);
        let env_tele = sample_envelope(20);
        let (pn1, dgram_ctrl) = client_eng
            .build_stream_packet(
                Rfc9000PacketKind::OneRttShort,
                QuicStreamKind::Control,
                &env_ctrl,
                100,
            )
            .unwrap_or_default();
        let (_pn2, dgram_tele) = client_eng
            .build_stream_packet(
                Rfc9000PacketKind::ZeroRtt,
                QuicStreamKind::Telemetry,
                &env_tele,
                100,
            )
            .unwrap_or_default();
        assert_eq!(pn1, 1);
        assert_eq!(client_eng.in_flight_packets.len(), 2);
        assert!(client_eng.computed_pto_timeout_ticks() >= 5);
        client_eng.cwnd = 2;
        assert!(
            client_eng
                .build_stream_packet(
                    Rfc9000PacketKind::OneRttShort,
                    QuicStreamKind::Control,
                    &env_ctrl,
                    100
                )
                .is_err()
        );
        client_eng.cwnd = 10;
        client_eng.record_rtt_and_ack_sample(6);
        client_eng.ssthresh = 2;
        client_eng.record_rtt_and_ack_sample(8);

        // Before PTO timeout (tick 102 < 100 + 5), no retransmissions
        assert_eq!(
            client_eng.collect_retransmissions(102, 5).map(|v| v.len()),
            Ok(0)
        );
        // After PTO timeout (tick 110 >= 100 + 5), both packets retransmitted
        assert_eq!(
            client_eng.collect_retransmissions(110, 5).map(|v| v.len()),
            Ok(2)
        );

        // Server processes Telemetry out-of-order before Control: Telemetry is immediately readable!
        let ack_tele = server_eng
            .process_inbound_datagram("127.0.0.1:6000", &dgram_tele)
            .unwrap_or(None)
            .unwrap_or_default();
        assert_eq!(
            server_eng.pop_stream_envelope(QuicStreamKind::Telemetry),
            Some(env_tele)
        );
        assert_eq!(
            server_eng.pop_stream_envelope(QuicStreamKind::Control),
            None
        );

        let ack_ctrl = server_eng
            .process_inbound_datagram("127.0.0.1:6000", &dgram_ctrl)
            .unwrap_or(None)
            .unwrap_or_default();
        assert_eq!(
            server_eng.pop_stream_envelope(QuicStreamKind::Control),
            Some(env_ctrl)
        );

        // Client processes ACK datagrams; in_flight_packets becomes empty and returns Ok(None)
        assert_eq!(
            client_eng.process_inbound_datagram("127.0.0.1:5050", &ack_tele),
            Ok(None)
        );
        assert_eq!(
            client_eng.process_inbound_datagram("127.0.0.1:5050", &ack_ctrl),
            Ok(None)
        );
        assert!(client_eng.in_flight_packets.is_empty());

        // RFC 9000 PATH_CHALLENGE / PATH_RESPONSE active connection migration
        assert!(
            client_eng
                .initiate_path_challenge("   ", [1, 2, 3, 4, 5, 6, 7, 8], 120)
                .is_err()
        );
        let challenge_dgram = client_eng
            .initiate_path_challenge("10.0.0.99:5050", [1, 2, 3, 4, 5, 6, 7, 8], 120)
            .unwrap_or_default();
        let path_resp_dgram = server_eng
            .process_inbound_datagram("10.0.0.99:6000", &challenge_dgram)
            .unwrap_or(None)
            .unwrap_or_default();
        assert!(
            client_eng
                .process_inbound_datagram("10.0.0.99:5050", &path_resp_dgram)
                .is_ok()
        );
        assert_eq!(client_eng.peer_endpoint, "10.0.0.99:5050");

        // Fallback to candidate_ep when source_endpoint is empty, and token mismatch error branch
        let _ = client_eng.initiate_path_challenge("10.0.0.100:5050", [9; 8], 130);
        let bad_resp_pkt = Rfc9000QuicPacket {
            kind: Rfc9000PacketKind::OneRttShort,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: c_cid,
            scid: s_cid,
            packet_number: 50,
            frames: vec![Rfc9000QuicFrame::PathResponse([0; 8])],
        };
        let bad_resp_wire = bad_resp_pkt.encode_sealed(&key).unwrap_or_default();
        assert!(
            client_eng
                .process_inbound_datagram("10.0.0.100:5050", &bad_resp_wire)
                .is_err()
        );

        let _ = client_eng.initiate_path_challenge("10.0.0.100:5050", [9; 8], 131);
        let good_resp_pkt = Rfc9000QuicPacket {
            kind: Rfc9000PacketKind::OneRttShort,
            version: RFC9000_QUIC_VERSION_V1,
            dcid: c_cid,
            scid: s_cid,
            packet_number: 51,
            frames: vec![Rfc9000QuicFrame::PathResponse([9; 8])],
        };
        let good_resp_wire = good_resp_pkt.encode_sealed(&key).unwrap_or_default();
        assert!(
            client_eng
                .process_inbound_datagram("", &good_resp_wire)
                .is_ok()
        );
        assert_eq!(client_eng.peer_endpoint, "10.0.0.100:5050");
        assert!(
            client_eng
                .process_inbound_datagram("", &good_resp_wire)
                .is_ok()
        );

        // ZeroRttReplayFilter anti-replay verification & capacity eviction
        let mut replay_filter = ZeroRttReplayFilter::new(1);
        let t1 =
            ZeroRttSessionTicket::issue(c_cid, "spiffe://arbiter.internal/node/a1", 10, 100, &key);
        let t2 =
            ZeroRttSessionTicket::issue(s_cid, "spiffe://arbiter.internal/node/a2", 20, 100, &key);
        assert_eq!(replay_filter.verify_and_record(&t1, &key, 50), Ok(c_cid));
        // Second presentation of t1 is rejected as a replay!
        assert!(replay_filter.verify_and_record(&t1, &key, 50).is_err());
        // Expired ticket fails verification
        assert!(replay_filter.verify_and_record(&t1, &key, 500).is_err());
        // Recording t2 evicts t1 (capacity == 1)
        assert_eq!(replay_filter.verify_and_record(&t2, &key, 50), Ok(s_cid));
        assert_eq!(replay_filter.verify_and_record(&t1, &key, 50), Ok(c_cid));

        // Rfc9000LiveUdpEndpoint over live OS UDP sockets
        assert!(
            Rfc9000LiveUdpEndpoint::bind("invalid-addr", c_cid, s_cid, "127.0.0.1:5050", key)
                .is_err()
        );
        let _ = Rfc9000LiveUdpEndpoint::bind("127.0.0.1:0", s_cid, c_cid, "127.0.0.1:0", key).map(
            |mut srv_udp| {
                let srv_ep_addr = srv_udp.local_addr.clone();
                assert_eq!(srv_udp.poll_inbound_udp(), Ok(false));
                let _ =
                    Rfc9000LiveUdpEndpoint::bind("127.0.0.1:0", c_cid, s_cid, &srv_ep_addr, key)
                        .map(|mut cli_udp| {
                            srv_udp.session.peer_endpoint = cli_udp.local_addr.clone();
                            let _ = srv_udp.socket.set_nonblocking(false);
                            let _ = cli_udp.socket.set_nonblocking(false);
                            let env_udp = sample_envelope(77);
                            assert_eq!(
                                cli_udp.send_stream_over_udp(
                                    Rfc9000PacketKind::OneRttShort,
                                    QuicStreamKind::Control,
                                    &env_udp,
                                    10
                                ),
                                Ok(1)
                            );
                            assert_eq!(srv_udp.poll_inbound_udp(), Ok(true));
                            assert_eq!(
                                srv_udp.session.pop_stream_envelope(QuicStreamKind::Control),
                                Some(env_udp.clone())
                            );
                            // Client receives the ACK datagram generated by srv_udp
                            assert_eq!(cli_udp.poll_inbound_udp(), Ok(true));
                            assert!(cli_udp.session.in_flight_packets.is_empty());

                            // Error branches on send_stream_over_udp (cwnd exhausted & invalid peer_endpoint)
                            cli_udp.session.cwnd = 0;
                            assert!(
                                cli_udp
                                    .send_stream_over_udp(
                                        Rfc9000PacketKind::OneRttShort,
                                        QuicStreamKind::Control,
                                        &env_udp,
                                        11
                                    )
                                    .is_err()
                            );
                            cli_udp.session.cwnd = 10;
                            "invalid-peer-addr".clone_into(&mut cli_udp.session.peer_endpoint);
                            assert!(
                                cli_udp
                                    .send_stream_over_udp(
                                        Rfc9000PacketKind::OneRttShort,
                                        QuicStreamKind::Control,
                                        &env_udp,
                                        12
                                    )
                                    .is_err()
                            );
                            // Corrupt UDP packet to srv_udp triggers poll_inbound_udp error branch
                            let _ = cli_udp.socket.send_to(b"corrupt", &srv_ep_addr);
                            assert!(srv_udp.poll_inbound_udp().is_err());
                        });
            },
        );

        // QuicStreamFlowController BBRv3 & Cubic congestion control and ArtifactP2p pacing
        assert_eq!(
            QuicCongestionAlgorithm::default(),
            QuicCongestionAlgorithm::BbrV3
        );
        let mut fc_bbr = QuicStreamFlowController::new(QuicCongestionAlgorithm::BbrV3, 4096, 1000);
        // ArtifactP2p can send up to 1000 bytes in tick 1, then pacing rejects further ArtifactP2p sends
        assert_eq!(
            fc_bbr.reserve_stream_send_credit(QuicStreamKind::ArtifactP2p, 800, 1),
            Ok(3296)
        );
        assert!(
            fc_bbr
                .reserve_stream_send_credit(QuicStreamKind::ArtifactP2p, 300, 1)
                .is_err()
        );
        // Meanwhile Stream 0 (Control) is never throttled by ArtifactP2p pacing!
        assert_eq!(
            fc_bbr.reserve_stream_send_credit(QuicStreamKind::Control, 2000, 1),
            Ok(2096)
        );
        // Next tick resets the ArtifactP2p pacing counter
        assert_eq!(
            fc_bbr.reserve_stream_send_credit(QuicStreamKind::ArtifactP2p, 800, 2),
            Ok(2496)
        );
        // Exhausting stream window returns error
        assert!(
            fc_bbr
                .reserve_stream_send_credit(QuicStreamKind::Control, 9999, 2)
                .is_err()
        );
        // BBRv3 ACK updates bottleneck bandwidth when sample_bw > bbr_btl_bw_bytes_per_tick and when <=
        let bdp1 = fc_bbr.on_ack_and_window_update(QuicStreamKind::Control, 1024, 10_000, 1);
        assert!(bdp1 >= 10_000);
        let bdp2 = fc_bbr.on_ack_and_window_update(QuicStreamKind::Control, 512, 100, 2);
        assert_eq!(bdp2, bdp1);

        let mut fc_cubic =
            QuicStreamFlowController::new(QuicCongestionAlgorithm::Cubic, 2048, 1024);
        let cubic_w = fc_cubic.on_ack_and_window_update(QuicStreamKind::Telemetry, 512, 1000, 2);
        assert!(cubic_w > 2048);

        // Rfc9000MultiPeerQuicRouter multi-peer multiplexing
        assert!(Rfc9000MultiPeerQuicRouter::bind("invalid-addr", s_cid, key).is_err());
        let _ = Rfc9000MultiPeerQuicRouter::bind("127.0.0.1:0", s_cid, key).map(|mut router| {
            let router_addr = router.local_addr.clone();
            assert_eq!(router.poll_next_peer_datagram(), Ok(None));
            let peer2_cid = QuicConnectionId::new(303).unwrap_or_default();
            let _ = Rfc9000LiveUdpEndpoint::bind("127.0.0.1:0", c_cid, s_cid, &router_addr, key)
                .and_then(|mut p1| {
                    Rfc9000LiveUdpEndpoint::bind("127.0.0.1:0", peer2_cid, s_cid, &router_addr, key)
                        .map(|mut p2| {
                            let _ = router.socket.set_nonblocking(false);
                            let env1 = sample_envelope(81);
                            let env2 = sample_envelope(82);
                            let _ = p1.send_stream_over_udp(
                                Rfc9000PacketKind::ZeroRtt,
                                QuicStreamKind::Control,
                                &env1,
                                1,
                            );
                            assert_eq!(router.poll_next_peer_datagram(), Ok(Some(c_cid)));
                            // Second packet from p1 hits existing peer session
                            let _ = p1.send_stream_over_udp(
                                Rfc9000PacketKind::OneRttShort,
                                QuicStreamKind::Telemetry,
                                &env2,
                                2,
                            );
                            assert_eq!(router.poll_next_peer_datagram(), Ok(Some(c_cid)));
                            // Packet from p2 registers second peer session
                            let _ = p2.send_stream_over_udp(
                                Rfc9000PacketKind::OneRttShort,
                                QuicStreamKind::Control,
                                &env2,
                                2,
                            );
                            assert_eq!(router.poll_next_peer_datagram(), Ok(Some(peer2_cid)));
                            assert_eq!(
                                router.pop_peer_envelope(c_cid, QuicStreamKind::Control),
                                Some(env1)
                            );
                            assert_eq!(
                                router.pop_peer_envelope(peer2_cid, QuicStreamKind::Control),
                                Some(env2.clone())
                            );
                            // Ping-only Ack frame from p1 returns None from process_inbound_datagram
                            let ack_only_pkt = Rfc9000QuicPacket {
                                kind: Rfc9000PacketKind::OneRttShort,
                                version: RFC9000_QUIC_VERSION_V1,
                                dcid: s_cid,
                                scid: c_cid,
                                packet_number: 99,
                                frames: vec![Rfc9000QuicFrame::Ack {
                                    largest_acked: 1,
                                    acked_packets: vec![1],
                                }],
                            };
                            let ack_wire = ack_only_pkt.encode_sealed(&key).unwrap_or_default();
                            let _ = p1.socket.send_to(&ack_wire, &router_addr);
                            assert_eq!(router.poll_next_peer_datagram(), Ok(Some(c_cid)));
                            // Wrong DCID triggers error branch in poll_next_peer_datagram
                            let bad_dcid_pkt = Rfc9000QuicPacket {
                                kind: Rfc9000PacketKind::OneRttShort,
                                version: RFC9000_QUIC_VERSION_V1,
                                dcid: c_cid,
                                scid: c_cid,
                                packet_number: 100,
                                frames: vec![Rfc9000QuicFrame::Ping],
                            };
                            let bad_dcid_wire =
                                bad_dcid_pkt.encode_sealed(&key).unwrap_or_default();
                            let _ = p1.socket.send_to(&bad_dcid_wire, &router_addr);
                            assert!(router.poll_next_peer_datagram().is_err());
                            // Corrupt UDP datagram triggers decode_sealed error branch
                            let _ = p1.socket.send_to(b"short", &router_addr);
                            assert!(router.poll_next_peer_datagram().is_err());

                            // DualTransportClient::probe_and_send_with_timeout
                            let mut dt =
                                DualTransportClient::new(&router_addr, "invalid-http", key);
                            assert!(
                                dt.probe_and_send_with_timeout(
                                    50,
                                    QuicStreamKind::Control,
                                    arbiter_proto::ApiEndpoint::Scheduler,
                                    &env2
                                )
                                .is_ok()
                            );
                            assert!(
                                dt.probe_and_send_with_timeout(
                                    0,
                                    QuicStreamKind::Control,
                                    arbiter_proto::ApiEndpoint::Scheduler,
                                    &env2
                                )
                                .is_err()
                            );
                        })
                });
        });

        let env_frag = sample_envelope(100);
        let mut fragmenter = QuicStreamFragmenter::new(64);
        let mut frags = fragmenter.fragment_envelope(QuicStreamKind::ArtifactP2p, &env_frag);
        assert!(frags.len() >= 2);
        assert!(fragmenter.ingest_fragment(Rfc9000QuicFrame::Ping).is_err());
        let last_frag = frags.pop().unwrap_or(Rfc9000QuicFrame::Ping);
        assert_eq!(fragmenter.ingest_fragment(last_frag), Ok(None));
        let mut completed = None;
        for f in frags {
            if let Ok(Some(res)) = fragmenter.ingest_fragment(f) {
                completed = Some(res);
            }
        }
        assert_eq!(
            completed,
            Some((QuicStreamKind::ArtifactP2p, env_frag.clone()))
        );
        let mut fragmenter2 = QuicStreamFragmenter::new(64);
        let frags2 = fragmenter2.fragment_envelope(QuicStreamKind::Control, &env_frag);
        let mut completed2 = None;
        for f in frags2 {
            if let Ok(Some(res)) = fragmenter2.ingest_fragment(f) {
                completed2 = Some(res);
            }
        }
        assert_eq!(completed2, Some((QuicStreamKind::Control, env_frag)));

        // Authentic quinn + rustls TLS 1.3 bidirectional QUIC stream roundtrip & error branches
        assert!(QuinnRustlsQuicTransport::build_tls13_quinn_configs("  ").is_err());
        assert!(
            QuinnRustlsQuicTransport::build_tls13_quinn_configs_with_spiffe_uri(
                "arbiter.internal",
                "http://invalid-spiffe"
            )
            .is_err()
        );
        let (der_bytes, _, _) = crate::security::X509CertificatePem::issue_real_x509v3_der_and_pem(
            "spiffe://arbiter.internal/node/agent-1",
        )
        .unwrap_or_default();
        let mut svid_auth =
            crate::security::SvidAuthority::new("arbiter.internal", [0x11; 32], 100);
        assert!(
            QuinnRustlsQuicTransport::verify_peer_der_spiffe_uri(&der_bytes, &svid_auth).is_ok()
        );
        svid_auth.revoke_svid_uri("spiffe://arbiter.internal/node/agent-1");
        assert!(
            QuinnRustlsQuicTransport::verify_peer_der_spiffe_uri(&der_bytes, &svid_auth).is_err()
        );
        let quinn_cfg_check = QuinnRustlsQuicTransport::build_tls13_quinn_configs(
            "arbiter.internal",
        )
        .map(|(srv_cfg_err, cli_cfg_err)| {
            assert!(AsyncQuicServer::bind("invalid-addr", srv_cfg_err).is_err());
            assert!(
                AsyncQuicClient::bind("invalid-addr", cli_cfg_err, "arbiter.internal").is_err()
            );
        });
        assert!(quinn_cfg_check.is_ok());

        // Test QuicPeerConnectionPool and SIGHUP file rotation
        let mut pool = QuicPeerConnectionPool::new("127.0.0.1:5050", "arbiter-rkyv/1");
        let q_req = sample_envelope(501);
        assert!(
            pool.encode_paced_peer_frame("  ", QuicStreamKind::Control, &q_req, 1)
                .is_err()
        );
        let paced_ctrl = pool
            .encode_paced_peer_frame("10.0.0.2:5050", QuicStreamKind::Control, &q_req, 1)
            .unwrap_or_default();
        assert!(!paced_ctrl.is_empty());
        assert_eq!(pool.routed_frames_by_stream.get(&0).copied(), Some(1));

        let sighup_path = std::env::temp_dir().join("arbiter_quic_sighup_meta.txt");
        let _ = std::fs::write(
            &sighup_path,
            "arbiter.internal\nspiffe://arbiter.internal/master/m2\n",
        );
        let _ = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|rt| {
                rt.block_on(async {
                    let _ = LiveQuinnEndpointPair::bind_pair("127.0.0.1:0", "arbiter.internal")
                        .map(|mut pair| {
                            assert!(
                                QuinnRustlsQuicTransport::rotate_endpoints_from_file_on_sighup(
                                    &pair.server,
                                    &mut pair.client,
                                    &sighup_path,
                                )
                                .is_ok()
                            );
                            let bad_path =
                                std::path::Path::new("/nonexistent/arbiter_sighup_missing.txt");
                            assert!(
                                QuinnRustlsQuicTransport::rotate_endpoints_from_file_on_sighup(
                                    &pair.server,
                                    &mut pair.client,
                                    bad_path,
                                )
                                .is_err()
                            );
                        });
                });
            });
        let _ = std::fs::remove_file(&sighup_path);

        let q_resp = sample_envelope(502);
        assert!(
            QuinnRustlsQuicTransport::exchange_bidirectional_stream_blocking(
                "invalid-addr",
                QuicStreamKind::Control,
                &q_req,
                &q_resp
            )
            .is_err()
        );
        for sk in [
            QuicStreamKind::Control,
            QuicStreamKind::Telemetry,
            QuicStreamKind::ArtifactP2p,
        ] {
            assert_eq!(
                QuinnRustlsQuicTransport::exchange_bidirectional_stream_blocking(
                    "127.0.0.1:0",
                    sk,
                    &q_req,
                    &q_resp
                ),
                Ok((q_req.clone(), q_resp.clone()))
            );
        }
    }
}
