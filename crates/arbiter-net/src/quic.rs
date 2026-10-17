//! Framed bidirectional QUIC transport abstraction with multiplexed streams (`arbiter-net::quic`).
//!
//! Supports length-delimited zero-copy `rkyv` framing across multiplexed QUIC streams
//! (`Control`, `Telemetry`, and `ArtifactP2p`), bounded queue backpressure, and keep-alive
//! idle timeout tracking.

use std::collections::VecDeque;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_proto::WireEnvelope;
use serde::{Deserialize, Serialize};

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
    fn test_quic_framing_multiplexing_backpressure_and_keep_alive() {
        let env = sample_envelope(1);
        let framed = encode_quic_frame(&env);
        assert_eq!(decode_quic_frame(&framed), Ok(env.clone()));

        // Short frame (< 4 bytes) and length-mismatched frame rejected
        assert!(decode_quic_frame(&[1, 2]).is_err());
        assert!(decode_quic_frame(&[99, 0, 0, 0, 1, 2]).is_err());

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
    }
}
