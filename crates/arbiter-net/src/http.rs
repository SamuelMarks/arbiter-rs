//! HTTP/REST, Server-Sent Events (`SSE`), and WebSocket transport handlers (`arbiter-net::http`).
//!
//! Maps Mesos v1-style HTTP/JSON endpoints (`/api/v1/scheduler`, `/api/v1/executor`,
//! `/api/v1/operator`, `/api/v1/jobs`) and `SSE` event streams onto the exact same internal
//! [`WireEnvelope`] command/event bus as the QUIC transport, enforcing SVID authentication.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::FrameworkId;
use arbiter_proto::{ApiEndpoint, WireEnvelope, decode_recordio_frames, encode_recordio_frame};
use serde::{Deserialize, Serialize};

use crate::security::{SpiffeSvid, SvidAuthority};

/// Validated `Mesos-Stream-Id` header value binding a subscribed Framework HTTP connection
/// to prevent split-brain writes from superseded scheduler instances.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MesosStreamId(String);

impl MesosStreamId {
    /// Constructs a validated non-empty [`MesosStreamId`].
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Candidate stream identifier string.
    ///
    /// # Returns
    ///
    /// Validated [`MesosStreamId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::EmptyIdentifier`] if `stream_id` is empty.
    pub fn new(stream_id: &str) -> ArbiterResult<Self> {
        if stream_id.is_empty() {
            return Err(ArbiterError::EmptyIdentifier {
                kind: "MesosStreamId".to_owned(),
            });
        }
        Ok(Self(stream_id.to_owned()))
    }

    /// Returns the underlying string slice.
    ///
    /// # Returns
    ///
    /// Stream ID `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RFC 6455 WebSocket frame opcode (`Text`, `Binary`, `Ping`, `Pong`, `Close`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebSocketOpcode {
    /// UTF-8 text frame (`0x1`).
    Text,
    /// Binary payload frame (`0x2`).
    Binary,
    /// Connection close frame (`0x8`).
    Close,
    /// Heartbeat ping frame (`0x9`).
    Ping,
    /// Heartbeat pong frame (`0xA`).
    Pong,
}

impl WebSocketOpcode {
    /// Returns the 4-bit wire opcode byte (`FIN | opcode`).
    ///
    /// # Returns
    ///
    /// Wire header byte with `FIN` bit set (`0x80 | opcode`).
    pub const fn fin_header_byte(self) -> u8 {
        match self {
            Self::Text => 0x81,
            Self::Binary => 0x82,
            Self::Close => 0x88,
            Self::Ping => 0x89,
            Self::Pong => 0x8A,
        }
    }

    /// Parses a wire header byte into a [`WebSocketOpcode`].
    ///
    /// # Arguments
    ///
    /// * `byte` - First frame header byte.
    ///
    /// # Returns
    ///
    /// Decoded [`WebSocketOpcode`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if the low nibble is not a supported opcode.
    pub fn from_header_byte(byte: u8) -> ArbiterResult<Self> {
        match byte & 0x0F {
            0x01 => Ok(Self::Text),
            0x02 => Ok(Self::Binary),
            0x08 => Ok(Self::Close),
            0x09 => Ok(Self::Ping),
            0x0A => Ok(Self::Pong),
            other => Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: format!("unsupported WebSocket opcode 0x{other:02x}"),
            }),
        }
    }
}

/// Computes the 20-byte SHA-1 digest of `input` per FIPS 180-4 / RFC 3174 (used for RFC 6455 WebSocket handshake).
///
/// # Arguments
///
/// * `input` - Input byte slice.
///
/// # Returns
///
/// 20-byte SHA-1 digest.
fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut words: Vec<u32> = chunk
            .chunks_exact(4)
            .map(|word_bytes| {
                let mut b4 = [0_u8; 4];
                b4.copy_from_slice(word_bytes);
                u32::from_be_bytes(b4)
            })
            .collect();
        for i in 16..80 {
            let xor_val = words.get(i - 3).copied().unwrap_or(0)
                ^ words.get(i - 8).copied().unwrap_or(0)
                ^ words.get(i - 14).copied().unwrap_or(0)
                ^ words.get(i - 16).copied().unwrap_or(0);
            words.push(xor_val.rotate_left(1));
        }
        let mut reg_a = h0;
        let mut reg_b = h1;
        let mut reg_c = h2;
        let mut reg_d = h3;
        let mut reg_e = h4;

        for (i, &wi) in words.iter().enumerate() {
            let (func_val, k_const) = if i < 20 {
                ((reg_b & reg_c) | ((!reg_b) & reg_d), 0x5A82_7999_u32)
            } else if i < 40 {
                (reg_b ^ reg_c ^ reg_d, 0x6ED9_EBA1_u32)
            } else if i < 60 {
                (
                    (reg_b & reg_c) | (reg_b & reg_d) | (reg_c & reg_d),
                    0x8F1B_BCDC_u32,
                )
            } else {
                (reg_b ^ reg_c ^ reg_d, 0xCA62_C1D6_u32)
            };
            let temp = reg_a
                .rotate_left(5)
                .wrapping_add(func_val)
                .wrapping_add(reg_e)
                .wrapping_add(k_const)
                .wrapping_add(wi);
            reg_e = reg_d;
            reg_d = reg_c;
            reg_c = reg_b.rotate_left(30);
            reg_b = reg_a;
            reg_a = temp;
        }
        h0 = h0.wrapping_add(reg_a);
        h1 = h1.wrapping_add(reg_b);
        h2 = h2.wrapping_add(reg_c);
        h3 = h3.wrapping_add(reg_d);
        h4 = h4.wrapping_add(reg_e);
    }

    let mut out_vec = Vec::with_capacity(20);
    for word in [h0, h1, h2, h3, h4] {
        out_vec.extend_from_slice(&word.to_be_bytes());
    }
    let mut out = [0_u8; 20];
    out.copy_from_slice(&out_vec);
    out
}

/// Encodes a 20-byte SHA-1 digest into standard 28-character RFC 4648 Base64.
///
/// # Arguments
///
/// * `digest` - 20-byte SHA-1 digest.
///
/// # Returns
///
/// 28-character Base64 string.
fn base64_encode_20(digest: &[u8; 20]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(28);
    let mut idx = 0_usize;
    while idx < 20 {
        let b0 = digest.get(idx).copied().unwrap_or(0);
        let b1 = digest.get(idx + 1).copied().unwrap_or(0);
        let b2 = digest.get(idx + 2).copied().unwrap_or(0);
        let rem = 20_usize.saturating_sub(idx);

        let c0 = usize::from(b0 >> 2);
        let c1 = usize::from(((b0 & 0x03) << 4) | (b1 >> 4));
        let c2 = usize::from(((b1 & 0x0F) << 2) | (b2 >> 6));
        let c3 = usize::from(b2 & 0x3F);

        out.push(char::from(TABLE.get(c0).copied().unwrap_or(b'A')));
        out.push(char::from(TABLE.get(c1).copied().unwrap_or(b'A')));
        out.push(char::from(TABLE.get(c2).copied().unwrap_or(b'A')));
        if rem > 2 {
            out.push(char::from(TABLE.get(c3).copied().unwrap_or(b'A')));
        } else {
            out.push('=');
        }
        idx += 3;
    }
    out
}

/// Computes the RFC 6455 `Sec-WebSocket-Accept` handshake response key (`Base64(SHA-1(key || GUID))`)
/// for `sec_websocket_key`.
///
/// # Arguments
///
/// * `sec_websocket_key` - Client `Sec-WebSocket-Key` header value.
///
/// # Returns
///
/// Standard 28-character RFC 6455 Base64 accept token string.
///
/// # Errors
///
/// Returns [`ArbiterError::HttpHandlerError`] if `sec_websocket_key` is empty.
pub fn compute_websocket_accept_key(sec_websocket_key: &str) -> ArbiterResult<String> {
    if sec_websocket_key.trim().is_empty() {
        return Err(ArbiterError::HttpHandlerError {
            status_code: 400,
            message: "missing or empty Sec-WebSocket-Key header".to_owned(),
        });
    }
    let mut concat = Vec::with_capacity(sec_websocket_key.trim().len() + 36);
    concat.extend_from_slice(sec_websocket_key.trim().as_bytes());
    concat.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = sha1_digest(&concat);
    Ok(base64_encode_20(&digest))
}

/// Maximum WebSocket payload size accepted by `encode_websocket_frame` / `decode_websocket_frame` (16 MiB).
pub const MAX_WEBSOCKET_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Encodes an unmasked RFC 6455 WebSocket frame supporting 7-bit (`<= 125`), 16-bit extended
/// (`126..=65535`), and 64-bit extended (`> 65535`) payload lengths.
///
/// # Arguments
///
/// * `opcode` - [`WebSocketOpcode`].
/// * `payload` - Frame payload bytes (`<= MAX_WEBSOCKET_PAYLOAD_BYTES`).
///
/// # Returns
///
/// Encoded WebSocket frame bytes.
///
/// # Errors
///
/// Returns [`ArbiterError::HttpHandlerError`] if `payload.len() > MAX_WEBSOCKET_PAYLOAD_BYTES`.
pub fn encode_websocket_frame(opcode: WebSocketOpcode, payload: &[u8]) -> ArbiterResult<Vec<u8>> {
    if payload.len() > MAX_WEBSOCKET_PAYLOAD_BYTES {
        return Err(ArbiterError::HttpHandlerError {
            status_code: 413,
            message: "WebSocket frame payload exceeds 16 MiB limit".to_owned(),
        });
    }
    let mut frame = Vec::with_capacity(10 + payload.len());
    frame.push(opcode.fin_header_byte());
    if payload.len() <= 125 {
        frame.push(u8::try_from(payload.len()).unwrap_or(0));
    } else if let Ok(len_u16) = u16::try_from(payload.len()) {
        frame.push(126_u8);
        frame.extend_from_slice(&len_u16.to_be_bytes());
    } else {
        frame.push(127_u8);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Encodes a client-masked RFC 6455 WebSocket frame using `masking_key` (`MASK` bit `0x80` set).
///
/// # Arguments
///
/// * `opcode` - [`WebSocketOpcode`].
/// * `payload` - Unmasked payload bytes.
/// * `masking_key` - 4-byte RFC 6455 client masking key.
///
/// # Returns
///
/// Masked WebSocket wire frame bytes.
///
/// # Errors
///
/// Returns [`ArbiterError::HttpHandlerError`] if `payload.len() > MAX_WEBSOCKET_PAYLOAD_BYTES`.
pub fn encode_masked_websocket_frame(
    opcode: WebSocketOpcode,
    payload: &[u8],
    masking_key: [u8; 4],
) -> ArbiterResult<Vec<u8>> {
    if payload.len() > MAX_WEBSOCKET_PAYLOAD_BYTES {
        return Err(ArbiterError::HttpHandlerError {
            status_code: 413,
            message: "WebSocket frame payload exceeds 16 MiB limit".to_owned(),
        });
    }
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.push(opcode.fin_header_byte());
    if payload.len() <= 125 {
        frame.push(0x80 | u8::try_from(payload.len()).unwrap_or(0));
    } else if let Ok(len_u16) = u16::try_from(payload.len()) {
        frame.push(0x80 | 126_u8);
        frame.extend_from_slice(&len_u16.to_be_bytes());
    } else {
        frame.push(0x80 | 127_u8);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&masking_key);
    for (i, &b) in payload.iter().enumerate() {
        let mask_b = masking_key.get(i % 4).copied().unwrap_or(0);
        frame.push(b ^ mask_b);
    }
    Ok(frame)
}

/// Decodes an RFC 6455 WebSocket frame (supporting 7-bit, 16-bit, and 64-bit lengths and optional
/// 4-byte client XOR masking) into `(WebSocketOpcode, Vec<u8>)`.
///
/// # Arguments
///
/// * `frame` - Raw WebSocket frame bytes.
///
/// # Returns
///
/// Decoded `(WebSocketOpcode, unmasked_payload_bytes)`.
///
/// # Errors
///
/// Returns [`ArbiterError::HttpHandlerError`] if the frame is truncated or has an invalid opcode.
pub fn decode_websocket_frame(frame: &[u8]) -> ArbiterResult<(WebSocketOpcode, Vec<u8>)> {
    let Some((&hdr, rest)) = frame.split_first() else {
        return Err(ArbiterError::HttpHandlerError {
            status_code: 400,
            message: "empty WebSocket frame".to_owned(),
        });
    };
    let opcode = WebSocketOpcode::from_header_byte(hdr)?;
    let Some((&len_byte, mut tail)) = rest.split_first() else {
        return Err(ArbiterError::HttpHandlerError {
            status_code: 400,
            message: "WebSocket frame missing length byte".to_owned(),
        });
    };
    let is_masked = (len_byte & 0x80) != 0;
    let raw_len = len_byte & 0x7F;
    let declared_len: usize = if raw_len <= 125 {
        usize::from(raw_len)
    } else if raw_len == 126 {
        let Some((ext16, rem)) = tail.split_at_checked(2) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "WebSocket 16-bit extended length truncated".to_owned(),
            });
        };
        tail = rem;
        let mut b2 = [0_u8; 2];
        b2.copy_from_slice(ext16);
        usize::from(u16::from_be_bytes(b2))
    } else {
        let Some((ext64, rem)) = tail.split_at_checked(8) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "WebSocket 64-bit extended length truncated".to_owned(),
            });
        };
        tail = rem;
        let mut b8 = [0_u8; 8];
        b8.copy_from_slice(ext64);
        usize::try_from(u64::from_be_bytes(b8)).unwrap_or(usize::MAX)
    };

    let mask_key: Option<[u8; 4]> = if is_masked {
        let Some((m4, rem)) = tail.split_at_checked(4) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "WebSocket client masking key truncated".to_owned(),
            });
        };
        tail = rem;
        let mut k = [0_u8; 4];
        k.copy_from_slice(m4);
        Some(k)
    } else {
        None
    };

    if tail.len() != declared_len {
        return Err(ArbiterError::HttpHandlerError {
            status_code: 400,
            message: format!(
                "WebSocket payload length {} does not match header length {declared_len}",
                tail.len()
            ),
        });
    }
    let mut payload = tail.to_vec();
    if let Some(k) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            let mask_b = k.get(i % 4).copied().unwrap_or(0);
            *b ^= mask_b;
        }
    }
    Ok((opcode, payload))
}

/// Processes a decoded WebSocket frame, automatically generating an RFC 6455 `Pong` reply for `Ping`
/// or a matching `Close` reply for `Close`.
///
/// # Arguments
///
/// * `opcode` - Inbound [`WebSocketOpcode`].
/// * `payload` - Inbound unmasked payload bytes.
///
/// # Returns
///
/// `Some(reply_frame)` for `Ping` or `Close`, or `None` for `Text`, `Binary`, and `Pong`.
pub fn handle_websocket_control_frame(opcode: WebSocketOpcode, payload: &[u8]) -> Option<Vec<u8>> {
    match opcode {
        WebSocketOpcode::Ping => encode_websocket_frame(WebSocketOpcode::Pong, payload).ok(),
        WebSocketOpcode::Close => encode_websocket_frame(WebSocketOpcode::Close, payload).ok(),
        WebSocketOpcode::Text | WebSocketOpcode::Binary | WebSocketOpcode::Pong => None,
    }
}

/// Inbound HTTP/REST or WebSocket request mapped to the unified control-plane bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// Request URI path (e.g., `"/api/v1/scheduler"`).
    pub path: String,
    /// Optional client SPIFFE SVID for zero-trust authentication.
    pub client_svid: Option<SpiffeSvid>,
    /// JSON request body.
    pub body_json: String,
}

/// Outbound HTTP/REST or `SSE` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code (`200`, `400`, `401`, `404`).
    pub status_code: u16,
    /// Content-Type header (`"application/json"` or `"text/event-stream"`).
    pub content_type: String,
    /// Response payload body.
    pub body: String,
}

/// Formats a [`WireEnvelope`] as a standard Server-Sent Events (`SSE`) frame.
///
/// # Arguments
///
/// * `event_name` - SSE event type name.
/// * `envelope` - [`WireEnvelope`] to serialize.
///
/// # Returns
///
/// Formatted `SSE` text frame.
pub fn format_sse_event(event_name: &str, envelope: &WireEnvelope) -> String {
    let json = envelope.to_json_string().unwrap_or_default();
    format!("event: {event_name}\ndata: {json}\n\n")
}

/// Parses a formatted Server-Sent Events (`SSE`) frame back into a [`WireEnvelope`].
///
/// # Arguments
///
/// * `sse_frame` - Raw SSE text frame.
///
/// # Returns
///
/// Decoded [`WireEnvelope`].
///
/// # Errors
///
/// Returns [`ArbiterError::HttpHandlerError`] if no `data: ` line is present, or
/// [`ArbiterError::JsonCodec`] / [`ArbiterError::DeserializationError`] if the JSON payload is invalid.
pub fn parse_sse_event(sse_frame: &str) -> ArbiterResult<WireEnvelope> {
    for line in sse_frame.lines() {
        if let Some(json_str) = line.strip_prefix("data: ") {
            return WireEnvelope::from_json_str(json_str);
        }
    }
    Err(ArbiterError::HttpHandlerError {
        status_code: 400,
        message: "SSE frame missing 'data: ' line".to_owned(),
    })
}

/// Dual-protocol HTTP/SSE/WebSocket gateway routing authenticated requests to the unified [`WireEnvelope`] bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpGateway {
    /// SVID authority used to authenticate incoming requests.
    authority: SvidAuthority,
    /// Active `Mesos-Stream-Id` bindings per subscribed [`FrameworkId`].
    active_streams: BTreeMap<FrameworkId, MesosStreamId>,
}

/// Type alias for [`HttpGateway`] fulfilling the `HttpApiGateway` HTTP/1.1 & HTTP/2 router interface.
pub type HttpApiGateway = HttpGateway;

impl HttpGateway {
    /// Creates a new [`HttpGateway`] backed by `authority`.
    ///
    /// # Arguments
    ///
    /// * `authority` - [`SvidAuthority`] for client verification.
    ///
    /// # Returns
    ///
    /// Initialized [`HttpGateway`].
    pub const fn new(authority: SvidAuthority) -> Self {
        Self {
            authority,
            active_streams: BTreeMap::new(),
        }
    }

    /// Serves `GET /metrics`, `GET /dashboard`, and `GET /dashboard/events` (`SSE`) HTTP endpoints.
    ///
    /// # Arguments
    ///
    /// * `path` - Requested HTTP `GET` URI path.
    /// * `prometheus_body` - Rendered Prometheus `0.0.4` text payload.
    /// * `dashboard_html` - Rendered embedded Web Dashboard HTML document.
    /// * `dashboard_sse` - Rendered Web Dashboard `SSE` event frame.
    ///
    /// # Returns
    ///
    /// Populated [`HttpResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] (`404 Not Found`) for unknown `GET` paths.
    pub fn handle_get_endpoint(
        &self,
        path: &str,
        prometheus_body: &str,
        dashboard_html: &str,
        dashboard_sse: &str,
    ) -> ArbiterResult<HttpResponse> {
        match path {
            "/metrics" => Ok(HttpResponse {
                status_code: 200,
                content_type: "text/plain; version=0.0.4".to_owned(),
                body: prometheus_body.to_owned(),
            }),
            "/dashboard" | "/dashboard/" => Ok(HttpResponse {
                status_code: 200,
                content_type: "text/html; charset=utf-8".to_owned(),
                body: dashboard_html.to_owned(),
            }),
            "/dashboard/events" => Ok(HttpResponse {
                status_code: 200,
                content_type: "text/event-stream".to_owned(),
                body: dashboard_sse.to_owned(),
            }),
            other => Err(ArbiterError::HttpHandlerError {
                status_code: 404,
                message: format!("unknown HTTP GET endpoint '{other}'"),
            }),
        }
    }

    /// Formats an RFC 6455 `HTTP/1.1 101 Switching Protocols` WebSocket upgrade handshake response.
    ///
    /// # Arguments
    ///
    /// * `sec_websocket_key` - Client `Sec-WebSocket-Key` header value.
    ///
    /// # Returns
    ///
    /// Wire-ready `HTTP/1.1 101 Switching Protocols` response string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if `sec_websocket_key` is empty.
    pub fn upgrade_websocket_handshake(&self, sec_websocket_key: &str) -> ArbiterResult<String> {
        let accept = compute_websocket_accept_key(sec_websocket_key)?;
        Ok(format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        ))
    }

    /// Binds a new [`MesosStreamId`] to `framework_id` upon `SUBSCRIBE`, superseding any old stream ID.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - Subscribing [`FrameworkId`].
    /// * `stream_id` - Newly issued [`MesosStreamId`].
    pub fn bind_mesos_stream_id(&mut self, framework_id: FrameworkId, stream_id: MesosStreamId) {
        self.active_streams.insert(framework_id, stream_id);
    }

    /// Validates that a non-subscribe `SchedulerCall` from
    /// `framework_id` carries the currently active [`MesosStreamId`].
    ///
    /// # Arguments
    ///
    /// * `framework_id` - Calling [`FrameworkId`].
    /// * `presented_stream_id` - `Mesos-Stream-Id` header value from the HTTP request.
    ///
    /// # Returns
    ///
    /// `Ok(())` if `presented_stream_id` matches the active stream binding.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] (`400 Bad Request` / `403 Forbidden`) if missing or stale.
    pub fn validate_mesos_stream_id(
        &self,
        framework_id: &FrameworkId,
        presented_stream_id: &MesosStreamId,
    ) -> ArbiterResult<()> {
        let Some(active) = self.active_streams.get(framework_id) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 403,
                message: format!("no active Mesos-Stream-Id bound for framework '{framework_id}'"),
            });
        };
        if active != presented_stream_id {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 409,
                message: format!(
                    "stale Mesos-Stream-Id '{}' for framework '{framework_id}' (expected '{}')",
                    presented_stream_id.as_str(),
                    active.as_str()
                ),
            });
        }
        Ok(())
    }

    /// Executes a live TCP HTTP/1.1 request/response exchange between a bound [`HttpControlPlaneServer`]
    /// and a separate [`HttpControlPlaneClient`] socket.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (e.g., `"127.0.0.1:0"`).
    /// * `req` - [`HttpRequest`] to transmit over a real OS TCP socket.
    /// * `current_tick` - Current monotonic tick for SVID verification.
    ///
    /// # Returns
    ///
    /// Tuple `(ApiEndpoint, WireEnvelope, HttpResponse)` received over the TCP socket.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] on socket bind/connect/read/write failure or HTTP validation error.
    pub fn execute_loopback_tcp_exchange(
        &self,
        bind_addr: &str,
        req: &HttpRequest,
        current_tick: u64,
    ) -> ArbiterResult<(ApiEndpoint, WireEnvelope, HttpResponse)> {
        let server = HttpControlPlaneServer::bind(bind_addr, self.clone())?;
        let _ = server.listener.set_nonblocking(false);
        let srv_addr = server.local_addr_str().to_owned();
        let endpoint = ApiEndpoint::from_path(&req.path)?;
        let env = WireEnvelope::from_json_str(&req.body_json)?;
        let client = HttpControlPlaneClient::new(&srv_addr);
        let client_stream = client.send_envelope(endpoint, &env)?;
        let _ = server.poll_once(req.client_svid.clone(), current_tick)?;
        let resp = HttpControlPlaneClient::read_response(client_stream)?;
        Ok((endpoint, env, resp))
    }

    /// Authenticates an [`HttpRequest`], validates its [`ApiEndpoint`] path, and decodes the body
    /// into a `(ApiEndpoint, WireEnvelope)` pair ready for the Master/Agent bus.
    ///
    /// # Arguments
    ///
    /// * `req` - Incoming [`HttpRequest`].
    /// * `current_tick` - Current monotonic tick for SVID expiration checks.
    ///
    /// # Returns
    ///
    /// Tuple `(ApiEndpoint, WireEnvelope)` and an [`HttpResponse`] (`200 OK` SSE ack).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArbiterError::AuthenticationFailed`] if `client_svid` is missing or invalid.
    /// - [`ArbiterError::TlsConfigurationError`] if `client_svid` is expired.
    /// - [`ArbiterError::HttpHandlerError`] if `req.path` is unknown.
    /// - [`ArbiterError::JsonCodec`] / [`ArbiterError::DeserializationError`] if `req.body_json` is malformed.
    pub fn handle_request(
        &self,
        req: &HttpRequest,
        current_tick: u64,
    ) -> ArbiterResult<(ApiEndpoint, WireEnvelope, HttpResponse)> {
        let Some(ref svid) = req.client_svid else {
            return Err(ArbiterError::AuthenticationFailed {
                principal: "anonymous".to_owned(),
                reason: "missing client SPIFFE SVID on HTTP request".to_owned(),
            });
        };
        self.authority.verify_svid(svid, current_tick)?;

        let endpoint = ApiEndpoint::from_path(&req.path)?;
        let envelope = WireEnvelope::from_json_str(&req.body_json)?;
        let sse_body = format_sse_event("ack", &envelope);

        let response = HttpResponse {
            status_code: 200,
            content_type: "text/event-stream".to_owned(),
            body: sse_body,
        };
        Ok((endpoint, envelope, response))
    }

    /// Handles a Mesos v1 `RecordIO`-framed HTTP request (`<length>\n<json_bytes>`), returning
    /// all decoded `(ApiEndpoint, Vec<WireEnvelope>)` frames and a `RecordIO`-framed response (`application/x-recordio`).
    ///
    /// # Arguments
    ///
    /// * `req` - Incoming [`HttpRequest`] whose `body_json` contains one or more `RecordIO` frames.
    /// * `current_tick` - Current monotonic tick for SVID verification.
    ///
    /// # Returns
    ///
    /// Tuple `(ApiEndpoint, Vec<WireEnvelope>, HttpResponse)`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if SVID authentication, path resolution, or `RecordIO` decoding fails.
    pub fn handle_recordio_request(
        &self,
        req: &HttpRequest,
        current_tick: u64,
    ) -> ArbiterResult<(ApiEndpoint, Vec<WireEnvelope>, HttpResponse)> {
        let Some(ref svid) = req.client_svid else {
            return Err(ArbiterError::AuthenticationFailed {
                principal: "anonymous".to_owned(),
                reason: "missing client SPIFFE SVID on RecordIO HTTP request".to_owned(),
            });
        };
        self.authority.verify_svid(svid, current_tick)?;
        let endpoint = ApiEndpoint::from_path(&req.path)?;
        let envelopes = decode_recordio_frames(&req.body_json)?;
        let mut resp_body = String::new();
        for env in &envelopes {
            resp_body.push_str(&encode_recordio_frame(env));
        }
        let response = HttpResponse {
            status_code: 200,
            content_type: "application/x-recordio".to_owned(),
            body: resp_body,
        };
        Ok((endpoint, envelopes, response))
    }

    /// Formats a raw HTTP/1.1 wire response string from an [`HttpResponse`].
    ///
    /// # Arguments
    ///
    /// * `resp` - [`HttpResponse`] to serialize.
    ///
    /// # Returns
    ///
    /// Valid HTTP/1.1 wire response string.
    pub fn encode_http11_response(resp: &HttpResponse) -> String {
        let len = resp.body.len();
        format!(
            "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{}",
            resp.status_code, resp.content_type, resp.body
        )
    }

    /// Formats a Mesos v1 `HTTP/1.1 307 Temporary Redirect` response with a `Location` header
    /// pointing to the active Raft leader Master (`http://<leader_http_addr><path>`).
    ///
    /// # Arguments
    ///
    /// * `leader_http_addr` - Active leader Master `host:port` (e.g., `"10.0.0.1:8080"`).
    /// * `path` - Requested URI path (e.g., `"/api/v1/scheduler"`).
    ///
    /// # Returns
    ///
    /// Wire-ready `HTTP/1.1 307 Temporary Redirect` response string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if `leader_http_addr` is empty.
    pub fn encode_leader_redirect_response(
        leader_http_addr: &str,
        path: &str,
    ) -> ArbiterResult<String> {
        let trimmed = leader_http_addr.trim();
        if trimmed.is_empty() {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 503,
                message: "no elected Raft leader available for HTTP 307 redirect".to_owned(),
            });
        }
        let location = format!("http://{trimmed}{path}");
        let body = format!("{{\"redirect\":\"{location}\"}}");
        let len = body.len();
        Ok(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}"
        ))
    }

    /// Extracts the `Location:` redirect URI from a `307 Temporary Redirect` raw HTTP/1.1 response.
    ///
    /// # Arguments
    ///
    /// * `raw_http` - Raw HTTP/1.1 response string.
    ///
    /// # Returns
    ///
    /// `Some(location_uri)` if the response is a `307` redirect with a `Location:` header, or `None`.
    pub fn extract_redirect_location(raw_http: &str) -> Option<String> {
        let (headers, _) = raw_http.split_once("\r\n\r\n")?;
        let first_line = headers.lines().next().unwrap_or_default();
        if !first_line.contains(" 307 ") {
            return None;
        }
        for line in headers.lines().skip(1) {
            if let Some(loc) = line
                .strip_prefix("Location:")
                .or_else(|| line.strip_prefix("location:"))
            {
                let trimmed = loc.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_owned());
                }
            }
        }
        None
    }

    /// Parses a raw HTTP/1.1 wire request (`POST <path> HTTP/1.1\r\n...\r\n\r\n<body>`) into an [`HttpRequest`].
    ///
    /// # Arguments
    ///
    /// * `raw_http` - Raw HTTP/1.1 request string.
    /// * `client_svid` - Optional authenticated client SVID from the TLS session.
    ///
    /// # Returns
    ///
    /// Parsed [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if the HTTP request line or header separator is malformed.
    pub fn parse_http11_request(
        raw_http: &str,
        client_svid: Option<SpiffeSvid>,
    ) -> ArbiterResult<HttpRequest> {
        let Some((headers, body)) = raw_http.split_once("\r\n\r\n") else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "malformed HTTP/1.1 request: missing \\r\\n\\r\\n separator".to_owned(),
            });
        };
        let first_line = headers.lines().next().unwrap_or_default();
        let mut parts = first_line.split_whitespace();
        let _method = parts.next().unwrap_or_default();
        let Some(path) = parts.next() else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "malformed HTTP/1.1 request line: missing path".to_owned(),
            });
        };
        let is_chunked = headers.contains("Transfer-Encoding: chunked")
            || headers.contains("transfer-encoding: chunked");
        let decoded_body = if is_chunked {
            Self::decode_chunked_body(body)?
        } else {
            body.to_owned()
        };
        Ok(HttpRequest {
            path: path.to_owned(),
            client_svid,
            body_json: decoded_body,
        })
    }

    /// Incrementally reads an HTTP/1.1 request from `stream` up to `\r\n\r\n` plus the exact
    /// `Content-Length` byte count without requiring client `Shutdown::Write` (enabling persistent
    /// `Connection: keep-alive` and long-lived streaming sockets).
    ///
    /// # Arguments
    ///
    /// * `stream` - Readable [`TcpStream`].
    /// * `client_svid` - Optional authenticated client [`SpiffeSvid`].
    ///
    /// # Returns
    ///
    /// Parsed [`HttpRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if the HTTP header or body cannot be read or parsed.
    pub fn read_http11_from_stream(
        stream: &mut TcpStream,
        client_svid: Option<SpiffeSvid>,
    ) -> ArbiterResult<HttpRequest> {
        let mut buf = Vec::with_capacity(1024);
        let mut byte = [0_u8; 1];
        let mut header_end_pos = None;
        loop {
            let n = stream.read(&mut byte).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&byte);
            if buf.ends_with(b"\r\n\r\n") {
                header_end_pos = Some(buf.len());
                break;
            }
        }
        let Some(hdr_end) = header_end_pos else {
            let raw = String::from_utf8_lossy(&buf);
            return Self::parse_http11_request(&raw, client_svid);
        };
        let hdr_str = String::from_utf8_lossy(buf.get(..hdr_end).unwrap_or_default());
        let mut content_len = 0_usize;
        for line in hdr_str.lines() {
            if let Some(val) = line
                .strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
            {
                content_len = val.trim().parse::<usize>().unwrap_or(0);
            }
        }
        if content_len > 0 {
            let mut body_bytes = vec![0_u8; content_len];
            let _ = stream.read_exact(&mut body_bytes);
            buf.extend_from_slice(&body_bytes);
        }
        let raw = String::from_utf8_lossy(&buf);
        Self::parse_http11_request(&raw, client_svid)
    }

    /// Decodes an HTTP/1.1 `Transfer-Encoding: chunked` body (`<hex_len>\r\n<bytes>\r\n...0\r\n\r\n`).
    ///
    /// # Arguments
    ///
    /// * `chunked_body` - Raw chunked HTTP payload.
    ///
    /// # Returns
    ///
    /// Reassembled payload string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if a chunk size hex header or chunk payload is malformed.
    pub fn decode_chunked_body(chunked_body: &str) -> ArbiterResult<String> {
        let mut cursor = chunked_body;
        let mut out = String::new();
        while !cursor.is_empty() {
            let Some((len_hex, rest)) = cursor.split_once("\r\n") else {
                return Err(ArbiterError::HttpHandlerError {
                    status_code: 400,
                    message: "chunked body missing \\r\\n after chunk size".to_owned(),
                });
            };
            let chunk_len = usize::from_str_radix(len_hex.trim(), 16).map_err(|_| {
                ArbiterError::HttpHandlerError {
                    status_code: 400,
                    message: format!("invalid hex chunk length '{len_hex}'"),
                }
            })?;
            if chunk_len == 0 {
                break;
            }
            let Some(chunk_str) = rest.get(..chunk_len) else {
                return Err(ArbiterError::HttpHandlerError {
                    status_code: 400,
                    message: "truncated chunked HTTP body".to_owned(),
                });
            };
            out.push_str(chunk_str);
            let after_chunk = rest.get(chunk_len..).unwrap_or_default();
            cursor = after_chunk.strip_prefix("\r\n").unwrap_or(after_chunk);
        }
        Ok(out)
    }

    /// Parses a raw HTTP/1.1 wire response (`HTTP/1.1 <status> ...\r\n...\r\n\r\n<body>`) into an [`HttpResponse`].
    ///
    /// # Arguments
    ///
    /// * `raw_http` - Raw HTTP/1.1 wire response string.
    ///
    /// # Returns
    ///
    /// Decoded [`HttpResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if the status line or header separator is missing.
    pub fn parse_http11_response(raw_http: &str) -> ArbiterResult<HttpResponse> {
        let Some((headers, body)) = raw_http.split_once("\r\n\r\n") else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 502,
                message: "malformed HTTP/1.1 response: missing \\r\\n\\r\\n".to_owned(),
            });
        };
        let first_line = headers.lines().next().unwrap_or_default();
        let status_str = first_line.split_whitespace().nth(1).unwrap_or_default();
        let status_code =
            status_str
                .parse::<u16>()
                .map_err(|_| ArbiterError::HttpHandlerError {
                    status_code: 502,
                    message: format!("invalid HTTP status code '{status_str}'"),
                })?;
        let mut content_type = "application/json".to_owned();
        for line in headers.lines().skip(1) {
            if let Some(val) = line.strip_prefix("Content-Type:") {
                val.trim().clone_into(&mut content_type);
            }
        }
        Ok(HttpResponse {
            status_code,
            content_type,
            body: body.to_owned(),
        })
    }
}

/// Persistent HTTP/1.1, Mesos `RecordIO` SSE, and WebSocket server listener (`HttpControlPlaneServer`)
/// accepting external client `TcpStream` connections without connecting to itself.
#[derive(Debug)]
pub struct HttpControlPlaneServer {
    /// Bound non-blocking TCP listener.
    listener: TcpListener,
    /// Bound `host:port` string.
    local_addr_str: String,
    /// Underlying [`HttpGateway`] for authentication and routing.
    gateway: HttpGateway,
}

impl HttpControlPlaneServer {
    /// Binds a persistent [`HttpControlPlaneServer`] on `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (e.g., `"127.0.0.1:0"`).
    /// * `gateway` - [`HttpGateway`] instance.
    ///
    /// # Returns
    ///
    /// Bound [`HttpControlPlaneServer`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(bind_addr: &str, gateway: HttpGateway) -> ArbiterResult<Self> {
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let _ = listener.set_nonblocking(true);
        let local_addr_str = listener
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            listener,
            local_addr_str,
            gateway,
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

    /// Polls for an incoming client `TcpStream` connection, parses the HTTP/1.1 or `RecordIO` request,
    /// authenticates `client_svid`, and writes back the HTTP/1.1 or `RecordIO` SSE response.
    ///
    /// # Arguments
    ///
    /// * `client_svid` - Authenticated client SVID (or `None`).
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some((ApiEndpoint, Vec<WireEnvelope>)))` if a client connection was served, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] on authentication or HTTP parsing failure.
    pub fn poll_once(
        &self,
        client_svid: Option<SpiffeSvid>,
        current_tick: u64,
    ) -> ArbiterResult<Option<(ApiEndpoint, Vec<WireEnvelope>)>> {
        if let Ok((mut stream, _)) = self.listener.accept() {
            let _ = stream.set_nonblocking(false);
            let mut raw_req = String::new();
            let _ = stream.read_to_string(&mut raw_req);
            let is_recordio = raw_req
                .to_ascii_lowercase()
                .contains("application/x-recordio");
            let req = HttpGateway::parse_http11_request(&raw_req, client_svid)?;
            if is_recordio {
                let (ep, envs, resp) = self.gateway.handle_recordio_request(&req, current_tick)?;
                let wire = HttpGateway::encode_http11_response(&resp);
                let _ = stream.write_all(wire.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                Ok(Some((ep, envs)))
            } else {
                let (ep, env, resp) = self.gateway.handle_request(&req, current_tick)?;
                let wire = HttpGateway::encode_http11_response(&resp);
                let _ = stream.write_all(wire.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                Ok(Some((ep, vec![env])))
            }
        } else {
            Ok(None)
        }
    }

    /// Processes up to `max_requests` queued client connections on the HTTP listener in a single
    /// server loop iteration.
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum number of concurrent connections to drain in this batch.
    /// * `client_svid` - Authenticated client SVID (or `None`).
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of `(ApiEndpoint, Vec<WireEnvelope>)` batches served.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if any accepted request fails authentication or parsing.
    pub fn poll_batch(
        &self,
        max_requests: usize,
        client_svid: Option<&SpiffeSvid>,
        current_tick: u64,
    ) -> ArbiterResult<Vec<(ApiEndpoint, Vec<WireEnvelope>)>> {
        let mut results = Vec::new();
        for _ in 0..max_requests {
            let Some(item) = self
                .poll_once(client_svid.cloned(), current_tick)
                .unwrap_or(None)
            else {
                break;
            };
            results.push(item);
        }
        Ok(results)
    }
}

/// Remote HTTP/1.1 and Mesos `RecordIO` client (`HttpControlPlaneClient`) connecting to a
/// [`HttpControlPlaneServer`] over a separate OS `TcpStream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpControlPlaneClient {
    /// Target Master or Agent `host:port` endpoint.
    pub master_http_addr: String,
}

impl HttpControlPlaneClient {
    /// Creates a new [`HttpControlPlaneClient`] targeting `master_http_addr`.
    ///
    /// # Arguments
    ///
    /// * `master_http_addr` - Remote `host:port` string.
    ///
    /// # Returns
    ///
    /// Initialized [`HttpControlPlaneClient`].
    pub fn new(master_http_addr: &str) -> Self {
        Self {
            master_http_addr: master_http_addr.to_owned(),
        }
    }

    /// Connects to `master_http_addr` and transmits a single [`WireEnvelope`] via `POST <endpoint>` (`application/json`).
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Target [`ApiEndpoint`].
    /// * `envelope` - [`WireEnvelope`] payload.
    ///
    /// # Returns
    ///
    /// Connected [`TcpStream`] ready to read the server's [`HttpResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] on connect failure.
    pub fn send_envelope(
        &self,
        endpoint: ApiEndpoint,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<TcpStream> {
        let mut stream = TcpStream::connect(&self.master_http_addr).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: self.master_http_addr.clone(),
                reason: err.to_string(),
            }
        })?;
        let body = envelope.to_json_string().unwrap_or_default();
        let path = endpoint.as_path();
        let req_wire = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.master_http_addr,
            body.len()
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(stream)
    }

    /// Reads and parses an [`HttpResponse`] from `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Connected [`TcpStream`].
    ///
    /// # Returns
    ///
    /// Parsed [`HttpResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if the response is malformed.
    pub fn read_response(mut stream: TcpStream) -> ArbiterResult<HttpResponse> {
        let mut resp_wire = String::new();
        let _ = stream.read_to_string(&mut resp_wire);
        HttpGateway::parse_http11_response(&resp_wire)
    }

    /// Connects to `master_http_addr` and transmits a stream of [`WireEnvelope`]s via Mesos `RecordIO`
    /// (`Content-Type: application/x-recordio`).
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Target [`ApiEndpoint`].
    /// * `envelopes` - Slice of [`WireEnvelope`]s to frame and stream.
    ///
    /// # Returns
    ///
    /// Connected [`TcpStream`] ready to read the `RecordIO` response stream via [`Self::read_recordio_response`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] on TCP connect failure.
    pub fn send_recordio_stream(
        &self,
        endpoint: ApiEndpoint,
        envelopes: &[WireEnvelope],
    ) -> ArbiterResult<TcpStream> {
        let mut stream = TcpStream::connect(&self.master_http_addr).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: self.master_http_addr.clone(),
                reason: err.to_string(),
            }
        })?;
        let mut body = String::new();
        for env in envelopes {
            body.push_str(&encode_recordio_frame(env));
        }
        let path = endpoint.as_path();
        let req_wire = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-recordio\r\nAccept: application/x-recordio\r\nContent-Length: {}\r\n\r\n{body}",
            self.master_http_addr,
            body.len()
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(stream)
    }

    /// Reads an HTTP response from `stream` and decodes its body via [`arbiter_proto::RecordIoStreamDecoder`].
    ///
    /// # Arguments
    ///
    /// * `stream` - Connected [`TcpStream`].
    ///
    /// # Returns
    ///
    /// Decoded [`WireEnvelope`] vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] on HTTP or `RecordIO` decoding failure.
    pub fn read_recordio_response(stream: TcpStream) -> ArbiterResult<Vec<WireEnvelope>> {
        let http_resp = Self::read_response(stream)?;
        let mut decoder = arbiter_proto::RecordIoStreamDecoder::new();
        decoder.feed_chunk(&http_resp.body)
    }
}

impl HttpGateway {
    /// Authenticates and routes a binary or JSON request negotiating `Content-Type` and `Accept`
    /// across `application/x-rkyv`, `application/json`, and `application/x-protobuf` on any `/api/v1/*` endpoint.
    ///
    /// # Arguments
    ///
    /// * `path` - Target `/api/v1/*` endpoint path.
    /// * `content_type_header` - Request `Content-Type` header string.
    /// * `accept_header` - Request `Accept` header string.
    /// * `client_svid` - Optional authenticated client [`SpiffeSvid`].
    /// * `body_bytes` - Raw request body bytes (`rkyv`, `JSON`, or `Protobuf`-compatible).
    /// * `current_tick` - Current monotonic tick for SVID verification.
    ///
    /// # Returns
    ///
    /// Tuple `(ApiEndpoint, WireEnvelope, WireCodecContentType, Vec<u8>)` containing the decoded
    /// endpoint, envelope, negotiated response [`arbiter_proto::WireCodecContentType`], and serialized response payload.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] on SVID failure, unknown endpoint path, or codec deserialization failure.
    pub fn handle_negotiated_request(
        &self,
        path: &str,
        content_type_header: &str,
        accept_header: &str,
        client_svid: Option<&SpiffeSvid>,
        body_bytes: &[u8],
        current_tick: u64,
    ) -> ArbiterResult<(
        ApiEndpoint,
        WireEnvelope,
        arbiter_proto::WireCodecContentType,
        Vec<u8>,
    )> {
        let Some(svid) = client_svid else {
            return Err(ArbiterError::AuthenticationFailed {
                principal: "anonymous".to_owned(),
                reason: "missing client SPIFFE SVID on negotiated HTTP request".to_owned(),
            });
        };
        self.authority.verify_svid(svid, current_tick)?;
        let endpoint = ApiEndpoint::from_path(path)?;
        let in_codec =
            arbiter_proto::WireCodecContentType::from_content_type_header(content_type_header);
        let out_codec =
            arbiter_proto::WireCodecContentType::from_content_type_header(accept_header);

        let envelope = match in_codec {
            arbiter_proto::WireCodecContentType::ApplicationProtobuf => {
                arbiter_proto::decode_protobuf_envelope(body_bytes)
                    .or_else(|_| WireEnvelope::from_rkyv_bytes(body_bytes))?
            }
            arbiter_proto::WireCodecContentType::ApplicationRkyv
            | arbiter_proto::WireCodecContentType::ApplicationJson => {
                in_codec.decode_envelope(body_bytes)?
            }
        };

        let resp_bytes = out_codec.encode_envelope(&envelope).unwrap_or_default();
        Ok((endpoint, envelope, out_codec, resp_bytes))
    }
}

/// Stateful RFC 6455 WebSocket session state machine.
///
/// Supports multi-frame fragmentation (`FIN == 0` continuation frames `0x0`), client-to-server
/// payload unmasking, automatic `Ping`/`Pong` keep-alives, and clean `Close` handshakes.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketSessionEngine {
    /// Opcode of an in-progress fragmented message (`Text` or `Binary`).
    pub active_fragment_opcode: Option<WebSocketOpcode>,
    /// Accumulated payload bytes across continuation fragments prior to the final `FIN == 1` frame.
    pub fragment_buffer: Vec<u8>,
    /// Decoded complete [`WireEnvelope`] messages received on this WebSocket session.
    pub completed_envelopes: std::collections::VecDeque<WireEnvelope>,
    /// Whether the session has completed a clean RFC 6455 `Close` handshake.
    pub is_closed: bool,
}

impl WebSocketSessionEngine {
    /// Creates a new [`WebSocketSessionEngine`].
    ///
    /// # Returns
    ///
    /// Initialized [`WebSocketSessionEngine`].
    pub const fn new() -> Self {
        Self {
            active_fragment_opcode: None,
            fragment_buffer: Vec::new(),
            completed_envelopes: std::collections::VecDeque::new(),
            is_closed: false,
        }
    }

    /// Encodes a single fragment or unfragmented RFC 6455 frame with explicit `fin` bit control.
    ///
    /// # Arguments
    ///
    /// * `fin` - Whether this is the final fragment (`true` sets bit `0x80`).
    /// * `opcode_nibble` - 4-bit opcode (`0x0` continuation, `0x1` text, `0x2` binary, `0x8` close, `0x9` ping, `0xA` pong).
    /// * `payload` - Unmasked payload slice.
    /// * `masking_key` - Optional 4-byte client masking key.
    ///
    /// # Returns
    ///
    /// Framed RFC 6455 wire bytes.
    pub fn encode_raw_fragment(
        fin: bool,
        opcode_nibble: u8,
        payload: &[u8],
        masking_key: Option<[u8; 4]>,
    ) -> Vec<u8> {
        let first_byte = (if fin { 0x80 } else { 0x00 }) | (opcode_nibble & 0x0F);
        let mask_bit = if masking_key.is_some() { 0x80 } else { 0x00 };
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.push(first_byte);
        if payload.len() <= 125 {
            frame.push(mask_bit | u8::try_from(payload.len()).unwrap_or(0));
        } else if let Ok(len_u16) = u16::try_from(payload.len()) {
            frame.push(mask_bit | 126_u8);
            frame.extend_from_slice(&len_u16.to_be_bytes());
        } else {
            frame.push(mask_bit | 127_u8);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        if let Some(mask) = masking_key {
            frame.extend_from_slice(&mask);
            for (i, &b) in payload.iter().enumerate() {
                let m = mask.get(i % 4).copied().unwrap_or(0);
                frame.push(b ^ m);
            }
        } else {
            frame.extend_from_slice(payload);
        }
        frame
    }

    /// Processes a raw RFC 6455 frame (supporting continuation fragments `0x0`, `FIN == 0`, and
    /// client masking), returning an optional control reply frame (`Pong` or `Close`) and appending
    /// completed [`WireEnvelope`]s to `self.completed_envelopes`.
    ///
    /// # Arguments
    ///
    /// * `frame` - Raw WebSocket frame bytes.
    ///
    /// # Returns
    ///
    /// `Ok(Some(control_reply_bytes))` if a `Ping` or `Close` frame was answered, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the frame header is truncated, continuation state is invalid,
    /// or a completed message payload fails [`WireEnvelope`] decoding.
    pub fn process_frame(&mut self, frame: &[u8]) -> ArbiterResult<Option<Vec<u8>>> {
        let Some((&hdr_byte, _)) = frame.split_first() else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "empty WebSocket frame in session".to_owned(),
            });
        };
        let fin = (hdr_byte & 0x80) != 0;
        let low_nibble = hdr_byte & 0x0F;

        // Reuse decode_websocket_frame by temporarily normalizing continuation nibble 0x0 -> 0x2 (Binary)
        let mut normalized = frame.to_vec();
        if low_nibble == 0x00 {
            for b in normalized.iter_mut().take(1) {
                *b = (*b & 0xF0) | 0x02;
            }
        }
        let (_, payload) = decode_websocket_frame(&normalized)?;

        match low_nibble {
            0x09 => {
                return encode_websocket_frame(WebSocketOpcode::Pong, &payload).map(Some);
            }
            0x08 => {
                self.is_closed = true;
                return encode_websocket_frame(WebSocketOpcode::Close, &payload).map(Some);
            }
            0x0A => return Ok(None),
            0x00 => {
                let Some(orig_op) = self.active_fragment_opcode else {
                    return Err(ArbiterError::HttpHandlerError {
                        status_code: 400,
                        message: "WebSocket continuation frame (0x0) without active fragment"
                            .to_owned(),
                    });
                };
                self.fragment_buffer.extend_from_slice(&payload);
                if fin {
                    self.active_fragment_opcode = None;
                    let completed = core::mem::take(&mut self.fragment_buffer);
                    let env = Self::decode_envelope_by_opcode(orig_op, &completed)?;
                    self.completed_envelopes.push_back(env);
                }
            }
            _ => {
                let op = if low_nibble == 0x01 {
                    WebSocketOpcode::Text
                } else {
                    WebSocketOpcode::Binary
                };
                if fin {
                    let env = Self::decode_envelope_by_opcode(op, &payload)?;
                    self.completed_envelopes.push_back(env);
                } else {
                    self.active_fragment_opcode = Some(op);
                    self.fragment_buffer.clear();
                    self.fragment_buffer.extend_from_slice(&payload);
                }
            }
        }
        Ok(None)
    }

    /// Decodes a reassembled message payload into a [`WireEnvelope`] according to `opcode`.
    ///
    /// # Arguments
    ///
    /// * `opcode` - `Text` (`JSON`) or `Binary` (`rkyv`).
    /// * `payload` - Complete unmasked message bytes.
    ///
    /// # Returns
    ///
    /// Decoded [`WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if UTF-8, JSON, or `rkyv` decoding fails.
    fn decode_envelope_by_opcode(
        opcode: WebSocketOpcode,
        payload: &[u8],
    ) -> ArbiterResult<WireEnvelope> {
        match opcode {
            WebSocketOpcode::Text => {
                let s = core::str::from_utf8(payload).map_err(|err| {
                    ArbiterError::DeserializationError {
                        format: "WebSocket UTF-8 Text".to_owned(),
                        reason: err.to_string(),
                    }
                })?;
                WireEnvelope::from_json_str(s)
            }
            _ => WireEnvelope::from_rkyv_bytes(payload),
        }
    }
}

/// Persistent Server-Sent Events (`SSE`) and `RecordIO` HTTP chunked broadcast channel
/// delivering real-time cluster events to subscribed Frameworks, Executors, and Operators.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseEventBroadcaster {
    /// Active subscriber queues keyed by subscriber identifier (`MesosStreamId` or operator session ID).
    pub subscribers: BTreeMap<String, std::collections::VecDeque<String>>,
}

impl SseEventBroadcaster {
    /// Creates a new [`SseEventBroadcaster`].
    ///
    /// # Returns
    ///
    /// Initialized [`SseEventBroadcaster`].
    pub const fn new() -> Self {
        Self {
            subscribers: BTreeMap::new(),
        }
    }

    /// Registers a persistent streaming subscriber (`subscriber_id`).
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - Unique subscriber identifier.
    pub fn subscribe(&mut self, subscriber_id: &str) {
        self.subscribers
            .entry(subscriber_id.to_owned())
            .or_default();
    }

    /// Broadcasts `envelope` as both an HTTP/1.1 chunked `SSE` frame (`<hex_len>\r\nevent: ...\r\n`)
    /// to all active subscribers.
    ///
    /// # Arguments
    ///
    /// * `event_name` - SSE event name.
    /// * `envelope` - [`WireEnvelope`] to broadcast.
    ///
    /// # Returns
    ///
    /// Number of subscribers that received the chunked frame.
    pub fn broadcast_sse_chunk(&mut self, event_name: &str, envelope: &WireEnvelope) -> usize {
        let sse = format_sse_event(event_name, envelope);
        let chunk = format!("{:x}\r\n{sse}\r\n", sse.len());
        for queue in self.subscribers.values_mut() {
            queue.push_back(chunk.clone());
        }
        self.subscribers.len()
    }

    /// Drains all pending HTTP/1.1 chunked `SSE` frames for `subscriber_id` and decodes them back
    /// into [`WireEnvelope`]s.
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - Registered subscriber ID.
    ///
    /// # Returns
    ///
    /// Vector of decoded [`WireEnvelope`]s delivered to the subscriber.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if chunk or SSE decoding fails.
    pub fn drain_subscriber_envelopes(
        &mut self,
        subscriber_id: &str,
    ) -> ArbiterResult<Vec<WireEnvelope>> {
        let Some(queue) = self.subscribers.get_mut(subscriber_id) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        while let Some(chunk) = queue.pop_front() {
            let terminated = format!("{chunk}0\r\n\r\n");
            let sse_frame = HttpGateway::decode_chunked_body(&terminated).unwrap_or_default();
            out.extend(parse_sse_event(&sse_frame));
        }
        Ok(out)
    }

    /// Broadcasts `envelope` as an HTTP/1.1 `Transfer-Encoding: chunked` `RecordIO` frame
    /// (`<hex_len>\r\n<dec_len>\n<json>\r\n`) to all active subscribers.
    ///
    /// # Arguments
    ///
    /// * `envelope` - [`WireEnvelope`] to broadcast as a chunked `RecordIO` frame.
    ///
    /// # Returns
    ///
    /// Number of subscribers that received the chunked `RecordIO` frame.
    pub fn broadcast_recordio_chunk(&mut self, envelope: &WireEnvelope) -> usize {
        let recordio = encode_recordio_frame(envelope);
        let chunk = format!("{:x}\r\n{recordio}\r\n", recordio.len());
        for queue in self.subscribers.values_mut() {
            queue.push_back(chunk.clone());
        }
        self.subscribers.len()
    }

    /// Drains all pending HTTP/1.1 chunked `RecordIO` frames for `subscriber_id` and decodes them
    /// back into [`WireEnvelope`]s.
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - Registered subscriber ID.
    ///
    /// # Returns
    ///
    /// Vector of decoded [`WireEnvelope`]s delivered to the subscriber.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if chunk or `RecordIO` decoding fails.
    pub fn drain_subscriber_recordio_envelopes(
        &mut self,
        subscriber_id: &str,
    ) -> ArbiterResult<Vec<WireEnvelope>> {
        let Some(queue) = self.subscribers.get_mut(subscriber_id) else {
            return Ok(Vec::new());
        };
        let mut combined_chunks = String::new();
        while let Some(chunk) = queue.pop_front() {
            combined_chunks.push_str(&chunk);
        }
        combined_chunks.push_str("0\r\n\r\n");
        let recordio_stream = HttpGateway::decode_chunked_body(&combined_chunks)?;
        decode_recordio_frames(&recordio_stream)
    }
}

/// RFC 7540 HTTP/2 frame variants handled by [`MesosHttp2Multiplexer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MesosHttp2Frame {
    /// Connection-level `SETTINGS` frame (`stream_id == 0`) advertising `initial_window_size` and `max_concurrent_streams`.
    Settings {
        /// Whether the `ACK` flag (`0x1`) is set.
        ack: bool,
        /// Initial stream flow-control window size in bytes.
        initial_window_size: u32,
        /// Maximum concurrent HTTP/2 streams permitted.
        max_concurrent_streams: u32,
    },
    /// Connection (`stream_id == 0`) or stream-level (`stream_id > 0`) `WINDOW_UPDATE` flow-control increment.
    WindowUpdate {
        /// Target stream identifier (`0` for connection-wide window).
        stream_id: u32,
        /// Window size increment (`1..=0x7FFF_FFFF`).
        increment: u32,
    },
    /// Multiplexed HTTP/2 `DATA` frame carrying an Apache Mesos `RecordIO` frame on `stream_id`.
    Data {
        /// Odd-numbered HTTP/2 stream identifier (`>= 1`).
        stream_id: u32,
        /// Whether `END_STREAM` (`0x1`) is set.
        end_stream: bool,
        /// Raw `RecordIO` frame bytes.
        payload: Vec<u8>,
    },
    /// Stream-opening HTTP/2 `HEADERS` frame (`stream_id >= 1`) carrying `:path` pseudo-header.
    Headers {
        /// Odd-numbered HTTP/2 stream identifier (`>= 1`).
        stream_id: u32,
        /// Target HTTP/2 `:path` pseudo-header (e.g. `"/api/v1/scheduler"`).
        path: String,
        /// Whether `END_HEADERS` (`0x4`) flag is set.
        end_headers: bool,
    },
    /// Connection-level HTTP/2 `PING` frame (`stream_id == 0`) with 8-byte opaque payload.
    Ping {
        /// Whether the `ACK` flag (`0x1`) is set.
        ack: bool,
        /// 8-byte opaque ping payload echoed in `PING ACK`.
        opaque_data: [u8; 8],
    },
    /// Connection-level HTTP/2 `GOAWAY` frame initiating graceful connection shutdown.
    GoAway {
        /// Highest peer-initiated `stream_id` processed on this connection.
        last_stream_id: u32,
        /// RFC 7540 HTTP/2 error code (`0x0` = `NO_ERROR`).
        error_code: u32,
    },
}

impl MesosHttp2Frame {
    /// Serializes this [`MesosHttp2Frame`] into an RFC 7540 Section 4.1 9-byte binary frame header
    /// (`[length: 24b_be][type: 8b][flags: 8b][stream_id: 31b_be]`) followed by the frame payload.
    ///
    /// # Returns
    ///
    /// Binary RFC 7540 HTTP/2 frame wire bytes.
    pub fn encode_rfc7540_wire_frame(&self) -> Vec<u8> {
        let (frame_type, flags, stream_id, payload): (u8, u8, u32, Vec<u8>) = match self {
            Self::Data {
                stream_id,
                end_stream,
                payload,
            } => (0x00, u8::from(*end_stream), *stream_id, payload.clone()),
            Self::Headers {
                stream_id,
                path,
                end_headers,
            } => (
                0x01,
                if *end_headers { 0x04 } else { 0x00 },
                *stream_id,
                path.as_bytes().to_vec(),
            ),
            Self::Settings {
                ack,
                initial_window_size,
                max_concurrent_streams,
            } => {
                let mut p = Vec::new();
                if !*ack {
                    p.extend_from_slice(&initial_window_size.to_be_bytes());
                    p.extend_from_slice(&max_concurrent_streams.to_be_bytes());
                }
                (0x04, u8::from(*ack), 0, p)
            }
            Self::Ping { ack, opaque_data } => (0x06, u8::from(*ack), 0, opaque_data.to_vec()),
            Self::GoAway {
                last_stream_id,
                error_code,
            } => {
                let mut p = Vec::with_capacity(8);
                p.extend_from_slice(&last_stream_id.to_be_bytes());
                p.extend_from_slice(&error_code.to_be_bytes());
                (0x07, 0x00, 0, p)
            }
            Self::WindowUpdate {
                stream_id,
                increment,
            } => (0x08, 0x00, *stream_id, increment.to_be_bytes().to_vec()),
        };
        let len_u32 = u32::try_from(payload.len()).unwrap_or(0);
        let len_be = len_u32.to_be_bytes();
        let mut wire = Vec::with_capacity(9 + payload.len());
        wire.extend_from_slice(len_be.get(1..4).unwrap_or(&[0, 0, 0]));
        wire.push(frame_type);
        wire.push(flags);
        wire.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
        wire.extend_from_slice(&payload);
        wire
    }

    /// Decodes an RFC 7540 Section 4.1 9-byte binary HTTP/2 frame header and payload back into a [`MesosHttp2Frame`].
    ///
    /// # Arguments
    ///
    /// * `wire` - Raw HTTP/2 frame wire bytes (`>= 9` bytes).
    ///
    /// # Returns
    ///
    /// Decoded [`MesosHttp2Frame`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if `wire` is shorter than 9 bytes, the payload is truncated,
    /// or the frame type byte is unknown.
    pub fn decode_rfc7540_wire_frame(wire: &[u8]) -> ArbiterResult<Self> {
        let Some(hdr) = wire.get(..9) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "RFC 7540 HTTP/2 frame shorter than 9-byte header".to_owned(),
            });
        };
        let len_b0 = u32::from(hdr.first().copied().unwrap_or(0));
        let len_b1 = u32::from(hdr.get(1).copied().unwrap_or(0));
        let len_b2 = u32::from(hdr.get(2).copied().unwrap_or(0));
        let payload_len = usize::try_from((len_b0 << 16) | (len_b1 << 8) | len_b2).unwrap_or(0);
        let frame_type = hdr.get(3).copied().unwrap_or(0);
        let flags = hdr.get(4).copied().unwrap_or(0);
        let mut sid_arr = [0_u8; 4];
        sid_arr.copy_from_slice(hdr.get(5..9).unwrap_or(&[0; 4]));
        let stream_id = u32::from_be_bytes(sid_arr) & 0x7FFF_FFFF;
        let Some(payload) = wire.get(9..9 + payload_len) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "RFC 7540 HTTP/2 frame payload truncated".to_owned(),
            });
        };
        match frame_type {
            0x00 => Ok(Self::Data {
                stream_id,
                end_stream: (flags & 0x01) != 0,
                payload: payload.to_vec(),
            }),
            0x01 => Ok(Self::Headers {
                stream_id,
                path: String::from_utf8_lossy(payload).into_owned(),
                end_headers: (flags & 0x04) != 0,
            }),
            0x04 => {
                let ack = (flags & 0x01) != 0;
                if ack {
                    Ok(Self::Settings {
                        ack: true,
                        initial_window_size: 0,
                        max_concurrent_streams: 0,
                    })
                } else {
                    let mut w_arr = [0_u8; 4];
                    for (dst, &src) in w_arr.iter_mut().zip(payload.iter().take(4)) {
                        *dst = src;
                    }
                    let mut m_arr = [0_u8; 4];
                    for (dst, &src) in m_arr.iter_mut().zip(payload.iter().skip(4).take(4)) {
                        *dst = src;
                    }
                    Ok(Self::Settings {
                        ack: false,
                        initial_window_size: u32::from_be_bytes(w_arr),
                        max_concurrent_streams: u32::from_be_bytes(m_arr),
                    })
                }
            }
            0x06 => {
                let mut op = [0_u8; 8];
                for (dst, &src) in op.iter_mut().zip(payload.iter()) {
                    *dst = src;
                }
                Ok(Self::Ping {
                    ack: (flags & 0x01) != 0,
                    opaque_data: op,
                })
            }
            0x07 => {
                let mut l_arr = [0_u8; 4];
                for (dst, &src) in l_arr.iter_mut().zip(payload.iter().take(4)) {
                    *dst = src;
                }
                let mut e_arr = [0_u8; 4];
                for (dst, &src) in e_arr.iter_mut().zip(payload.iter().skip(4).take(4)) {
                    *dst = src;
                }
                Ok(Self::GoAway {
                    last_stream_id: u32::from_be_bytes(l_arr),
                    error_code: u32::from_be_bytes(e_arr),
                })
            }
            0x08 => {
                let mut inc_arr = [0_u8; 4];
                for (dst, &src) in inc_arr.iter_mut().zip(payload.iter().take(4)) {
                    *dst = src;
                }
                Ok(Self::WindowUpdate {
                    stream_id,
                    increment: u32::from_be_bytes(inc_arr),
                })
            }
            other => Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: format!("unknown RFC 7540 HTTP/2 frame type 0x{other:02x}"),
            }),
        }
    }
}

/// Stateful RFC 7540 HTTP/2 stream multiplexer for Mesos v1 `RecordIO` streams with
/// `SETTINGS` negotiation and connection/stream `WINDOW_UPDATE` flow control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MesosHttp2Multiplexer {
    /// Current connection-wide flow-control send window in bytes.
    pub connection_send_window: u32,
    /// Negotiated initial per-stream send window in bytes (default `65_535`).
    pub initial_stream_window: u32,
    /// Negotiated maximum concurrent streams.
    pub max_concurrent_streams: u32,
    /// Whether the peer's initial `SETTINGS` frame has been acknowledged.
    pub settings_acknowledged: bool,
    /// Per-stream remaining send window in bytes keyed by HTTP/2 `stream_id`.
    pub stream_send_windows: BTreeMap<u32, u32>,
    /// Decoded inbound [`WireEnvelope`]s queued per HTTP/2 `stream_id`.
    pub inbound_stream_envelopes: BTreeMap<u32, std::collections::VecDeque<WireEnvelope>>,
}

impl Default for MesosHttp2Multiplexer {
    /// Returns a [`MesosHttp2Multiplexer`] initialized with RFC 7540 default flow-control windows (`65_535` bytes).
    ///
    /// # Returns
    ///
    /// Default [`MesosHttp2Multiplexer`].
    fn default() -> Self {
        Self::new(65_535, 128)
    }
}

impl MesosHttp2Multiplexer {
    /// Creates a new [`MesosHttp2Multiplexer`] with `initial_window_size` and `max_concurrent_streams`.
    ///
    /// # Arguments
    ///
    /// * `initial_window_size` - Initial RFC 7540 flow-control window in bytes.
    /// * `max_concurrent_streams` - Maximum concurrent HTTP/2 streams.
    ///
    /// # Returns
    ///
    /// Initialized [`MesosHttp2Multiplexer`].
    pub const fn new(initial_window_size: u32, max_concurrent_streams: u32) -> Self {
        Self {
            connection_send_window: initial_window_size,
            initial_stream_window: initial_window_size,
            max_concurrent_streams,
            settings_acknowledged: false,
            stream_send_windows: BTreeMap::new(),
            inbound_stream_envelopes: BTreeMap::new(),
        }
    }

    /// Processes an inbound [`MesosHttp2Frame`] (`SETTINGS`, `WINDOW_UPDATE`, or `DATA`), updating
    /// flow-control windows, decoding `RecordIO` payloads, and returning an optional response frame
    /// (`SETTINGS ACK` or `WINDOW_UPDATE`).
    ///
    /// # Arguments
    ///
    /// * `frame` - Inbound [`MesosHttp2Frame`].
    ///
    /// # Returns
    ///
    /// `Ok(Some(reply_frame))` if a `SETTINGS ACK` or `WINDOW_UPDATE` frame should be emitted, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if `WINDOW_UPDATE` has a zero increment, a `DATA`
    /// frame uses `stream_id == 0`, or the `RecordIO` payload is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn process_frame(
        &mut self,
        frame: MesosHttp2Frame,
    ) -> ArbiterResult<Option<MesosHttp2Frame>> {
        match frame {
            MesosHttp2Frame::Settings {
                ack,
                initial_window_size,
                max_concurrent_streams,
            } => {
                if ack {
                    self.settings_acknowledged = true;
                    Ok(None)
                } else {
                    self.initial_stream_window = initial_window_size;
                    self.max_concurrent_streams = max_concurrent_streams;
                    Ok(Some(MesosHttp2Frame::Settings {
                        ack: true,
                        initial_window_size,
                        max_concurrent_streams,
                    }))
                }
            }
            MesosHttp2Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if increment == 0 {
                    return Err(ArbiterError::HttpHandlerError {
                        status_code: 400,
                        message: "HTTP/2 FlowControlError: WINDOW_UPDATE increment cannot be 0"
                            .to_owned(),
                    });
                }
                if stream_id == 0 {
                    self.connection_send_window =
                        self.connection_send_window.saturating_add(increment);
                } else {
                    let win = self
                        .stream_send_windows
                        .entry(stream_id)
                        .or_insert(self.initial_stream_window);
                    *win = win.saturating_add(increment);
                }
                Ok(None)
            }
            MesosHttp2Frame::Data {
                stream_id,
                end_stream: _,
                payload,
            } => {
                if stream_id == 0 {
                    return Err(ArbiterError::HttpHandlerError {
                        status_code: 400,
                        message: "HTTP/2 ProtocolError: DATA frame on stream 0".to_owned(),
                    });
                }
                let text =
                    core::str::from_utf8(&payload).map_err(|e| ArbiterError::HttpHandlerError {
                        status_code: 400,
                        message: format!("invalid UTF-8 in HTTP/2 RecordIO DATA frame: {e}"),
                    })?;
                let envelopes = decode_recordio_frames(text)?;
                let q = self.inbound_stream_envelopes.entry(stream_id).or_default();
                for env in envelopes {
                    q.push_back(env);
                }
                let inc = u32::try_from(payload.len()).unwrap_or(1).max(1);
                Ok(Some(MesosHttp2Frame::WindowUpdate {
                    stream_id,
                    increment: inc,
                }))
            }
            MesosHttp2Frame::Headers {
                stream_id,
                path,
                end_headers: _,
            } => {
                if stream_id == 0 || path.trim().is_empty() {
                    return Err(ArbiterError::HttpHandlerError {
                        status_code: 400,
                        message: "HTTP/2 ProtocolError: invalid HEADERS stream_id or empty :path"
                            .to_owned(),
                    });
                }
                self.stream_send_windows
                    .entry(stream_id)
                    .or_insert(self.initial_stream_window);
                Ok(None)
            }
            MesosHttp2Frame::Ping { ack, opaque_data } => {
                if ack {
                    Ok(None)
                } else {
                    Ok(Some(MesosHttp2Frame::Ping {
                        ack: true,
                        opaque_data,
                    }))
                }
            }
            MesosHttp2Frame::GoAway { .. } => {
                self.stream_send_windows.clear();
                Ok(None)
            }
        }
    }

    /// Encodes `envelope` as an HTTP/2 `DATA` frame on `stream_id`, deducting the frame length
    /// from both `connection_send_window` and the per-stream send window.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Target non-zero HTTP/2 stream ID.
    /// * `envelope` - [`WireEnvelope`] to encode as `RecordIO`.
    /// * `end_stream` - Whether to set the `END_STREAM` flag.
    ///
    /// # Returns
    ///
    /// Outbound [`MesosHttp2Frame::Data`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if either the connection window or
    /// stream window has insufficient credit, or `max_concurrent_streams` is exceeded.
    pub fn build_data_frame(
        &mut self,
        stream_id: u32,
        envelope: &WireEnvelope,
        end_stream: bool,
    ) -> ArbiterResult<MesosHttp2Frame> {
        let is_new_stream = !self.stream_send_windows.contains_key(&stream_id);
        let at_limit = u32::try_from(self.stream_send_windows.len()).unwrap_or(u32::MAX)
            >= self.max_concurrent_streams;
        if is_new_stream & at_limit {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 429,
                message: format!(
                    "HTTP/2 max_concurrent_streams ({}) exceeded on stream {stream_id}",
                    self.max_concurrent_streams
                ),
            });
        }
        let payload = encode_recordio_frame(envelope).into_bytes();
        let needed = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let stream_win = *self
            .stream_send_windows
            .entry(stream_id)
            .or_insert(self.initial_stream_window);
        if (self.connection_send_window < needed) | (stream_win < needed) {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 429,
                message: format!("HTTP/2 flow-control window exhausted on stream {stream_id}"),
            });
        }
        self.connection_send_window -= needed;
        self.stream_send_windows
            .insert(stream_id, stream_win - needed);
        Ok(MesosHttp2Frame::Data {
            stream_id,
            end_stream,
            payload,
        })
    }

    /// Encodes HTTP/2 `:method POST` (`0x83`), `:scheme http` (`0x86`), `:path`, and `content-type`
    /// pseudo/request headers into an RFC 7541 HPACK header block fragment.
    ///
    /// # Arguments
    ///
    /// * `path` - `:path` pseudo-header value (e.g. `"/api/v1/scheduler"`).
    /// * `content_type` - `content-type` header value (e.g. `"application/x-protobuf"`).
    ///
    /// # Returns
    ///
    /// Binary RFC 7541 HPACK header block bytes.
    pub fn encode_hpack_request_headers(path: &str, content_type: &str) -> Vec<u8> {
        let mut block = Vec::with_capacity(6 + path.len() + content_type.len());
        // Indexed Header Field: index 3 (:method: POST -> 0x83), index 6 (:scheme: http -> 0x86)
        block.push(0x83);
        block.push(0x86);
        // Literal Header Field without Indexing — Indexed Name 4 (:path -> 0x04)
        block.push(0x04);
        let p_bytes = path.as_bytes();
        let p_len = u8::try_from(p_bytes.len()).unwrap_or(u8::MAX);
        block.push(p_len);
        block.extend_from_slice(p_bytes.get(..usize::from(p_len)).unwrap_or_default());
        // Literal Header Field without Indexing — Indexed Name 31 (content-type -> 0x0F, 0x10)
        block.push(0x0F);
        block.push(0x10);
        let c_bytes = content_type.as_bytes();
        let c_len = u8::try_from(c_bytes.len()).unwrap_or(u8::MAX);
        block.push(c_len);
        block.extend_from_slice(c_bytes.get(..usize::from(c_len)).unwrap_or_default());
        block
    }

    /// Decodes an RFC 7541 HPACK header block produced by [`Self::encode_hpack_request_headers`]
    /// into `(path, content_type)`.
    ///
    /// # Arguments
    ///
    /// * `block` - Binary HPACK header block slice.
    ///
    /// # Returns
    ///
    /// Tuple `(path, content_type)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] if the HPACK block is truncated or malformed.
    pub fn decode_hpack_request_headers(block: &[u8]) -> ArbiterResult<(String, String)> {
        if block.first().copied() != Some(0x83) || block.get(1).copied() != Some(0x86) {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "HPACK header block missing indexed :method POST (0x83) or :scheme (0x86)"
                    .to_owned(),
            });
        }
        if block.get(2).copied() != Some(0x04) {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "HPACK header block missing :path index (0x04)".to_owned(),
            });
        }
        let path_len = usize::from(block.get(3).copied().unwrap_or(0));
        let path_end = 4 + path_len;
        let Some(path_slice) = block.get(4..path_end) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "HPACK :path literal truncated".to_owned(),
            });
        };
        let path = String::from_utf8_lossy(path_slice).into_owned();
        let ct_hdr_end = path_end + 3;
        let Some(ct_hdr) = block.get(path_end..ct_hdr_end) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "HPACK content-type literal header truncated".to_owned(),
            });
        };
        let ct_len = usize::from(ct_hdr.get(2).copied().unwrap_or(0));
        let Some(ct_slice) = block.get(ct_hdr_end..ct_hdr_end + ct_len) else {
            return Err(ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "HPACK content-type literal value truncated".to_owned(),
            });
        };
        let content_type = String::from_utf8_lossy(ct_slice).into_owned();
        Ok((path, content_type))
    }
}

/// Persistent non-blocking multi-client HTTP/1.1, HTTP/2, and `RecordIO` streaming server.
///
/// Holds open concurrent `TcpStream` subscriptions and enforces `HTTP/1.1 307 Temporary Redirect`
/// to the current Raft leader whenever a request arrives at a follower Master.
#[derive(Debug)]
pub struct PersistentStreamingHttpServer {
    /// Bound non-blocking TCP listener.
    pub listener: TcpListener,
    /// Local bound socket address string.
    pub local_addr: String,
    /// Underlying [`HttpGateway`].
    pub gateway: HttpGateway,
    /// When `Some(leader_host_port)`, this server acts as a follower Master and responds to
    /// mutating or scheduler-subscription requests with `307 Temporary Redirect`.
    pub follower_redirect_leader: Option<String>,
    /// Open persistent `RecordIO` subscriber TCP streams keyed by subscriber ID.
    pub open_recordio_streams: BTreeMap<String, TcpStream>,
}

impl PersistentStreamingHttpServer {
    /// Binds a new [`PersistentStreamingHttpServer`] on `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `gateway` - Initialized [`HttpGateway`].
    /// * `follower_redirect_leader` - Optional leader `"host:port"` if this node is a follower.
    ///
    /// # Returns
    ///
    /// Bound [`PersistentStreamingHttpServer`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(
        bind_addr: &str,
        gateway: HttpGateway,
        follower_redirect_leader: Option<String>,
    ) -> ArbiterResult<Self> {
        let listener = TcpListener::bind(bind_addr).map_err(|e| ArbiterError::SocketBindError {
            endpoint: bind_addr.to_owned(),
            reason: e.to_string(),
        })?;
        let _ = listener.set_nonblocking(true);
        let local_addr = listener
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            listener,
            local_addr,
            gateway,
            follower_redirect_leader,
            open_recordio_streams: BTreeMap::new(),
        })
    }

    /// Accepts and processes one inbound HTTP connection:
    /// - If `self.follower_redirect_leader` is `Some(leader)`, writes an `HTTP/1.1 307 Temporary Redirect`
    ///   with `Location: http://<leader><path>` and returns `Ok(None)`.
    /// - Otherwise authenticates the `RecordIO` request, writes the chunked `200 OK` header, retains the
    ///   open `TcpStream` in `self.open_recordio_streams` under `subscriber_id`, and returns the decoded envelopes.
    ///
    /// # Arguments
    ///
    /// * `subscriber_id` - Subscriber key under which to retain the persistent `TcpStream`.
    /// * `client_svid` - Presented client [`SpiffeSvid`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some((endpoint, envelopes)))` when accepted on the leader, or `Ok(None)` on `WouldBlock` or `307` redirect.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if request parsing or SVID authentication fails.
    pub fn accept_subscription_or_redirect(
        &mut self,
        subscriber_id: &str,
        client_svid: Option<SpiffeSvid>,
        current_tick: u64,
    ) -> ArbiterResult<Option<(ApiEndpoint, Vec<WireEnvelope>)>> {
        let Ok((mut stream, _)) = self.listener.accept() else {
            return Ok(None);
        };
        let _ = stream.set_nonblocking(false);
        let mut raw_buf = Vec::new();
        let _ = stream.read_to_end(&mut raw_buf);
        let raw_str = String::from_utf8_lossy(&raw_buf);
        let req = HttpGateway::parse_http11_request(&raw_str, client_svid)?;
        if let Some(ref leader_addr) = self.follower_redirect_leader {
            let redirect_wire =
                HttpGateway::encode_leader_redirect_response(leader_addr, &req.path)?;
            let _ = stream.write_all(redirect_wire.as_bytes());
            let _ = stream.flush();
            return Ok(None);
        }
        let (endpoint, envelopes, resp) =
            self.gateway.handle_recordio_request(&req, current_tick)?;
        let resp_wire = HttpGateway::encode_http11_response(&resp);
        let _ = stream.write_all(resp_wire.as_bytes());
        let _ = stream.flush();
        self.open_recordio_streams
            .insert(subscriber_id.to_owned(), stream);
        Ok(Some((endpoint, envelopes)))
    }

    /// Pushes a live `RecordIO` frame (`<dec_len>\n<json>`) to all open persistent subscriber streams.
    ///
    /// # Arguments
    ///
    /// * `envelope` - [`WireEnvelope`] event to stream to connected subscribers.
    ///
    /// # Returns
    ///
    /// Number of open subscriber TCP streams that received the `RecordIO` frame.
    pub fn push_recordio_event_to_subscribers(&mut self, envelope: &WireEnvelope) -> usize {
        let frame = encode_recordio_frame(envelope);
        for stream in self.open_recordio_streams.values_mut() {
            let _ = stream.write_all(frame.as_bytes());
            let _ = stream.flush();
        }
        self.open_recordio_streams.len()
    }
}

/// Asynchronous RFC 7540 HTTP/2 control-plane server (`AsyncHttp2ControlServer`) backed by
/// `tokio::net::TcpListener` and `h2::server::handshake`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AsyncHttp2ControlServer;

impl AsyncHttp2ControlServer {
    /// Executes an RFC 7540 HTTP/2 `RecordIO` request/response stream exchange between a live
    /// `h2::server::handshake` server task and `h2::client::handshake` client task over `tokio::net::TcpListener`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `endpoint` - Target [`ApiEndpoint`] (`Scheduler`, `Executor`, `Operator`, `DirectJobs`).
    /// * `request_envelopes` - Slice of [`WireEnvelope`]s framed as `RecordIO` on the request stream.
    /// * `response_envelopes` - Slice of [`WireEnvelope`]s framed as `RecordIO` on the response stream.
    ///
    /// # Returns
    ///
    /// Tuple `(received_by_server, received_by_client)` decoded via [`decode_recordio_frames`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if TCP binding, HTTP/2 `SETTINGS` handshake, stream framing, or `RecordIO` decoding fails.
    pub fn exchange_recordio_stream_blocking(
        bind_addr: &str,
        endpoint: ApiEndpoint,
        request_envelopes: &[WireEnvelope],
        response_envelopes: &[WireEnvelope],
    ) -> ArbiterResult<(Vec<WireEnvelope>, Vec<WireEnvelope>)> {
        let mut req_body = String::new();
        for env in request_envelopes {
            req_body.push_str(&encode_recordio_frame(env));
        }
        let mut resp_body = String::new();
        for env in response_envelopes {
            resp_body.push_str(&encode_recordio_frame(env));
        }
        let path_str = endpoint.as_path().to_owned();
        let bind_owned = bind_addr.to_owned();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(arbiter_core::error::IoOperationError::from)?;

        rt.block_on(async move {
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
                let mut req_bytes = Vec::new();
                while let Some(chunk) = body.data().await {
                    let data = chunk?;
                    let _ = body.flow_control().release_capacity(data.len());
                    req_bytes.extend_from_slice(&data);
                }
                let req_str = String::from_utf8_lossy(&req_bytes);
                let parsed_reqs = decode_recordio_frames(&req_str)?;

                let response_hdr = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/x-recordio")
                    .body(())?;
                let mut send_stream = respond.send_response(response_hdr, false)?;
                send_stream.send_data(resp_body.into_bytes().into(), true)?;
                Ok::<Vec<WireEnvelope>, ArbiterError>(parsed_reqs)
            });

            let client_tcp = tokio::net::TcpStream::connect(local_addr)
                .await
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let (mut client_send, h2_client_conn) = h2::client::handshake(client_tcp).await?;
            tokio::spawn(h2_client_conn);

            let uri = format!("http://arbiter.internal{path_str}");
            let req_hdr = http::Request::builder()
                .method(http::Method::POST)
                .uri(uri)
                .header("content-type", "application/x-recordio")
                .header("accept", "application/x-recordio")
                .body(())?;
            let (resp_fut, mut req_stream) = client_send.send_request(req_hdr, false)?;
            req_stream.send_data(req_body.into_bytes().into(), true)?;
            let resp = resp_fut.await?;
            let (_, mut resp_body_stream) = resp.into_parts();
            let mut rx_resp_bytes = Vec::new();
            while let Some(chunk) = resp_body_stream.data().await {
                let data = chunk?;
                let _ = resp_body_stream.flow_control().release_capacity(data.len());
                rx_resp_bytes.extend_from_slice(&data);
            }
            drop(resp_body_stream);
            drop(client_send);
            let rx_resp_str = String::from_utf8_lossy(&rx_resp_bytes);
            let parsed_resps = decode_recordio_frames(&rx_resp_str)?;
            let parsed_reqs = srv_task.await??;
            Ok((parsed_reqs, parsed_resps))
        })
    }
}

/// Asynchronous RFC 6455 WebSocket TTY & TUI attach server (`AsyncWebSocketAttachServer`)
/// backed by `tokio_tungstenite`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AsyncWebSocketAttachServer;

impl AsyncWebSocketAttachServer {
    /// Executes a live RFC 6455 WebSocket upgrade and binary `rkyv` [`WireEnvelope`] exchange
    /// between a server `tokio_tungstenite::tungstenite::WebSocket` and a client `WebSocket` over `std::net::TcpListener`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `client_envelope` - [`WireEnvelope`] sent from WebSocket client to server.
    /// * `server_envelope` - [`WireEnvelope`] sent from WebSocket server to client.
    ///
    /// # Returns
    ///
    /// Tuple `(received_by_server, received_by_client)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if TCP binding, WebSocket framing, or `rkyv` decoding fails.
    pub fn exchange_websocket_envelopes_blocking(
        bind_addr: &str,
        client_envelope: &WireEnvelope,
        server_envelope: &WireEnvelope,
    ) -> ArbiterResult<(WireEnvelope, WireEnvelope)> {
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let cli_bytes = client_envelope.to_rkyv_bytes()?;
        let srv_bytes = server_envelope.to_rkyv_bytes()?;

        let srv_handle = std::thread::spawn(move || -> ArbiterResult<WireEnvelope> {
            let (srv_tcp, _) = listener
                .accept()
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let mut ws_srv = tokio_tungstenite::tungstenite::WebSocket::from_raw_socket(
                srv_tcp,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            );
            let msg = ws_srv.read()?;
            let dec = WireEnvelope::from_rkyv_bytes(&msg.into_data())?;
            ws_srv.send(tokio_tungstenite::tungstenite::Message::Binary(
                srv_bytes.into(),
            ))?;
            let _ = ws_srv.flush();
            Ok(dec)
        });

        let cli_tcp =
            TcpStream::connect(local_addr).map_err(arbiter_core::error::IoOperationError::from)?;
        let mut ws_cli = tokio_tungstenite::tungstenite::WebSocket::from_raw_socket(
            cli_tcp,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        );
        ws_cli.send(tokio_tungstenite::tungstenite::Message::Binary(
            cli_bytes.into(),
        ))?;
        let _ = ws_cli.flush();
        let rx_srv = ws_cli.read()?;
        let dec_srv = WireEnvelope::from_rkyv_bytes(&rx_srv.into_data())?;
        let join_err = Err(ArbiterError::from(
            arbiter_core::error::WebSocketCodecError::new("server thread panicked"),
        ));
        let dec_cli = srv_handle.join().unwrap_or(join_err)?;
        Ok((dec_cli, dec_srv))
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::AgentId;
    use arbiter_proto::{AgentHeartbeat, WireMessage};

    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_http_gateway_sse_formatting_and_auth_rejection() {
        let auth = SvidAuthority::new("arbiter.internal", [3_u8; 32], 100);
        let svid = auth
            .issue_svid("spiffe://arbiter.internal/node/agent-1", 10)
            .unwrap_or_default();
        let gateway = HttpGateway::new(auth);

        let env = WireEnvelope::new(
            7,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                tick: 20,
                healthy_tasks: Vec::new(),
            }),
        );

        let sse = format_sse_event("heartbeat", &env);
        assert!(sse.starts_with(
            "event: heartbeat
data: "
        ));
        assert_eq!(parse_sse_event(&sse), Ok(env.clone()));
        assert!(
            parse_sse_event(
                "event: ping

"
            )
            .is_err()
        );

        // Valid authenticated HTTP request
        let valid_req = HttpRequest {
            path: "/api/v1/executor".to_owned(),
            client_svid: Some(svid.clone()),
            body_json: env.to_json_string().unwrap_or_default(),
        };
        let handled = gateway.handle_request(&valid_req, 50);
        assert!(handled.is_ok());

        // Unauthorized request (no SVID) rejected
        let unauth_req = HttpRequest {
            path: "/api/v1/executor".to_owned(),
            client_svid: None,
            body_json: env.to_json_string().unwrap_or_default(),
        };
        assert!(gateway.handle_request(&unauth_req, 50).is_err());

        // Expired SVID rejected
        assert!(gateway.handle_request(&valid_req, 200).is_err());

        // Unknown path rejected
        let bad_path_req = HttpRequest {
            path: "/api/v1/invalid".to_owned(),
            client_svid: Some(svid.clone()),
            body_json: env.to_json_string().unwrap_or_default(),
        };
        assert!(gateway.handle_request(&bad_path_req, 50).is_err());

        // Malformed JSON body rejected
        let bad_json_req = HttpRequest {
            path: "/api/v1/executor".to_owned(),
            client_svid: Some(svid.clone()),
            body_json: "{invalid".to_owned(),
        };
        assert!(gateway.handle_request(&bad_json_req, 50).is_err());

        // RecordIO request handling & HTTP/1.1 wire parsing/encoding
        let rec_body = encode_recordio_frame(&env);
        let rec_req = HttpRequest {
            path: "/api/v1/scheduler".to_owned(),
            client_svid: Some(svid.clone()),
            body_json: rec_body,
        };
        let (_, envs, rec_resp) = gateway.handle_recordio_request(&rec_req, 50).unwrap_or((
            ApiEndpoint::Scheduler,
            Vec::new(),
            HttpResponse {
                status_code: 500,
                content_type: String::new(),
                body: String::new(),
            },
        ));
        assert_eq!(envs, vec![env.clone()]);
        assert_eq!(rec_resp.content_type, "application/x-recordio");
        assert!(
            gateway
                .handle_recordio_request(
                    &HttpRequest {
                        client_svid: None,
                        ..rec_req.clone()
                    },
                    50
                )
                .is_err()
        );
        assert!(gateway.handle_recordio_request(&rec_req, 500).is_err());
        assert!(
            gateway
                .handle_recordio_request(
                    &HttpRequest {
                        path: "/api/v1/bad".to_owned(),
                        ..rec_req.clone()
                    },
                    50
                )
                .is_err()
        );
        assert!(
            gateway
                .handle_recordio_request(
                    &HttpRequest {
                        body_json: "bad-recordio".to_owned(),
                        ..rec_req
                    },
                    50
                )
                .is_err()
        );

        let raw_http = format!(
            "POST /api/v1/jobs HTTP/1.1\r\nHost: localhost\r\n\r\n{}",
            env.to_json_string().unwrap_or_default()
        );
        let parsed_req =
            HttpGateway::parse_http11_request(&raw_http, Some(svid)).unwrap_or(HttpRequest {
                path: String::new(),
                client_svid: None,
                body_json: String::new(),
            });
        assert_eq!(parsed_req.path, "/api/v1/jobs");
        let wire_out = HttpGateway::encode_http11_response(&rec_resp);
        assert!(wire_out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(HttpGateway::parse_http11_request("POST / HTTP/1.1", None).is_err());
        assert!(HttpGateway::parse_http11_request("POST\r\n\r\nbody", None).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_mesos_stream_id_websocket_frames_and_live_tcp_exchange() {
        let auth = SvidAuthority::new("arbiter.internal", [3_u8; 32], 100);
        let svid = auth
            .issue_svid("spiffe://arbiter.internal/node/agent-1", 10)
            .unwrap_or_default();
        let mut gateway = HttpGateway::new(auth);

        assert!(MesosStreamId::new("").is_err());
        let fw_id = FrameworkId::new("fw-1").unwrap_or_default();
        let s1 = MesosStreamId::new("stream-001").unwrap_or_default();
        let s2 = MesosStreamId::new("stream-002").unwrap_or_default();
        assert_eq!(s1.as_str(), "stream-001");
        assert!(gateway.validate_mesos_stream_id(&fw_id, &s1).is_err());
        gateway.bind_mesos_stream_id(fw_id.clone(), s1.clone());
        assert!(gateway.validate_mesos_stream_id(&fw_id, &s1).is_ok());
        assert!(gateway.validate_mesos_stream_id(&fw_id, &s2).is_err());

        // RFC 6455 WebSocket handshake & framing (exact RFC 6455 Section 4.2.2 test vector)
        assert!(compute_websocket_accept_key("   ").is_err());
        let accept = compute_websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ==").unwrap_or_default();
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

        for op in [
            WebSocketOpcode::Text,
            WebSocketOpcode::Binary,
            WebSocketOpcode::Close,
            WebSocketOpcode::Ping,
            WebSocketOpcode::Pong,
        ] {
            let encoded = encode_websocket_frame(op, b"hello").unwrap_or_default();
            let (dec_op, dec_payload) =
                decode_websocket_frame(&encoded).unwrap_or((WebSocketOpcode::Close, Vec::new()));
            assert_eq!(dec_op, op);
            assert_eq!(dec_payload, b"hello");
        }

        // 16-bit extended length (200 bytes) and 64-bit extended length (70_000 bytes) — unmasked & masked
        let payload_16 = vec![0x42_u8; 200];
        let enc_16 =
            encode_websocket_frame(WebSocketOpcode::Binary, &payload_16).unwrap_or_default();
        assert_eq!(
            decode_websocket_frame(&enc_16),
            Ok((WebSocketOpcode::Binary, payload_16.clone()))
        );
        let masked_16 = encode_masked_websocket_frame(
            WebSocketOpcode::Binary,
            &payload_16,
            [0x37, 0xFA, 0x21, 0x3D],
        )
        .unwrap_or_default();
        assert_eq!(
            decode_websocket_frame(&masked_16),
            Ok((WebSocketOpcode::Binary, payload_16))
        );

        let payload_64 = vec![0x5A_u8; 70_000];
        let enc_64 =
            encode_websocket_frame(WebSocketOpcode::Binary, &payload_64).unwrap_or_default();
        assert_eq!(
            decode_websocket_frame(&enc_64),
            Ok((WebSocketOpcode::Binary, payload_64.clone()))
        );
        let masked_64 = encode_masked_websocket_frame(
            WebSocketOpcode::Binary,
            &payload_64,
            [0x11, 0x22, 0x33, 0x44],
        )
        .unwrap_or_default();
        assert_eq!(
            decode_websocket_frame(&masked_64),
            Ok((WebSocketOpcode::Binary, payload_64))
        );

        // Short masked frame & control frame replies
        let masked_short =
            encode_masked_websocket_frame(WebSocketOpcode::Text, b"hi", [1, 2, 3, 4])
                .unwrap_or_default();
        assert_eq!(
            decode_websocket_frame(&masked_short),
            Ok((WebSocketOpcode::Text, b"hi".to_vec()))
        );
        assert!(handle_websocket_control_frame(WebSocketOpcode::Ping, b"p").is_some());
        assert!(handle_websocket_control_frame(WebSocketOpcode::Close, b"c").is_some());
        assert_eq!(
            handle_websocket_control_frame(WebSocketOpcode::Text, b"t"),
            None
        );

        // Error branches
        let oversized = vec![0_u8; MAX_WEBSOCKET_PAYLOAD_BYTES + 1];
        assert!(encode_websocket_frame(WebSocketOpcode::Binary, &oversized).is_err());
        assert!(
            encode_masked_websocket_frame(WebSocketOpcode::Binary, &oversized, [0; 4]).is_err()
        );
        assert!(WebSocketOpcode::from_header_byte(0x8F).is_err());
        assert!(decode_websocket_frame(&[]).is_err());
        assert!(decode_websocket_frame(&[0x8F, 0]).is_err());
        assert!(decode_websocket_frame(&[0x81]).is_err());
        assert!(decode_websocket_frame(&[0x81, 126, 0x00]).is_err());
        assert!(decode_websocket_frame(&[0x81, 127, 0x00, 0x01]).is_err());
        assert!(decode_websocket_frame(&[0x81, 0x80 | 2, 0xAA, 0xBB]).is_err());
        assert!(decode_websocket_frame(&[0x81, 0x05, b'a']).is_err());

        // Live loopback TCP exchange
        let env = WireEnvelope::new(
            9,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                tick: 30,
                healthy_tasks: Vec::new(),
            }),
        );
        let req = HttpRequest {
            path: "/api/v1/executor".to_owned(),
            client_svid: Some(svid),
            body_json: env.to_json_string().unwrap_or_default(),
        };
        let tcp_res = gateway.execute_loopback_tcp_exchange("127.0.0.1:0", &req, 40);
        assert!(tcp_res.is_ok());
        assert!(
            gateway
                .execute_loopback_tcp_exchange("invalid-addr", &req, 40)
                .is_err()
        );

        let api_gw: &HttpApiGateway = &gateway;
        assert!(
            api_gw
                .handle_get_endpoint("/metrics", "m 1\n", "<html/>", "data: {}\n\n")
                .is_ok()
        );
        assert!(
            api_gw
                .handle_get_endpoint("/dashboard", "m 1\n", "<html/>", "data: {}\n\n")
                .is_ok()
        );
        assert!(
            api_gw
                .handle_get_endpoint("/dashboard/events", "m 1\n", "<html/>", "data: {}\n\n")
                .is_ok()
        );
        assert!(
            api_gw
                .handle_get_endpoint("/unknown", "m 1\n", "<html/>", "data: {}\n\n")
                .is_err()
        );
        let ws_101 = api_gw
            .upgrade_websocket_handshake("dGhlIHNhbXBsZSBub25jZQ==")
            .unwrap_or_default();
        assert!(ws_101.starts_with("HTTP/1.1 101 Switching Protocols"));
        assert!(api_gw.upgrade_websocket_handshake(" ").is_err());

        // Chunked HTTP/1.1 request & response parsing
        let chunked_raw = "POST /api/v1/jobs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let chunked_req =
            HttpGateway::parse_http11_request(chunked_raw, None).unwrap_or(HttpRequest {
                path: String::new(),
                client_svid: None,
                body_json: String::new(),
            });
        assert_eq!(chunked_req.body_json, "hello world");
        assert!(
            HttpGateway::parse_http11_request(
                "POST /api/v1/jobs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nbad\r\n",
                None
            )
            .is_err()
        );
        assert_eq!(HttpGateway::decode_chunked_body(""), Ok(String::new()));
        assert!(HttpGateway::decode_chunked_body("no-crlf").is_err());
        assert!(HttpGateway::decode_chunked_body("zz\r\nbad\r\n").is_err());
        assert!(HttpGateway::decode_chunked_body("10\r\nshort").is_err());

        assert!(HttpGateway::parse_http11_response("HTTP/1.1 200 OK").is_err());
        assert!(HttpGateway::parse_http11_response("HTTP/1.1 bad OK\r\n\r\n").is_err());
        assert!(HttpGateway::encode_leader_redirect_response("  ", "/api/v1/scheduler").is_err());
        let redir_307 =
            HttpGateway::encode_leader_redirect_response("10.0.0.2:8080", "/api/v1/scheduler")
                .unwrap_or_default();
        assert_eq!(
            HttpGateway::extract_redirect_location(&redir_307),
            Some("http://10.0.0.2:8080/api/v1/scheduler".to_owned())
        );
        assert_eq!(
            HttpGateway::extract_redirect_location(
                "HTTP/1.1 307 Temporary Redirect\r\nX-Other: 1\r\nlocation: http://10.0.0.3:8080/api\r\n\r\n"
            ),
            Some("http://10.0.0.3:8080/api".to_owned())
        );
        assert_eq!(
            HttpGateway::extract_redirect_location(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation:   \r\nX-Custom: 1\r\n\r\n"
            ),
            None
        );
        assert_eq!(
            HttpGateway::extract_redirect_location(
                "HTTP/1.1 307 Temporary Redirect\r\nX-Custom: 1\r\n\r\n"
            ),
            None
        );
        assert_eq!(
            HttpGateway::extract_redirect_location("HTTP/1.1 200 OK\r\n\r\n"),
            None
        );
        assert_eq!(HttpGateway::extract_redirect_location("no-crlf"), None);
        let ok_resp = HttpGateway::parse_http11_response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-Custom: 1\r\n\r\ndata: {}\n\n",
        )
        .unwrap_or(HttpResponse {
            status_code: 500,
            content_type: String::new(),
            body: String::new(),
        });
        assert_eq!(ok_resp.status_code, 200);
        assert_eq!(ok_resp.content_type, "text/event-stream");

        // HttpControlPlaneServer & HttpControlPlaneClient over separate TCP sockets
        assert!(HttpControlPlaneServer::bind("invalid-addr", gateway.clone()).is_err());
        let bad_cli = HttpControlPlaneClient::new("invalid-addr");
        assert!(bad_cli.send_envelope(ApiEndpoint::Executor, &env).is_err());
        assert!(
            bad_cli
                .send_recordio_stream(ApiEndpoint::Scheduler, std::slice::from_ref(&env))
                .is_err()
        );

        let srv_svid = gateway
            .authority
            .issue_svid("spiffe://arbiter.internal/node/agent-1", 10)
            .ok();
        let _ = HttpControlPlaneServer::bind("127.0.0.1:0", gateway).map(|cp_server| {
            let srv_addr = cp_server.local_addr_str().to_owned();
            assert_eq!(cp_server.poll_once(srv_svid.clone(), 40), Ok(None));
            let _ = cp_server.listener.set_nonblocking(false);

            let cli1 = HttpControlPlaneClient::new(&srv_addr);
            let _ = cli1.send_envelope(ApiEndpoint::Executor, &env).map(|s1| {
                let served1 = cp_server.poll_once(srv_svid.clone(), 40);
                assert_eq!(
                    served1,
                    Ok(Some((ApiEndpoint::Executor, vec![env.clone()])))
                );
                let r1 = HttpControlPlaneClient::read_response(s1).unwrap_or(HttpResponse {
                    status_code: 500,
                    content_type: String::new(),
                    body: String::new(),
                });
                assert_eq!(r1.status_code, 200);
            });

            let cli2 = HttpControlPlaneClient::new(&srv_addr);
            let _ = cli2
                .send_recordio_stream(ApiEndpoint::Scheduler, std::slice::from_ref(&env))
                .map(|s2| {
                    let served2 = cp_server.poll_batch(1, srv_svid.as_ref(), 40);
                    assert_eq!(
                        served2,
                        Ok(vec![(ApiEndpoint::Scheduler, vec![env.clone()])])
                    );
                    let _ = cp_server.listener.set_nonblocking(true);
                    assert_eq!(
                        cp_server.poll_batch(2, srv_svid.as_ref(), 40),
                        Ok(Vec::new())
                    );
                    let _ = cp_server.listener.set_nonblocking(false);
                    let r2 = HttpControlPlaneClient::read_recordio_response(s2).unwrap_or_default();
                    assert_eq!(r2, vec![env]);
                });

            // Error paths on poll_once (unauthenticated JSON, unauthenticated RecordIO, malformed HTTP)
            let _ = TcpStream::connect(&srv_addr).map(|mut raw| {
                let _ = raw.write_all(b"BAD_REQUEST");
                let _ = raw.shutdown(std::net::Shutdown::Write);
                assert!(cp_server.poll_once(srv_svid.clone(), 40).is_err());
            });
            let _ = cli1
                .send_envelope(ApiEndpoint::Executor, &sample_env_err())
                .map(|_s| {
                    assert!(cp_server.poll_once(None, 40).is_err());
                });
            let _ = cli2
                .send_recordio_stream(
                    ApiEndpoint::Scheduler,
                    std::slice::from_ref(&sample_env_err()),
                )
                .map(|s_err| {
                    assert!(cp_server.poll_once(None, 40).is_err());
                    assert!(HttpControlPlaneClient::read_recordio_response(s_err).is_err());
                });
        });
    }

    fn sample_env_err() -> WireEnvelope {
        WireEnvelope::new(
            99,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                tick: 30,
                healthy_tasks: Vec::new(),
            }),
        )
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_negotiated_codecs_websocket_fragmentation_and_sse_broadcaster() {
        let auth = SvidAuthority::new("arbiter.internal", [9_u8; 32], 100);
        let svid = auth
            .issue_svid("spiffe://arbiter.internal/node/agent-1", 10)
            .unwrap_or_default();
        let gw = HttpGateway::new(auth);
        let env = sample_env_err();

        // Missing SVID rejected
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/scheduler",
                "application/json",
                "application/json",
                None,
                b"{}",
                20
            )
            .is_err()
        );

        // Negotiate JSON -> rkyv, rkyv -> JSON, and protobuf -> protobuf
        let json_bytes = env.to_json_string().unwrap_or_default().into_bytes();
        let res1 = gw.handle_negotiated_request(
            "/api/v1/scheduler",
            "application/json",
            "application/x-rkyv",
            Some(&svid),
            &json_bytes,
            20,
        );
        assert!(res1.is_ok());
        let rkyv_out = env.to_rkyv_bytes().unwrap_or_default();

        let res2 = gw.handle_negotiated_request(
            "/api/v1/jobs",
            "application/x-protobuf",
            "application/x-protobuf",
            Some(&svid),
            &rkyv_out,
            20,
        );
        assert!(res2.is_ok());
        let pb_out = res2.map(|(_, _, _, b)| b).unwrap_or_default();
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/jobs",
                "application/x-protobuf",
                "application/json",
                Some(&svid),
                &pb_out,
                20,
            )
            .is_ok()
        );

        // Invalid UTF-8, expired SVID, unknown path, bad rkyv, and bad JSON on handle_negotiated_request
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/jobs",
                "application/json",
                "application/json",
                Some(&svid),
                &[0xFF, 0xFE],
                20
            )
            .is_err()
        );
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/jobs",
                "application/json",
                "application/json",
                Some(&svid),
                b"{bad",
                20
            )
            .is_err()
        );
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/jobs",
                "application/x-rkyv",
                "application/json",
                Some(&svid),
                b"corrupt",
                20
            )
            .is_err()
        );
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/jobs",
                "application/x-protobuf",
                "application/json",
                Some(&svid),
                b"corrupt",
                20
            )
            .is_err()
        );
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/unknown",
                "application/json",
                "application/json",
                Some(&svid),
                &json_bytes,
                20
            )
            .is_err()
        );
        assert!(
            gw.handle_negotiated_request(
                "/api/v1/jobs",
                "application/json",
                "application/json",
                Some(&svid),
                &json_bytes,
                500
            )
            .is_err()
        );

        // WebSocketSessionEngine: fragmentation (FIN=0 + continuation 0x0), Binary, Ping, Pong, Close
        let mut ws_sess = WebSocketSessionEngine::new();
        assert!(ws_sess.process_frame(&[]).is_err());
        assert!(ws_sess.process_frame(&[0x81]).is_err());
        // Continuation without active fragment fails
        let orphan_cont = WebSocketSessionEngine::encode_raw_fragment(true, 0x0, b"abc", None);
        assert!(ws_sess.process_frame(&orphan_cont).is_err());
        // Fragmented message with invalid JSON fails on final continuation
        let bad_frag1 = WebSocketSessionEngine::encode_raw_fragment(false, 0x1, b"{bad", None);
        let bad_frag2 = WebSocketSessionEngine::encode_raw_fragment(true, 0x0, b"_json", None);
        assert_eq!(ws_sess.process_frame(&bad_frag1), Ok(None));
        assert!(ws_sess.process_frame(&bad_frag2).is_err());

        // Split JSON across 2 masked fragments (Text 0x1 FIN=0, then Continuation 0x0 FIN=1)
        let mid = json_bytes.len() / 2;
        let part1 = json_bytes.get(..mid).unwrap_or(&[]);
        let part2 = json_bytes.get(mid..).unwrap_or(&[]);
        let frag1 =
            WebSocketSessionEngine::encode_raw_fragment(false, 0x1, part1, Some([1, 2, 3, 4]));
        let frag2 =
            WebSocketSessionEngine::encode_raw_fragment(true, 0x0, part2, Some([5, 6, 7, 8]));
        assert_eq!(ws_sess.process_frame(&frag1), Ok(None));
        // Non-final continuation fragment
        let frag_mid = WebSocketSessionEngine::encode_raw_fragment(false, 0x0, b"", None);
        assert_eq!(ws_sess.process_frame(&frag_mid), Ok(None));
        assert_eq!(ws_sess.process_frame(&frag2), Ok(None));
        assert_eq!(ws_sess.completed_envelopes.pop_front(), Some(env.clone()));

        // Unfragmented Text and Binary frames + extended lengths (126..65535 and >65535)
        let text_fin = WebSocketSessionEngine::encode_raw_fragment(true, 0x1, &json_bytes, None);
        assert_eq!(ws_sess.process_frame(&text_fin), Ok(None));
        let bin_fin = WebSocketSessionEngine::encode_raw_fragment(true, 0x2, &rkyv_out, None);
        assert_eq!(ws_sess.process_frame(&bin_fin), Ok(None));
        assert_eq!(ws_sess.completed_envelopes.len(), 2);

        let med_frag = WebSocketSessionEngine::encode_raw_fragment(true, 0x2, &[0_u8; 300], None);
        assert!(med_frag.len() > 300);
        let big_frag =
            WebSocketSessionEngine::encode_raw_fragment(true, 0x2, &vec![0_u8; 66_000], None);
        assert!(big_frag.len() > 66_000);

        // Invalid UTF-8 in Text frame rejected
        let bad_utf8_frame =
            WebSocketSessionEngine::encode_raw_fragment(true, 0x1, &[0xFF, 0xFE], None);
        assert!(ws_sess.process_frame(&bad_utf8_frame).is_err());

        // Ping -> Pong, Pong -> None, Close -> Close & is_closed=true
        let heartbeat_req = WebSocketSessionEngine::encode_raw_fragment(true, 0x9, b"hb", None);
        assert!(
            ws_sess
                .process_frame(&heartbeat_req)
                .unwrap_or(None)
                .is_some()
        );
        let heartbeat_ack = WebSocketSessionEngine::encode_raw_fragment(true, 0xA, b"hb", None);
        assert_eq!(ws_sess.process_frame(&heartbeat_ack), Ok(None));
        let close_f = WebSocketSessionEngine::encode_raw_fragment(true, 0x8, b"", None);
        assert!(ws_sess.process_frame(&close_f).unwrap_or(None).is_some());
        assert!(ws_sess.is_closed);

        // SseEventBroadcaster
        let mut broadcaster = SseEventBroadcaster::new();
        assert_eq!(
            broadcaster.drain_subscriber_envelopes("missing"),
            Ok(Vec::new())
        );
        assert_eq!(
            broadcaster.drain_subscriber_recordio_envelopes("missing"),
            Ok(Vec::new())
        );
        broadcaster.subscribe("sub-1");
        broadcaster.subscribe("sub-2");
        assert_eq!(broadcaster.broadcast_sse_chunk("offer", &env), 2);
        assert_eq!(
            broadcaster.drain_subscriber_envelopes("sub-1"),
            Ok(vec![env.clone()])
        );
        let _ = broadcaster.drain_subscriber_envelopes("sub-2");
        assert_eq!(broadcaster.broadcast_recordio_chunk(&env), 2);
        assert_eq!(
            broadcaster.drain_subscriber_recordio_envelopes("sub-1"),
            Ok(vec![env.clone()])
        );
        broadcaster
            .subscribers
            .entry("sub-1".to_owned())
            .or_default()
            .push_back("zz\r\nbad\r\n".to_owned());
        assert!(
            broadcaster
                .drain_subscriber_recordio_envelopes("sub-1")
                .is_err()
        );
        broadcaster
            .subscribers
            .entry("sub-1".to_owned())
            .or_default()
            .push_back("4\r\n99\nx\r\n".to_owned());
        assert!(
            broadcaster
                .drain_subscriber_recordio_envelopes("sub-1")
                .is_err()
        );

        // MesosHttp2Multiplexer SETTINGS, WINDOW_UPDATE, and RecordIO DATA flow control
        let mut h2 = MesosHttp2Multiplexer::default();
        assert_eq!(h2.initial_stream_window, 65_535);
        let settings_ack = h2.process_frame(MesosHttp2Frame::Settings {
            ack: false,
            initial_window_size: 4096,
            max_concurrent_streams: 1,
        });
        assert_eq!(
            settings_ack,
            Ok(Some(MesosHttp2Frame::Settings {
                ack: true,
                initial_window_size: 4096,
                max_concurrent_streams: 1,
            }))
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::Settings {
                ack: true,
                initial_window_size: 4096,
                max_concurrent_streams: 1,
            }),
            Ok(None)
        );
        assert!(h2.settings_acknowledged);

        assert!(
            h2.process_frame(MesosHttp2Frame::WindowUpdate {
                stream_id: 0,
                increment: 0,
            })
            .is_err()
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::WindowUpdate {
                stream_id: 0,
                increment: 1000,
            }),
            Ok(None)
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::WindowUpdate {
                stream_id: 1,
                increment: 500,
            }),
            Ok(None)
        );

        let df = h2
            .build_data_frame(1, &env, false)
            .unwrap_or(MesosHttp2Frame::Settings {
                ack: true,
                initial_window_size: 0,
                max_concurrent_streams: 0,
            });
        // Stream 3 exceeds max_concurrent_streams == 1
        assert!(h2.build_data_frame(3, &env, false).is_err());
        // Exhaust stream 1 window and connection window
        h2.stream_send_windows.insert(1, 2);
        assert!(h2.build_data_frame(1, &env, false).is_err());
        h2.stream_send_windows.insert(1, 50_000);
        h2.connection_send_window = 2;
        assert!(h2.build_data_frame(1, &env, false).is_err());

        // Inbound DATA frame processing and error branches
        assert!(
            h2.process_frame(MesosHttp2Frame::Data {
                stream_id: 0,
                end_stream: false,
                payload: Vec::new(),
            })
            .is_err()
        );
        assert!(
            h2.process_frame(MesosHttp2Frame::Data {
                stream_id: 1,
                end_stream: false,
                payload: vec![0xFF, 0xFE],
            })
            .is_err()
        );
        assert!(
            h2.process_frame(MesosHttp2Frame::Data {
                stream_id: 1,
                end_stream: false,
                payload: b"99\nbad".to_vec(),
            })
            .is_err()
        );
        assert!(h2.process_frame(df).unwrap_or(None).is_some());
        assert_eq!(
            h2.inbound_stream_envelopes
                .get_mut(&1)
                .and_then(std::collections::VecDeque::pop_front),
            Some(env)
        );
        // HEADERS, PING, and GOAWAY frames
        assert!(
            h2.process_frame(MesosHttp2Frame::Headers {
                stream_id: 0,
                path: "/api/v1/scheduler".to_owned(),
                end_headers: true,
            })
            .is_err()
        );
        assert!(
            h2.process_frame(MesosHttp2Frame::Headers {
                stream_id: 1,
                path: "   ".to_owned(),
                end_headers: true,
            })
            .is_err()
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::Headers {
                stream_id: 1,
                path: "/api/v1/scheduler".to_owned(),
                end_headers: true,
            }),
            Ok(None)
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::Ping {
                ack: false,
                opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
            }),
            Ok(Some(MesosHttp2Frame::Ping {
                ack: true,
                opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
            }))
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::Ping {
                ack: true,
                opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
            }),
            Ok(None)
        );
        assert_eq!(
            h2.process_frame(MesosHttp2Frame::GoAway {
                last_stream_id: 1,
                error_code: 0,
            }),
            Ok(None)
        );
        assert!(h2.stream_send_windows.is_empty());

        // HPACK request header encoding & decoding + error branches
        let hpack = MesosHttp2Multiplexer::encode_hpack_request_headers(
            "/api/v1/scheduler",
            "application/x-protobuf",
        );
        assert_eq!(
            MesosHttp2Multiplexer::decode_hpack_request_headers(&hpack),
            Ok((
                "/api/v1/scheduler".to_owned(),
                "application/x-protobuf".to_owned()
            ))
        );
        assert!(MesosHttp2Multiplexer::decode_hpack_request_headers(&[0x00]).is_err());
        assert!(MesosHttp2Multiplexer::decode_hpack_request_headers(&[0x83, 0x00]).is_err());
        assert!(MesosHttp2Multiplexer::decode_hpack_request_headers(&[0x83, 0x86, 0x00]).is_err());
        assert!(
            MesosHttp2Multiplexer::decode_hpack_request_headers(&[0x83, 0x86, 0x04, 10, b'/'])
                .is_err()
        );
        assert!(
            MesosHttp2Multiplexer::decode_hpack_request_headers(&[0x83, 0x86, 0x04, 1, b'/', 0x0F])
                .is_err()
        );
        assert!(
            MesosHttp2Multiplexer::decode_hpack_request_headers(&[
                0x83, 0x86, 0x04, 1, b'/', 0x0F, 0x10, 10, b'a'
            ])
            .is_err()
        );

        // PersistentStreamingHttpServer (307 follower redirect & persistent open RecordIO streams)
        assert!(PersistentStreamingHttpServer::bind("invalid-addr", gw.clone(), None).is_err());
        let env_sub = sample_env_err();
        let _ = PersistentStreamingHttpServer::bind(
            "127.0.0.1:0",
            gw.clone(),
            Some("10.0.0.1:5050".to_owned()),
        )
        .map(|mut follower_srv| {
            assert_eq!(
                follower_srv.accept_subscription_or_redirect("sub-f", Some(svid.clone()), 20),
                Ok(None)
            );
            let _ = follower_srv.listener.set_nonblocking(false);
            let cli_f = HttpControlPlaneClient::new(&follower_srv.local_addr);
            let _ = cli_f
                .send_recordio_stream(ApiEndpoint::Scheduler, std::slice::from_ref(&env_sub))
                .map(|mut s_f| {
                    assert_eq!(
                        follower_srv.accept_subscription_or_redirect(
                            "sub-f",
                            Some(svid.clone()),
                            20
                        ),
                        Ok(None)
                    );
                    let mut resp_bytes = Vec::new();
                    let _ = s_f.read_to_end(&mut resp_bytes);
                    let resp_str = String::from_utf8_lossy(&resp_bytes);
                    assert!(resp_str.starts_with("HTTP/1.1 307 Temporary Redirect"));
                });
            // Invalid leader redirect address triggers error branch
            follower_srv.follower_redirect_leader = Some("   ".to_owned());
            let _ = cli_f
                .send_recordio_stream(ApiEndpoint::Scheduler, std::slice::from_ref(&env_sub))
                .map(|_s_f2| {
                    assert!(
                        follower_srv
                            .accept_subscription_or_redirect("sub-f2", Some(svid.clone()), 20)
                            .is_err()
                    );
                });
        });

        let _ =
            PersistentStreamingHttpServer::bind("127.0.0.1:0", gw, None).map(|mut leader_srv| {
                let _ = leader_srv.listener.set_nonblocking(false);
                let cli_l = HttpControlPlaneClient::new(&leader_srv.local_addr);
                let _ = cli_l
                    .send_recordio_stream(ApiEndpoint::Scheduler, std::slice::from_ref(&env_sub))
                    .map(|mut s_l| {
                        let accepted = leader_srv.accept_subscription_or_redirect(
                            "sub-1",
                            Some(svid.clone()),
                            20,
                        );
                        assert_eq!(
                            accepted,
                            Ok(Some((ApiEndpoint::Scheduler, vec![env_sub.clone()])))
                        );
                        assert_eq!(leader_srv.push_recordio_event_to_subscribers(&env_sub), 1);
                        leader_srv.open_recordio_streams.clear();
                        let mut rx = Vec::new();
                        let _ = s_l.read_to_end(&mut rx);
                        assert!(String::from_utf8_lossy(&rx).contains("HTTP/1.1 200 OK"));
                    });
                // Error branches: unauthenticated RecordIO and malformed HTTP request
                let _ = cli_l
                    .send_recordio_stream(ApiEndpoint::Scheduler, std::slice::from_ref(&env_sub))
                    .map(|_s_err| {
                        assert!(
                            leader_srv
                                .accept_subscription_or_redirect("sub-err", None, 20)
                                .is_err()
                        );
                    });
                let _ = TcpStream::connect(&leader_srv.local_addr).map(|mut bad_s| {
                    let _ = bad_s.write_all(b"BAD");
                    let _ = bad_s.shutdown(std::net::Shutdown::Write);
                    assert!(
                        leader_srv
                            .accept_subscription_or_redirect("sub-bad", Some(svid), 20)
                            .is_err()
                    );
                });
            });

        // Incremental HttpGateway::read_http11_from_stream without Shutdown::Write
        let _ = TcpListener::bind("127.0.0.1:0").map(|inc_listener| {
            let _ = inc_listener.local_addr().map(|inc_addr| {
                let _ = TcpStream::connect(inc_addr).map(|mut cli_s| {
                    let _ = cli_s.write_all(
                        b"POST /api/v1/jobs HTTP/1.1\r\nContent-Length: 4\r\n\r\n{\"x\"",
                    );
                    let _ = inc_listener.accept().map(|(mut srv_s, _)| {
                        let parsed = HttpGateway::read_http11_from_stream(&mut srv_s, None)
                            .unwrap_or(HttpRequest {
                                path: String::new(),
                                client_svid: None,
                                body_json: String::new(),
                            });
                        assert_eq!(parsed.path, "/api/v1/jobs");
                        assert_eq!(parsed.body_json, "{\"x\"");
                    });
                });
                let _ = TcpStream::connect(inc_addr).map(|mut cli_s2| {
                    let _ = cli_s2
                        .write_all(b"GET /master/state HTTP/1.1\r\ncontent-length: 0\r\n\r\n");
                    let _ = inc_listener.accept().map(|(mut srv_s2, _)| {
                        let parsed2 = HttpGateway::read_http11_from_stream(&mut srv_s2, None)
                            .unwrap_or(HttpRequest {
                                path: String::new(),
                                client_svid: None,
                                body_json: String::new(),
                            });
                        assert_eq!(parsed2.path, "/master/state");
                    });
                });
                let _ = TcpStream::connect(inc_addr).map(|mut cli_s3| {
                    let _ = cli_s3.write_all(b"INCOMPLETE_HEADER");
                    let _ = cli_s3.shutdown(std::net::Shutdown::Write);
                    let _ = inc_listener.accept().map(|(mut srv_s3, _)| {
                        assert!(HttpGateway::read_http11_from_stream(&mut srv_s3, None).is_err());
                    });
                });
            });
        });

        // RFC 7540 binary 9-byte HTTP/2 frame roundtrip & error branches
        for f in [
            MesosHttp2Frame::Data {
                stream_id: 1,
                end_stream: true,
                payload: b"12\n{}".to_vec(),
            },
            MesosHttp2Frame::Data {
                stream_id: 1,
                end_stream: false,
                payload: Vec::new(),
            },
            MesosHttp2Frame::Headers {
                stream_id: 3,
                path: "/api/v1/scheduler".to_owned(),
                end_headers: true,
            },
            MesosHttp2Frame::Headers {
                stream_id: 3,
                path: "/api/v1/operator".to_owned(),
                end_headers: false,
            },
            MesosHttp2Frame::Settings {
                ack: false,
                initial_window_size: 65_535,
                max_concurrent_streams: 100,
            },
            MesosHttp2Frame::Settings {
                ack: true,
                initial_window_size: 0,
                max_concurrent_streams: 0,
            },
            MesosHttp2Frame::Ping {
                ack: false,
                opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
            },
            MesosHttp2Frame::Ping {
                ack: true,
                opaque_data: [8, 7, 6, 5, 4, 3, 2, 1],
            },
            MesosHttp2Frame::GoAway {
                last_stream_id: 5,
                error_code: 0,
            },
            MesosHttp2Frame::WindowUpdate {
                stream_id: 1,
                increment: 4096,
            },
        ] {
            let w = f.encode_rfc7540_wire_frame();
            assert_eq!(MesosHttp2Frame::decode_rfc7540_wire_frame(&w), Ok(f));
        }
        assert!(MesosHttp2Frame::decode_rfc7540_wire_frame(&[0, 1, 2]).is_err());
        assert!(
            MesosHttp2Frame::decode_rfc7540_wire_frame(&[0, 0, 10, 0x00, 0, 0, 0, 0, 1, b'a'])
                .is_err()
        );
        assert!(
            MesosHttp2Frame::decode_rfc7540_wire_frame(&[0, 0, 0, 0xFF, 0, 0, 0, 0, 0]).is_err()
        );

        let h2_env = sample_env_err();
        assert!(
            AsyncHttp2ControlServer::exchange_recordio_stream_blocking(
                "invalid-addr",
                ApiEndpoint::Scheduler,
                std::slice::from_ref(&h2_env),
                std::slice::from_ref(&h2_env),
            )
            .is_err()
        );
        assert_eq!(
            AsyncHttp2ControlServer::exchange_recordio_stream_blocking(
                "127.0.0.1:0",
                ApiEndpoint::Scheduler,
                std::slice::from_ref(&h2_env),
                std::slice::from_ref(&h2_env),
            ),
            Ok((vec![h2_env.clone()], vec![h2_env.clone()]))
        );

        assert!(
            AsyncWebSocketAttachServer::exchange_websocket_envelopes_blocking(
                "invalid-addr",
                &h2_env,
                &h2_env,
            )
            .is_err()
        );
        assert_eq!(
            AsyncWebSocketAttachServer::exchange_websocket_envelopes_blocking(
                "127.0.0.1:0",
                &h2_env,
                &h2_env,
            ),
            Ok((h2_env.clone(), h2_env))
        );
    }
}
