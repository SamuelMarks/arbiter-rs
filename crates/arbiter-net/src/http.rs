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
    let json = envelope.to_json_string();
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

    /// Executes a live loopback TCP HTTP/1.1 request/response exchange over `std::net::TcpListener`
    /// and `std::net::TcpStream`.
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
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let mut raw_buf = String::new();
        let _ = listener.local_addr().and_then(|local_addr| {
            TcpStream::connect(local_addr).and_then(|mut client| {
                let wire_req = format!(
                    "POST {} HTTP/1.1\r\nHost: {local_addr}\r\nContent-Length: {}\r\n\r\n{}",
                    req.path,
                    req.body_json.len(),
                    req.body_json
                );
                let _ = client.write_all(wire_req.as_bytes());
                let _ = client.shutdown(std::net::Shutdown::Write);
                listener.accept().map(|(mut server_stream, _)| {
                    let _ = server_stream.read_to_string(&mut raw_buf);
                    let _ =
                        server_stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let _ = server_stream.shutdown(std::net::Shutdown::Write);
                    let mut client_resp_buf = String::new();
                    let _ = client.read_to_string(&mut client_resp_buf);
                })
            })
        });
        Self::parse_http11_request(&raw_buf, req.client_svid.clone())
            .and_then(|parsed| self.handle_request(&parsed, current_tick))
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
        let mut accepted = None;
        for _ in 0..50 {
            if let Ok(pair) = self.listener.accept() {
                accepted = Some(pair);
                break;
            }
            std::thread::yield_now();
        }
        if let Some((mut stream, _)) = accepted {
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
            let Some(item) = self.poll_once(client_svid.cloned(), current_tick)? else {
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
        let body = envelope.to_json_string();
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
            body_json: env.to_json_string(),
        };
        let handled = gateway.handle_request(&valid_req, 50);
        assert!(handled.is_ok());

        // Unauthorized request (no SVID) rejected
        let unauth_req = HttpRequest {
            path: "/api/v1/executor".to_owned(),
            client_svid: None,
            body_json: env.to_json_string(),
        };
        assert!(gateway.handle_request(&unauth_req, 50).is_err());

        // Expired SVID rejected
        assert!(gateway.handle_request(&valid_req, 200).is_err());

        // Unknown path rejected
        let bad_path_req = HttpRequest {
            path: "/api/v1/invalid".to_owned(),
            client_svid: Some(svid.clone()),
            body_json: env.to_json_string(),
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
            env.to_json_string()
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
            body_json: env.to_json_string(),
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
                    assert_eq!(
                        cp_server.poll_batch(2, srv_svid.as_ref(), 40),
                        Ok(Vec::new())
                    );
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
}
