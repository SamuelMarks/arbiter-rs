//! Unified error model (`ArbiterError`) and result type alias (`ArbiterResult`) for the Arbiter ecosystem.
//!
//! All failure modes across domain validation, arithmetic, resource accounting, scheduling,
//! consensus, fencing, networking, security, OS isolation, hardware probing, and CLI lifecycle
//! are represented in a single strongly-typed enum using `derive_more`.

use derive_more::{Display, Error, From};
use serde::{Deserialize, Serialize};

/// Standard result alias used uniformly across all Arbiter crates.
pub type ArbiterResult<T> = core::result::Result<T, ArbiterError>;

/// Wrapper error for JSON serialization/deserialization failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("JSON codec error: {message}")]
pub struct JsonCodecError {
    /// Human-readable description of the codec failure.
    pub message: String,
}

impl JsonCodecError {
    /// Creates a new [`JsonCodecError`].
    ///
    /// # Arguments
    ///
    /// * `message` - Diagnostic JSON codec failure message.
    ///
    /// # Returns
    ///
    /// Structured [`JsonCodecError`].
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

impl From<serde_json::Error> for JsonCodecError {
    /// Converts a `serde_json::Error` into a [`JsonCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `serde_json` error.
    ///
    /// # Returns
    ///
    /// A structured [`JsonCodecError`].
    fn from(err: serde_json::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<serde_json::Error> for ArbiterError {
    /// Converts a `serde_json::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `serde_json::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::JsonCodec`].
    fn from(err: serde_json::Error) -> Self {
        Self::JsonCodec(JsonCodecError::from(err))
    }
}

/// Wrapper error for standard library I/O failures (`std::io::Error`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("I/O operation error ({kind}): {message}")]
pub struct IoOperationError {
    /// Canonical `std::io::ErrorKind` name.
    pub kind: String,
    /// Human-readable description of the I/O failure.
    pub message: String,
}

impl IoOperationError {
    /// Creates a new [`IoOperationError`].
    ///
    /// # Arguments
    ///
    /// * `kind` - Canonical `std::io::ErrorKind` name.
    /// * `message` - Diagnostic I/O failure message.
    ///
    /// # Returns
    ///
    /// Structured [`IoOperationError`].
    pub fn new(kind: &str, message: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl From<std::io::Error> for IoOperationError {
    /// Converts a `std::io::Error` into an [`IoOperationError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `std::io::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`IoOperationError`].
    fn from(err: std::io::Error) -> Self {
        Self::new(&format!("{:?}", err.kind()), &err.to_string())
    }
}

impl From<std::io::Error> for ArbiterError {
    /// Converts a `std::io::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `std::io::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::IoOperation`].
    fn from(err: std::io::Error) -> Self {
        Self::IoOperation(IoOperationError::from(err))
    }
}

/// Wrapper error for zero-copy `rkyv` binary serialization/deserialization failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("rkyv binary codec error: {message}")]
pub struct RkyvCodecError {
    /// Human-readable description of the `rkyv` codec failure.
    pub message: String,
}

impl RkyvCodecError {
    /// Creates a new [`RkyvCodecError`].
    ///
    /// # Arguments
    ///
    /// * `message` - Diagnostic `rkyv` codec failure message.
    ///
    /// # Returns
    ///
    /// Structured [`RkyvCodecError`].
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

impl From<rkyv::rancor::Error> for RkyvCodecError {
    /// Converts an `rkyv::rancor::Error` into an [`RkyvCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rkyv::rancor::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`RkyvCodecError`].
    fn from(err: rkyv::rancor::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<rkyv::rancor::Error> for ArbiterError {
    /// Converts an `rkyv::rancor::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rkyv::rancor::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::RkyvCodec`].
    fn from(err: rkyv::rancor::Error) -> Self {
        Self::RkyvCodec(RkyvCodecError::from(err))
    }
}

/// Wrapper error for QUIC transport and stream framing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("QUIC transport error (stream {stream_id}): {message}")]
pub struct QuicTransportError {
    /// Multiplexed QUIC stream identifier (`0` = Control, `1` = Telemetry, `2` = `ArtifactP2p`).
    pub stream_id: u64,
    /// Human-readable description of the QUIC failure.
    pub message: String,
}

impl QuicTransportError {
    /// Creates a new [`QuicTransportError`] for `stream_id` and `message`.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - QUIC stream identifier.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`QuicTransportError`].
    pub fn new(stream_id: u64, message: &str) -> Self {
        Self {
            stream_id,
            message: message.to_owned(),
        }
    }
}

impl From<quinn::ConnectionError> for QuicTransportError {
    /// Converts a `quinn::ConnectionError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ConnectionError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::ConnectionError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::WriteError> for QuicTransportError {
    /// Converts a `quinn::WriteError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::WriteError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::WriteError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::ReadError> for QuicTransportError {
    /// Converts a `quinn::ReadError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ReadError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::ReadError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::ConnectError> for QuicTransportError {
    /// Converts a `quinn::ConnectError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ConnectError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::ConnectError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::SendDatagramError> for QuicTransportError {
    /// Converts a `quinn::SendDatagramError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::SendDatagramError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::SendDatagramError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::ConnectionError> for ArbiterError {
    /// Converts a `quinn::ConnectionError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ConnectionError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::ConnectionError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::WriteError> for ArbiterError {
    /// Converts a `quinn::WriteError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::WriteError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::WriteError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::ReadError> for ArbiterError {
    /// Converts a `quinn::ReadError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ReadError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::ReadError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::ConnectError> for ArbiterError {
    /// Converts a `quinn::ConnectError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ConnectError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::ConnectError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::SendDatagramError> for ArbiterError {
    /// Converts a `quinn::SendDatagramError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::SendDatagramError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::SendDatagramError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::ReadToEndError> for QuicTransportError {
    /// Converts a `quinn::ReadToEndError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ReadToEndError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::ReadToEndError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::ReadToEndError> for ArbiterError {
    /// Converts a `quinn::ReadToEndError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ReadToEndError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::ReadToEndError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::ReadExactError> for QuicTransportError {
    /// Converts a `quinn::ReadExactError` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ReadExactError`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::ReadExactError) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::ReadExactError> for ArbiterError {
    /// Converts a `quinn::ReadExactError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ReadExactError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::ReadExactError) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

impl From<quinn::ClosedStream> for QuicTransportError {
    /// Converts a `quinn::ClosedStream` into a [`QuicTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ClosedStream`.
    ///
    /// # Returns
    ///
    /// A structured [`QuicTransportError`].
    fn from(err: quinn::ClosedStream) -> Self {
        Self::new(0, &err.to_string())
    }
}

impl From<quinn::ClosedStream> for ArbiterError {
    /// Converts a `quinn::ClosedStream` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `quinn::ClosedStream`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::QuicTransport`].
    fn from(err: quinn::ClosedStream) -> Self {
        Self::QuicTransport(QuicTransportError::from(err))
    }
}

/// Wrapper error for TLS 1.3 handshake and X.509v3 certificate codec failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("TLS codec error: {message}")]
pub struct RustlsCodecError {
    /// Human-readable description of the TLS failure.
    pub message: String,
}

impl RustlsCodecError {
    /// Creates a new [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `message` - Diagnostic TLS error message.
    ///
    /// # Returns
    ///
    /// Structured [`RustlsCodecError`].
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

impl From<rustls::Error> for RustlsCodecError {
    /// Converts a `rustls::Error` into a [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rustls::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`RustlsCodecError`].
    fn from(err: rustls::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for RustlsCodecError {
    /// Converts a `rustls::pki_types::InvalidDnsNameError` into a [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `InvalidDnsNameError`.
    ///
    /// # Returns
    ///
    /// A structured [`RustlsCodecError`].
    fn from(err: rustls::pki_types::InvalidDnsNameError) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<rustls::pki_types::pem::Error> for RustlsCodecError {
    /// Converts a `rustls::pki_types::pem::Error` into a [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rustls::pki_types::pem::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`RustlsCodecError`].
    fn from(err: rustls::pki_types::pem::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<rustls::Error> for ArbiterError {
    /// Converts a `rustls::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rustls::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::RustlsCodec`].
    fn from(err: rustls::Error) -> Self {
        Self::RustlsCodec(RustlsCodecError::from(err))
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for ArbiterError {
    /// Converts an `InvalidDnsNameError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `InvalidDnsNameError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::RustlsCodec`].
    fn from(err: rustls::pki_types::InvalidDnsNameError) -> Self {
        Self::RustlsCodec(RustlsCodecError::from(err))
    }
}

impl From<rustls::pki_types::pem::Error> for ArbiterError {
    /// Converts a `rustls::pki_types::pem::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rustls::pki_types::pem::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::RustlsCodec`].
    fn from(err: rustls::pki_types::pem::Error) -> Self {
        Self::RustlsCodec(RustlsCodecError::from(err))
    }
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for RustlsCodecError {
    /// Converts a `quinn::crypto::rustls::NoInitialCipherSuite` into a [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `NoInitialCipherSuite` error.
    ///
    /// # Returns
    ///
    /// A structured [`RustlsCodecError`].
    fn from(err: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for ArbiterError {
    /// Converts a `quinn::crypto::rustls::NoInitialCipherSuite` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `NoInitialCipherSuite` error.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::RustlsCodec`].
    fn from(err: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Self::RustlsCodec(RustlsCodecError::from(err))
    }
}

/// Wrapper error for HTTP/1.1, HTTP/2, and `RecordIO` transport failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("HTTP transport error (status {status_code}): {message}")]
pub struct HttpTransportError {
    /// Associated HTTP status code (`400`, `500`, `502`, etc.).
    pub status_code: u16,
    /// Human-readable description of the HTTP transport failure.
    pub message: String,
}

impl HttpTransportError {
    /// Creates a new [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `status_code` - HTTP status code.
    /// * `message` - Diagnostic HTTP error message.
    ///
    /// # Returns
    ///
    /// Structured [`HttpTransportError`].
    pub fn new(status_code: u16, message: &str) -> Self {
        Self {
            status_code,
            message: message.to_owned(),
        }
    }
}

impl From<http::Error> for HttpTransportError {
    /// Converts an `http::Error` into an [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`HttpTransportError`].
    fn from(err: http::Error) -> Self {
        Self::new(400, &err.to_string())
    }
}

impl From<http::uri::InvalidUri> for HttpTransportError {
    /// Converts an `http::uri::InvalidUri` into an [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::uri::InvalidUri`.
    ///
    /// # Returns
    ///
    /// A structured [`HttpTransportError`].
    fn from(err: http::uri::InvalidUri) -> Self {
        Self::new(400, &err.to_string())
    }
}

impl From<http::header::InvalidHeaderValue> for HttpTransportError {
    /// Converts an `http::header::InvalidHeaderValue` into an [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::header::InvalidHeaderValue`.
    ///
    /// # Returns
    ///
    /// A structured [`HttpTransportError`].
    fn from(err: http::header::InvalidHeaderValue) -> Self {
        Self::new(400, &err.to_string())
    }
}

impl From<http::header::ToStrError> for HttpTransportError {
    /// Converts an `http::header::ToStrError` into an [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::header::ToStrError`.
    ///
    /// # Returns
    ///
    /// A structured [`HttpTransportError`].
    fn from(err: http::header::ToStrError) -> Self {
        Self::new(400, &err.to_string())
    }
}

impl From<h2::Error> for HttpTransportError {
    /// Converts an `h2::Error` into an [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `h2::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`HttpTransportError`].
    fn from(err: h2::Error) -> Self {
        Self::new(502, &err.to_string())
    }
}

impl From<http::Error> for ArbiterError {
    /// Converts an `http::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::HttpTransport`].
    fn from(err: http::Error) -> Self {
        Self::HttpTransport(HttpTransportError::from(err))
    }
}

impl From<http::uri::InvalidUri> for ArbiterError {
    /// Converts an `http::uri::InvalidUri` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::uri::InvalidUri`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::HttpTransport`].
    fn from(err: http::uri::InvalidUri) -> Self {
        Self::HttpTransport(HttpTransportError::from(err))
    }
}

impl From<http::header::InvalidHeaderValue> for ArbiterError {
    /// Converts an `http::header::InvalidHeaderValue` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::header::InvalidHeaderValue`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::HttpTransport`].
    fn from(err: http::header::InvalidHeaderValue) -> Self {
        Self::HttpTransport(HttpTransportError::from(err))
    }
}

impl From<http::header::ToStrError> for ArbiterError {
    /// Converts an `http::header::ToStrError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `http::header::ToStrError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::HttpTransport`].
    fn from(err: http::header::ToStrError) -> Self {
        Self::HttpTransport(HttpTransportError::from(err))
    }
}

impl From<h2::Error> for ArbiterError {
    /// Converts an `h2::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `h2::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::HttpTransport`].
    fn from(err: h2::Error) -> Self {
        Self::HttpTransport(HttpTransportError::from(err))
    }
}

/// Wrapper error for RFC 6455 WebSocket upgrade and frame codec failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("WebSocket codec error: {message}")]
pub struct WebSocketCodecError {
    /// Human-readable description of the WebSocket failure.
    pub message: String,
}

impl WebSocketCodecError {
    /// Creates a new [`WebSocketCodecError`].
    ///
    /// # Arguments
    ///
    /// * `message` - Diagnostic WebSocket error message.
    ///
    /// # Returns
    ///
    /// Structured [`WebSocketCodecError`].
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for WebSocketCodecError {
    /// Converts a `tokio_tungstenite::tungstenite::Error` into a [`WebSocketCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tungstenite::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`WebSocketCodecError`].
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ArbiterError {
    /// Converts a `tokio_tungstenite::tungstenite::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tungstenite::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::WebSocketCodec`].
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocketCodec(WebSocketCodecError::from(err))
    }
}

/// Wrapper error for external etcd v3 gRPC/HTTP2 client failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("etcd v3 client error on '{endpoint}': {message}")]
pub struct EtcdClientError {
    /// Target etcd v3 endpoint URI.
    pub endpoint: String,
    /// Human-readable description of the etcd client failure.
    pub message: String,
}

impl EtcdClientError {
    /// Creates a new [`EtcdClientError`].
    ///
    /// # Arguments
    ///
    /// * `endpoint` - etcd endpoint URI.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`EtcdClientError`].
    pub fn new(endpoint: &str, message: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for external `PostgreSQL` wire-protocol SQL client failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("PostgreSQL client error (SQLSTATE {sqlstate}): {message}")]
pub struct PostgresClientError {
    /// 5-character SQLSTATE code (e.g., `"40001"` serialization failure, `"08006"` connection failure).
    pub sqlstate: String,
    /// Human-readable description of the `PostgreSQL` client failure.
    pub message: String,
}

impl PostgresClientError {
    /// Creates a new [`PostgresClientError`].
    ///
    /// # Arguments
    ///
    /// * `sqlstate` - 5-character SQLSTATE code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`PostgresClientError`].
    pub fn new(sqlstate: &str, message: &str) -> Self {
        Self {
            sqlstate: sqlstate.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl From<tokio_postgres::Error> for PostgresClientError {
    /// Converts a `tokio_postgres::Error` into a [`PostgresClientError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tokio_postgres::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`PostgresClientError`].
    fn from(err: tokio_postgres::Error) -> Self {
        Self::new("08006", &err.to_string())
    }
}

impl From<tokio_postgres::Error> for ArbiterError {
    /// Converts a `tokio_postgres::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tokio_postgres::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::PostgresClient`].
    fn from(err: tokio_postgres::Error) -> Self {
        Self::PostgresClient(PostgresClientError::from(err))
    }
}

/// Wrapper error for Tier-2 Out-of-Band Redfish BMC HTTPS power fencing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Redfish BMC fence error on '{bmc_endpoint}' (HTTP {status_code}): {message}")]
pub struct RedfishFenceError {
    /// Target BMC Redfish endpoint URI.
    pub bmc_endpoint: String,
    /// HTTP status code returned by the BMC (`400`, `401`, `500`, `503`, etc.).
    pub status_code: u16,
    /// Human-readable diagnostic message from the Redfish response.
    pub message: String,
}

impl RedfishFenceError {
    /// Creates a new [`RedfishFenceError`].
    ///
    /// # Arguments
    ///
    /// * `bmc_endpoint` - Target BMC Redfish URI.
    /// * `status_code` - HTTP status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`RedfishFenceError`].
    pub fn new(bmc_endpoint: &str, status_code: u16, message: &str) -> Self {
        Self {
            bmc_endpoint: bmc_endpoint.to_owned(),
            status_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for Tier-2 Out-of-Band IPMI v2 RMCP+ chassis power control failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("IPMI v2 fence error on '{bmc_address}' (code 0x{completion_code:02x}): {reason}")]
pub struct IpmiFenceError {
    /// Target BMC address (`host:623`).
    pub bmc_address: String,
    /// IPMI completion code byte (`0x00` = normal, `0xC0` = node busy, etc.).
    pub completion_code: u8,
    /// Human-readable description of the IPMI failure.
    pub reason: String,
}

impl IpmiFenceError {
    /// Creates a new [`IpmiFenceError`].
    ///
    /// # Arguments
    ///
    /// * `bmc_address` - Target BMC IP/host address.
    /// * `completion_code` - Raw IPMI completion code byte.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`IpmiFenceError`].
    pub fn new(bmc_address: &str, completion_code: u8, reason: &str) -> Self {
        Self {
            bmc_address: bmc_address.to_owned(),
            completion_code,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Tier-2 `NVMe` Persistent Reservation (`PROUT` Preempt-and-Abort) storage fencing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("NVMe reservation error on '{device_path}' (status 0x{nvme_status:04x}): {reason}")]
pub struct NvmeReservationError {
    /// Block or character device path (e.g., `"/dev/nvme0n1"`).
    pub device_path: String,
    /// 16-bit `NVMe` status code (e.g., `0x0083` Reservation Conflict).
    pub nvme_status: u16,
    /// Human-readable description of the `NVMe` reservation failure.
    pub reason: String,
}

impl NvmeReservationError {
    /// Creates a new [`NvmeReservationError`].
    ///
    /// # Arguments
    ///
    /// * `device_path` - Target `NVMe` device path.
    /// * `nvme_status` - Raw 16-bit `NVMe` status code.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`NvmeReservationError`].
    pub fn new(device_path: &str, nvme_status: u16, reason: &str) -> Self {
        Self {
            device_path: device_path.to_owned(),
            nvme_status,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for OCI Distribution Specification v1.1 image manifest and layer pull failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "OCI registry error on '{registry_uri}' (status {status_code}, digest '{digest}'): {reason}"
)]
pub struct OciRegistryError {
    /// OCI registry endpoint or image reference URI.
    pub registry_uri: String,
    /// HTTP status code returned by the registry.
    pub status_code: u16,
    /// Content digest (`sha256:...`) being fetched.
    pub digest: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl OciRegistryError {
    /// Creates a new [`OciRegistryError`].
    ///
    /// # Arguments
    ///
    /// * `registry_uri` - Target OCI registry URI.
    /// * `status_code` - HTTP status code.
    /// * `digest` - Layer or manifest digest string.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`OciRegistryError`].
    pub fn new(registry_uri: &str, status_code: u16, digest: &str, reason: &str) -> Self {
        Self {
            registry_uri: registry_uri.to_owned(),
            status_code,
            digest: digest.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for OpenTelemetry (`OTLP/HTTP`) metric and trace export failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("OTLP export error on '{collector_endpoint}' (status {status_code}): {reason}")]
pub struct OtlpExportError {
    /// Target OTLP collector endpoint URI.
    pub collector_endpoint: String,
    /// HTTP status code returned by the collector.
    pub status_code: u16,
    /// Human-readable failure reason.
    pub reason: String,
}

impl OtlpExportError {
    /// Creates a new [`OtlpExportError`].
    ///
    /// # Arguments
    ///
    /// * `collector_endpoint` - Target OTLP collector endpoint URI.
    /// * `status_code` - HTTP status code.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`OtlpExportError`].
    pub fn new(collector_endpoint: &str, status_code: u16, reason: &str) -> Self {
        Self {
            collector_endpoint: collector_endpoint.to_owned(),
            status_code,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for low-level OS system call failures (`clone3`, `seccomp`, `jail_set`, `CreateJobObjectW`, `ioctl`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("OS syscall '{syscall}' failed (errno {errno}): {reason}")]
pub struct OsSyscallError {
    /// Name of the system call or kernel primitive.
    pub syscall: String,
    /// Numeric OS error code (`errno` or `GetLastError()`).
    pub errno: i32,
    /// Human-readable failure description.
    pub reason: String,
}

impl OsSyscallError {
    /// Creates a new [`OsSyscallError`].
    ///
    /// # Arguments
    ///
    /// * `syscall` - System call name.
    /// * `errno` - Numeric OS error code.
    /// * `reason` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`OsSyscallError`].
    pub fn new(syscall: &str, errno: i32, reason: &str) -> Self {
        Self {
            syscall: syscall.to_owned(),
            errno,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for TLS 1.3 / mTLS peer handshake and ALPN negotiation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("TLS handshake error with peer '{peer}' (ALPN '{alpn}'): {reason}")]
pub struct TlsHandshakeError {
    /// Remote peer address or SPIFFE ID.
    pub peer: String,
    /// Negotiated or attempted ALPN protocol identifier.
    pub alpn: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl TlsHandshakeError {
    /// Creates a new [`TlsHandshakeError`].
    ///
    /// # Arguments
    ///
    /// * `peer` - Remote peer endpoint or identity.
    /// * `alpn` - ALPN protocol string.
    /// * `reason` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`TlsHandshakeError`].
    pub fn new(peer: &str, alpn: &str, reason: &str) -> Self {
        Self {
            peer: peer.to_owned(),
            alpn: alpn.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for archive decompression and container layer unpacking failures (`gzip`, `zstd`, `zip`, `tar`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Archive format error ({format}) in '{archive_name}': {reason}")]
pub struct ArchiveFormatError {
    /// Compression or archive format (`tar.gz`, `tar.zst`, `zip`, `ustar`).
    pub format: String,
    /// Archive URI or file name.
    pub archive_name: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl ArchiveFormatError {
    /// Creates a new [`ArchiveFormatError`].
    ///
    /// # Arguments
    ///
    /// * `format` - Archive format identifier.
    /// * `archive_name` - Archive name or URI.
    /// * `reason` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`ArchiveFormatError`].
    pub fn new(format: &str, archive_name: &str, reason: &str) -> Self {
        Self {
            format: format.to_owned(),
            archive_name: archive_name.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for external subprocess execution failures (`runc`, `bhyvectl`, `zfs`, `nvidia-smi`, `sg_persist`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Subprocess '{program}' failed (exit code {exit_code}): {stderr}")]
pub struct SubprocessExecError {
    /// Executed binary or command name.
    pub program: String,
    /// Process exit status code.
    pub exit_code: i32,
    /// Captured standard error or diagnostic message.
    pub stderr: String,
}

impl SubprocessExecError {
    /// Creates a new [`SubprocessExecError`].
    ///
    /// # Arguments
    ///
    /// * `program` - Program name.
    /// * `exit_code` - Exit status code.
    /// * `stderr` - Diagnostic stderr string.
    ///
    /// # Returns
    ///
    /// Structured [`SubprocessExecError`].
    pub fn new(program: &str, exit_code: i32, stderr: &str) -> Self {
        Self {
            program: program.to_owned(),
            exit_code,
            stderr: stderr.to_owned(),
        }
    }
}

/// Wrapper error for POSIX kernel system call failures (`clone3`, `unshare`, `jail_set`, `rctl`, `pset_bind`, `setrlimit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("POSIX syscall '{syscall}' failed (errno {errno}): {message}")]
pub struct PosixSyscallError {
    /// Name of the POSIX system call.
    pub syscall: String,
    /// Numeric POSIX `errno` value.
    pub errno: i32,
    /// Human-readable error message.
    pub message: String,
}

impl PosixSyscallError {
    /// Creates a new [`PosixSyscallError`].
    ///
    /// # Arguments
    ///
    /// * `syscall` - POSIX syscall name.
    /// * `errno` - Numeric `errno`.
    /// * `message` - Diagnostic message.
    ///
    /// # Returns
    ///
    /// Structured [`PosixSyscallError`].
    pub fn new(syscall: &str, errno: i32, message: &str) -> Self {
        Self {
            syscall: syscall.to_owned(),
            errno,
            message: message.to_owned(),
        }
    }
}

#[cfg(unix)]
impl From<nix::errno::Errno> for PosixSyscallError {
    /// Converts a `nix::errno::Errno` into a [`PosixSyscallError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `nix::errno::Errno`.
    ///
    /// # Returns
    ///
    /// A structured [`PosixSyscallError`].
    fn from(err: nix::errno::Errno) -> Self {
        Self::new("nix", err as i32, err.desc())
    }
}

#[cfg(unix)]
impl From<nix::errno::Errno> for ArbiterError {
    /// Converts a `nix::errno::Errno` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `nix::errno::Errno`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::PosixSyscall`].
    fn from(err: nix::errno::Errno) -> Self {
        Self::PosixSyscall(PosixSyscallError::from(err))
    }
}

/// Wrapper error for Windows Win32 / Host Compute Service (`HCS`) API failures (`CreateJobObjectW`, `SetThreadGroupAffinity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Win32 API '{function}' failed (code 0x{error_code:08x}): {message}")]
pub struct Win32ApiError {
    /// Name of the Win32 or HCS API function.
    pub function: String,
    /// Win32 `GetLastError()` or `HRESULT` code.
    pub error_code: u32,
    /// Human-readable error message.
    pub message: String,
}

impl Win32ApiError {
    /// Creates a new [`Win32ApiError`].
    ///
    /// # Arguments
    ///
    /// * `function` - Win32 API function name.
    /// * `error_code` - Numeric Win32 error code.
    /// * `message` - Diagnostic message.
    ///
    /// # Returns
    ///
    /// Structured [`Win32ApiError`].
    pub fn new(function: &str, error_code: u32, message: &str) -> Self {
        Self {
            function: function.to_owned(),
            error_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for X.509v3 certificate chain, ASN.1 DER/PEM, or SPIFFE URI SAN validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("X.509 certificate error for '{subject}': {reason}")]
pub struct X509CertificateError {
    /// Certificate subject or SPIFFE ID context.
    pub subject: String,
    /// Human-readable validation failure reason.
    pub reason: String,
}

impl X509CertificateError {
    /// Creates a new [`X509CertificateError`].
    ///
    /// # Arguments
    ///
    /// * `subject` - Certificate subject or SPIFFE URI.
    /// * `reason` - Validation failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`X509CertificateError`].
    pub fn new(subject: &str, reason: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl From<rcgen::Error> for X509CertificateError {
    /// Converts an `rcgen::Error` into an [`X509CertificateError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rcgen::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`X509CertificateError`].
    fn from(err: rcgen::Error) -> Self {
        Self::new("rcgen", &err.to_string())
    }
}

impl From<der::Error> for X509CertificateError {
    /// Converts a `der::Error` into an [`X509CertificateError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `der::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`X509CertificateError`].
    fn from(err: der::Error) -> Self {
        Self::new("ASN.1 DER", &err.to_string())
    }
}

impl From<rcgen::Error> for ArbiterError {
    /// Converts an `rcgen::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rcgen::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::X509Certificate`].
    fn from(err: rcgen::Error) -> Self {
        Self::X509Certificate(X509CertificateError::from(err))
    }
}

impl From<der::Error> for ArbiterError {
    /// Converts a `der::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `der::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::X509Certificate`].
    fn from(err: der::Error) -> Self {
        Self::X509Certificate(X509CertificateError::from(err))
    }
}

/// Wrapper error for PKCS#8 private key and SPKI ASN.1 DER encoding/decoding failures (`Pkcs8DerError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("PKCS#8 DER key error in '{context}': {reason}")]
pub struct Pkcs8DerError {
    /// Key algorithm or ASN.1 structure context (`Ed25519`, `ECDSA-P256`, `PrivateKeyInfo`).
    pub context: String,
    /// Human-readable DER encoding/decoding failure reason.
    pub reason: String,
}

impl Pkcs8DerError {
    /// Creates a new [`Pkcs8DerError`].
    ///
    /// # Arguments
    ///
    /// * `context` - Key structure or algorithm context.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`Pkcs8DerError`].
    pub fn new(context: &str, reason: &str) -> Self {
        Self {
            context: context.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl From<der::Error> for Pkcs8DerError {
    /// Converts a `der::Error` into a [`Pkcs8DerError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `der::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`Pkcs8DerError`].
    fn from(err: der::Error) -> Self {
        Self::new("PKCS#8-DER", &err.to_string())
    }
}

/// Wrapper error for `rcgen` X.509v3 certificate generation and signing failures (`RcgenCertError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("rcgen X.509v3 certificate generation error for '{subject_san}': {reason}")]
pub struct RcgenCertError {
    /// Target SPIFFE URI SAN or certificate subject.
    pub subject_san: String,
    /// Human-readable `rcgen` failure reason.
    pub reason: String,
}

impl RcgenCertError {
    /// Creates a new [`RcgenCertError`].
    ///
    /// # Arguments
    ///
    /// * `subject_san` - Target SPIFFE URI SAN or subject name.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`RcgenCertError`].
    pub fn new(subject_san: &str, reason: &str) -> Self {
        Self {
            subject_san: subject_san.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl From<rcgen::Error> for RcgenCertError {
    /// Converts an `rcgen::Error` into an [`RcgenCertError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rcgen::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`RcgenCertError`].
    fn from(err: rcgen::Error) -> Self {
        Self::new("spiffe://arbiter.internal", &err.to_string())
    }
}

/// Wrapper error for RFC 5280 X.509v3 DER/PEM certificate parsing and extension extraction failures (`X509ParseError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("X.509v3 parse error at OID '{oid}': {reason}")]
pub struct X509ParseError {
    /// Object Identifier (`OID`, e.g., `"2.5.29.17"` for `subjectAltName`) or field being parsed.
    pub oid: String,
    /// Human-readable parsing failure reason.
    pub reason: String,
}

impl X509ParseError {
    /// Creates a new [`X509ParseError`].
    ///
    /// # Arguments
    ///
    /// * `oid` - Object Identifier or certificate section.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`X509ParseError`].
    pub fn new(oid: &str, reason: &str) -> Self {
        Self {
            oid: oid.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl From<der::Error> for X509ParseError {
    /// Converts a `der::Error` into an [`X509ParseError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `der::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`X509ParseError`].
    fn from(err: der::Error) -> Self {
        Self::new("2.5.29.17", &err.to_string())
    }
}

/// Wrapper error for asymmetric digital signature (`Ed25519`, `ECDSA-P256`) or MAC verification failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Cryptographic signature error ({algorithm}): {reason}")]
pub struct CryptoSignatureError {
    /// Signature algorithm identifier (`Ed25519`, `ECDSA-P256`, `HMAC-SHA256`).
    pub algorithm: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl CryptoSignatureError {
    /// Creates a new [`CryptoSignatureError`].
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Cryptographic algorithm name.
    /// * `reason` - Failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`CryptoSignatureError`].
    pub fn new(algorithm: &str, reason: &str) -> Self {
        Self {
            algorithm: algorithm.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl From<ed25519_dalek::SignatureError> for CryptoSignatureError {
    /// Converts an `ed25519_dalek::SignatureError` into a [`CryptoSignatureError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying signature error (`ed25519_dalek` / `p256::ecdsa`).
    ///
    /// # Returns
    ///
    /// A structured [`CryptoSignatureError`].
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::new("Ed25519/ECDSA", &err.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for ArbiterError {
    /// Converts an `ed25519_dalek::SignatureError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying signature error.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::CryptoSignature`].
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::CryptoSignature(CryptoSignatureError::from(err))
    }
}

impl From<base16ct::Error> for CryptoSignatureError {
    /// Converts a `base16ct::Error` hexadecimal decoding failure into a [`CryptoSignatureError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `base16ct::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`CryptoSignatureError`].
    fn from(err: base16ct::Error) -> Self {
        Self::new("Hex-Base16", &err.to_string())
    }
}

impl From<base16ct::Error> for ArbiterError {
    /// Converts a `base16ct::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `base16ct::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::CryptoSignature`].
    fn from(err: base16ct::Error) -> Self {
        Self::CryptoSignature(CryptoSignatureError::from(err))
    }
}

impl From<base64::DecodeError> for CryptoSignatureError {
    /// Converts a `base64::DecodeError` into a [`CryptoSignatureError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `base64::DecodeError`.
    ///
    /// # Returns
    ///
    /// A structured [`CryptoSignatureError`].
    fn from(err: base64::DecodeError) -> Self {
        Self::new("Base64", &err.to_string())
    }
}

impl From<base64::DecodeError> for ArbiterError {
    /// Converts a `base64::DecodeError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `base64::DecodeError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::CryptoSignature`].
    fn from(err: base64::DecodeError) -> Self {
        Self::CryptoSignature(CryptoSignatureError::from(err))
    }
}

impl From<hmac::digest::InvalidLength> for CryptoSignatureError {
    /// Converts an `hmac::digest::InvalidLength` key length error into a [`CryptoSignatureError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `hmac::digest::InvalidLength`.
    ///
    /// # Returns
    ///
    /// A structured [`CryptoSignatureError`].
    fn from(err: hmac::digest::InvalidLength) -> Self {
        Self::new("HMAC-SHA256", &err.to_string())
    }
}

impl From<hmac::digest::InvalidLength> for ArbiterError {
    /// Converts an `hmac::digest::InvalidLength` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `hmac::digest::InvalidLength`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::CryptoSignature`].
    fn from(err: hmac::digest::InvalidLength) -> Self {
        Self::CryptoSignature(CryptoSignatureError::from(err))
    }
}

impl From<rustls::server::VerifierBuilderError> for RustlsCodecError {
    /// Converts a `rustls::server::VerifierBuilderError` into a [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `VerifierBuilderError`.
    ///
    /// # Returns
    ///
    /// A structured [`RustlsCodecError`].
    fn from(err: rustls::server::VerifierBuilderError) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<rustls::server::VerifierBuilderError> for ArbiterError {
    /// Converts a `rustls::server::VerifierBuilderError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `VerifierBuilderError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::RustlsCodec`].
    fn from(err: rustls::server::VerifierBuilderError) -> Self {
        Self::RustlsCodec(RustlsCodecError::from(err))
    }
}

/// Wrapper error for pseudo-terminal (`PTY` / `ConPTY`) allocation or attach failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("PTY allocation error for container '{container_id}': {reason}")]
pub struct PtyAllocationError {
    /// Target container or task identifier.
    pub container_id: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl PtyAllocationError {
    /// Creates a new [`PtyAllocationError`].
    ///
    /// # Arguments
    ///
    /// * `container_id` - Target container identifier.
    /// * `reason` - PTY failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`PtyAllocationError`].
    pub fn new(container_id: &str, reason: &str) -> Self {
        Self {
            container_id: container_id.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Mesos Fetcher artifact download, checksum verification, or extraction failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Fetcher download error for URI '{uri}': {reason}")]
pub struct FetcherDownloadError {
    /// Artifact source URI (`http://`, `https://`, `file://`, `oci://`).
    pub uri: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl FetcherDownloadError {
    /// Creates a new [`FetcherDownloadError`].
    ///
    /// # Arguments
    ///
    /// * `uri` - Source artifact URI.
    /// * `reason` - Failure description.
    ///
    /// # Returns
    ///
    /// Structured [`FetcherDownloadError`].
    pub fn new(uri: &str, reason: &str) -> Self {
        Self {
            uri: uri.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for low-level OS syscall execution failures with errno context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Syscall execution error '{syscall}' (errno {errno_code}): {message}")]
pub struct SyscallExecutionError {
    /// Name of the invoked system call.
    pub syscall: String,
    /// Numeric operating system `errno` or status code.
    pub errno_code: i32,
    /// Human-readable error message.
    pub message: String,
}

impl SyscallExecutionError {
    /// Creates a new [`SyscallExecutionError`].
    ///
    /// # Arguments
    ///
    /// * `syscall` - Name of the invoked system call.
    /// * `errno_code` - Numeric operating system `errno` code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`SyscallExecutionError`].
    pub fn new(syscall: &str, errno_code: i32, message: &str) -> Self {
        Self {
            syscall: syscall.to_owned(),
            errno_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for Container Storage Interface (`CSI`) gRPC endpoint failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("CSI gRPC error on '{endpoint}' (status {grpc_status}): {message}")]
pub struct CsiGrpcError {
    /// Target CSI Unix Domain Socket or gRPC endpoint.
    pub endpoint: String,
    /// Numeric gRPC status code (`0..=16`).
    pub grpc_status: u32,
    /// Human-readable gRPC status message.
    pub message: String,
}

impl CsiGrpcError {
    /// Creates a new [`CsiGrpcError`].
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Target CSI socket or endpoint.
    /// * `grpc_status` - Numeric gRPC status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`CsiGrpcError`].
    pub fn new(endpoint: &str, grpc_status: u32, message: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            grpc_status,
            message: message.to_owned(),
        }
    }
}

impl From<tonic::Status> for CsiGrpcError {
    /// Converts a `tonic::Status` into a [`CsiGrpcError`].
    ///
    /// # Arguments
    ///
    /// * `status` - The underlying `tonic::Status`.
    ///
    /// # Returns
    ///
    /// A structured [`CsiGrpcError`].
    fn from(status: tonic::Status) -> Self {
        #[allow(clippy::cast_sign_loss)]
        let code = status.code() as i32 as u32;
        Self::new("grpc", code, status.message())
    }
}

impl From<tonic::Status> for ArbiterError {
    /// Converts a `tonic::Status` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `status` - The underlying `tonic::Status`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::CsiGrpc`].
    fn from(status: tonic::Status) -> Self {
        Self::CsiGrpc(CsiGrpcError::from(status))
    }
}

/// Wrapper error for archive entry extraction and path-security validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Archive extraction error ({archive_format}) at entry '{entry_path}': {reason}")]
pub struct ArchiveExtractionError {
    /// Archive container format (`tar`, `tar.gz`, `tar.zst`, `tar.xz`, `zip`).
    pub archive_format: String,
    /// Relative entry path inside the archive that failed validation or extraction.
    pub entry_path: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl ArchiveExtractionError {
    /// Creates a new [`ArchiveExtractionError`].
    ///
    /// # Arguments
    ///
    /// * `archive_format` - Archive format identifier.
    /// * `entry_path` - Entry path inside the archive.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`ArchiveExtractionError`].
    pub fn new(archive_format: &str, entry_path: &str, reason: &str) -> Self {
        Self {
            archive_format: archive_format.to_owned(),
            entry_path: entry_path.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Container Network Interface (`CNI`) plugin execution failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("CNI plugin '{plugin_name}' error for container '{container_id}': {reason}")]
pub struct CniPluginError {
    /// Name of the CNI network plugin (`bridge`, `calico`, `macvlan`, `portmap`).
    pub plugin_name: String,
    /// Target container identifier.
    pub container_id: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl CniPluginError {
    /// Creates a new [`CniPluginError`].
    ///
    /// # Arguments
    ///
    /// * `plugin_name` - Name of the CNI plugin.
    /// * `container_id` - Target container identifier.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`CniPluginError`].
    pub fn new(plugin_name: &str, container_id: &str, reason: &str) -> Self {
        Self {
            plugin_name: plugin_name.to_owned(),
            container_id: container_id.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Agent revocable resource oversubscription and `QoS` controller failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "Oversubscription QoS error on agent '{agent_id}' (revocable {revocable_cpu_m}m): {reason}"
)]
pub struct OversubscriptionQosError {
    /// Hosting Agent identifier.
    pub agent_id: String,
    /// Revocable CPU millicores involved in the `QoS` violation.
    pub revocable_cpu_m: u64,
    /// Human-readable `QoS` failure or eviction reason.
    pub reason: String,
}

impl OversubscriptionQosError {
    /// Creates a new [`OversubscriptionQosError`].
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting Agent identifier.
    /// * `revocable_cpu_m` - Revocable CPU millicores.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`OversubscriptionQosError`].
    pub fn new(agent_id: &str, revocable_cpu_m: u64, reason: &str) -> Self {
        Self {
            agent_id: agent_id.to_owned(),
            revocable_cpu_m,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Master Registry recovery and strict agent re-registration failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Master registry recovery error on '{master_id}' (strict={strict_mode}): {reason}")]
pub struct RegistryRecoveryError {
    /// Master node identifier.
    pub master_id: String,
    /// Whether strict registry recovery mode was enabled.
    pub strict_mode: bool,
    /// Human-readable recovery failure reason.
    pub reason: String,
}

impl RegistryRecoveryError {
    /// Creates a new [`RegistryRecoveryError`].
    ///
    /// # Arguments
    ///
    /// * `master_id` - Master node identifier.
    /// * `strict_mode` - Whether strict registry mode is active.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`RegistryRecoveryError`].
    pub fn new(master_id: &str, strict_mode: bool, reason: &str) -> Self {
        Self {
            master_id: master_id.to_owned(),
            strict_mode,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for X25519 ECDH key agreement and RFC 5869 HKDF-SHA256 key derivation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Key exchange error ({protocol}): {reason}")]
pub struct KeyExchangeError {
    /// Key exchange or KDF protocol name (`X25519`, `HKDF-SHA256`).
    pub protocol: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl KeyExchangeError {
    /// Creates a new [`KeyExchangeError`].
    ///
    /// # Arguments
    ///
    /// * `protocol` - Key exchange or KDF protocol identifier.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`KeyExchangeError`].
    pub fn new(protocol: &str, reason: &str) -> Self {
        Self {
            protocol: protocol.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for ChaCha20-Poly1305 and AES-256-GCM AEAD encryption/decryption and tag verification failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("AEAD cipher error ({cipher}): {reason}")]
pub struct AeadCipherError {
    /// AEAD cipher algorithm (`ChaCha20-Poly1305`, `AES-256-GCM`).
    pub cipher: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl AeadCipherError {
    /// Creates a new [`AeadCipherError`].
    ///
    /// # Arguments
    ///
    /// * `cipher` - AEAD cipher algorithm name.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`AeadCipherError`].
    pub fn new(cipher: &str, reason: &str) -> Self {
        Self {
            cipher: cipher.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

impl From<ring::error::Unspecified> for AeadCipherError {
    /// Converts a `ring::error::Unspecified` cryptographic error into an [`AeadCipherError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `ring::error::Unspecified`.
    ///
    /// # Returns
    ///
    /// A structured [`AeadCipherError`].
    fn from(err: ring::error::Unspecified) -> Self {
        Self::new("ring-aead", &err.to_string())
    }
}

impl From<ring::error::Unspecified> for ArbiterError {
    /// Converts a `ring::error::Unspecified` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `ring::error::Unspecified`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::AeadCipher`].
    fn from(err: ring::error::Unspecified) -> Self {
        Self::AeadCipher(AeadCipherError::from(err))
    }
}

impl From<ring::error::KeyRejected> for AeadCipherError {
    /// Converts a `ring::error::KeyRejected` key validation error into an [`AeadCipherError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `ring::error::KeyRejected`.
    ///
    /// # Returns
    ///
    /// A structured [`AeadCipherError`].
    fn from(err: ring::error::KeyRejected) -> Self {
        Self::new("ring-key", &err.to_string())
    }
}

impl From<ring::error::KeyRejected> for ArbiterError {
    /// Converts a `ring::error::KeyRejected` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `ring::error::KeyRejected`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::AeadCipher`].
    fn from(err: ring::error::KeyRejected) -> Self {
        Self::AeadCipher(AeadCipherError::from(err))
    }
}

impl From<chacha20poly1305::Error> for AeadCipherError {
    /// Converts a `chacha20poly1305::Error` AEAD tag or key error into an [`AeadCipherError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `chacha20poly1305::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`AeadCipherError`].
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::new("ChaCha20-Poly1305", &err.to_string())
    }
}

impl From<chacha20poly1305::Error> for ArbiterError {
    /// Converts a `chacha20poly1305::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `chacha20poly1305::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::AeadCipher`].
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::AeadCipher(AeadCipherError::from(err))
    }
}

/// Wrapper error for compressed archive bitstream failures (`DEFLATE`/`gzip`, `Zstandard`, `XZ`/`LZMA2`, `ZIP`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Archive decompression error ({codec}) at offset {byte_offset}: {reason}")]
pub struct ArchiveDecompressionError {
    /// Compression codec name (`gzip`, `deflate`, `zstd`, `xz`, `zip`).
    pub codec: String,
    /// Byte offset in the compressed stream where the error occurred.
    pub byte_offset: u64,
    /// Human-readable failure reason.
    pub reason: String,
}

impl ArchiveDecompressionError {
    /// Creates a new [`ArchiveDecompressionError`].
    ///
    /// # Arguments
    ///
    /// * `codec` - Compression codec identifier.
    /// * `byte_offset` - Byte offset in the input stream.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`ArchiveDecompressionError`].
    pub fn new(codec: &str, byte_offset: u64, reason: &str) -> Self {
        Self {
            codec: codec.to_owned(),
            byte_offset,
            reason: reason.to_owned(),
        }
    }
}

impl From<zip::result::ZipError> for ArchiveDecompressionError {
    /// Converts a `zip::result::ZipError` into an [`ArchiveDecompressionError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `ZipError`.
    ///
    /// # Returns
    ///
    /// A structured [`ArchiveDecompressionError`].
    fn from(err: zip::result::ZipError) -> Self {
        Self::new("zip", 0, &err.to_string())
    }
}

impl From<zip::result::ZipError> for ArbiterError {
    /// Converts a `zip::result::ZipError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `ZipError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::ArchiveDecompression`].
    fn from(err: zip::result::ZipError) -> Self {
        Self::ArchiveDecompression(ArchiveDecompressionError::from(err))
    }
}

impl From<flate2::DecompressError> for ArchiveDecompressionError {
    /// Converts a `flate2::DecompressError` into an [`ArchiveDecompressionError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `flate2::DecompressError`.
    ///
    /// # Returns
    ///
    /// A structured [`ArchiveDecompressionError`].
    fn from(err: flate2::DecompressError) -> Self {
        Self::new("deflate", 0, &err.to_string())
    }
}

impl From<flate2::DecompressError> for ArbiterError {
    /// Converts a `flate2::DecompressError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `flate2::DecompressError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::ArchiveDecompression`].
    fn from(err: flate2::DecompressError) -> Self {
        Self::ArchiveDecompression(ArchiveDecompressionError::from(err))
    }
}

impl From<lzma_rs::error::Error> for ArchiveDecompressionError {
    /// Converts an `lzma_rs::error::Error` XZ/LZMA2 codec error into an [`ArchiveDecompressionError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `lzma_rs::error::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`ArchiveDecompressionError`].
    fn from(err: lzma_rs::error::Error) -> Self {
        Self::new("xz", 0, &err.to_string())
    }
}

impl From<lzma_rs::error::Error> for ArbiterError {
    /// Converts an `lzma_rs::error::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `lzma_rs::error::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::ArchiveDecompression`].
    fn from(err: lzma_rs::error::Error) -> Self {
        Self::ArchiveDecompression(ArchiveDecompressionError::from(err))
    }
}

/// Wrapper error for malformed RFC 1035 / RFC 2782 DNS wire packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("DNS wire packet error for '{qname}' (rcode {rcode}): {reason}")]
pub struct DnsWirePacketError {
    /// Queried domain name or packet context.
    pub qname: String,
    /// Numeric DNS response code (`RCODE`).
    pub rcode: u8,
    /// Human-readable failure reason.
    pub reason: String,
}

impl DnsWirePacketError {
    /// Creates a new [`DnsWirePacketError`].
    ///
    /// # Arguments
    ///
    /// * `qname` - Queried domain name or context.
    /// * `rcode` - DNS `RCODE` byte.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`DnsWirePacketError`].
    pub fn new(qname: &str, rcode: u8, reason: &str) -> Self {
        Self {
            qname: qname.to_owned(),
            rcode,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Protobuf binary wire encoding and decoding failures (`application/x-protobuf`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Protobuf wire codec error at field tag {field_tag} (wire_type {wire_type}): {reason}")]
pub struct ProtobufCodecError {
    /// Protobuf field number (`tag >> 3`).
    pub field_tag: u32,
    /// Protobuf 3-bit wire type (`0 = Varint`, `1 = 64-bit`, `2 = Length-delimited`, `5 = 32-bit`).
    pub wire_type: u8,
    /// Human-readable failure reason.
    pub reason: String,
}

impl ProtobufCodecError {
    /// Creates a new [`ProtobufCodecError`].
    ///
    /// # Arguments
    ///
    /// * `field_tag` - Protobuf field number.
    /// * `wire_type` - Protobuf 3-bit wire type.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`ProtobufCodecError`].
    pub fn new(field_tag: u32, wire_type: u8, reason: &str) -> Self {
        Self {
            field_tag,
            wire_type,
            reason: reason.to_owned(),
        }
    }
}

impl From<prost::DecodeError> for ProtobufCodecError {
    /// Converts a `prost::DecodeError` into a [`ProtobufCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `prost::DecodeError`.
    ///
    /// # Returns
    ///
    /// A structured [`ProtobufCodecError`].
    fn from(err: prost::DecodeError) -> Self {
        Self::new(0, 2, &err.to_string())
    }
}

impl From<prost::EncodeError> for ProtobufCodecError {
    /// Converts a `prost::EncodeError` into a [`ProtobufCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `prost::EncodeError`.
    ///
    /// # Returns
    ///
    /// A structured [`ProtobufCodecError`].
    fn from(err: prost::EncodeError) -> Self {
        Self::new(0, 2, &err.to_string())
    }
}

impl From<prost::DecodeError> for ArbiterError {
    /// Converts a `prost::DecodeError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `prost::DecodeError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::ProtobufCodec`].
    fn from(err: prost::DecodeError) -> Self {
        Self::ProtobufCodec(ProtobufCodecError::from(err))
    }
}

impl From<prost::EncodeError> for ArbiterError {
    /// Converts a `prost::EncodeError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `prost::EncodeError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::ProtobufCodec`].
    fn from(err: prost::EncodeError) -> Self {
        Self::ProtobufCodec(ProtobufCodecError::from(err))
    }
}

/// Wrapper error for NVIDIA Management Library (`NVML` / `libnvidia-ml.so`) FFI probe failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("NVML FFI probe error on '{device_id}' (nvmlReturn_t={nvml_code}): {message}")]
pub struct NvmlProbeError {
    /// GPU device identifier or `PCIe` BDF address.
    pub device_id: String,
    /// Numeric `nvmlReturn_t` status code.
    pub nvml_code: u32,
    /// Human-readable NVML error description.
    pub message: String,
}

impl NvmlProbeError {
    /// Creates a new [`NvmlProbeError`].
    ///
    /// # Arguments
    ///
    /// * `device_id` - GPU identifier or `PCIe` BDF address.
    /// * `nvml_code` - Numeric `nvmlReturn_t` error code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`NvmlProbeError`].
    pub fn new(device_id: &str, nvml_code: u32, message: &str) -> Self {
        Self {
            device_id: device_id.to_owned(),
            nvml_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for AMD `ROCm` SMI / `KFD` (`libamd_smi.so` / `librocm_smi64.so`) probe failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("ROCm SMI probe error on '{node_id}' (rsmi_status_t={rsmi_status}): {message}")]
pub struct RocmSmiError {
    /// KFD topology node or DRM card identifier.
    pub node_id: String,
    /// Numeric `rsmi_status_t` / `amdsmi_status_t` status code.
    pub rsmi_status: u32,
    /// Human-readable `ROCm` SMI error description.
    pub message: String,
}

impl RocmSmiError {
    /// Creates a new [`RocmSmiError`].
    ///
    /// # Arguments
    ///
    /// * `node_id` - KFD node or DRM card identifier.
    /// * `rsmi_status` - Numeric SMI status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`RocmSmiError`].
    pub fn new(node_id: &str, rsmi_status: u32, message: &str) -> Self {
        Self {
            node_id: node_id.to_owned(),
            rsmi_status,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for Intel `oneAPI` Level Zero (`libze_loader.so`) XPU probe failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "Intel Level Zero probe error on '{device_id}' (ze_result_t=0x{ze_result:08x}): {message}"
)]
pub struct LevelZeroProbeError {
    /// Intel XPU device or tile identifier.
    pub device_id: String,
    /// Numeric `ze_result_t` status code.
    pub ze_result: u32,
    /// Human-readable Level Zero error description.
    pub message: String,
}

impl LevelZeroProbeError {
    /// Creates a new [`LevelZeroProbeError`].
    ///
    /// # Arguments
    ///
    /// * `device_id` - XPU device or tile identifier.
    /// * `ze_result` - Numeric `ze_result_t` status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`LevelZeroProbeError`].
    pub fn new(device_id: &str, ze_result: u32, message: &str) -> Self {
        Self {
            device_id: device_id.to_owned(),
            ze_result,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for Google Cloud TPU (`libtpu.so` / `/dev/accel*` / `/dev/vfio/*`) probe failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Google libtpu probe error on '{accel_dev}' (status_code={status_code}): {message}")]
pub struct LibTpuProbeError {
    /// Accelerator device path or slice identifier.
    pub accel_dev: String,
    /// Numeric driver or `libtpu` status code.
    pub status_code: i32,
    /// Human-readable TPU driver failure message.
    pub message: String,
}

impl LibTpuProbeError {
    /// Creates a new [`LibTpuProbeError`].
    ///
    /// # Arguments
    ///
    /// * `accel_dev` - Accelerator device path or slice identifier.
    /// * `status_code` - Numeric status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`LibTpuProbeError`].
    pub fn new(accel_dev: &str, status_code: i32, message: &str) -> Self {
        Self {
            accel_dev: accel_dev.to_owned(),
            status_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for `InfiniBand` / `RoCE` v2 (`libibverbs` / `rdma-core`) fabric discovery failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("InfiniBand verbs probe error on HCA '{hca_name}' port {port_num}: {reason}")]
pub struct IbVerbsProbeError {
    /// RDMA Host Channel Adapter (`HCA`) name (e.g., `mlx5_0`).
    pub hca_name: String,
    /// Physical IB/RoCE port number (`>= 1`).
    pub port_num: u8,
    /// Human-readable fabric probe failure reason.
    pub reason: String,
}

impl IbVerbsProbeError {
    /// Creates a new [`IbVerbsProbeError`].
    ///
    /// # Arguments
    ///
    /// * `hca_name` - RDMA HCA device name.
    /// * `port_num` - Physical port number.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`IbVerbsProbeError`].
    pub fn new(hca_name: &str, port_num: u8, reason: &str) -> Self {
        Self {
            hca_name: hca_name.to_owned(),
            port_num,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Linux `Firecracker` `MicroVM` Unix-socket REST API failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "Firecracker MicroVM API error on '{socket_path}' ({http_method} {api_path} -> {status_code}): {fault_message}"
)]
pub struct FirecrackerApiError {
    /// Firecracker control Unix Domain Socket path.
    pub socket_path: String,
    /// HTTP method (`PUT`, `PATCH`, `GET`).
    pub http_method: String,
    /// Firecracker API route (`/boot-source`, `/actions`, etc.).
    pub api_path: String,
    /// HTTP response status code.
    pub status_code: u16,
    /// Diagnostic fault message returned by Firecracker.
    pub fault_message: String,
}

impl FirecrackerApiError {
    /// Creates a new [`FirecrackerApiError`].
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Firecracker UDS path.
    /// * `http_method` - HTTP verb.
    /// * `api_path` - API endpoint path.
    /// * `status_code` - HTTP status code.
    /// * `fault_message` - Fault message body.
    ///
    /// # Returns
    ///
    /// Structured [`FirecrackerApiError`].
    pub fn new(
        socket_path: &str,
        http_method: &str,
        api_path: &str,
        status_code: u16,
        fault_message: &str,
    ) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
            http_method: http_method.to_owned(),
            api_path: api_path.to_owned(),
            status_code,
            fault_message: fault_message.to_owned(),
        }
    }
}

/// Wrapper error for FreeBSD `bhyve` / `bhyvectl` / `vmm.ko` hypervisor control failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("FreeBSD bhyve hypervisor error for VM '{vm_name}' (exit_code={exit_code}): {reason}")]
pub struct BhyveCtlError {
    /// `bhyve` virtual machine instance name (`/dev/vmm/<vm_name>`).
    pub vm_name: String,
    /// Process exit code or `ioctl` `errno`.
    pub exit_code: i32,
    /// Human-readable failure reason.
    pub reason: String,
}

impl BhyveCtlError {
    /// Creates a new [`BhyveCtlError`].
    ///
    /// # Arguments
    ///
    /// * `vm_name` - Virtual machine instance name.
    /// * `exit_code` - Exit status or `errno`.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`BhyveCtlError`].
    pub fn new(vm_name: &str, exit_code: i32, reason: &str) -> Self {
        Self {
            vm_name: vm_name.to_owned(),
            exit_code,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Windows `Hyper-V` Host Compute Service (`HCS` / `vmcompute.dll`) failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "Windows Hyper-V HCS error for compute system '{system_id}' (HRESULT=0x{hresult:08x}): {message}"
)]
pub struct HyperVHcsError {
    /// HCS compute system identifier.
    pub system_id: String,
    /// Win32 `HRESULT` error code.
    pub hresult: u32,
    /// Human-readable HCS error message.
    pub message: String,
}

impl HyperVHcsError {
    /// Creates a new [`HyperVHcsError`].
    ///
    /// # Arguments
    ///
    /// * `system_id` - HCS compute system identifier.
    /// * `hresult` - Win32 `HRESULT` error code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`HyperVHcsError`].
    pub fn new(system_id: &str, hresult: u32, message: &str) -> Self {
        Self {
            system_id: system_id.to_owned(),
            hresult,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for macOS `Virtualization.framework` (`VZVirtualMachine`) hypervisor failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "macOS Virtualization.framework error for VM '{vm_id}' (VZErrorCode={error_code}): {description}"
)]
pub struct AppleVzError {
    /// Virtual machine identifier.
    pub vm_id: String,
    /// Numeric `VZErrorCode` domain value.
    pub error_code: i64,
    /// Human-readable `NSError` localized description.
    pub description: String,
}

impl AppleVzError {
    /// Creates a new [`AppleVzError`].
    ///
    /// # Arguments
    ///
    /// * `vm_id` - Virtual machine identifier.
    /// * `error_code` - Numeric `VZErrorCode`.
    /// * `description` - Diagnostic failure description.
    ///
    /// # Returns
    ///
    /// Structured [`AppleVzError`].
    pub fn new(vm_id: &str, error_code: i64, description: &str) -> Self {
        Self {
            vm_id: vm_id.to_owned(),
            error_code,
            description: description.to_owned(),
        }
    }
}

/// Wrapper error for OS signal delivery (`SIGTERM`, `SIGKILL`, `SIGSTOP`, `SIGCONT`, `SIGUSR1`) failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Signal delivery error (signal {signal_num} to PID {target_pid}): {reason}")]
pub struct SignalDeliveryError {
    /// Target OS process identifier (`PID`).
    pub target_pid: u32,
    /// Numeric POSIX/OS signal number.
    pub signal_num: i32,
    /// Human-readable failure reason.
    pub reason: String,
}

impl SignalDeliveryError {
    /// Creates a new [`SignalDeliveryError`].
    ///
    /// # Arguments
    ///
    /// * `target_pid` - Target OS process identifier.
    /// * `signal_num` - Numeric POSIX signal number.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`SignalDeliveryError`].
    pub fn new(target_pid: u32, signal_num: i32, reason: &str) -> Self {
        Self {
            target_pid,
            signal_num,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for interactive terminal raw-mode (`termios` / `stty` / ANSI alternate screen) failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Terminal raw-mode error on '{tty_device}': {reason}")]
pub struct TerminalRawModeError {
    /// Terminal device or stream name (e.g., `"/dev/tty"`, `"stdin"`).
    pub tty_device: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl TerminalRawModeError {
    /// Creates a new [`TerminalRawModeError`].
    ///
    /// # Arguments
    ///
    /// * `tty_device` - Terminal device or stream name.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`TerminalRawModeError`].
    pub fn new(tty_device: &str, reason: &str) -> Self {
        Self {
            tty_device: tty_device.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for FUSE (`/dev/fuse`), `overlayfs`, `nullfs`, or `lofs` rootfs mount failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("FUSE/overlay mount error at '{mountpoint}' (fstype '{fs_type}'): {reason}")]
pub struct FuseMountError {
    /// Target filesystem mountpoint path.
    pub mountpoint: String,
    /// Filesystem or mount mechanism (`fuse`, `overlayfs`, `nullfs`, `lofs`, `hardlink`).
    pub fs_type: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl FuseMountError {
    /// Creates a new [`FuseMountError`].
    ///
    /// # Arguments
    ///
    /// * `mountpoint` - Target mountpoint directory path.
    /// * `fs_type` - Filesystem or mount type.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`FuseMountError`].
    pub fn new(mountpoint: &str, fs_type: &str, reason: &str) -> Self {
        Self {
            mountpoint: mountpoint.to_owned(),
            fs_type: fs_type.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Linux `CRIU` (`criu dump` / `criu restore`) process tree checkpoint failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("CRIU checkpoint error ({action} on PID {pid} at '{image_dir}'): {reason}")]
pub struct CriuCheckpointError {
    /// CRIU action (`dump`, `restore`, `pre-dump`).
    pub action: String,
    /// Target process tree root PID.
    pub pid: u32,
    /// Checkpoint image directory path.
    pub image_dir: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl CriuCheckpointError {
    /// Creates a new [`CriuCheckpointError`].
    ///
    /// # Arguments
    ///
    /// * `action` - CRIU operation (`dump` or `restore`).
    /// * `pid` - Target process identifier.
    /// * `image_dir` - Checkpoint directory path.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`CriuCheckpointError`].
    pub fn new(action: &str, pid: u32, image_dir: &str, reason: &str) -> Self {
        Self {
            action: action.to_owned(),
            pid,
            image_dir: image_dir.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for ZFS dataset management (`zfs create`, `zfs snapshot`, `zfs clone`, `zfs destroy`) failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("ZFS command '{subcommand}' failed on dataset '{dataset}': {reason}")]
pub struct ZfsCommandError {
    /// ZFS subcommand (`create`, `snapshot`, `clone`, `destroy`, `set`).
    pub subcommand: String,
    /// Target ZFS pool/dataset path (e.g., `"tank/arbiter/vol-1"`).
    pub dataset: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl ZfsCommandError {
    /// Creates a new [`ZfsCommandError`].
    ///
    /// # Arguments
    ///
    /// * `subcommand` - ZFS subcommand name.
    /// * `dataset` - Target ZFS dataset name.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`ZfsCommandError`].
    pub fn new(subcommand: &str, dataset: &str, reason: &str) -> Self {
        Self {
            subcommand: subcommand.to_owned(),
            dataset: dataset.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for asynchronous runtime task join, timer elapsed, or event-loop failures (`AsyncRuntimeError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Async runtime error during '{operation}': {message}")]
pub struct AsyncRuntimeError {
    /// Asynchronous operation or task context (`join`, `timeout`, `signal`).
    pub operation: String,
    /// Human-readable failure description.
    pub message: String,
}

impl AsyncRuntimeError {
    /// Creates a new [`AsyncRuntimeError`].
    ///
    /// # Arguments
    ///
    /// * `operation` - Asynchronous operation name.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`AsyncRuntimeError`].
    pub fn new(operation: &str, message: &str) -> Self {
        Self {
            operation: operation.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl From<tokio::task::JoinError> for AsyncRuntimeError {
    /// Converts a `tokio::task::JoinError` into an [`AsyncRuntimeError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tokio::task::JoinError`.
    ///
    /// # Returns
    ///
    /// A structured [`AsyncRuntimeError`].
    fn from(err: tokio::task::JoinError) -> Self {
        Self::new("tokio::join", &err.to_string())
    }
}

impl From<tokio::task::JoinError> for ArbiterError {
    /// Converts a `tokio::task::JoinError` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tokio::task::JoinError`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::AsyncRuntime`].
    fn from(err: tokio::task::JoinError) -> Self {
        Self::AsyncRuntime(AsyncRuntimeError::from(err))
    }
}

impl From<tokio::time::error::Elapsed> for AsyncRuntimeError {
    /// Converts a `tokio::time::error::Elapsed` timeout error into an [`AsyncRuntimeError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tokio::time::error::Elapsed`.
    ///
    /// # Returns
    ///
    /// A structured [`AsyncRuntimeError`].
    fn from(err: tokio::time::error::Elapsed) -> Self {
        Self::new("tokio::timeout", &err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for ArbiterError {
    /// Converts a `tokio::time::error::Elapsed` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `tokio::time::error::Elapsed`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::AsyncRuntime`].
    fn from(err: tokio::time::error::Elapsed) -> Self {
        Self::AsyncRuntime(AsyncRuntimeError::from(err))
    }
}

/// Wrapper error for generic gRPC transport and status failures (`GrpcTransportError`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("gRPC transport error on '{endpoint}' (status {status_code}): {message}")]
pub struct GrpcTransportError {
    /// Target gRPC endpoint or service URI.
    pub endpoint: String,
    /// Numeric gRPC status code (`0..=16`).
    pub status_code: u32,
    /// Human-readable gRPC status message.
    pub message: String,
}

impl GrpcTransportError {
    /// Creates a new [`GrpcTransportError`].
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Target gRPC endpoint URI.
    /// * `status_code` - Numeric gRPC status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`GrpcTransportError`].
    pub fn new(endpoint: &str, status_code: u32, message: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            status_code,
            message: message.to_owned(),
        }
    }
}

impl From<tonic::Status> for GrpcTransportError {
    /// Converts a `tonic::Status` into a [`GrpcTransportError`].
    ///
    /// # Arguments
    ///
    /// * `status` - The underlying `tonic::Status`.
    ///
    /// # Returns
    ///
    /// A structured [`GrpcTransportError`].
    fn from(status: tonic::Status) -> Self {
        #[allow(clippy::cast_sign_loss)]
        let code = status.code() as i32 as u32;
        Self::new("grpc", code, status.message())
    }
}

/// Wrapper error for runtime shared-library loading (`dlopen` / `LoadLibraryExW` / `dlsym`) failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Dynamic library error in '{library_path}' (symbol '{symbol}'): {message}")]
pub struct DynamicLibraryError {
    /// Shared library path or soname (`libnvidia-ml.so.1`, `libamd_smi.so`, `libfdb_c.so`).
    pub library_path: String,
    /// Symbol name being resolved (or `"<dlopen>"` on library open failure).
    pub symbol: String,
    /// Human-readable OS loader diagnostic message.
    pub message: String,
}

impl DynamicLibraryError {
    /// Creates a new [`DynamicLibraryError`].
    ///
    /// # Arguments
    ///
    /// * `library_path` - Shared library path or soname.
    /// * `symbol` - Symbol name being resolved.
    /// * `message` - Diagnostic loader error message.
    ///
    /// # Returns
    ///
    /// Structured [`DynamicLibraryError`].
    pub fn new(library_path: &str, symbol: &str, message: &str) -> Self {
        Self {
            library_path: library_path.to_owned(),
            symbol: symbol.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl From<libloading::Error> for DynamicLibraryError {
    /// Converts a `libloading::Error` into a [`DynamicLibraryError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `libloading::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`DynamicLibraryError`].
    fn from(err: libloading::Error) -> Self {
        Self::new("libloading", "<dlopen/dlsym>", &err.to_string())
    }
}

impl From<libloading::Error> for ArbiterError {
    /// Converts a `libloading::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `libloading::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::DynamicLibrary`].
    fn from(err: libloading::Error) -> Self {
        Self::DynamicLibrary(DynamicLibraryError::from(err))
    }
}

/// Wrapper error for embedded `SQLite` WAL (`PRAGMA journal_mode=WAL`) transactional storage failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("SQLite WAL storage error on '{db_path}' (code {sqlite_code}): {message}")]
pub struct SqliteStorageError {
    /// Path to the `SQLite` database or `.wal` file.
    pub db_path: String,
    /// Numeric `SQLite` result/extended error code (e.g., `5` for `SQLITE_BUSY`, `14` for `SQLITE_CANTOPEN`).
    pub sqlite_code: i32,
    /// Human-readable `SQLite` storage diagnostic message.
    pub message: String,
}

impl SqliteStorageError {
    /// Creates a new [`SqliteStorageError`].
    ///
    /// # Arguments
    ///
    /// * `db_path` - Database or WAL file path.
    /// * `sqlite_code` - Numeric `SQLite` error code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`SqliteStorageError`].
    pub fn new(db_path: &str, sqlite_code: i32, message: &str) -> Self {
        Self {
            db_path: db_path.to_owned(),
            sqlite_code,
            message: message.to_owned(),
        }
    }
}

impl From<rusqlite::Error> for SqliteStorageError {
    /// Converts a `rusqlite::Error` into a [`SqliteStorageError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rusqlite::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`SqliteStorageError`].
    fn from(err: rusqlite::Error) -> Self {
        let code = if let rusqlite::Error::SqliteFailure(ref ffi_err, _) = err {
            ffi_err.extended_code
        } else {
            1
        };
        Self::new("rusqlite", code, &err.to_string())
    }
}

impl From<rusqlite::Error> for ArbiterError {
    /// Converts a `rusqlite::Error` directly into an [`ArbiterError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rusqlite::Error`.
    ///
    /// # Returns
    ///
    /// [`ArbiterError::SqliteStorage`].
    fn from(err: rusqlite::Error) -> Self {
        Self::SqliteStorage(SqliteStorageError::from(err))
    }
}

/// Wrapper error for `HashiCorp Consul` HTTP KV/Session API (`/v1/kv/*`, `/v1/session/*`) failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Consul HTTP API error at '{endpoint}' (status {status_code}): {message}")]
pub struct ConsulClientError {
    /// Target `Consul` HTTP endpoint URI.
    pub endpoint: String,
    /// HTTP status code returned by `Consul` (`0` on transport failure).
    pub status_code: u16,
    /// Human-readable `Consul` error message.
    pub message: String,
}

impl ConsulClientError {
    /// Creates a new [`ConsulClientError`].
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Target `Consul` HTTP endpoint URI.
    /// * `status_code` - HTTP status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`ConsulClientError`].
    pub fn new(endpoint: &str, status_code: u16, message: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            status_code,
            message: message.to_owned(),
        }
    }
}

/// Comprehensive, strongly-typed error enum covering all failure modes in Arbiter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error, From)]
pub enum ArbiterError {
    /// An identifier string was empty when a non-empty value was required.
    #[display("Empty identifier provided for kind '{kind}'")]
    EmptyIdentifier {
        /// The domain identifier kind that was empty.
        kind: String,
    },

    /// An identifier contained characters outside the permitted ASCII/URL-safe set or exceeded length bounds.
    #[display("Invalid identifier '{value}' for kind '{kind}': {reason}")]
    InvalidIdentifierCharacters {
        /// The domain identifier kind.
        kind: String,
        /// The rejected identifier value.
        value: String,
        /// Explanation of why the identifier is invalid.
        reason: String,
    },

    /// A resource quantity violated domain invariants (e.g., zero when positive required, or out of range).
    #[display("Invalid resource quantity {quantity} for '{resource}': {reason}")]
    InvalidResourceQuantity {
        /// Name of the resource type.
        resource: String,
        /// The invalid numeric value.
        quantity: u64,
        /// Reason the quantity is invalid.
        reason: String,
    },

    /// A numeric or port range had `start > end` or violated bounds.
    #[display("Invalid range bounds [{start}, {end}] for '{context}'")]
    InvalidRangeBounds {
        /// Context or type of the range.
        context: String,
        /// Start of the range.
        start: u64,
        /// End of the range.
        end: u64,
    },

    /// A hardware topology graph contained cycles, dangling edges, or invalid interconnect links.
    #[display("Invalid hardware topology graph: {reason}")]
    InvalidTopologyGraph {
        /// Detailed explanation of the topology violation.
        reason: String,
    },

    /// A role weight or basis point share was zero or exceeded the allowed maximum.
    #[display("Invalid share weight {weight_bps} bps: {reason}")]
    InvalidShareWeight {
        /// The rejected weight in basis points.
        weight_bps: u64,
        /// Explanation of the constraint violation.
        reason: String,
    },

    /// A role quota had guaranteed minimum exceeding hard maximum capacity.
    #[display("Invalid quota bounds for role '{role}': {reason}")]
    InvalidQuotaBounds {
        /// Name of the role.
        role: String,
        /// Description of the quota bound mismatch.
        reason: String,
    },

    /// Checked integer addition or multiplication overflowed `u64::MAX`.
    #[display("Arithmetic overflow during '{operation}'")]
    ArithmeticOverflow {
        /// Description of the arithmetic operation that overflowed.
        operation: String,
    },

    /// Checked integer subtraction underflowed below zero.
    #[display("Arithmetic underflow during '{operation}'")]
    ArithmeticUnderflow {
        /// Description of the arithmetic operation that underflowed.
        operation: String,
    },

    /// Checked integer division or remainder encountered a zero divisor.
    #[display("Division by zero during '{operation}'")]
    DivisionByZero {
        /// Description of the division operation.
        operation: String,
    },

    /// Requested resources exceed available capacity.
    #[display("Insufficient '{resource}': requested {requested}, available {available}")]
    InsufficientResources {
        /// The resource dimension that was exhausted.
        resource: String,
        /// Requested amount.
        requested: u64,
        /// Available amount.
        available: u64,
    },

    /// Attempted to combine or compare incompatible resource types.
    #[display("Resource type mismatch: expected '{expected}', found '{found}'")]
    ResourceTypeMismatch {
        /// Expected resource type or vendor.
        expected: String,
        /// Actual resource type or vendor encountered.
        found: String,
    },

    /// A hardware device ID was registered more than once in the same bundle or topology.
    #[display("Duplicate device ID '{device_id}'")]
    DuplicateDeviceId {
        /// The duplicated device identifier.
        device_id: String,
    },

    /// Referenced hardware device ID was not found.
    #[display("Device '{device_id}' not found")]
    DeviceNotFound {
        /// The missing device identifier.
        device_id: String,
    },

    /// An NVIDIA MIG profile slice configuration was invalid or unsupported.
    #[display("Invalid NVIDIA MIG profile '{profile}': {reason}")]
    InvalidMigProfile {
        /// The MIG profile string or identifier.
        profile: String,
        /// Reason the profile is invalid.
        reason: String,
    },

    /// A TPU topology slice specification had invalid torus dimensions or unhealthy ICI links.
    #[display("Invalid TPU topology slice '{slice}': {reason}")]
    InvalidTpuTopologySlice {
        /// Description or ID of the TPU slice.
        slice: String,
        /// Reason the slice is invalid.
        reason: String,
    },

    /// Hardware nodes cannot be linked via the requested interconnect fabric.
    #[display(
        "Incompatible interconnect '{interconnect}' between '{source_node}' and '{target_node}'"
    )]
    IncompatibleInterconnect {
        /// The interconnect type name.
        interconnect: String,
        /// Source node identifier.
        source_node: String,
        /// Target node identifier.
        target_node: String,
    },

    /// No registered agents satisfied the task's resource and topology constraints.
    #[display("No eligible agents found for workload '{workload}': {reason}")]
    NoEligibleAgents {
        /// Workload or task identifier.
        workload: String,
        /// Summary of why agents were filtered out.
        reason: String,
    },

    /// Atomic gang scheduling failed to place all members of a task group simultaneously.
    #[display(
        "Gang constraint unsatisfied for group '{group_id}': placed {placed}/{required} members"
    )]
    GangConstraintUnsatisfied {
        /// Task group identifier.
        group_id: String,
        /// Number of members that could be placed.
        placed: usize,
        /// Total members required for atomic gang launch.
        required: usize,
    },

    /// Preemption solver could not free sufficient topology-compatible capacity.
    #[display("Preemption failed for workload '{workload}': {reason}")]
    PreemptionFailed {
        /// Incoming high-priority workload identifier.
        workload: String,
        /// Reason preemption could not satisfy the request.
        reason: String,
    },

    /// Allocation would exceed the role's hard maximum quota.
    #[display("Quota exceeded for role '{role}' on resource '{resource}'")]
    QuotaExceeded {
        /// Role identifier.
        role: String,
        /// Resource dimension that exceeded quota.
        resource: String,
    },

    /// Referenced role does not exist in the hierarchy.
    #[display("Role '{role}' not found")]
    RoleNotFound {
        /// Missing role name.
        role: String,
    },

    /// Referenced framework ID is not registered.
    #[display("Framework '{framework_id}' not found")]
    FrameworkNotFound {
        /// Missing framework identifier.
        framework_id: String,
    },

    /// Resource offer TTL elapsed before acceptance.
    #[display("Offer '{offer_id}' has expired")]
    OfferExpired {
        /// Expired offer identifier.
        offer_id: String,
    },

    /// Resource offer was already accepted, declined, or rescinded.
    #[display("Offer '{offer_id}' was already consumed")]
    OfferAlreadyConsumed {
        /// Consumed offer identifier.
        offer_id: String,
    },

    /// State store read operation failed.
    #[display("State store read error on key '{key}': {reason}")]
    StoreReadError {
        /// Key or prefix being read.
        key: String,
        /// Failure reason.
        reason: String,
    },

    /// State store write or delete operation failed.
    #[display("State store write error on key '{key}': {reason}")]
    StoreWriteError {
        /// Key being mutated.
        key: String,
        /// Failure reason.
        reason: String,
    },

    /// Atomic Compare-And-Swap failed due to version or value mismatch.
    #[display("CAS conflict on key '{key}': expected revision {expected_rev}, actual {actual_rev}")]
    CasConflict {
        /// Key targeted by CAS.
        key: String,
        /// Expected revision or state description.
        expected_rev: u64,
        /// Actual revision encountered.
        actual_rev: u64,
    },

    /// Embedded Raft consensus protocol error.
    #[display("Raft consensus error in term {term}: {reason}")]
    RaftConsensusError {
        /// Current Raft term.
        term: u64,
        /// Reason for consensus failure.
        reason: String,
    },

    /// Mutating operation was submitted to a non-leader Raft node.
    #[display("Node '{node_id}' is not the Raft leader (known leader: '{leader_hint}')")]
    NotLeader {
        /// ID of the follower/candidate node that rejected the write.
        node_id: String,
        /// Optional hint of the current leader ID (empty if unknown).
        leader_hint: String,
    },

    /// Time-bounded election or heartbeat lease has expired.
    #[display("Lease '{lease_id}' expired at tick {expired_at_tick}")]
    LeaseExpired {
        /// Identifier of the expired lease.
        lease_id: String,
        /// Monotonic tick or timestamp when the lease expired.
        expired_at_tick: u64,
    },

    /// Operation presented a fencing token older than the current active epoch.
    #[display("Stale fencing token {presented_token} (minimum required: {current_token})")]
    FencingTokenStale {
        /// The rejected stale token value.
        presented_token: u64,
        /// The active monotonic fencing token value.
        current_token: u64,
    },

    /// Hardware or OS STONITH fencing action failed to execute cleanly.
    #[display("Fence execution failed on target '{target}': {reason}")]
    FenceExecutionFailed {
        /// Target agent or task being fenced.
        target: String,
        /// Failure details.
        reason: String,
    },

    /// Overlapping primary leases or conflicting quorum partitions were detected.
    #[display("Split-brain detected in election group '{group_id}': {details}")]
    SplitBrainDetected {
        /// Election group or cluster identifier.
        group_id: String,
        /// Diagnostic details of the conflict.
        details: String,
    },

    /// Remote federated cluster peer could not be reached.
    #[display("Federation peer '{peer_cluster}' is unreachable: {reason}")]
    FederationPeerUnreachable {
        /// Target peer cluster ID.
        peer_cluster: String,
        /// Connectivity failure reason.
        reason: String,
    },

    /// Wire or storage serialization failed.
    #[display("Serialization error ({format}): {reason}")]
    SerializationError {
        /// Format name (e.g., `rkyv`, `json`).
        format: String,
        /// Failure description.
        reason: String,
    },

    /// Wire or storage deserialization failed.
    #[display("Deserialization error ({format}): {reason}")]
    DeserializationError {
        /// Format name (e.g., `rkyv`, `json`).
        format: String,
        /// Failure description.
        reason: String,
    },

    /// JSON codec error automatically converted via `From<JsonCodecError>`.
    #[display("JSON codec failure: {_0}")]
    #[from]
    JsonCodec(JsonCodecError),

    /// Standard I/O operation error automatically converted via `From<IoOperationError>`.
    #[display("I/O failure: {_0}")]
    #[from]
    IoOperation(IoOperationError),

    /// Zero-copy `rkyv` binary codec error automatically converted via `From<RkyvCodecError>`.
    #[display("rkyv binary codec failure: {_0}")]
    #[from]
    RkyvCodec(RkyvCodecError),

    /// QUIC transport error automatically converted via `From<QuicTransportError>`.
    #[display("QUIC transport failure: {_0}")]
    #[from]
    QuicTransport(QuicTransportError),

    /// TLS 1.3 codec error automatically converted via `From<RustlsCodecError>`.
    #[display("TLS codec failure: {_0}")]
    #[from]
    RustlsCodec(RustlsCodecError),

    /// HTTP transport error automatically converted via `From<HttpTransportError>`.
    #[display("HTTP transport failure: {_0}")]
    #[from]
    HttpTransport(HttpTransportError),

    /// WebSocket codec error automatically converted via `From<WebSocketCodecError>`.
    #[display("WebSocket codec failure: {_0}")]
    #[from]
    WebSocketCodec(WebSocketCodecError),

    /// etcd v3 client error automatically converted via `From<EtcdClientError>`.
    #[display("etcd v3 client failure: {_0}")]
    #[from]
    EtcdClient(EtcdClientError),

    /// `PostgreSQL` client error automatically converted via `From<PostgresClientError>`.
    #[display("PostgreSQL client failure: {_0}")]
    #[from]
    PostgresClient(PostgresClientError),

    /// Tier-2 Out-of-Band Redfish BMC power fencing error automatically converted via `From<RedfishFenceError>`.
    #[display("Redfish BMC fence failure: {_0}")]
    #[from]
    RedfishFence(RedfishFenceError),

    /// Tier-2 Out-of-Band IPMI v2 chassis control error automatically converted via `From<IpmiFenceError>`.
    #[display("IPMI v2 fence failure: {_0}")]
    #[from]
    IpmiFence(IpmiFenceError),

    /// Tier-2 `NVMe` Persistent Reservation fencing error automatically converted via `From<NvmeReservationError>`.
    #[display("NVMe reservation failure: {_0}")]
    #[from]
    NvmeReservation(NvmeReservationError),

    /// OCI image registry pull error automatically converted via `From<OciRegistryError>`.
    #[display("OCI registry failure: {_0}")]
    #[from]
    OciRegistry(OciRegistryError),

    /// OpenTelemetry OTLP export error automatically converted via `From<OtlpExportError>`.
    #[display("OTLP export failure: {_0}")]
    #[from]
    OtlpExport(OtlpExportError),

    /// Low-level OS system call error automatically converted via `From<OsSyscallError>`.
    #[display("OS syscall failure: {_0}")]
    #[from]
    OsSyscall(OsSyscallError),

    /// TLS 1.3 handshake error automatically converted via `From<TlsHandshakeError>`.
    #[display("TLS handshake failure: {_0}")]
    #[from]
    TlsHandshake(TlsHandshakeError),

    /// Archive format decompression error automatically converted via `From<ArchiveFormatError>`.
    #[display("Archive format failure: {_0}")]
    #[from]
    ArchiveFormat(ArchiveFormatError),

    /// External subprocess execution error automatically converted via `From<SubprocessExecError>`.
    #[display("Subprocess execution failure: {_0}")]
    #[from]
    SubprocessExec(SubprocessExecError),

    /// Multi-key state store transaction was aborted.
    #[display("Transaction aborted: {reason}")]
    TransactionAborted {
        /// Reason the transaction was rolled back.
        reason: String,
    },

    /// Generic network transport error.
    #[display("Transport error on '{endpoint}': {reason}")]
    TransportError {
        /// Endpoint address or stream identifier.
        endpoint: String,
        /// Reason for transport failure.
        reason: String,
    },

    /// QUIC connection or stream multiplexing error.
    #[display("QUIC connection error (stream {stream_id}): {reason}")]
    QuicConnectionError {
        /// QUIC stream identifier.
        stream_id: u64,
        /// Error description.
        reason: String,
    },

    /// HTTP/REST, SSE, or WebSocket handler error.
    #[display("HTTP handler error (status {status_code}): {message}")]
    HttpHandlerError {
        /// HTTP status code.
        status_code: u16,
        /// Diagnostic message.
        message: String,
    },

    /// mTLS certificate or TLS configuration error.
    #[display("TLS configuration error: {reason}")]
    TlsConfigurationError {
        /// Detailed TLS failure reason.
        reason: String,
    },

    /// SPIFFE workload identity URI SAN is malformed, untrusted, or expired.
    #[display("Invalid SPIFFE identity '{uri}': {reason}")]
    SpiffeIdentityInvalid {
        /// The rejected SPIFFE URI string.
        uri: String,
        /// Validation failure reason.
        reason: String,
    },

    /// OIDC/JWT or mTLS client authentication failed.
    #[display("Authentication failed for principal '{principal}': {reason}")]
    AuthenticationFailed {
        /// Principal identifier.
        principal: String,
        /// Failure reason.
        reason: String,
    },

    /// RBAC or ABAC policy engine denied the requested action.
    #[display(
        "Authorization denied for principal '{principal}' on action '{action}' targeting '{resource}'"
    )]
    AuthorizationDenied {
        /// Principal requesting access.
        principal: String,
        /// Requested action.
        action: String,
        /// Target resource.
        resource: String,
    },

    /// Envelope AEAD decryption of a task secret failed due to key mismatch or ciphertext tampering.
    #[display("Secret decryption failed for secret '{secret_id}': {reason}")]
    SecretDecryptionFailed {
        /// Secret identifier.
        secret_id: String,
        /// Failure reason.
        reason: String,
    },

    /// Requested OS isolator primitive is not supported on the host operating system.
    #[display("Isolator '{isolator}' is not supported on OS '{os}'")]
    IsolatorUnsupportedOnOs {
        /// Name of the isolation mechanism.
        isolator: String,
        /// Operating system name.
        os: String,
    },

    /// Linux `cgroups v2` hierarchy configuration or limit enforcement failed.
    #[display("Linux cgroup v2 error at '{cgroup_path}': {reason}")]
    CgroupError {
        /// Cgroup filesystem path.
        cgroup_path: String,
        /// Failure reason.
        reason: String,
    },

    /// Linux namespace or `seccomp-bpf` setup failed.
    #[display("Linux namespace error ({namespace_kind}): {reason}")]
    NamespaceError {
        /// Type of namespace (`pid`, `net`, `mnt`, etc.).
        namespace_kind: String,
        /// Failure reason.
        reason: String,
    },

    /// FreeBSD Jail or RCTL/RACCT resource limit operation failed.
    #[display("FreeBSD jail error for '{jail_name}': {reason}")]
    JailError {
        /// Jail name or JID.
        jail_name: String,
        /// Failure reason.
        reason: String,
    },

    /// illumos Zone, processor set (`pset`), or Crossbow VNIC operation failed.
    #[display("illumos zone error for '{zone_name}': {reason}")]
    ZoneError {
        /// Zone name.
        zone_name: String,
        /// Failure reason.
        reason: String,
    },

    /// Windows Job Object or Processor Group affinity operation failed.
    #[display("Windows Job Object error for '{job_name}': {reason}")]
    JobObjectError {
        /// Job Object identifier.
        job_name: String,
        /// Failure reason.
        reason: String,
    },

    /// macOS `sandbox-exec`, `setrlimit`, or Mach `QoS` policy operation failed.
    #[display("Sandbox error ({mechanism}): {reason}")]
    SandboxError {
        /// Underlying sandbox mechanism.
        mechanism: String,
        /// Failure reason.
        reason: String,
    },

    /// OCI container runtime (`runc`, `crun`, `containerd`, `ocijail`, `runhcs`) failed.
    #[display("Container runtime '{runtime}' error for container '{container_id}': {reason}")]
    ContainerRuntimeError {
        /// Runtime binary or driver name.
        runtime: String,
        /// Container identifier.
        container_id: String,
        /// Failure reason.
        reason: String,
    },

    /// `MicroVM` driver (`Firecracker`, `bhyve`, `Hyper-V`, `Virtualization.framework`) failed.
    #[display("MicroVM engine '{engine}' error for VM '{vm_id}': {reason}")]
    MicroVmError {
        /// `MicroVM` hypervisor name.
        engine: String,
        /// Virtual machine identifier.
        vm_id: String,
        /// Failure reason.
        reason: String,
    },

    /// OS user/group privilege drop or working directory switch failed.
    #[display("User switch error for user '{user}': {reason}")]
    UserSwitchError {
        /// Target OS username or UID.
        user: String,
        /// Failure reason.
        reason: String,
    },

    /// System CPU, NUMA, memory, or fabric hardware discovery probe failed.
    #[display("Hardware probe '{probe_name}' failed: {reason}")]
    ProbeFailed {
        /// Name of the hardware collector.
        probe_name: String,
        /// Failure reason.
        reason: String,
    },

    /// NVIDIA Management Library (NVML) probe or telemetry error.
    #[display("NVIDIA NVML error on device '{device}': {reason}")]
    NvmlError {
        /// GPU identifier or index.
        device: String,
        /// NVML error details.
        reason: String,
    },

    /// AMD `ROCm` / SMI probe or telemetry error.
    #[display("AMD ROCm error on device '{device}': {reason}")]
    RocmError {
        /// GPU identifier or index.
        device: String,
        /// `ROCm` error details.
        reason: String,
    },

    /// Apple Silicon Metal / `IOKit` GPU or Neural Engine probe error.
    #[display("Apple Metal probe error: {reason}")]
    MetalError {
        /// Error details.
        reason: String,
    },

    /// Intel Level Zero (XPU) probe or sub-device tile error.
    #[display("Intel Level Zero error on device '{device}': {reason}")]
    LevelZeroError {
        /// Device identifier.
        device: String,
        /// Error details.
        reason: String,
    },

    /// Google Cloud TPU or Edge TPU driver probe error.
    #[display("TPU driver error on device '{device}': {reason}")]
    TpuDriverError {
        /// TPU device path or ID.
        device: String,
        /// Error details.
        reason: String,
    },

    /// Prometheus or OpenTelemetry metric registration conflict.
    #[display("Metric registration error for '{metric_name}': {reason}")]
    MetricRegistrationError {
        /// Name of the metric.
        metric_name: String,
        /// Conflict or validation reason.
        reason: String,
    },

    /// Task readiness or liveness health probe failed beyond threshold.
    #[display(
        "Health check failed for task '{task_id}' after {consecutive_failures} attempts: {reason}"
    )]
    HealthCheckFailed {
        /// Task identifier.
        task_id: String,
        /// Number of consecutive probe failures.
        consecutive_failures: u32,
        /// Diagnostic failure message.
        reason: String,
    },

    /// Command-line interface argument parsing or subcommand dispatch error.
    #[display("Invalid CLI arguments: {reason}")]
    InvalidCliArguments {
        /// Description of the invalid flag or argument.
        reason: String,
    },

    /// Graceful shutdown signal handler registration or execution error.
    #[display("Shutdown signal error: {reason}")]
    ShutdownSignalError {
        /// Error details.
        reason: String,
    },

    /// Invalid state machine transition for a task lifecycle.
    #[display("Invalid task state transition from '{from_state}' to '{to_state}'")]
    TaskStateTransitionInvalid {
        /// Current state name.
        from_state: String,
        /// Attempted target state name.
        to_state: String,
    },

    /// Benchmark or simulation configuration parameter violated domain invariants.
    #[display("Invalid benchmark configuration for '{parameter}': {reason}")]
    InvalidBenchmarkConfig {
        /// Name of the invalid benchmark parameter.
        parameter: String,
        /// Explanation of why the configuration is invalid.
        reason: String,
    },

    /// Active client transactional ledger detected a lost committed write or divergent history.
    #[display(
        "Linearizability violation in group '{group_id}': lost_writes={lost_writes}, divergent_writes={divergent_writes}"
    )]
    LinearizabilityViolation {
        /// Election group or service identifier.
        group_id: String,
        /// Count of acknowledged client writes missing after failover.
        lost_writes: u64,
        /// Count of split-brain or divergent writes detected.
        divergent_writes: u64,
    },

    /// Wire-traffic simulation model drifted beyond the allowed basis-point threshold from empirical capture.
    #[display(
        "Wire-traffic calibration drift {observed_drift_bps} bps exceeded maximum allowed {max_allowed_bps} bps"
    )]
    CalibrationDriftExceeded {
        /// Observed drift in basis points.
        observed_drift_bps: u64,
        /// Maximum permitted drift in basis points.
        max_allowed_bps: u64,
    },

    /// Failed to bind a TCP, UDP, or Unix Domain Socket listener endpoint.
    #[display("Socket bind error on '{endpoint}': {reason}")]
    SocketBindError {
        /// Endpoint address or UDS path.
        endpoint: String,
        /// Operating system or validation failure reason.
        reason: String,
    },

    /// Read or write operation on an open network or IPC socket failed.
    #[display("Socket I/O error on '{endpoint}': {reason}")]
    SocketIoError {
        /// Endpoint address or stream identifier.
        endpoint: String,
        /// Operating system I/O failure reason.
        reason: String,
    },

    /// X.509 certificate chain, validity window, or URI Subject Alternative Name validation failed.
    #[display("X.509 certificate validation error for '{subject}': {reason}")]
    X509ValidationError {
        /// Subject or URI SAN being verified.
        subject: String,
        /// Validation failure reason.
        reason: String,
    },

    /// Operating system child process creation (`fork`/`exec`/`CreateProcess`) failed.
    #[display("Failed to spawn process '{command}': {reason}")]
    ProcessSpawnError {
        /// Executable command or path.
        command: String,
        /// OS failure reason.
        reason: String,
    },

    /// Delivering a signal (`SIGTERM`, `SIGKILL`, `SIGUSR1`) or Job Object termination to a PID failed.
    #[display("Failed to deliver signal '{signal}' to PID {pid}: {reason}")]
    ProcessSignalError {
        /// Target OS process identifier.
        pid: u32,
        /// Signal name or number.
        signal: String,
        /// OS failure reason.
        reason: String,
    },

    /// Container Storage Interface (`CSI` v1.9) controller or node RPC failed.
    #[display("CSI RPC '{method}' failed for volume '{volume_id}': {reason}")]
    CsiRpcError {
        /// CSI gRPC method name (`NodeStageVolume`, `NodePublishVolume`, etc.).
        method: String,
        /// Target volume identifier.
        volume_id: String,
        /// Plugin failure reason.
        reason: String,
    },

    /// Cluster DNS or SRV service discovery resolution failed.
    #[display("DNS resolution error for '{fqdn}': {reason}")]
    DnsResolutionError {
        /// Queried fully-qualified domain name.
        fqdn: String,
        /// Resolution failure reason.
        reason: String,
    },

    /// Archive extraction or sandbox path materialization failed.
    #[display("Archive extraction error for '{archive}': {reason}")]
    ArchiveExtractionError {
        /// Archive URI or file name.
        archive: String,
        /// Extraction or path security failure reason.
        reason: String,
    },

    /// ASN.1 DER or PEM X.509v3 certificate parsing failed.
    #[display("X.509 ASN.1 parse error in '{context}': {reason}")]
    X509Asn1ParseError {
        /// Certificate section or extension OID context.
        context: String,
        /// Detailed ASN.1 decoding failure reason.
        reason: String,
    },

    /// Asymmetric cryptographic signature creation or verification (`Ed25519` / `ECDSA-P256`) failed.
    #[display("Cryptographic signature error ({algorithm}): {reason}")]
    CryptographicSignatureError {
        /// Signature algorithm name (`EdDSA`, `ES256`, `HS256`).
        algorithm: String,
        /// Verification or signing failure reason.
        reason: String,
    },

    /// Hardware watchdog device (`/dev/watchdog`) open, pet, or timeout operation failed.
    #[display("Hardware watchdog device error on '{device_path}': {reason}")]
    WatchdogDeviceError {
        /// Watchdog device path (e.g., `"/dev/watchdog"`).
        device_path: String,
        /// Device I/O or timeout failure reason.
        reason: String,
    },

    /// UDP or TCP RFC 1035 DNS wire packet parsing or encoding failed.
    #[display("DNS wire protocol error for '{query_name}': {reason}")]
    DnsProtocolError {
        /// Queried DNS label or packet context.
        query_name: String,
        /// Wire format error reason.
        reason: String,
    },

    /// Wrapped [`PosixSyscallError`].
    #[display("POSIX syscall failure: {_0}")]
    #[from]
    PosixSyscall(PosixSyscallError),

    /// Wrapped [`Win32ApiError`].
    #[display("Win32 API failure: {_0}")]
    #[from]
    Win32Api(Win32ApiError),

    /// Wrapped [`X509CertificateError`].
    #[display("X.509 certificate failure: {_0}")]
    #[from]
    X509Certificate(X509CertificateError),

    /// Wrapped [`CryptoSignatureError`].
    #[display("Cryptographic signature failure: {_0}")]
    #[from]
    CryptoSignature(CryptoSignatureError),

    /// Wrapped [`PtyAllocationError`].
    #[display("PTY allocation failure: {_0}")]
    #[from]
    PtyAllocation(PtyAllocationError),

    /// Wrapped [`FetcherDownloadError`].
    #[display("Fetcher download failure: {_0}")]
    #[from]
    FetcherDownload(FetcherDownloadError),

    /// Wrapped [`SyscallExecutionError`].
    #[display("Syscall execution failure: {_0}")]
    #[from]
    SyscallExecution(SyscallExecutionError),

    /// Wrapped [`CsiGrpcError`].
    #[display("CSI gRPC failure: {_0}")]
    #[from]
    CsiGrpc(CsiGrpcError),

    /// Wrapped [`ArchiveExtractionError`].
    #[display("Archive extraction detail failure: {_0}")]
    #[from]
    ArchiveExtractionDetail(ArchiveExtractionError),

    /// Wrapped [`CniPluginError`].
    #[display("CNI plugin failure: {_0}")]
    #[from]
    CniPlugin(CniPluginError),

    /// Wrapped [`OversubscriptionQosError`].
    #[display("Oversubscription QoS failure: {_0}")]
    #[from]
    OversubscriptionQos(OversubscriptionQosError),

    /// Wrapped [`RegistryRecoveryError`].
    #[display("Registry recovery failure: {_0}")]
    #[from]
    RegistryRecovery(RegistryRecoveryError),

    /// Wrapped [`KeyExchangeError`].
    #[display("Key exchange failure: {_0}")]
    #[from]
    KeyExchange(KeyExchangeError),

    /// Wrapped [`AeadCipherError`].
    #[display("AEAD cipher failure: {_0}")]
    #[from]
    AeadCipher(AeadCipherError),

    /// Wrapped [`ArchiveDecompressionError`].
    #[display("Archive decompression failure: {_0}")]
    #[from]
    ArchiveDecompression(ArchiveDecompressionError),

    /// Wrapped [`DnsWirePacketError`].
    #[display("DNS wire packet failure: {_0}")]
    #[from]
    DnsWirePacket(DnsWirePacketError),

    /// Wrapped [`ProtobufCodecError`].
    #[display("Protobuf wire codec failure: {_0}")]
    #[from]
    ProtobufCodec(ProtobufCodecError),

    /// Wrapped [`NvmlProbeError`].
    #[display("NVML FFI probe failure: {_0}")]
    #[from]
    NvmlProbe(NvmlProbeError),

    /// Wrapped [`RocmSmiError`].
    #[display("ROCm SMI probe failure: {_0}")]
    #[from]
    RocmSmi(RocmSmiError),

    /// Wrapped [`LevelZeroProbeError`].
    #[display("Intel Level Zero probe failure: {_0}")]
    #[from]
    LevelZeroProbe(LevelZeroProbeError),

    /// Wrapped [`LibTpuProbeError`].
    #[display("Google libtpu probe failure: {_0}")]
    #[from]
    LibTpuProbe(LibTpuProbeError),

    /// Wrapped [`IbVerbsProbeError`].
    #[display("InfiniBand verbs probe failure: {_0}")]
    #[from]
    IbVerbsProbe(IbVerbsProbeError),

    /// Wrapped [`FirecrackerApiError`].
    #[display("Firecracker MicroVM API failure: {_0}")]
    #[from]
    FirecrackerApi(FirecrackerApiError),

    /// Wrapped [`BhyveCtlError`].
    #[display("FreeBSD bhyve hypervisor failure: {_0}")]
    #[from]
    BhyveCtl(BhyveCtlError),

    /// Wrapped [`HyperVHcsError`].
    #[display("Windows Hyper-V HCS failure: {_0}")]
    #[from]
    HyperVHcs(HyperVHcsError),

    /// Wrapped [`AppleVzError`].
    #[display("macOS Virtualization.framework failure: {_0}")]
    #[from]
    AppleVz(AppleVzError),

    /// Wrapped [`SignalDeliveryError`].
    #[display("Signal delivery failure: {_0}")]
    #[from]
    SignalDelivery(SignalDeliveryError),

    /// Wrapped [`TerminalRawModeError`].
    #[display("Terminal raw-mode failure: {_0}")]
    #[from]
    TerminalRawMode(TerminalRawModeError),

    /// Wrapped [`FuseMountError`].
    #[display("FUSE/overlay mount failure: {_0}")]
    #[from]
    FuseMount(FuseMountError),

    /// Wrapped [`CriuCheckpointError`].
    #[display("CRIU checkpoint failure: {_0}")]
    #[from]
    CriuCheckpoint(CriuCheckpointError),

    /// Wrapped [`ZfsCommandError`].
    #[display("ZFS command failure: {_0}")]
    #[from]
    ZfsCommand(ZfsCommandError),

    /// Wrapped [`AsyncRuntimeError`].
    #[display("Async runtime failure: {_0}")]
    #[from]
    AsyncRuntime(AsyncRuntimeError),

    /// Wrapped [`GrpcTransportError`].
    #[display("gRPC transport failure: {_0}")]
    #[from]
    GrpcTransport(GrpcTransportError),

    /// Wrapped [`DynamicLibraryError`].
    #[display("Dynamic library failure: {_0}")]
    #[from]
    DynamicLibrary(DynamicLibraryError),

    /// Wrapped [`Pkcs8DerError`].
    #[display("PKCS#8 DER key failure: {_0}")]
    #[from]
    Pkcs8Der(Pkcs8DerError),

    /// Wrapped [`RcgenCertError`].
    #[display("rcgen X.509v3 certificate generation failure: {_0}")]
    #[from]
    RcgenCert(RcgenCertError),

    /// Wrapped [`X509ParseError`].
    #[display("X.509v3 parse failure: {_0}")]
    #[from]
    X509Parse(X509ParseError),

    /// Wrapped [`SqliteStorageError`].
    #[display("SQLite WAL storage failure: {_0}")]
    #[from]
    SqliteStorage(SqliteStorageError),

    /// Wrapped [`ConsulClientError`].
    #[display("Consul HTTP client failure: {_0}")]
    #[from]
    ConsulClient(ConsulClientError),
}

/// Generates bidirectional `TryFrom<ArbiterError>` conversions for wrapped domain error structs.
macro_rules! impl_try_from_arbiter_error {
    ($(($variant:ident, $wrapper:ty)),* $(,)?) => {
        $(
            impl TryFrom<ArbiterError> for $wrapper {
                type Error = ArbiterError;

                /// Attempts to extract the inner wrapper error from an [`ArbiterError`].
                ///
                /// # Arguments
                ///
                /// * `err` - The outer [`ArbiterError`] enum value.
                ///
                /// # Returns
                ///
                /// The extracted inner wrapper struct when `err` matches the expected variant.
                ///
                /// # Errors
                ///
                /// Returns the original [`ArbiterError`] if it is a different variant.
                fn try_from(err: ArbiterError) -> Result<Self, Self::Error> {
                    if let ArbiterError::$variant(inner) = err {
                        Ok(inner)
                    } else {
                        Err(err)
                    }
                }
            }
        )*
    };
}

impl_try_from_arbiter_error!(
    (JsonCodec, JsonCodecError),
    (IoOperation, IoOperationError),
    (RkyvCodec, RkyvCodecError),
    (QuicTransport, QuicTransportError),
    (RustlsCodec, RustlsCodecError),
    (HttpTransport, HttpTransportError),
    (WebSocketCodec, WebSocketCodecError),
    (EtcdClient, EtcdClientError),
    (PostgresClient, PostgresClientError),
    (RedfishFence, RedfishFenceError),
    (IpmiFence, IpmiFenceError),
    (NvmeReservation, NvmeReservationError),
    (OciRegistry, OciRegistryError),
    (OtlpExport, OtlpExportError),
    (OsSyscall, OsSyscallError),
    (TlsHandshake, TlsHandshakeError),
    (ArchiveFormat, ArchiveFormatError),
    (SubprocessExec, SubprocessExecError),
    (PosixSyscall, PosixSyscallError),
    (Win32Api, Win32ApiError),
    (X509Certificate, X509CertificateError),
    (CryptoSignature, CryptoSignatureError),
    (PtyAllocation, PtyAllocationError),
    (FetcherDownload, FetcherDownloadError),
    (SyscallExecution, SyscallExecutionError),
    (CsiGrpc, CsiGrpcError),
    (ArchiveExtractionDetail, ArchiveExtractionError),
    (CniPlugin, CniPluginError),
    (OversubscriptionQos, OversubscriptionQosError),
    (RegistryRecovery, RegistryRecoveryError),
    (KeyExchange, KeyExchangeError),
    (AeadCipher, AeadCipherError),
    (ArchiveDecompression, ArchiveDecompressionError),
    (DnsWirePacket, DnsWirePacketError),
    (ProtobufCodec, ProtobufCodecError),
    (NvmlProbe, NvmlProbeError),
    (RocmSmi, RocmSmiError),
    (LevelZeroProbe, LevelZeroProbeError),
    (LibTpuProbe, LibTpuProbeError),
    (IbVerbsProbe, IbVerbsProbeError),
    (FirecrackerApi, FirecrackerApiError),
    (BhyveCtl, BhyveCtlError),
    (HyperVHcs, HyperVHcsError),
    (AppleVz, AppleVzError),
    (SignalDelivery, SignalDeliveryError),
    (TerminalRawMode, TerminalRawModeError),
    (FuseMount, FuseMountError),
    (CriuCheckpoint, CriuCheckpointError),
    (ZfsCommand, ZfsCommandError),
    (AsyncRuntime, AsyncRuntimeError),
    (GrpcTransport, GrpcTransportError),
    (DynamicLibrary, DynamicLibraryError),
    (Pkcs8Der, Pkcs8DerError),
    (RcgenCert, RcgenCertError),
    (X509Parse, X509ParseError),
    (SqliteStorage, SqliteStorageError),
    (ConsulClient, ConsulClientError),
);

impl ArbiterError {
    /// Maps this [`ArbiterError`] to the corresponding Apache Mesos v1 `TaskStatus::Reason`
    /// canonical string identifier (`REASON_CONTAINER_LAUNCH_FAILED`, `REASON_COMMAND_EXECUTOR_FAILED`,
    /// `REASON_CONTAINER_LIMITATION_MEMORY`, `REASON_TASK_HEALTH_CHECK_STATUS_UPDATED`, etc.).
    ///
    /// # Returns
    ///
    /// Static Apache Mesos v1 reason code identifier string.
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub fn to_mesos_reason_code(&self) -> &'static str {
        match self {
            Self::InsufficientResources { resource, .. } => match resource.as_str() {
                "cpu" | "REASON_CONTAINER_LIMITATION_CPU" => "REASON_CONTAINER_LIMITATION_CPU",
                "disk" | "REASON_CONTAINER_LIMITATION_DISK" => "REASON_CONTAINER_LIMITATION_DISK",
                _ => "REASON_CONTAINER_LIMITATION_MEMORY",
            },
            Self::QuotaExceeded { resource, .. } => match resource.as_str() {
                "cpu" | "REASON_CONTAINER_LIMITATION_CPU" => "REASON_CONTAINER_LIMITATION_CPU",
                "disk" | "REASON_CONTAINER_LIMITATION_DISK" => "REASON_CONTAINER_LIMITATION_DISK",
                _ => "REASON_CONTAINER_LIMITATION_MEMORY",
            },
            Self::CgroupError { .. }
            | Self::NamespaceError { .. }
            | Self::JailError { .. }
            | Self::ZoneError { .. }
            | Self::JobObjectError { .. }
            | Self::SandboxError { .. }
            | Self::ContainerRuntimeError { .. }
            | Self::MicroVmError { .. }
            | Self::IsolatorUnsupportedOnOs { .. } => "REASON_CONTAINER_LAUNCH_FAILED",
            Self::FetcherDownload(_)
            | Self::ArchiveFormat(_)
            | Self::ArchiveDecompression(_)
            | Self::ArchiveExtractionDetail(_)
            | Self::ArchiveExtractionError { .. }
            | Self::OciRegistry(_) => "REASON_CONTAINER_PRE_LAUNCH_FAILED",
            Self::HealthCheckFailed { task_id, .. } => {
                if task_id == "mesos-check" {
                    "REASON_TASK_CHECK_STATUS_UPDATED"
                } else {
                    "REASON_TASK_HEALTH_CHECK_STATUS_UPDATED"
                }
            }
            Self::OversubscriptionQos(_) | Self::PreemptionFailed { .. } => {
                "REASON_EXECUTOR_PREEMPTED"
            }
            Self::AuthenticationFailed { .. } | Self::SpiffeIdentityInvalid { .. } => {
                "REASON_TASK_UNAUTHORIZED"
            }
            Self::AuthorizationDenied { action, .. } => {
                if action == "LAUNCH_GROUP" {
                    "REASON_TASK_GROUP_UNAUTHORIZED"
                } else {
                    "REASON_TASK_UNAUTHORIZED"
                }
            }
            Self::FrameworkNotFound { framework_id } => {
                if framework_id == "removed" {
                    "REASON_FRAMEWORK_REMOVED"
                } else {
                    "REASON_INVALID_FRAMEWORKID"
                }
            }
            Self::OfferExpired { .. } | Self::OfferAlreadyConsumed { .. } => {
                "REASON_INVALID_OFFERS"
            }
            Self::GangConstraintUnsatisfied { .. } => "REASON_TASK_GROUP_INVALID",
            Self::InvalidResourceQuantity { .. }
            | Self::ResourceTypeMismatch { .. }
            | Self::DeviceNotFound { .. } => "REASON_RESOURCES_UNKNOWN",
            Self::TaskStateTransitionInvalid {
                from_state,
                to_state,
            } => match (from_state.as_str(), to_state.as_str()) {
                ("RECONCILE", _) => "REASON_RECONCILIATION",
                ("LAUNCHING", "KILLED") => "REASON_TASK_KILLED_DURING_LAUNCH",
                ("RUNNING", "MAX_COMPLETION_TIME") => "REASON_MAX_COMPLETION_TIME_REACHED",
                ("UNKNOWN", _) => "REASON_TASK_UNKNOWN",
                _ => "REASON_TASK_INVALID",
            },
            Self::PtyAllocation(_) => "REASON_IO_SWITCHBOARD_EXITED",
            Self::RegistryRecovery(reg) => match reg.reason.as_str() {
                "REASON_SLAVE_REMOVED" => "REASON_SLAVE_REMOVED",
                "REASON_SLAVE_RESTARTED" => "REASON_SLAVE_RESTARTED",
                "REASON_SLAVE_UNKNOWN" => "REASON_SLAVE_UNKNOWN",
                _ => "REASON_SLAVE_DISCONNECTED",
            },
            Self::LeaseExpired { lease_id, .. } => match lease_id.as_str() {
                "REASON_EXECUTOR_REREGISTRATION_TIMEOUT" => {
                    "REASON_EXECUTOR_REREGISTRATION_TIMEOUT"
                }
                _ => "REASON_EXECUTOR_REGISTRATION_TIMEOUT",
            },
            Self::ProcessSignalError { signal, .. } => match signal.as_str() {
                "REASON_EXECUTOR_UNREGISTERED" => "REASON_EXECUTOR_UNREGISTERED",
                _ => "REASON_EXECUTOR_TERMINATED",
            },
            Self::StoreWriteError { key, .. } if key == "REASON_GC_ERROR" => "REASON_GC_ERROR",
            Self::NotLeader { .. }
            | Self::RaftConsensusError { .. }
            | Self::FenceExecutionFailed { .. }
            | Self::FencingTokenStale { .. }
            | Self::SplitBrainDetected { .. } => "REASON_MASTER_DISCONNECTED",
            _ => "REASON_COMMAND_EXECUTOR_FAILED",
        }
    }

    /// Reconstructs a canonical [`ArbiterError`] from an Apache Mesos v1 `TaskStatus::Reason`
    /// code string and diagnostic message.
    ///
    /// # Arguments
    ///
    /// * `reason_code` - Apache Mesos v1 `TaskStatus::Reason` string (e.g., `"REASON_CONTAINER_LAUNCH_FAILED"`).
    /// * `message` - Diagnostic description accompanying the status update or error event.
    ///
    /// # Returns
    ///
    /// Mapped [`ArbiterError`] corresponding to `reason_code`.
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub fn from_mesos_reason_code(reason_code: &str, message: &str) -> Self {
        match reason_code {
            "REASON_CONTAINER_LIMITATION_CPU"
            | "REASON_CONTAINER_LIMITATION_DISK"
            | "REASON_CONTAINER_LIMITATION_MEMORY" => Self::InsufficientResources {
                resource: reason_code.to_owned(),
                requested: 1,
                available: 0,
            },
            "REASON_CONTAINER_LAUNCH_FAILED" => Self::ContainerRuntimeError {
                runtime: "mesos-containerizer".to_owned(),
                container_id: "unknown".to_owned(),
                reason: message.to_owned(),
            },
            "REASON_CONTAINER_PRE_LAUNCH_FAILED" => {
                Self::from(FetcherDownloadError::new("mesos-fetcher", message))
            }
            "REASON_TASK_CHECK_STATUS_UPDATED" => Self::HealthCheckFailed {
                task_id: "mesos-check".to_owned(),
                consecutive_failures: 1,
                reason: message.to_owned(),
            },
            "REASON_TASK_HEALTH_CHECK_STATUS_UPDATED" => Self::HealthCheckFailed {
                task_id: "mesos-task".to_owned(),
                consecutive_failures: 1,
                reason: message.to_owned(),
            },
            "REASON_EXECUTOR_PREEMPTED" => {
                Self::from(OversubscriptionQosError::new("mesos-agent", 0, message))
            }
            "REASON_TASK_GROUP_UNAUTHORIZED" => Self::AuthorizationDenied {
                principal: "mesos-framework".to_owned(),
                action: "LAUNCH_GROUP".to_owned(),
                resource: message.to_owned(),
            },
            "REASON_TASK_UNAUTHORIZED" => Self::AuthorizationDenied {
                principal: "mesos-framework".to_owned(),
                action: "LAUNCH".to_owned(),
                resource: message.to_owned(),
            },
            "REASON_FRAMEWORK_REMOVED" => Self::FrameworkNotFound {
                framework_id: "removed".to_owned(),
            },
            "REASON_INVALID_FRAMEWORKID" => Self::FrameworkNotFound {
                framework_id: message.to_owned(),
            },
            "REASON_INVALID_OFFERS" => Self::OfferExpired {
                offer_id: message.to_owned(),
            },
            "REASON_TASK_GROUP_INVALID" => Self::GangConstraintUnsatisfied {
                group_id: message.to_owned(),
                placed: 0,
                required: 1,
            },
            "REASON_RESOURCES_UNKNOWN" => Self::DeviceNotFound {
                device_id: message.to_owned(),
            },
            "REASON_RECONCILIATION" => Self::TaskStateTransitionInvalid {
                from_state: "RECONCILE".to_owned(),
                to_state: message.to_owned(),
            },
            "REASON_TASK_KILLED_DURING_LAUNCH" => Self::TaskStateTransitionInvalid {
                from_state: "LAUNCHING".to_owned(),
                to_state: "KILLED".to_owned(),
            },
            "REASON_MAX_COMPLETION_TIME_REACHED" => Self::TaskStateTransitionInvalid {
                from_state: "RUNNING".to_owned(),
                to_state: "MAX_COMPLETION_TIME".to_owned(),
            },
            "REASON_TASK_UNKNOWN" => Self::TaskStateTransitionInvalid {
                from_state: "UNKNOWN".to_owned(),
                to_state: message.to_owned(),
            },
            "REASON_TASK_INVALID" => Self::TaskStateTransitionInvalid {
                from_state: "INVALID".to_owned(),
                to_state: message.to_owned(),
            },
            "REASON_IO_SWITCHBOARD_EXITED" => {
                Self::from(PtyAllocationError::new("io-switchboard", message))
            }
            "REASON_SLAVE_DISCONNECTED"
            | "REASON_SLAVE_REMOVED"
            | "REASON_SLAVE_RESTARTED"
            | "REASON_SLAVE_UNKNOWN" => Self::from(RegistryRecoveryError::new(
                "mesos-master",
                true,
                reason_code,
            )),
            "REASON_EXECUTOR_REGISTRATION_TIMEOUT" | "REASON_EXECUTOR_REREGISTRATION_TIMEOUT" => {
                Self::LeaseExpired {
                    lease_id: reason_code.to_owned(),
                    expired_at_tick: 1,
                }
            }
            "REASON_EXECUTOR_TERMINATED" | "REASON_EXECUTOR_UNREGISTERED" => {
                Self::ProcessSignalError {
                    pid: 0,
                    signal: reason_code.to_owned(),
                    reason: message.to_owned(),
                }
            }
            "REASON_GC_ERROR" => Self::StoreWriteError {
                key: "REASON_GC_ERROR".to_owned(),
                reason: message.to_owned(),
            },
            "REASON_MASTER_DISCONNECTED" => Self::NotLeader {
                node_id: "mesos-master".to_owned(),
                leader_hint: message.to_owned(),
            },
            _ => Self::from(SubprocessExecError::new(reason_code, 1, message)),
        }
    }

    /// Maps this [`ArbiterError`] to the canonical HTTP/1.1 or HTTP/2 status code (`u16`).
    ///
    /// # Returns
    ///
    /// Numeric HTTP status code (`307`, `400`, `401`, `403`, `404`, `409`, `429`, `500`, `502`, `503`).
    pub const fn to_http_status_code(&self) -> u16 {
        match self {
            Self::NotLeader { .. } => 307,
            Self::AuthenticationFailed { .. } | Self::SpiffeIdentityInvalid { .. } => 401,
            Self::AuthorizationDenied { .. } => 403,
            Self::DeviceNotFound { .. }
            | Self::RoleNotFound { .. }
            | Self::FrameworkNotFound { .. } => 404,
            Self::CasConflict { .. }
            | Self::DuplicateDeviceId { .. }
            | Self::OfferAlreadyConsumed { .. }
            | Self::OfferExpired { .. }
            | Self::FencingTokenStale { .. }
            | Self::SplitBrainDetected { .. } => 409,
            Self::InsufficientResources { .. }
            | Self::NoEligibleAgents { .. }
            | Self::GangConstraintUnsatisfied { .. }
            | Self::QuotaExceeded { .. } => 429,
            Self::HttpHandlerError { status_code, .. } => *status_code,
            Self::HttpTransport(inner) => inner.status_code,
            Self::RaftConsensusError { .. }
            | Self::FederationPeerUnreachable { .. }
            | Self::TransportError { .. }
            | Self::QuicConnectionError { .. }
            | Self::QuicTransport(_) => 503,
            Self::EmptyIdentifier { .. }
            | Self::InvalidIdentifierCharacters { .. }
            | Self::InvalidResourceQuantity { .. }
            | Self::InvalidRangeBounds { .. }
            | Self::InvalidTopologyGraph { .. }
            | Self::InvalidShareWeight { .. }
            | Self::InvalidQuotaBounds { .. }
            | Self::InvalidMigProfile { .. }
            | Self::InvalidTpuTopologySlice { .. }
            | Self::InvalidCliArguments { .. }
            | Self::InvalidBenchmarkConfig { .. }
            | Self::DeserializationError { .. }
            | Self::JsonCodec(_)
            | Self::ProtobufCodec(_)
            | Self::RkyvCodec(_) => 400,
            _ => 500,
        }
    }

    /// Maps this [`ArbiterError`] to a canonical `tonic::Status` gRPC response status.
    ///
    /// # Returns
    ///
    /// `tonic::Status` carrying the corresponding gRPC status code and formatted message.
    pub fn to_tonic_status(&self) -> tonic::Status {
        let msg = self.to_string();
        match self.to_http_status_code() {
            400 => tonic::Status::invalid_argument(msg),
            401 => tonic::Status::unauthenticated(msg),
            403 => tonic::Status::permission_denied(msg),
            404 => tonic::Status::not_found(msg),
            409 => tonic::Status::aborted(msg),
            429 => tonic::Status::resource_exhausted(msg),
            307 | 503 => tonic::Status::unavailable(msg),
            _ => tonic::Status::internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_all_error_variants_display_and_source() {
        let variants: Vec<ArbiterError> = vec![
            ArbiterError::EmptyIdentifier {
                kind: "AgentId".to_owned(),
            },
            ArbiterError::InvalidIdentifierCharacters {
                kind: "TaskId".to_owned(),
                value: "bad id!".to_owned(),
                reason: "contains spaces".to_owned(),
            },
            ArbiterError::InvalidResourceQuantity {
                resource: "cpu".to_owned(),
                quantity: 0,
                reason: "must be positive".to_owned(),
            },
            ArbiterError::InvalidRangeBounds {
                context: "PortRange".to_owned(),
                start: 9000,
                end: 8000,
            },
            ArbiterError::InvalidTopologyGraph {
                reason: "cycle detected".to_owned(),
            },
            ArbiterError::InvalidShareWeight {
                weight_bps: 0,
                reason: "weight cannot be zero".to_owned(),
            },
            ArbiterError::InvalidQuotaBounds {
                role: "prod".to_owned(),
                reason: "min > max".to_owned(),
            },
            ArbiterError::ArithmeticOverflow {
                operation: "Millicores::checked_add".to_owned(),
            },
            ArbiterError::ArithmeticUnderflow {
                operation: "Bytes::checked_sub".to_owned(),
            },
            ArbiterError::DivisionByZero {
                operation: "SharePartsPerBillion::from_ratio".to_owned(),
            },
            ArbiterError::InsufficientResources {
                resource: "memory".to_owned(),
                requested: 1024,
                available: 512,
            },
            ArbiterError::ResourceTypeMismatch {
                expected: "Nvidia".to_owned(),
                found: "Amd".to_owned(),
            },
            ArbiterError::DuplicateDeviceId {
                device_id: "gpu-0".to_owned(),
            },
            ArbiterError::DeviceNotFound {
                device_id: "gpu-9".to_owned(),
            },
            ArbiterError::InvalidMigProfile {
                profile: "9g.99gb".to_owned(),
                reason: "unknown profile".to_owned(),
            },
            ArbiterError::InvalidTpuTopologySlice {
                slice: "v5p-3x3".to_owned(),
                reason: "non-contiguous torus".to_owned(),
            },
            ArbiterError::IncompatibleInterconnect {
                interconnect: "NvLink".to_owned(),
                source_node: "cpu-0".to_owned(),
                target_node: "nic-0".to_owned(),
            },
            ArbiterError::NoEligibleAgents {
                workload: "job-1".to_owned(),
                reason: "no TPU v5p available".to_owned(),
            },
            ArbiterError::GangConstraintUnsatisfied {
                group_id: "gang-1".to_owned(),
                placed: 2,
                required: 4,
            },
            ArbiterError::PreemptionFailed {
                workload: "urgent-1".to_owned(),
                reason: "all tasks non-preemptible".to_owned(),
            },
            ArbiterError::QuotaExceeded {
                role: "analytics".to_owned(),
                resource: "gpu".to_owned(),
            },
            ArbiterError::RoleNotFound {
                role: "unknown-role".to_owned(),
            },
            ArbiterError::FrameworkNotFound {
                framework_id: "fw-99".to_owned(),
            },
            ArbiterError::OfferExpired {
                offer_id: "offer-1".to_owned(),
            },
            ArbiterError::OfferAlreadyConsumed {
                offer_id: "offer-2".to_owned(),
            },
            ArbiterError::StoreReadError {
                key: "/agents/1".to_owned(),
                reason: "disk read error".to_owned(),
            },
            ArbiterError::StoreWriteError {
                key: "/tasks/1".to_owned(),
                reason: "read-only filesystem".to_owned(),
            },
            ArbiterError::CasConflict {
                key: "/leader".to_owned(),
                expected_rev: 3,
                actual_rev: 4,
            },
            ArbiterError::RaftConsensusError {
                term: 12,
                reason: "quorum lost".to_owned(),
            },
            ArbiterError::NotLeader {
                node_id: "master-2".to_owned(),
                leader_hint: "master-1".to_owned(),
            },
            ArbiterError::LeaseExpired {
                lease_id: "lease-10".to_owned(),
                expired_at_tick: 500,
            },
            ArbiterError::FencingTokenStale {
                presented_token: 41,
                current_token: 42,
            },
            ArbiterError::FenceExecutionFailed {
                target: "agent-3".to_owned(),
                reason: "zone halt timed out".to_owned(),
            },
            ArbiterError::SplitBrainDetected {
                group_id: "pg-ha".to_owned(),
                details: "two active primaries".to_owned(),
            },
            ArbiterError::FederationPeerUnreachable {
                peer_cluster: "us-west-2".to_owned(),
                reason: "connection timed out".to_owned(),
            },
            ArbiterError::SerializationError {
                format: "rkyv".to_owned(),
                reason: "buffer full".to_owned(),
            },
            ArbiterError::DeserializationError {
                format: "json".to_owned(),
                reason: "unexpected EOF".to_owned(),
            },
            ArbiterError::TransactionAborted {
                reason: "conflicting key write".to_owned(),
            },
            ArbiterError::TransportError {
                endpoint: "127.0.0.1:5050".to_owned(),
                reason: "connection reset".to_owned(),
            },
            ArbiterError::QuicConnectionError {
                stream_id: 7,
                reason: "stream closed".to_owned(),
            },
            ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "bad request".to_owned(),
            },
            ArbiterError::TlsConfigurationError {
                reason: "expired certificate".to_owned(),
            },
            ArbiterError::SpiffeIdentityInvalid {
                uri: "http://bad".to_owned(),
                reason: "scheme must be spiffe://".to_owned(),
            },
            ArbiterError::AuthenticationFailed {
                principal: "user-1".to_owned(),
                reason: "invalid signature".to_owned(),
            },
            ArbiterError::AuthorizationDenied {
                principal: "user-1".to_owned(),
                action: "LaunchTask".to_owned(),
                resource: "role:prod".to_owned(),
            },
            ArbiterError::SecretDecryptionFailed {
                secret_id: "sec-1".to_owned(),
                reason: "authentication tag mismatch".to_owned(),
            },
            ArbiterError::IsolatorUnsupportedOnOs {
                isolator: "FreeBsdJail".to_owned(),
                os: "Linux".to_owned(),
            },
            ArbiterError::CgroupError {
                cgroup_path: "/sys/fs/cgroup/arbiter".to_owned(),
                reason: "permission denied".to_owned(),
            },
            ArbiterError::NamespaceError {
                namespace_kind: "CLONE_NEWNET".to_owned(),
                reason: "EINVAL".to_owned(),
            },
            ArbiterError::JailError {
                jail_name: "arbiter_task_1".to_owned(),
                reason: "jail_set failed".to_owned(),
            },
            ArbiterError::ZoneError {
                zone_name: "zone_task_1".to_owned(),
                reason: "zoneadm boot failed".to_owned(),
            },
            ArbiterError::JobObjectError {
                job_name: "job_task_1".to_owned(),
                reason: "SetInformationJobObject failed".to_owned(),
            },
            ArbiterError::SandboxError {
                mechanism: "sandbox-exec".to_owned(),
                reason: "profile syntax error".to_owned(),
            },
            ArbiterError::ContainerRuntimeError {
                runtime: "crun".to_owned(),
                container_id: "c-1".to_owned(),
                reason: "rootfs missing".to_owned(),
            },
            ArbiterError::MicroVmError {
                engine: "bhyve".to_owned(),
                vm_id: "vm-1".to_owned(),
                reason: "vmm.ko not loaded".to_owned(),
            },
            ArbiterError::UserSwitchError {
                user: "nobody".to_owned(),
                reason: "setgid failed".to_owned(),
            },
            ArbiterError::ProbeFailed {
                probe_name: "LinuxSysfsProbe".to_owned(),
                reason: "/sys not mounted".to_owned(),
            },
            ArbiterError::NvmlError {
                device: "GPU-0".to_owned(),
                reason: "driver not loaded".to_owned(),
            },
            ArbiterError::RocmError {
                device: "card0".to_owned(),
                reason: "kfd unavailable".to_owned(),
            },
            ArbiterError::MetalError {
                reason: "no Metal device".to_owned(),
            },
            ArbiterError::LevelZeroError {
                device: "ze0".to_owned(),
                reason: "zeInit failed".to_owned(),
            },
            ArbiterError::TpuDriverError {
                device: "/dev/accel0".to_owned(),
                reason: "busy".to_owned(),
            },
            ArbiterError::MetricRegistrationError {
                metric_name: "arbiter_cpu_total".to_owned(),
                reason: "already registered".to_owned(),
            },
            ArbiterError::HealthCheckFailed {
                task_id: "task-1".to_owned(),
                consecutive_failures: 3,
                reason: "connection refused".to_owned(),
            },
            ArbiterError::InvalidCliArguments {
                reason: "unknown flag --foo".to_owned(),
            },
            ArbiterError::ShutdownSignalError {
                reason: "signal handler failed".to_owned(),
            },
            ArbiterError::TaskStateTransitionInvalid {
                from_state: "Finished".to_owned(),
                to_state: "Running".to_owned(),
            },
            ArbiterError::InvalidBenchmarkConfig {
                parameter: "NodeCount".to_owned(),
                reason: "must be non-zero".to_owned(),
            },
            ArbiterError::LinearizabilityViolation {
                group_id: "pg-ha".to_owned(),
                lost_writes: 1,
                divergent_writes: 0,
            },
            ArbiterError::CalibrationDriftExceeded {
                observed_drift_bps: 650,
                max_allowed_bps: 500,
            },
            ArbiterError::SocketBindError {
                endpoint: "0.0.0.0:5050".to_owned(),
                reason: "address in use".to_owned(),
            },
            ArbiterError::SocketIoError {
                endpoint: "127.0.0.1:5050".to_owned(),
                reason: "broken pipe".to_owned(),
            },
            ArbiterError::X509ValidationError {
                subject: "spiffe://arbiter.internal/node/a1".to_owned(),
                reason: "certificate expired".to_owned(),
            },
            ArbiterError::ProcessSpawnError {
                command: "/bin/nonexistent".to_owned(),
                reason: "ENOENT".to_owned(),
            },
            ArbiterError::ProcessSignalError {
                pid: 4242,
                signal: "SIGKILL".to_owned(),
                reason: "ESRCH".to_owned(),
            },
            ArbiterError::CsiRpcError {
                method: "NodePublishVolume".to_owned(),
                volume_id: "vol-1".to_owned(),
                reason: "socket timeout".to_owned(),
            },
            ArbiterError::DnsResolutionError {
                fqdn: "pg-0.db.arbiter.internal".to_owned(),
                reason: "NXDOMAIN".to_owned(),
            },
            ArbiterError::ArchiveExtractionError {
                archive: "bundle.tar.zst".to_owned(),
                reason: "corrupt header".to_owned(),
            },
            ArbiterError::X509Asn1ParseError {
                context: "OID 2.5.29.17".to_owned(),
                reason: "truncated DER tag".to_owned(),
            },
            ArbiterError::CryptographicSignatureError {
                algorithm: "EdDSA".to_owned(),
                reason: "invalid Ed25519 curve point".to_owned(),
            },
            ArbiterError::WatchdogDeviceError {
                device_path: "/dev/watchdog".to_owned(),
                reason: "watchdog timer expired".to_owned(),
            },
            ArbiterError::DnsProtocolError {
                query_name: "pg-0.db.prod.arbiter.internal".to_owned(),
                reason: "truncated DNS header".to_owned(),
            },
        ];

        for err in &variants {
            let msg = err.to_string();
            assert!(!msg.is_empty());
            assert!(err.source().is_none());
            let cloned = err.clone();
            assert_eq!(&cloned, err);
        }
    }

    #[test]
    fn test_json_codec_error_conversion_and_source() {
        let serde_err: serde_json::Error = serde::de::Error::custom("malformed json payload");
        let codec_err = JsonCodecError::from(serde_err);
        assert!(codec_err.to_string().contains("JSON codec error:"));
        assert!(std::error::Error::source(&codec_err).is_none());

        let arbiter_err = ArbiterError::from(codec_err);
        assert!(arbiter_err.to_string().contains("JSON codec failure:"));
        assert!(std::error::Error::source(&arbiter_err).is_some());

        let serde_err2: serde_json::Error = serde::de::Error::custom("direct serde error");
        let direct_serde_arb = ArbiterError::from(serde_err2);
        assert!(direct_serde_arb.to_string().contains("JSON codec failure:"));

        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "socket closed");
        let io_wrap = IoOperationError::from(io_err);
        assert!(io_wrap.to_string().contains("BrokenPipe"));
        assert!(std::error::Error::source(&io_wrap).is_none());
        let arbiter_io = ArbiterError::from(io_wrap);
        assert!(arbiter_io.to_string().contains("I/O failure:"));
        assert!(std::error::Error::source(&arbiter_io).is_some());

        let direct_io_arb = ArbiterError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));
        assert!(direct_io_arb.to_string().contains("I/O failure:"));

        let rkyv_err = <rkyv::rancor::Error as rkyv::rancor::Source>::new(IoOperationError {
            kind: "InvalidData".to_owned(),
            message: "bad archive".to_owned(),
        });
        let rkyv_wrap = RkyvCodecError::from(rkyv_err);
        assert!(rkyv_wrap.to_string().contains("rkyv binary codec error:"));
        assert!(std::error::Error::source(&rkyv_wrap).is_none());
        let arbiter_rkyv = ArbiterError::from(rkyv_wrap);
        assert!(
            arbiter_rkyv
                .to_string()
                .contains("rkyv binary codec failure:")
        );
        assert!(std::error::Error::source(&arbiter_rkyv).is_some());

        let rkyv_err2 = <rkyv::rancor::Error as rkyv::rancor::Source>::new(IoOperationError {
            kind: "InvalidData".to_owned(),
            message: "direct rkyv error".to_owned(),
        });
        let direct_rkyv_arb = ArbiterError::from(rkyv_err2);
        assert!(
            direct_rkyv_arb
                .to_string()
                .contains("rkyv binary codec failure:")
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_transport_and_store_wrapper_errors() {
        let quic_wrap = QuicTransportError::new(1, "stream reset");
        assert!(quic_wrap.to_string().contains("QUIC transport error"));
        assert!(std::error::Error::source(&quic_wrap).is_none());
        let arbiter_quic = ArbiterError::from(quic_wrap);
        assert!(arbiter_quic.to_string().contains("QUIC transport failure:"));
        assert!(std::error::Error::source(&arbiter_quic).is_some());

        let tls_wrap = RustlsCodecError::new("bad certificate");
        assert!(tls_wrap.to_string().contains("TLS codec error:"));
        assert!(std::error::Error::source(&tls_wrap).is_none());
        let arbiter_tls = ArbiterError::from(tls_wrap);
        assert!(arbiter_tls.to_string().contains("TLS codec failure:"));
        assert!(std::error::Error::source(&arbiter_tls).is_some());

        let http_wrap = HttpTransportError::new(502, "bad gateway");
        assert!(http_wrap.to_string().contains("HTTP transport error"));
        assert!(std::error::Error::source(&http_wrap).is_none());
        let arbiter_http = ArbiterError::from(http_wrap);
        assert!(arbiter_http.to_string().contains("HTTP transport failure:"));
        assert!(std::error::Error::source(&arbiter_http).is_some());

        let ws_wrap = WebSocketCodecError::new("invalid frame mask");
        assert!(ws_wrap.to_string().contains("WebSocket codec error:"));
        assert!(std::error::Error::source(&ws_wrap).is_none());
        let arbiter_ws = ArbiterError::from(ws_wrap);
        assert!(arbiter_ws.to_string().contains("WebSocket codec failure:"));
        assert!(std::error::Error::source(&arbiter_ws).is_some());

        let etcd_wrap = EtcdClientError::new("http://127.0.0.1:2379", "unavailable");
        assert!(etcd_wrap.to_string().contains("etcd v3 client error"));
        assert!(std::error::Error::source(&etcd_wrap).is_none());
        let arbiter_etcd = ArbiterError::from(etcd_wrap);
        assert!(arbiter_etcd.to_string().contains("etcd v3 client failure:"));
        assert!(std::error::Error::source(&arbiter_etcd).is_some());

        let pg_wrap = PostgresClientError::new("40001", "serialization_failure");
        assert!(pg_wrap.to_string().contains("PostgreSQL client error"));
        assert!(std::error::Error::source(&pg_wrap).is_none());
        let arbiter_pg = ArbiterError::from(pg_wrap);
        assert!(
            arbiter_pg
                .to_string()
                .contains("PostgreSQL client failure:")
        );
        assert!(std::error::Error::source(&arbiter_pg).is_some());

        let redfish_wrap = RedfishFenceError::new("https://bmc.node1/redfish/v1", 503, "BMC busy");
        assert!(redfish_wrap.to_string().contains("Redfish BMC fence error"));
        assert!(std::error::Error::source(&redfish_wrap).is_none());
        let arbiter_redfish = ArbiterError::from(redfish_wrap);
        assert!(
            arbiter_redfish
                .to_string()
                .contains("Redfish BMC fence failure:")
        );
        assert!(std::error::Error::source(&arbiter_redfish).is_some());

        let ipmi_wrap = IpmiFenceError::new("10.0.0.10:623", 0xC0, "Node Busy");
        assert!(ipmi_wrap.to_string().contains("IPMI v2 fence error"));
        assert!(std::error::Error::source(&ipmi_wrap).is_none());
        let arbiter_ipmi = ArbiterError::from(ipmi_wrap);
        assert!(arbiter_ipmi.to_string().contains("IPMI v2 fence failure:"));
        assert!(std::error::Error::source(&arbiter_ipmi).is_some());

        let nvme_wrap = NvmeReservationError::new("/dev/nvme0n1", 0x0083, "Reservation Conflict");
        assert!(nvme_wrap.to_string().contains("NVMe reservation error"));
        assert!(std::error::Error::source(&nvme_wrap).is_none());
        let arbiter_nvme = ArbiterError::from(nvme_wrap);
        assert!(
            arbiter_nvme
                .to_string()
                .contains("NVMe reservation failure:")
        );
        assert!(std::error::Error::source(&arbiter_nvme).is_some());

        let oci_wrap = OciRegistryError::new(
            "https://registry-1.docker.io",
            404,
            "sha256:deadbeef",
            "manifest unknown",
        );
        assert!(oci_wrap.to_string().contains("OCI registry error"));
        assert!(std::error::Error::source(&oci_wrap).is_none());
        let arbiter_oci = ArbiterError::from(oci_wrap);
        assert!(arbiter_oci.to_string().contains("OCI registry failure:"));
        assert!(std::error::Error::source(&arbiter_oci).is_some());

        let otlp_wrap =
            OtlpExportError::new("http://127.0.0.1:4318/v1/metrics", 502, "collector down");
        assert!(otlp_wrap.to_string().contains("OTLP export error"));
        assert!(std::error::Error::source(&otlp_wrap).is_none());
        let arbiter_otlp = ArbiterError::from(otlp_wrap);
        assert!(arbiter_otlp.to_string().contains("OTLP export failure:"));
        assert!(std::error::Error::source(&arbiter_otlp).is_some());

        let sys_wrap = OsSyscallError::new("clone3", 1, "EPERM");
        assert!(sys_wrap.to_string().contains("OS syscall 'clone3'"));
        assert!(std::error::Error::source(&sys_wrap).is_none());
        let arbiter_sys = ArbiterError::from(sys_wrap);
        assert!(arbiter_sys.to_string().contains("OS syscall failure:"));
        assert!(std::error::Error::source(&arbiter_sys).is_some());

        let hs_wrap = TlsHandshakeError::new("10.0.0.2:4433", "arbiter-rkyv/1", "expired SVID");
        assert!(hs_wrap.to_string().contains("TLS handshake error"));
        assert!(std::error::Error::source(&hs_wrap).is_none());
        let arbiter_tls_hs = ArbiterError::from(hs_wrap);
        assert!(
            arbiter_tls_hs
                .to_string()
                .contains("TLS handshake failure:")
        );
        assert!(std::error::Error::source(&arbiter_tls_hs).is_some());

        let arch_wrap = ArchiveFormatError::new("tar.zst", "bundle.tar.zst", "bad magic");
        assert!(arch_wrap.to_string().contains("Archive format error"));
        assert!(std::error::Error::source(&arch_wrap).is_none());
        let arbiter_arch = ArbiterError::from(arch_wrap);
        assert!(arbiter_arch.to_string().contains("Archive format failure:"));
        assert!(std::error::Error::source(&arbiter_arch).is_some());

        let sub_wrap = SubprocessExecError::new("runc", 127, "command not found");
        assert!(sub_wrap.to_string().contains("Subprocess 'runc' failed"));
        assert!(std::error::Error::source(&sub_wrap).is_none());
        let arbiter_sub = ArbiterError::from(sub_wrap);
        assert!(
            arbiter_sub
                .to_string()
                .contains("Subprocess execution failure:")
        );
        assert!(std::error::Error::source(&arbiter_sub).is_some());

        let posix_wrap = PosixSyscallError::new("unshare", 1, "EPERM");
        assert!(posix_wrap.to_string().contains("POSIX syscall 'unshare'"));
        assert!(std::error::Error::source(&posix_wrap).is_none());
        let arbiter_posix = ArbiterError::from(posix_wrap);
        assert!(arbiter_posix.to_string().contains("POSIX syscall failure:"));
        assert!(std::error::Error::source(&arbiter_posix).is_some());

        let win32_wrap = Win32ApiError::new("CreateJobObjectW", 5, "ERROR_ACCESS_DENIED");
        assert!(
            win32_wrap
                .to_string()
                .contains("Win32 API 'CreateJobObjectW'")
        );
        assert!(std::error::Error::source(&win32_wrap).is_none());
        let arbiter_win32 = ArbiterError::from(win32_wrap);
        assert!(arbiter_win32.to_string().contains("Win32 API failure:"));
        assert!(std::error::Error::source(&arbiter_win32).is_some());

        let x509_wrap = X509CertificateError::new("spiffe://arbiter.internal/agent/a1", "expired");
        assert!(x509_wrap.to_string().contains("X.509 certificate error"));
        assert!(std::error::Error::source(&x509_wrap).is_none());
        let arbiter_x509 = ArbiterError::from(x509_wrap);
        assert!(
            arbiter_x509
                .to_string()
                .contains("X.509 certificate failure:")
        );
        assert!(std::error::Error::source(&arbiter_x509).is_some());

        let sig_wrap = CryptoSignatureError::new("Ed25519", "bad point");
        assert!(
            sig_wrap
                .to_string()
                .contains("Cryptographic signature error")
        );
        assert!(std::error::Error::source(&sig_wrap).is_none());
        let arbiter_sig = ArbiterError::from(sig_wrap);
        assert!(
            arbiter_sig
                .to_string()
                .contains("Cryptographic signature failure:")
        );
        assert!(std::error::Error::source(&arbiter_sig).is_some());

        let pty_wrap = PtyAllocationError::new("cid-1", "openpty failed");
        assert!(pty_wrap.to_string().contains("PTY allocation error"));
        assert!(std::error::Error::source(&pty_wrap).is_none());
        let arbiter_pty = ArbiterError::from(pty_wrap);
        assert!(arbiter_pty.to_string().contains("PTY allocation failure:"));
        assert!(std::error::Error::source(&arbiter_pty).is_some());

        let fetch_wrap = FetcherDownloadError::new("https://example.com/a.tar.gz", "404");
        assert!(fetch_wrap.to_string().contains("Fetcher download error"));
        assert!(std::error::Error::source(&fetch_wrap).is_none());
        let arbiter_fetch = ArbiterError::from(fetch_wrap);
        assert!(
            arbiter_fetch
                .to_string()
                .contains("Fetcher download failure:")
        );
        assert!(std::error::Error::source(&arbiter_fetch).is_some());

        let sysexec_wrap = SyscallExecutionError::new("pivot_root", 22, "EINVAL");
        assert!(
            sysexec_wrap
                .to_string()
                .contains("Syscall execution error 'pivot_root'")
        );
        assert!(std::error::Error::source(&sysexec_wrap).is_none());
        let arbiter_sysexec = ArbiterError::from(sysexec_wrap);
        assert!(
            arbiter_sysexec
                .to_string()
                .contains("Syscall execution failure:")
        );
        assert!(std::error::Error::source(&arbiter_sysexec).is_some());

        let csi_wrap = CsiGrpcError::new("/var/lib/csi/csi.sock", 14, "UNAVAILABLE");
        assert!(csi_wrap.to_string().contains("CSI gRPC error"));
        assert!(std::error::Error::source(&csi_wrap).is_none());
        let arbiter_csi = ArbiterError::from(csi_wrap);
        assert!(arbiter_csi.to_string().contains("CSI gRPC failure:"));
        assert!(std::error::Error::source(&arbiter_csi).is_some());

        let arch_ext_wrap =
            ArchiveExtractionError::new("tar.gz", "../etc/shadow", "path traversal");
        assert!(
            arch_ext_wrap
                .to_string()
                .contains("Archive extraction error")
        );
        assert!(std::error::Error::source(&arch_ext_wrap).is_none());
        let arbiter_arch_ext = ArbiterError::from(arch_ext_wrap);
        assert!(
            arbiter_arch_ext
                .to_string()
                .contains("Archive extraction detail failure:")
        );
        assert!(std::error::Error::source(&arbiter_arch_ext).is_some());

        let netplugin_wrap = CniPluginError::new("bridge", "ctr-1", "IPAM exhausted");
        assert!(netplugin_wrap.to_string().contains("CNI plugin 'bridge'"));
        assert!(std::error::Error::source(&netplugin_wrap).is_none());
        let arbiter_netplugin = ArbiterError::from(netplugin_wrap);
        assert!(
            arbiter_netplugin
                .to_string()
                .contains("CNI plugin failure:")
        );
        assert!(std::error::Error::source(&arbiter_netplugin).is_some());

        let qos_wrap =
            OversubscriptionQosError::new("agent-1", 4000, "primary CPU contention detected");
        assert!(qos_wrap.to_string().contains("Oversubscription QoS error"));
        assert!(std::error::Error::source(&qos_wrap).is_none());
        let arbiter_qos = ArbiterError::from(qos_wrap);
        assert!(
            arbiter_qos
                .to_string()
                .contains("Oversubscription QoS failure:")
        );
        assert!(std::error::Error::source(&arbiter_qos).is_some());

        let reg_wrap = RegistryRecoveryError::new("master-1", true, "unregistered agent");
        assert!(
            reg_wrap
                .to_string()
                .contains("Master registry recovery error")
        );
        assert!(std::error::Error::source(&reg_wrap).is_none());
        let arbiter_reg = ArbiterError::from(reg_wrap);
        assert!(
            arbiter_reg
                .to_string()
                .contains("Registry recovery failure:")
        );
        assert!(std::error::Error::source(&arbiter_reg).is_some());

        let kex_wrap = KeyExchangeError::new("X25519", "low-order point rejected");
        assert!(kex_wrap.to_string().contains("Key exchange error"));
        assert!(std::error::Error::source(&kex_wrap).is_none());
        let arbiter_kex = ArbiterError::from(kex_wrap);
        assert!(arbiter_kex.to_string().contains("Key exchange failure:"));
        assert!(std::error::Error::source(&arbiter_kex).is_some());

        let aead_wrap = AeadCipherError::new("ChaCha20-Poly1305", "Poly1305 MAC mismatch");
        assert!(aead_wrap.to_string().contains("AEAD cipher error"));
        assert!(std::error::Error::source(&aead_wrap).is_none());
        let arbiter_aead = ArbiterError::from(aead_wrap);
        assert!(arbiter_aead.to_string().contains("AEAD cipher failure:"));
        assert!(std::error::Error::source(&arbiter_aead).is_some());

        let decomp_wrap = ArchiveDecompressionError::new("gzip", 42, "invalid Huffman code");
        assert!(
            decomp_wrap
                .to_string()
                .contains("Archive decompression error")
        );
        assert!(std::error::Error::source(&decomp_wrap).is_none());
        let arbiter_decomp = ArbiterError::from(decomp_wrap);
        assert!(
            arbiter_decomp
                .to_string()
                .contains("Archive decompression failure:")
        );
        assert!(std::error::Error::source(&arbiter_decomp).is_some());

        let dns_pkt_wrap = DnsWirePacketError::new("pg-0.db.arbiter.internal", 3, "NXDOMAIN");
        assert!(dns_pkt_wrap.to_string().contains("DNS wire packet error"));
        assert!(std::error::Error::source(&dns_pkt_wrap).is_none());
        let arbiter_dns_pkt = ArbiterError::from(dns_pkt_wrap);
        assert!(
            arbiter_dns_pkt
                .to_string()
                .contains("DNS wire packet failure:")
        );
        assert!(std::error::Error::source(&arbiter_dns_pkt).is_some());

        let proto_wire_wrap = ProtobufCodecError::new(1, 2, "truncated varint");
        assert!(
            proto_wire_wrap
                .to_string()
                .contains("Protobuf wire codec error")
        );
        assert!(std::error::Error::source(&proto_wire_wrap).is_none());
        let arbiter_proto_wire = ArbiterError::from(proto_wire_wrap);
        assert!(
            arbiter_proto_wire
                .to_string()
                .contains("Protobuf wire codec failure:")
        );
        assert!(std::error::Error::source(&arbiter_proto_wire).is_some());

        let nvidia_ffi_wrap =
            NvmlProbeError::new("0000:c1:00.0", 9, "NVML_ERROR_DRIVER_NOT_LOADED");
        assert!(nvidia_ffi_wrap.to_string().contains("NVML FFI probe error"));
        assert!(std::error::Error::source(&nvidia_ffi_wrap).is_none());
        let arbiter_nvidia_ffi = ArbiterError::from(nvidia_ffi_wrap);
        assert!(
            arbiter_nvidia_ffi
                .to_string()
                .contains("NVML FFI probe failure:")
        );
        assert!(std::error::Error::source(&arbiter_nvidia_ffi).is_some());

        let rocm_wrap = RocmSmiError::new("node-1", 2, "RSMI_STATUS_INVALID_ARGS");
        assert!(rocm_wrap.to_string().contains("ROCm SMI probe error"));
        assert!(std::error::Error::source(&rocm_wrap).is_none());
        let arbiter_rocm = ArbiterError::from(rocm_wrap);
        assert!(arbiter_rocm.to_string().contains("ROCm SMI probe failure:"));
        assert!(std::error::Error::source(&arbiter_rocm).is_some());

        let ze_wrap =
            LevelZeroProbeError::new("ze-tile-0", 0x7800_0001, "ZE_RESULT_ERROR_UNINITIALIZED");
        assert!(ze_wrap.to_string().contains("Intel Level Zero probe error"));
        assert!(std::error::Error::source(&ze_wrap).is_none());
        let arbiter_ze = ArbiterError::from(ze_wrap);
        assert!(
            arbiter_ze
                .to_string()
                .contains("Intel Level Zero probe failure:")
        );
        assert!(std::error::Error::source(&arbiter_ze).is_some());

        let tpu_wrap = LibTpuProbeError::new("/dev/accel0", -16, "EBUSY");
        assert!(tpu_wrap.to_string().contains("Google libtpu probe error"));
        assert!(std::error::Error::source(&tpu_wrap).is_none());
        let arbiter_tpu = ArbiterError::from(tpu_wrap);
        assert!(
            arbiter_tpu
                .to_string()
                .contains("Google libtpu probe failure:")
        );
        assert!(std::error::Error::source(&arbiter_tpu).is_some());

        let ib_wrap = IbVerbsProbeError::new("mlx5_0", 1, "port link down");
        assert!(ib_wrap.to_string().contains("InfiniBand verbs probe error"));
        assert!(std::error::Error::source(&ib_wrap).is_none());
        let arbiter_ib = ArbiterError::from(ib_wrap);
        assert!(
            arbiter_ib
                .to_string()
                .contains("InfiniBand verbs probe failure:")
        );
        assert!(std::error::Error::source(&arbiter_ib).is_some());

        let fc_wrap = FirecrackerApiError::new(
            "/run/firecracker/vm-1.sock",
            "PUT",
            "/boot-source",
            400,
            "Invalid kernel path",
        );
        assert!(
            fc_wrap
                .to_string()
                .contains("Firecracker MicroVM API error")
        );
        assert!(std::error::Error::source(&fc_wrap).is_none());
        let arbiter_fc = ArbiterError::from(fc_wrap);
        assert!(
            arbiter_fc
                .to_string()
                .contains("Firecracker MicroVM API failure:")
        );
        assert!(std::error::Error::source(&arbiter_fc).is_some());

        let bhyve_wrap = BhyveCtlError::new("arbiter-vm-1", 1, "vmm.ko not loaded");
        assert!(
            bhyve_wrap
                .to_string()
                .contains("FreeBSD bhyve hypervisor error")
        );
        assert!(std::error::Error::source(&bhyve_wrap).is_none());
        let arbiter_bhyve = ArbiterError::from(bhyve_wrap);
        assert!(
            arbiter_bhyve
                .to_string()
                .contains("FreeBSD bhyve hypervisor failure:")
        );
        assert!(std::error::Error::source(&arbiter_bhyve).is_some());

        let hyperv_wrap =
            HyperVHcsError::new("vm-hcs-1", 0x8037_0102, "HCS_E_TERMINATED_DURING_START");
        assert!(
            hyperv_wrap
                .to_string()
                .contains("Windows Hyper-V HCS error")
        );
        assert!(std::error::Error::source(&hyperv_wrap).is_none());
        let arbiter_hyperv = ArbiterError::from(hyperv_wrap);
        assert!(
            arbiter_hyperv
                .to_string()
                .contains("Windows Hyper-V HCS failure:")
        );
        assert!(std::error::Error::source(&arbiter_hyperv).is_some());

        let vz_wrap = AppleVzError::new("vm-vz-1", 2, "VZErrorInvalidVirtualMachineConfiguration");
        assert!(
            vz_wrap
                .to_string()
                .contains("macOS Virtualization.framework error")
        );
        assert!(std::error::Error::source(&vz_wrap).is_none());
        let arbiter_vz = ArbiterError::from(vz_wrap);
        assert!(
            arbiter_vz
                .to_string()
                .contains("macOS Virtualization.framework failure:")
        );
        assert!(std::error::Error::source(&arbiter_vz).is_some());

        let sig_del_wrap = SignalDeliveryError::new(1234, 9, "ESRCH");
        assert!(sig_del_wrap.to_string().contains("Signal delivery error"));
        assert!(std::error::Error::source(&sig_del_wrap).is_none());
        let arbiter_sig_del = ArbiterError::from(sig_del_wrap);
        assert!(
            arbiter_sig_del
                .to_string()
                .contains("Signal delivery failure:")
        );
        assert!(std::error::Error::source(&arbiter_sig_del).is_some());

        let raw_mode_wrap = TerminalRawModeError::new("/dev/tty", "not a terminal");
        assert!(
            raw_mode_wrap
                .to_string()
                .contains("Terminal raw-mode error")
        );
        assert!(std::error::Error::source(&raw_mode_wrap).is_none());
        let arbiter_raw_mode = ArbiterError::from(raw_mode_wrap);
        assert!(
            arbiter_raw_mode
                .to_string()
                .contains("Terminal raw-mode failure:")
        );
        assert!(std::error::Error::source(&arbiter_raw_mode).is_some());

        let fuse_wrap = FuseMountError::new("/mnt/rootfs", "fuse", "/dev/fuse unavailable");
        assert!(fuse_wrap.to_string().contains("FUSE/overlay mount error"));
        assert!(std::error::Error::source(&fuse_wrap).is_none());
        let arbiter_fuse = ArbiterError::from(fuse_wrap);
        assert!(
            arbiter_fuse
                .to_string()
                .contains("FUSE/overlay mount failure:")
        );
        assert!(std::error::Error::source(&arbiter_fuse).is_some());

        let criu_wrap = CriuCheckpointError::new("dump", 4242, "/tmp/ckpt", "ptrace denied");
        assert!(criu_wrap.to_string().contains("CRIU checkpoint error"));
        assert!(std::error::Error::source(&criu_wrap).is_none());
        let arbiter_criu = ArbiterError::from(criu_wrap);
        assert!(
            arbiter_criu
                .to_string()
                .contains("CRIU checkpoint failure:")
        );
        assert!(std::error::Error::source(&arbiter_criu).is_some());

        let zfs_wrap = ZfsCommandError::new("create", "tank/arbiter/v1", "pool not found");
        assert!(zfs_wrap.to_string().contains("ZFS command 'create'"));
        assert!(std::error::Error::source(&zfs_wrap).is_none());
        let arbiter_zfs = ArbiterError::from(zfs_wrap);
        assert!(arbiter_zfs.to_string().contains("ZFS command failure:"));
        assert!(std::error::Error::source(&arbiter_zfs).is_some());

        let async_wrap = AsyncRuntimeError::new("join_task", "task panicked");
        assert!(async_wrap.to_string().contains("Async runtime error"));
        assert!(std::error::Error::source(&async_wrap).is_none());
        let arbiter_async = ArbiterError::from(async_wrap);
        assert!(arbiter_async.to_string().contains("Async runtime failure:"));
        assert!(std::error::Error::source(&arbiter_async).is_some());

        let grpc_wrap = GrpcTransportError::new("unix:///tmp/csi.sock", 14, "unavailable");
        assert!(grpc_wrap.to_string().contains("gRPC transport error"));
        assert!(std::error::Error::source(&grpc_wrap).is_none());
        let arbiter_grpc = ArbiterError::from(grpc_wrap);
        assert!(arbiter_grpc.to_string().contains("gRPC transport failure:"));
        assert!(std::error::Error::source(&arbiter_grpc).is_some());
        let grpc_from_tonic = GrpcTransportError::from(tonic::Status::unavailable("down"));
        assert_eq!(grpc_from_tonic.status_code, 14);

        let dylib_wrap =
            DynamicLibraryError::new("libnvidia-ml.so.1", "nvmlInit_v2", "symbol not found");
        assert!(dylib_wrap.to_string().contains("Dynamic library error"));
        assert!(std::error::Error::source(&dylib_wrap).is_none());
        let arbiter_dylib = ArbiterError::from(dylib_wrap);
        assert!(
            arbiter_dylib
                .to_string()
                .contains("Dynamic library failure:")
        );
        assert!(std::error::Error::source(&arbiter_dylib).is_some());

        let pkcs8_wrap = Pkcs8DerError::from(der::Error::from(der::ErrorKind::Overlength));
        assert!(pkcs8_wrap.to_string().contains("PKCS#8 DER key error"));
        assert!(std::error::Error::source(&pkcs8_wrap).is_none());
        let arbiter_pkcs8 = ArbiterError::from(pkcs8_wrap);
        assert!(
            arbiter_pkcs8
                .to_string()
                .contains("PKCS#8 DER key failure:")
        );
        assert!(std::error::Error::source(&arbiter_pkcs8).is_some());

        let rcgen_cert_wrap = RcgenCertError::from(rcgen::Error::CouldNotParseCertificate);
        assert!(
            rcgen_cert_wrap
                .to_string()
                .contains("rcgen X.509v3 certificate generation error")
        );
        assert!(std::error::Error::source(&rcgen_cert_wrap).is_none());
        let arbiter_rcgen_cert = ArbiterError::from(rcgen_cert_wrap);
        assert!(
            arbiter_rcgen_cert
                .to_string()
                .contains("rcgen X.509v3 certificate generation failure:")
        );
        assert!(std::error::Error::source(&arbiter_rcgen_cert).is_some());

        let x509_parse_wrap = X509ParseError::from(der::Error::from(der::ErrorKind::Overlength));
        assert!(x509_parse_wrap.to_string().contains("X.509v3 parse error"));
        assert!(std::error::Error::source(&x509_parse_wrap).is_none());
        let arbiter_x509_parse = ArbiterError::from(x509_parse_wrap);
        assert!(
            arbiter_x509_parse
                .to_string()
                .contains("X.509v3 parse failure:")
        );
        assert!(std::error::Error::source(&arbiter_x509_parse).is_some());
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_third_party_error_conversions() {
        let quinn_conn_err = quinn::ConnectionError::TimedOut;
        let q_wrap = QuicTransportError::from(quinn_conn_err.clone());
        assert_eq!(q_wrap.stream_id, 0);
        assert!(
            ArbiterError::from(quinn_conn_err)
                .to_string()
                .contains("QUIC transport failure:")
        );

        let quinn_write_err = quinn::WriteError::ClosedStream;
        assert_eq!(
            QuicTransportError::from(quinn_write_err.clone()).stream_id,
            0
        );
        assert!(
            ArbiterError::from(quinn_write_err)
                .to_string()
                .contains("QUIC transport failure:")
        );

        let quinn_read_err = quinn::ReadError::ZeroRttRejected;
        assert_eq!(
            QuicTransportError::from(quinn_read_err.clone()).stream_id,
            0
        );
        assert!(
            ArbiterError::from(quinn_read_err)
                .to_string()
                .contains("QUIC transport failure:")
        );

        let quinn_connect_err = quinn::ConnectError::EndpointStopping;
        assert_eq!(
            QuicTransportError::from(quinn_connect_err.clone()).stream_id,
            0
        );
        assert!(
            ArbiterError::from(quinn_connect_err)
                .to_string()
                .contains("QUIC transport failure:")
        );

        let quinn_dgram = quinn::SendDatagramError::UnsupportedByPeer;
        assert_eq!(QuicTransportError::from(quinn_dgram.clone()).stream_id, 0);
        assert!(
            ArbiterError::from(quinn_dgram)
                .to_string()
                .contains("QUIC transport failure:")
        );

        let rustls_err = rustls::Error::InappropriateHandshakeMessage {
            expect_types: Vec::new(),
            got_type: rustls::HandshakeType::HelloRequest,
        };
        assert!(
            !RustlsCodecError::from(rustls_err.clone())
                .message
                .is_empty()
        );
        assert!(
            ArbiterError::from(rustls_err)
                .to_string()
                .contains("TLS codec failure:")
        );

        let dns_res1 = rustls::pki_types::ServerName::try_from("").map_err(RustlsCodecError::from);
        assert!(dns_res1.is_err());
        let dns_res2 = rustls::pki_types::ServerName::try_from("").map_err(ArbiterError::from);
        assert!(dns_res2.is_err());

        let http_res1 = http::Response::builder()
            .status(1000)
            .body(())
            .map_err(HttpTransportError::from);
        assert!(http_res1.is_err());
        let http_res2 = http::Response::builder()
            .status(1000)
            .body(())
            .map_err(ArbiterError::from);
        assert!(http_res2.is_err());

        let h2_err = h2::Error::from(h2::Reason::PROTOCOL_ERROR);
        assert_eq!(HttpTransportError::from(h2_err).status_code, 502);
        let h2_err2 = h2::Error::from(h2::Reason::INTERNAL_ERROR);
        assert!(
            ArbiterError::from(h2_err2)
                .to_string()
                .contains("HTTP transport failure:")
        );

        let ws_err = tokio_tungstenite::tungstenite::Error::ConnectionClosed;
        assert!(!WebSocketCodecError::from(ws_err).message.is_empty());
        let ws_err2 = tokio_tungstenite::tungstenite::Error::AlreadyClosed;
        assert!(
            ArbiterError::from(ws_err2)
                .to_string()
                .contains("WebSocket codec failure:")
        );

        let pg_res1 = "invalid_key=foo"
            .parse::<tokio_postgres::Config>()
            .map_err(PostgresClientError::from);
        assert!(pg_res1.is_err());
        let pg_res2 = "invalid_key=foo"
            .parse::<tokio_postgres::Config>()
            .map_err(ArbiterError::from);
        assert!(pg_res2.is_err());

        #[cfg(unix)]
        {
            let nix_err = nix::errno::Errno::EPERM;
            assert_eq!(
                PosixSyscallError::from(nix_err).errno,
                nix::errno::Errno::EPERM as i32
            );
            assert!(
                ArbiterError::from(nix_err)
                    .to_string()
                    .contains("POSIX syscall failure:")
            );
        }

        let rcgen_err = rcgen::Error::CouldNotParseCertificate;
        assert_eq!(X509CertificateError::from(rcgen_err).subject, "rcgen");
        let rcgen_err2 = rcgen::Error::CouldNotParseKeyPair;
        assert!(
            ArbiterError::from(rcgen_err2)
                .to_string()
                .contains("X.509 certificate failure:")
        );

        let der_err = der::Error::from(der::ErrorKind::Overlength);
        assert_eq!(X509CertificateError::from(der_err).subject, "ASN.1 DER");
        assert!(
            ArbiterError::from(der_err)
                .to_string()
                .contains("X.509 certificate failure:")
        );

        let sig_res1 =
            ed25519_dalek::Signature::from_slice(&[0_u8; 3]).map_err(CryptoSignatureError::from);
        assert!(sig_res1.is_err());
        let sig_res2 = ed25519_dalek::Signature::from_slice(&[0_u8; 3]).map_err(ArbiterError::from);
        assert!(sig_res2.is_err());

        let tonic_status = tonic::Status::unavailable("csi plugin down");
        assert_eq!(CsiGrpcError::from(tonic_status.clone()).grpc_status, 14);
        assert!(
            ArbiterError::from(tonic_status)
                .to_string()
                .contains("CSI gRPC failure:")
        );

        let zip_err = zip::result::ZipError::FileNotFound;
        assert_eq!(ArchiveDecompressionError::from(zip_err).codec, "zip");
        let zip_err2 =
            zip::result::ZipError::InvalidArchive(std::borrow::Cow::Borrowed("bad header"));
        assert!(
            ArbiterError::from(zip_err2)
                .to_string()
                .contains("Archive decompression failure:")
        );

        let prost_dec1 =
            <u64 as prost::Message>::decode(&[0x80_u8; 12][..]).map_err(ProtobufCodecError::from);
        assert!(prost_dec1.is_err());
        let prost_dec2 =
            <u64 as prost::Message>::decode(&[0x80_u8; 12][..]).map_err(ArbiterError::from);
        assert!(prost_dec2.is_err());

        let mut tiny_buf = [0_u8; 0];
        let mut slice_mut: &mut [u8] = &mut tiny_buf;
        let prost_enc1 = <u64 as prost::Message>::encode(&128_u64, &mut slice_mut)
            .map_err(ProtobufCodecError::from);
        assert!(prost_enc1.is_err());
        let mut tiny_buf2 = [0_u8; 0];
        let mut slice_mut2: &mut [u8] = &mut tiny_buf2;
        let prost_enc2 =
            <u64 as prost::Message>::encode(&128_u64, &mut slice_mut2).map_err(ArbiterError::from);
        assert!(prost_enc2.is_err());

        let rte_err = QuicTransportError::from(quinn::ReadToEndError::TooLong);
        assert!(rte_err.to_string().contains("stream 0"));
        let rte_arb = ArbiterError::from(quinn::ReadToEndError::TooLong);
        assert!(rte_arb.to_string().contains("QUIC transport failure"));

        let rex_err = QuicTransportError::from(quinn::ReadExactError::FinishedEarly(4));
        assert!(rex_err.to_string().contains("stream 0"));
        let rex_arb = ArbiterError::from(quinn::ReadExactError::FinishedEarly(4));
        assert!(rex_arb.to_string().contains("QUIC transport failure"));

        let cs_err = QuicTransportError::from(quinn::ClosedStream::default());
        assert!(cs_err.to_string().contains("stream 0"));
        let cs_arb = ArbiterError::from(quinn::ClosedStream::default());
        assert!(cs_arb.to_string().contains("QUIC transport failure"));

        let pem_err1 = <rustls::pki_types::CertificateDer<'static> as rustls::pki_types::pem::PemObject>::from_pem_slice(
            b"-----BEGIN CERTIFICATE-----\n!!bad-base64!!\n-----END CERTIFICATE-----\n",
        )
        .map_err(RustlsCodecError::from);
        assert!(pem_err1.is_err());
        let pem_err2 = <rustls::pki_types::CertificateDer<'static> as rustls::pki_types::pem::PemObject>::from_pem_slice(
            b"-----BEGIN CERTIFICATE-----\n!!bad-base64!!\n-----END CERTIFICATE-----\n",
        )
        .map_err(ArbiterError::from);
        assert!(pem_err2.is_err());

        let uri_err1 = "http://[::1"
            .parse::<http::Uri>()
            .map_err(HttpTransportError::from);
        assert!(uri_err1.is_err());
        let uri_err2 = "http://[::1"
            .parse::<http::Uri>()
            .map_err(ArbiterError::from);
        assert!(uri_err2.is_err());

        let hval_err1 = http::HeaderValue::from_bytes(b"\n").map_err(HttpTransportError::from);
        assert!(hval_err1.is_err());
        let hval_err2 = http::HeaderValue::from_bytes(b"\n").map_err(ArbiterError::from);
        assert!(hval_err2.is_err());

        let _ = http::HeaderValue::from_bytes(&[0xFF]).map(|non_ascii_hv| {
            let to_str_err1 = non_ascii_hv.to_str().map_err(HttpTransportError::from);
            assert!(to_str_err1.is_err());
            let to_str_err2 = non_ascii_hv.to_str().map_err(ArbiterError::from);
            assert!(to_str_err2.is_err());
        });

        let mut no_aes128_provider = rustls::crypto::ring::default_provider();
        no_aes128_provider
            .cipher_suites
            .retain(|cs| cs.suite() != rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        let no_init_res =
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(no_aes128_provider))
                .with_safe_default_protocol_versions()
                .map_err(ArbiterError::from)
                .and_then(|b| {
                    let cfg = b
                        .with_root_certificates(rustls::RootCertStore::empty())
                        .with_no_client_auth();
                    let _ = quinn::crypto::rustls::QuicClientConfig::try_from(cfg.clone())
                        .map_err(RustlsCodecError::from);
                    quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
                        .map_err(ArbiterError::from)
                });
        assert!(no_init_res.is_err());

        let mut dec = flate2::Decompress::new(true);
        let mut dec_out = [0_u8; 8];
        let flate_dec1 = dec
            .decompress(
                &[0xFF, 0xFF, 0xFF],
                &mut dec_out,
                flate2::FlushDecompress::Finish,
            )
            .map_err(ArchiveDecompressionError::from);
        assert!(flate_dec1.is_err());
        let mut dec2 = flate2::Decompress::new(true);
        let flate_dec2 = dec2
            .decompress(
                &[0xFF, 0xFF, 0xFF],
                &mut dec_out,
                flate2::FlushDecompress::Finish,
            )
            .map_err(ArbiterError::from);
        assert!(flate_dec2.is_err());

        let ring_unspec1 = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[0_u8; 4])
            .map_err(AeadCipherError::from);
        assert!(ring_unspec1.is_err());
        let ring_unspec2 = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[0_u8; 4])
            .map_err(ArbiterError::from);
        assert!(ring_unspec2.is_err());

        let ring_key_rej1 =
            ring::signature::Ed25519KeyPair::from_pkcs8(&[0_u8; 4]).map_err(AeadCipherError::from);
        assert!(ring_key_rej1.is_err());
        let ring_key_rej2 =
            ring::signature::Ed25519KeyPair::from_pkcs8(&[0_u8; 4]).map_err(ArbiterError::from);
        assert!(ring_key_rej2.is_err());

        let chacha_err1 = AeadCipherError::from(chacha20poly1305::Error);
        assert_eq!(chacha_err1.cipher, "ChaCha20-Poly1305");
        let chacha_err2 = ArbiterError::from(chacha20poly1305::Error);
        assert!(chacha_err2.to_string().contains("ChaCha20-Poly1305"));

        let mut bad_xz = std::io::Cursor::new(&b"not-an-xz-stream"[..]);
        let mut xz_out = Vec::new();
        let lzma_err1 = lzma_rs::xz_decompress(&mut bad_xz, &mut xz_out)
            .map_err(ArchiveDecompressionError::from);
        assert!(lzma_err1.is_err());
        let mut bad_xz2 = std::io::Cursor::new(&b"not-an-xz-stream"[..]);
        let lzma_err2 =
            lzma_rs::xz_decompress(&mut bad_xz2, &mut xz_out).map_err(ArbiterError::from);
        assert!(lzma_err2.is_err());

        let sqlite_err1 = SqliteStorageError::from(rusqlite::Error::InvalidQuery);
        assert_eq!(sqlite_err1.sqlite_code, 1);
        let sqlite_err2 = ArbiterError::from(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(5),
            Some("database is locked".to_owned()),
        ));
        assert!(sqlite_err2.to_string().contains("code 5"));

        let dylib_err1 = DynamicLibraryError::from(libloading::Error::DlOpenUnknown);
        assert_eq!(dylib_err1.library_path, "libloading");
        let dylib_err2 = ArbiterError::from(libloading::Error::DlSymUnknown);
        assert!(dylib_err2.to_string().contains("Dynamic library failure:"));

        let _ = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map(|rt| {
                rt.block_on(async {
                    let h = tokio::spawn(std::future::pending::<()>());
                    h.abort();
                    let join_res1 = h.await.map_err(AsyncRuntimeError::from);
                    assert!(join_res1.is_err());

                    let h2_task = tokio::spawn(std::future::pending::<()>());
                    h2_task.abort();
                    let join_res2 = h2_task.await.map_err(ArbiterError::from);
                    assert!(join_res2.is_err());

                    let elapsed1 = tokio::time::timeout(
                        std::time::Duration::from_nanos(1),
                        std::future::pending::<()>(),
                    )
                    .await
                    .map_err(AsyncRuntimeError::from);
                    assert!(elapsed1.is_err());

                    let elapsed2 = tokio::time::timeout(
                        std::time::Duration::from_nanos(1),
                        std::future::pending::<()>(),
                    )
                    .await
                    .map_err(ArbiterError::from);
                    assert!(elapsed2.is_err());
                });
            });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_mesos_reason_code_bidirectional_conversions() {
        let all_reason_codes = [
            "REASON_CONTAINER_LAUNCH_FAILED",
            "REASON_CONTAINER_LIMITATION_CPU",
            "REASON_CONTAINER_LIMITATION_DISK",
            "REASON_CONTAINER_LIMITATION_MEMORY",
            "REASON_CONTAINER_PRE_LAUNCH_FAILED",
            "REASON_EXECUTOR_PREEMPTED",
            "REASON_EXECUTOR_REGISTRATION_TIMEOUT",
            "REASON_EXECUTOR_REREGISTRATION_TIMEOUT",
            "REASON_EXECUTOR_TERMINATED",
            "REASON_EXECUTOR_UNREGISTERED",
            "REASON_FRAMEWORK_REMOVED",
            "REASON_GC_ERROR",
            "REASON_INVALID_FRAMEWORKID",
            "REASON_INVALID_OFFERS",
            "REASON_IO_SWITCHBOARD_EXITED",
            "REASON_MASTER_DISCONNECTED",
            "REASON_MAX_COMPLETION_TIME_REACHED",
            "REASON_RECONCILIATION",
            "REASON_RESOURCES_UNKNOWN",
            "REASON_SLAVE_DISCONNECTED",
            "REASON_SLAVE_REMOVED",
            "REASON_SLAVE_RESTARTED",
            "REASON_SLAVE_UNKNOWN",
            "REASON_TASK_CHECK_STATUS_UPDATED",
            "REASON_TASK_GROUP_INVALID",
            "REASON_TASK_GROUP_UNAUTHORIZED",
            "REASON_TASK_HEALTH_CHECK_STATUS_UPDATED",
            "REASON_TASK_INVALID",
            "REASON_TASK_KILLED_DURING_LAUNCH",
            "REASON_TASK_UNAUTHORIZED",
            "REASON_TASK_UNKNOWN",
            "REASON_COMMAND_EXECUTOR_FAILED",
        ];

        for code in all_reason_codes {
            let err = ArbiterError::from_mesos_reason_code(code, "diagnostic-detail");
            assert_eq!(err.to_mesos_reason_code(), code);
        }

        let extra_cases = [
            (
                ArbiterError::InsufficientResources {
                    resource: "cpu".to_owned(),
                    requested: 10,
                    available: 0,
                },
                "REASON_CONTAINER_LIMITATION_CPU",
            ),
            (
                ArbiterError::InsufficientResources {
                    resource: "disk".to_owned(),
                    requested: 10,
                    available: 0,
                },
                "REASON_CONTAINER_LIMITATION_DISK",
            ),
            (
                ArbiterError::QuotaExceeded {
                    role: "r1".to_owned(),
                    resource: "cpu".to_owned(),
                },
                "REASON_CONTAINER_LIMITATION_CPU",
            ),
            (
                ArbiterError::QuotaExceeded {
                    role: "r1".to_owned(),
                    resource: "disk".to_owned(),
                },
                "REASON_CONTAINER_LIMITATION_DISK",
            ),
            (
                ArbiterError::QuotaExceeded {
                    role: "r1".to_owned(),
                    resource: "mem".to_owned(),
                },
                "REASON_CONTAINER_LIMITATION_MEMORY",
            ),
            (
                ArbiterError::AuthenticationFailed {
                    principal: "p1".to_owned(),
                    reason: "bad".to_owned(),
                },
                "REASON_TASK_UNAUTHORIZED",
            ),
            (
                ArbiterError::EmptyIdentifier {
                    kind: "TaskId".to_owned(),
                },
                "REASON_COMMAND_EXECUTOR_FAILED",
            ),
        ];

        for (err, expected) in extra_cases {
            assert_eq!(err.to_mesos_reason_code(), expected);
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_try_from_arbiter_error_roundtrips() {
        macro_rules! check_try_from {
            ($ty:ty, $val:expr) => {{
                let orig: $ty = $val;
                let arb = ArbiterError::from(orig.clone());
                assert_eq!(<$ty>::try_from(arb), Ok(orig));
                let mismatch = ArbiterError::EmptyIdentifier {
                    kind: "mismatch".to_owned(),
                };
                assert!(<$ty>::try_from(mismatch).is_err());
            }};
        }

        check_try_from!(
            JsonCodecError,
            JsonCodecError {
                message: "e".to_owned(),
            }
        );
        check_try_from!(
            IoOperationError,
            IoOperationError {
                kind: "k".to_owned(),
                message: "m".to_owned()
            }
        );
        check_try_from!(
            RkyvCodecError,
            RkyvCodecError {
                message: "r".to_owned()
            }
        );
        check_try_from!(QuicTransportError, QuicTransportError::new(1, "q"));
        check_try_from!(RustlsCodecError, RustlsCodecError::new("tls"));
        check_try_from!(HttpTransportError, HttpTransportError::new(500, "http"));
        check_try_from!(WebSocketCodecError, WebSocketCodecError::new("ws"));
        check_try_from!(EtcdClientError, EtcdClientError::new("ep", "etcd"));
        check_try_from!(PostgresClientError, PostgresClientError::new("40001", "pg"));
        check_try_from!(RedfishFenceError, RedfishFenceError::new("ep", 500, "rf"));
        check_try_from!(IpmiFenceError, IpmiFenceError::new("ep", 1, "ipmi"));
        check_try_from!(NvmeReservationError, NvmeReservationError::new("d", 1, "n"));
        check_try_from!(OciRegistryError, OciRegistryError::new("r", 404, "d", "m"));
        check_try_from!(OtlpExportError, OtlpExportError::new("ep", 500, "otlp"));
        check_try_from!(OsSyscallError, OsSyscallError::new("sys", 1, "m"));
        check_try_from!(TlsHandshakeError, TlsHandshakeError::new("p", "a", "m"));
        check_try_from!(ArchiveFormatError, ArchiveFormatError::new("f", "p", "m"));
        check_try_from!(SubprocessExecError, SubprocessExecError::new("b", 1, "m"));
        check_try_from!(PosixSyscallError, PosixSyscallError::new("s", 1, "m"));
        check_try_from!(Win32ApiError, Win32ApiError::new("f", 1, "m"));
        check_try_from!(X509CertificateError, X509CertificateError::new("s", "m"));
        check_try_from!(CryptoSignatureError, CryptoSignatureError::new("a", "m"));
        check_try_from!(PtyAllocationError, PtyAllocationError::new("c", "m"));
        check_try_from!(FetcherDownloadError, FetcherDownloadError::new("u", "m"));
        check_try_from!(
            SyscallExecutionError,
            SyscallExecutionError::new("s", 1, "m")
        );
        check_try_from!(CsiGrpcError, CsiGrpcError::new("e", 1, "m"));
        check_try_from!(
            ArchiveExtractionError,
            ArchiveExtractionError::new("f", "e", "m")
        );
        check_try_from!(CniPluginError, CniPluginError::new("p", "c", "m"));
        check_try_from!(
            OversubscriptionQosError,
            OversubscriptionQosError::new("a", 1, "m")
        );
        check_try_from!(
            RegistryRecoveryError,
            RegistryRecoveryError::new("m", true, "r")
        );
        check_try_from!(KeyExchangeError, KeyExchangeError::new("p", "r"));
        check_try_from!(AeadCipherError, AeadCipherError::new("c", "r"));
        check_try_from!(
            ArchiveDecompressionError,
            ArchiveDecompressionError::new("c", 0, "r")
        );
        check_try_from!(DnsWirePacketError, DnsWirePacketError::new("q", 3, "r"));
        check_try_from!(ProtobufCodecError, ProtobufCodecError::new(1, 2, "r"));
        check_try_from!(NvmlProbeError, NvmlProbeError::new("d", 1, "m"));
        check_try_from!(RocmSmiError, RocmSmiError::new("n", 1, "m"));
        check_try_from!(LevelZeroProbeError, LevelZeroProbeError::new("d", 1, "m"));
        check_try_from!(LibTpuProbeError, LibTpuProbeError::new("d", 1, "m"));
        check_try_from!(IbVerbsProbeError, IbVerbsProbeError::new("h", 1, "r"));
        check_try_from!(
            FirecrackerApiError,
            FirecrackerApiError::new("s", "PUT", "/a", 400, "m")
        );
        check_try_from!(BhyveCtlError, BhyveCtlError::new("v", 1, "r"));
        check_try_from!(HyperVHcsError, HyperVHcsError::new("s", 1, "m"));
        check_try_from!(AppleVzError, AppleVzError::new("v", 1, "d"));
        check_try_from!(SignalDeliveryError, SignalDeliveryError::new(1, 9, "r"));
        check_try_from!(TerminalRawModeError, TerminalRawModeError::new("t", "r"));
        check_try_from!(FuseMountError, FuseMountError::new("m", "f", "r"));
        check_try_from!(
            CriuCheckpointError,
            CriuCheckpointError::new("d", 1, "i", "r")
        );
        check_try_from!(ZfsCommandError, ZfsCommandError::new("c", "d", "r"));
        check_try_from!(AsyncRuntimeError, AsyncRuntimeError::new("o", "m"));
        check_try_from!(GrpcTransportError, GrpcTransportError::new("e", 1, "m"));
        check_try_from!(DynamicLibraryError, DynamicLibraryError::new("l", "s", "m"));
        check_try_from!(Pkcs8DerError, Pkcs8DerError::new("c", "r"));
        check_try_from!(RcgenCertError, RcgenCertError::new("s", "r"));
        check_try_from!(X509ParseError, X509ParseError::new("o", "r"));
        check_try_from!(
            SqliteStorageError,
            SqliteStorageError::new("/tmp/a.db", 5, "busy")
        );
        check_try_from!(
            ConsulClientError,
            ConsulClientError::new("http://127.0.0.1:8500", 500, "err")
        );
    }

    #[test]
    fn test_base16_base64_and_hmac_error_conversions() {
        let hex_err1 = CryptoSignatureError::from(base16ct::Error::InvalidEncoding);
        assert_eq!(hex_err1.algorithm, "Hex-Base16");
        let hex_err2 = ArbiterError::from(base16ct::Error::InvalidLength);
        assert!(hex_err2.to_string().contains("Hex-Base16"));

        let b64_res1 = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, "!!!")
            .map_err(CryptoSignatureError::from);
        assert!(b64_res1.is_err());
        let b64_res2 = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, "!!!")
            .map_err(ArbiterError::from);
        assert!(b64_res2.is_err());

        let hmac_err1 = CryptoSignatureError::from(hmac::digest::InvalidLength);
        assert_eq!(hmac_err1.algorithm, "HMAC-SHA256");
        let hmac_err2 = ArbiterError::from(hmac::digest::InvalidLength);
        assert!(hmac_err2.to_string().contains("HMAC-SHA256"));

        let empty_roots = std::sync::Arc::new(rustls::RootCertStore::empty());
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let vb_res1 = rustls::server::WebPkiClientVerifier::builder_with_provider(
            empty_roots.clone(),
            provider.clone(),
        )
        .build()
        .map_err(RustlsCodecError::from);
        assert!(vb_res1.is_err());
        let vb_res2 =
            rustls::server::WebPkiClientVerifier::builder_with_provider(empty_roots, provider)
                .build()
                .map_err(ArbiterError::from);
        assert!(vb_res2.is_err());
    }

    #[test]
    fn test_http_and_tonic_status_code_mappings() {
        let cases: Vec<(ArbiterError, u16, tonic::Code)> = vec![
            (
                ArbiterError::NotLeader {
                    node_id: "m2".to_owned(),
                    leader_hint: "m1".to_owned(),
                },
                307,
                tonic::Code::Unavailable,
            ),
            (
                ArbiterError::AuthenticationFailed {
                    principal: "p".to_owned(),
                    reason: "r".to_owned(),
                },
                401,
                tonic::Code::Unauthenticated,
            ),
            (
                ArbiterError::AuthorizationDenied {
                    principal: "p".to_owned(),
                    action: "a".to_owned(),
                    resource: "r".to_owned(),
                },
                403,
                tonic::Code::PermissionDenied,
            ),
            (
                ArbiterError::DeviceNotFound {
                    device_id: "d".to_owned(),
                },
                404,
                tonic::Code::NotFound,
            ),
            (
                ArbiterError::CasConflict {
                    key: "k".to_owned(),
                    expected_rev: 1,
                    actual_rev: 2,
                },
                409,
                tonic::Code::Aborted,
            ),
            (
                ArbiterError::InsufficientResources {
                    resource: "cpu".to_owned(),
                    requested: 2,
                    available: 1,
                },
                429,
                tonic::Code::ResourceExhausted,
            ),
            (
                ArbiterError::HttpHandlerError {
                    status_code: 418,
                    message: "teapot".to_owned(),
                },
                418,
                tonic::Code::Internal,
            ),
            (
                ArbiterError::from(HttpTransportError::new(502, "bad gateway")),
                502,
                tonic::Code::Internal,
            ),
            (
                ArbiterError::RaftConsensusError {
                    term: 1,
                    reason: "quorum".to_owned(),
                },
                503,
                tonic::Code::Unavailable,
            ),
            (
                ArbiterError::EmptyIdentifier {
                    kind: "TaskId".to_owned(),
                },
                400,
                tonic::Code::InvalidArgument,
            ),
            (
                ArbiterError::StoreWriteError {
                    key: "k".to_owned(),
                    reason: "r".to_owned(),
                },
                500,
                tonic::Code::Internal,
            ),
        ];

        for (err, expected_http, expected_grpc) in cases {
            assert_eq!(err.to_http_status_code(), expected_http);
            assert_eq!(err.to_tonic_status().code(), expected_grpc);
        }
    }
}
