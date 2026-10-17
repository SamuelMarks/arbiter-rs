//! HTTP/REST, Server-Sent Events (`SSE`), and WebSocket transport handlers (`arbiter-net::http`).
//!
//! Maps Mesos v1-style HTTP/JSON endpoints (`/api/v1/scheduler`, `/api/v1/executor`,
//! `/api/v1/operator`, `/api/v1/jobs`) and `SSE` event streams onto the exact same internal
//! [`WireEnvelope`] command/event bus as the QUIC transport, enforcing SVID authentication.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_proto::{ApiEndpoint, WireEnvelope};
use serde::{Deserialize, Serialize};

use crate::security::{SpiffeSvid, SvidAuthority};

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
}

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
        Self { authority }
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
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::AgentId;
    use arbiter_proto::{AgentHeartbeat, WireMessage};

    use super::*;

    #[test]
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
            client_svid: Some(svid),
            body_json: "{invalid".to_owned(),
        };
        assert!(gateway.handle_request(&bad_json_req, 50).is_err());
    }
}
