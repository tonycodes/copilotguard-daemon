use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request payload sent to the CopilotGuard API for guardrail checking
#[derive(Debug, Serialize)]
pub struct InterceptRequestPayload {
    /// Unique request ID for correlation
    pub request_id: String,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Target host (e.g., copilot-proxy.githubusercontent.com)
    pub host: String,
    /// Request path (e.g., /v1/completions)
    pub path: String,
    /// Request headers (sanitized - no auth tokens)
    pub headers: HashMap<String, String>,
    /// Request body (truncated to 1MB max)
    pub body: String,
}

/// Response from the CopilotGuard API guardrail check
#[derive(Debug, Deserialize)]
pub struct InterceptRequestResponse {
    /// Whether the request should be blocked
    pub blocked: bool,
    /// Reason for blocking (if blocked)
    pub reason: Option<String>,
    /// Log ID for tracking (if logged)
    #[allow(dead_code)]
    pub log_id: Option<String>,
}

/// Payload sent to log the response after forwarding
#[derive(Debug, Serialize)]
pub struct InterceptResponsePayload {
    /// Request ID for correlation
    pub request_id: String,
    /// HTTP status code from the upstream response
    pub status_code: u16,
    /// Latency in milliseconds for the upstream request
    pub latency_ms: u64,
    /// Response body (truncated to 1MB max)
    pub body: String,
}

/// Response from the response logging endpoint
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct InterceptResponseResponse {
    /// Whether the log was recorded successfully
    pub logged: bool,
}

/// Health check response from the API
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    /// API status
    pub status: String,
    /// Optional message
    pub message: Option<String>,
}

/// Response from starting a device authorization flow
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuthStartResponse {
    /// Internal device code (used for polling)
    pub device_code: String,
    /// User-facing code to display
    pub user_code: String,
    /// URL where user should enter the code
    pub verification_url: String,
    /// URL with code pre-filled
    pub verification_url_complete: String,
    /// Seconds until the code expires
    pub expires_in: u64,
    /// Polling interval in seconds
    pub interval: u64,
}

/// Response from polling device authorization status
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuthPollResponse {
    /// Status: "pending", "authorized", or "expired"
    pub status: String,
    /// API key (only present when status is "authorized")
    pub api_key: Option<String>,
    /// Error code (if any)
    pub error: Option<String>,
    /// Human-readable message
    pub message: Option<String>,
}

/// Maximum body size to send to API (1MB)
pub const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Truncate body to max size, adding indicator if truncated
pub fn truncate_body(body: &[u8]) -> String {
    if body.len() > MAX_BODY_SIZE {
        let truncated = String::from_utf8_lossy(&body[..MAX_BODY_SIZE]);
        format!("{}... [TRUNCATED from {} bytes]", truncated, body.len())
    } else {
        String::from_utf8_lossy(body).to_string()
    }
}
