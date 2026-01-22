//! Policy client for fetching policies from the CopilotGuard API
//!
//! This module provides an HTTP client specifically for fetching signed policies
//! from the CopilotGuard API. It handles network errors, timeouts, and provides
//! proper error types for policy-related failures.

// Allow dead code during incremental implementation - this module is being
// built up over multiple phases and will be integrated into the proxy later.
#![allow(dead_code)]

use reqwest::Client;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};

use crate::policy::SignedPolicy;

/// Default timeout for policy fetches (5 seconds)
const DEFAULT_POLICY_TIMEOUT_SECS: u64 = 5;

/// Errors that can occur when fetching policies
#[derive(Debug, Error)]
pub enum PolicyClientError {
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("API returned error status: {status} - {message}")]
    ApiError { status: u16, message: String },

    #[error("Failed to parse policy response: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Request timed out after {0}ms")]
    Timeout(u64),

    #[error("No API key configured")]
    NoApiKey,

    #[error("Unauthorized: API key is invalid or expired")]
    Unauthorized,
}

/// Result type for policy client operations
pub type PolicyClientResult<T> = Result<T, PolicyClientError>;

/// HTTP client for fetching policies from the CopilotGuard API
pub struct PolicyClient {
    /// HTTP client instance
    client: Client,
    /// API base URL
    api_url: String,
    /// API key for authentication
    api_key: String,
    /// Timeout for policy fetches in milliseconds
    timeout_ms: u64,
}

impl PolicyClient {
    /// Create a new policy client
    ///
    /// # Arguments
    /// * `api_url` - The base URL of the CopilotGuard API (e.g., "https://api.guard.tony.codes")
    /// * `api_key` - The API key for authentication
    ///
    /// # Returns
    /// A new `PolicyClient` configured with default timeout (5 seconds)
    pub fn new(api_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self::with_timeout(
            api_url,
            api_key,
            DEFAULT_POLICY_TIMEOUT_SECS * 1000, // Convert to ms
        )
    }

    /// Create a new policy client with a custom timeout
    ///
    /// # Arguments
    /// * `api_url` - The base URL of the CopilotGuard API
    /// * `api_key` - The API key for authentication
    /// * `timeout_ms` - Timeout in milliseconds for policy fetches
    pub fn with_timeout(
        api_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout_ms: u64,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_url: api_url.into(),
            api_key: api_key.into(),
            timeout_ms,
        }
    }

    /// Fetch the policy from the CopilotGuard API
    ///
    /// # Returns
    /// The signed policy from the server, or an error if the fetch fails.
    ///
    /// # Errors
    /// - `NetworkError`: Connection failed
    /// - `Timeout`: Request took longer than the configured timeout
    /// - `Unauthorized`: API key is invalid or expired
    /// - `ApiError`: Server returned an error status
    /// - `ParseError`: Response body couldn't be parsed as a SignedPolicy
    pub async fn fetch_policy(&self) -> PolicyClientResult<SignedPolicy> {
        let url = format!("{}/api/v1/daemon/policy", self.api_url);

        debug!("Fetching policy from {}", url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    PolicyClientError::Timeout(self.timeout_ms)
                } else {
                    PolicyClientError::NetworkError(e)
                }
            })?;

        let status = response.status();

        if status.is_success() {
            let body = response.text().await?;
            debug!("Received policy response ({} bytes)", body.len());

            let policy: SignedPolicy = serde_json::from_str(&body)?;
            Ok(policy)
        } else if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            warn!("API key unauthorized or forbidden (status: {})", status);
            Err(PolicyClientError::Unauthorized)
        } else {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            warn!("Policy fetch failed with status {}: {}", status, message);
            Err(PolicyClientError::ApiError {
                status: status.as_u16(),
                message,
            })
        }
    }

    /// Get the configured API URL
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Get the configured timeout in milliseconds
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = PolicyClient::new("https://api.guard.tony.codes", "cg_test_key");
        assert_eq!(client.api_url(), "https://api.guard.tony.codes");
        assert_eq!(client.timeout_ms(), 5000);
    }

    #[test]
    fn test_client_with_custom_timeout() {
        let client = PolicyClient::with_timeout("https://example.com", "key", 10000);
        assert_eq!(client.timeout_ms(), 10000);
    }

    #[test]
    fn test_error_display() {
        let err = PolicyClientError::Timeout(5000);
        assert_eq!(err.to_string(), "Request timed out after 5000ms");

        let err = PolicyClientError::Unauthorized;
        assert_eq!(
            err.to_string(),
            "Unauthorized: API key is invalid or expired"
        );

        let err = PolicyClientError::ApiError {
            status: 500,
            message: "Internal server error".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "API returned error status: 500 - Internal server error"
        );

        let err = PolicyClientError::NoApiKey;
        assert_eq!(err.to_string(), "No API key configured");
    }

    // Note: Integration tests with actual HTTP calls would go in tests/policy_integration.rs
    // using a mock server. For now, we just test the client construction and error types.
}
