use anyhow::Result;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::api::{
    HealthResponse, InterceptRequestPayload, InterceptRequestResponse,
    InterceptResponsePayload, InterceptResponseResponse,
};
use crate::config::Config;

/// API client for communicating with the CopilotGuard API
pub struct ApiClient {
    /// HTTP client for API requests
    client: Client,
    /// API base URL
    api_url: String,
    /// API key for authentication
    api_key: Option<String>,
    /// Timeout for guardrail checks (ms)
    guardrail_timeout_ms: u64,
    /// Fail mode: "open" (allow on error) or "closed" (block on error)
    fail_mode: String,
}

impl ApiClient {
    /// Create a new API client from config
    pub fn new(config: &Config) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            api_url: config.api_url.clone(),
            api_key: config.api_key.clone(),
            guardrail_timeout_ms: config.guardrail_timeout_ms,
            fail_mode: config.api_fail_mode.clone(),
        })
    }

    /// Check if API key is configured
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Should we allow requests when API fails?
    fn should_fail_open(&self) -> bool {
        self.fail_mode == "open"
    }

    /// Check request against guardrails
    /// Returns (blocked, reason) tuple
    /// On error, returns based on fail_mode
    pub async fn check_request(&self, payload: InterceptRequestPayload) -> (bool, Option<String>) {
        let request_id = payload.request_id.clone();

        // If no API key, allow all (daemon works standalone)
        if self.api_key.is_none() {
            debug!("[{}] No API key configured, allowing request", request_id);
            return (false, None);
        }

        let url = format!("{}/api/v1/proxy/intercept/request", self.api_url);

        let result = tokio::time::timeout(
            Duration::from_millis(self.guardrail_timeout_ms),
            self.send_check_request(&url, &payload),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                if response.blocked {
                    info!(
                        "[{}] Request BLOCKED: {}",
                        request_id,
                        response.reason.as_deref().unwrap_or("No reason provided")
                    );
                    (true, response.reason)
                } else {
                    debug!("[{}] Request allowed by guardrails", request_id);
                    (false, None)
                }
            }
            Ok(Err(e)) => {
                warn!("[{}] API error checking request: {}", request_id, e);
                if self.should_fail_open() {
                    warn!("[{}] Fail-open: allowing request despite API error", request_id);
                    (false, None)
                } else {
                    warn!("[{}] Fail-closed: blocking request due to API error", request_id);
                    (true, Some("API error - fail-closed mode".to_string()))
                }
            }
            Err(_) => {
                warn!(
                    "[{}] API timeout after {}ms",
                    request_id, self.guardrail_timeout_ms
                );
                if self.should_fail_open() {
                    warn!("[{}] Fail-open: allowing request despite timeout", request_id);
                    (false, None)
                } else {
                    warn!("[{}] Fail-closed: blocking request due to timeout", request_id);
                    (true, Some("API timeout - fail-closed mode".to_string()))
                }
            }
        }
    }

    /// Internal method to send the check request
    async fn send_check_request(
        &self,
        url: &str,
        payload: &InterceptRequestPayload,
    ) -> Result<InterceptRequestResponse> {
        let mut req = self.client.post(url).json(payload);

        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let response = req.send().await?;
        let status = response.status();

        if status.is_success() {
            let body: InterceptRequestResponse = response.json().await?;
            Ok(body)
        } else if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            warn!("API key invalid or unauthorized (status: {})", status);
            // Return non-blocking on auth error - admin should fix key
            Ok(InterceptRequestResponse {
                blocked: false,
                reason: None,
                log_id: None,
            })
        } else {
            anyhow::bail!("API returned error status: {}", status)
        }
    }

    /// Log the response after forwarding (fire-and-forget)
    /// This runs async in the background and doesn't block the response
    pub fn log_response(&self, payload: InterceptResponsePayload) {
        // If no API key, skip logging
        if self.api_key.is_none() {
            debug!(
                "[{}] No API key configured, skipping response logging",
                payload.request_id
            );
            return;
        }

        let url = format!("{}/api/v1/proxy/intercept/response", self.api_url);
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        let request_id = payload.request_id.clone();

        // Spawn fire-and-forget task with 10s timeout
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                Self::send_log_response(&client, &url, &payload, api_key.as_deref()),
            )
            .await;

            match result {
                Ok(Ok(_)) => {
                    debug!("[{}] Response logged successfully", request_id);
                }
                Ok(Err(e)) => {
                    // Silent failure - don't impact user
                    debug!("[{}] Failed to log response: {}", request_id, e);
                }
                Err(_) => {
                    debug!("[{}] Response logging timed out", request_id);
                }
            }
        });
    }

    /// Internal method to send the log request
    async fn send_log_response(
        client: &Client,
        url: &str,
        payload: &InterceptResponsePayload,
        api_key: Option<&str>,
    ) -> Result<InterceptResponseResponse> {
        let mut req = client.post(url).json(payload);

        if let Some(key) = api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let response = req.send().await?;

        if response.status().is_success() {
            let body: InterceptResponseResponse = response.json().await?;
            Ok(body)
        } else {
            anyhow::bail!("API returned error status: {}", response.status())
        }
    }

    /// Test API connectivity
    pub async fn health_check(&self) -> Result<HealthResponse> {
        let url = format!("{}/health", self.api_url);

        let mut req = self.client.get(&url);

        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let response = req
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if response.status().is_success() {
            let body: HealthResponse = response.json().await?;
            Ok(body)
        } else {
            anyhow::bail!("Health check failed with status: {}", response.status())
        }
    }

    /// Test API key validity
    pub async fn validate_api_key(&self) -> Result<bool> {
        if self.api_key.is_none() {
            return Ok(false);
        }

        let url = format!("{}/api/v1/auth/me", self.api_url);

        let response = self
            .client
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_key.as_ref().unwrap()),
            )
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}

/// Create a shared API client wrapped in Arc
pub fn create_api_client(config: &Config) -> Result<Arc<ApiClient>> {
    Ok(Arc::new(ApiClient::new(config)?))
}
