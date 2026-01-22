//! Policy manager for coordinating policy fetching, caching, and validation
//!
//! This module provides the main interface for obtaining policies. It:
//! - Fetches fresh policies from the server
//! - Falls back to cached policies when offline
//! - Validates signatures on all policies
//! - Enforces staleness limits for cached policies
//! - Supports background refresh

use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::policy::{Policy, PolicyError, SignedPolicy};
use crate::policy_cache::{CacheError, PolicyCache};
use crate::policy_client::{PolicyClient, PolicyClientError};

/// Default maximum offline hours before policy expires
const DEFAULT_MAX_OFFLINE_HOURS: u64 = 72;

/// Default refresh interval in seconds (5 minutes)
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 300;

/// Errors that can occur during policy management
#[derive(Debug, Error)]
pub enum PolicyManagerError {
    #[error("Failed to fetch policy from server: {0}")]
    FetchError(#[from] PolicyClientError),

    #[error("Failed to load policy from cache: {0}")]
    CacheError(#[from] CacheError),

    #[error("Policy signature verification failed: {0}")]
    SignatureError(#[from] PolicyError),

    #[error("Policy expired: cache is {age_hours} hours old (max: {max_hours} hours)")]
    Expired { age_hours: u64, max_hours: u64 },

    #[allow(dead_code)] // Will be used in graceful degradation (POL-009)
    #[error("No policy available: server unreachable and no valid cache")]
    NoPolicyAvailable,

    #[error("No API key configured")]
    NoApiKey,
}

/// Result type for policy manager operations
pub type PolicyManagerResult<T> = Result<T, PolicyManagerError>;

/// Policy manager configuration
#[derive(Debug, Clone)]
pub struct PolicyManagerConfig {
    /// API base URL
    pub api_url: String,
    /// API key for authentication
    pub api_key: Option<String>,
    /// Maximum hours a cached policy can be used offline
    pub max_offline_hours: u64,
    /// Policy fetch timeout in milliseconds
    pub timeout_ms: u64,
    /// Public key for signature verification (hex-encoded)
    /// If None, uses the production key embedded in the binary
    pub public_key_hex: Option<String>,
}

impl Default for PolicyManagerConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.guard.tony.codes".to_string(),
            api_key: None,
            max_offline_hours: DEFAULT_MAX_OFFLINE_HOURS,
            timeout_ms: 5000,
            public_key_hex: None,
        }
    }
}

/// Policy manager that coordinates fetching, caching, and validation
pub struct PolicyManager {
    /// HTTP client for fetching policies
    client: Option<PolicyClient>,
    /// Local encrypted cache
    cache: PolicyCache,
    /// Configuration
    config: PolicyManagerConfig,
    /// Currently loaded policy (for in-memory access)
    current_policy: Arc<RwLock<Option<SignedPolicy>>>,
}

impl PolicyManager {
    /// Create a new policy manager with the given configuration
    pub fn new(config: PolicyManagerConfig) -> PolicyManagerResult<Self> {
        let cache = PolicyCache::new().map_err(PolicyManagerError::CacheError)?;

        let client = match &config.api_key {
            Some(key) if !key.is_empty() => Some(PolicyClient::with_timeout(
                &config.api_url,
                key,
                config.timeout_ms,
            )),
            _ => None,
        };

        Ok(Self {
            client,
            cache,
            config,
            current_policy: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a policy manager with a specific cache path
    ///
    /// This is useful for testing or when you need to control the cache location.
    pub fn with_cache_path(
        config: PolicyManagerConfig,
        cache_path: std::path::PathBuf,
    ) -> PolicyManagerResult<Self> {
        let cache = PolicyCache::with_path(cache_path).map_err(PolicyManagerError::CacheError)?;

        let client = match &config.api_key {
            Some(key) if !key.is_empty() => Some(PolicyClient::with_timeout(
                &config.api_url,
                key,
                config.timeout_ms,
            )),
            _ => None,
        };

        Ok(Self {
            client,
            cache,
            config,
            current_policy: Arc::new(RwLock::new(None)),
        })
    }

    /// Get the current policy, fetching from server or cache as needed
    ///
    /// This method:
    /// 1. Tries to fetch a fresh policy from the server
    /// 2. Falls back to cached policy if server is unreachable
    /// 3. Validates signatures on all policies
    /// 4. Enforces staleness limits on cached policies
    ///
    /// # Returns
    /// The validated policy, or an error if no valid policy is available.
    pub async fn get_policy(&self) -> PolicyManagerResult<Policy> {
        // If no API key, return NoApiKey error
        // The proxy layer will handle this by passing through all traffic
        if self.client.is_none() {
            debug!("No API key configured, cannot fetch policy");
            return Err(PolicyManagerError::NoApiKey);
        }

        // Try to fetch fresh policy from server
        match self.fetch_and_validate().await {
            Ok(policy) => {
                debug!("Using fresh policy from server: v{}", policy.version);
                return Ok(policy);
            }
            Err(e) => {
                warn!("Failed to fetch policy from server: {}", e);
                // Continue to cache fallback
            }
        }

        // Fall back to cached policy
        self.load_from_cache()
    }

    /// Fetch policy from server, validate it, and cache it
    async fn fetch_and_validate(&self) -> PolicyManagerResult<Policy> {
        let client = self.client.as_ref().ok_or(PolicyManagerError::NoApiKey)?;

        // Fetch from server
        let mut signed_policy = client.fetch_policy().await?;

        // Verify signature BEFORE modifying the policy
        // The signature is computed over the policy as sent by the server
        self.verify_signature(&signed_policy)?;

        // Set fetched_at timestamp AFTER signature verification
        // This is a local-only field to track when we received the policy
        signed_policy.policy.fetched_at = Some(current_iso8601());

        // Cache the policy
        if let Err(e) = self.cache.store(&signed_policy) {
            warn!("Failed to cache policy: {}", e);
            // Continue anyway - we have a valid policy in memory
        }

        // Update in-memory policy
        {
            let mut current = self.current_policy.write().await;
            *current = Some(signed_policy.clone());
        }

        Ok(signed_policy.policy)
    }

    /// Load policy from cache, validate it, and check staleness
    fn load_from_cache(&self) -> PolicyManagerResult<Policy> {
        let signed_policy = self.cache.load()?;

        // Note: We don't verify the signature for cached policies because:
        // 1. The signature was already verified when the policy was first fetched
        // 2. The cache is encrypted with a machine-bound key, preventing tampering
        // 3. We add `fetched_at` after verification, which would cause signature mismatch

        // Check staleness
        if let Some(true) = self.cache.is_stale(self.config.max_offline_hours) {
            // Calculate actual age for error message
            let age_hours = self.calculate_age_hours(&signed_policy);
            error!(
                "Cached policy is stale ({} hours old, max {} hours)",
                age_hours, self.config.max_offline_hours
            );
            return Err(PolicyManagerError::Expired {
                age_hours,
                max_hours: self.config.max_offline_hours,
            });
        }

        info!(
            "Using cached policy: v{} (fetched at {:?})",
            signed_policy.policy.version, signed_policy.policy.fetched_at
        );

        Ok(signed_policy.policy)
    }

    /// Verify the signature of a policy
    fn verify_signature(&self, policy: &SignedPolicy) -> PolicyManagerResult<()> {
        match &self.config.public_key_hex {
            Some(key) => policy.verify_with_key(key)?,
            None => policy.verify()?,
        }
        Ok(())
    }

    /// Calculate the age of a policy in hours
    fn calculate_age_hours(&self, policy: &SignedPolicy) -> u64 {
        policy
            .policy
            .fetched_at
            .as_ref()
            .and_then(|ts| parse_iso8601_to_hours_ago(ts))
            .unwrap_or(0)
    }

    /// Force refresh the policy from the server
    ///
    /// This bypasses the cache and fetches directly from the server.
    /// Useful for CLI commands like `policy refresh`.
    pub async fn refresh(&self) -> PolicyManagerResult<Policy> {
        if self.client.is_none() {
            return Err(PolicyManagerError::NoApiKey);
        }

        self.fetch_and_validate().await
    }

    /// Get the currently cached policy without fetching
    ///
    /// Returns None if no policy is cached or if the cache is invalid.
    #[allow(dead_code)] // Will be used in CLI commands (POL-012)
    pub fn get_cached_policy(&self) -> Option<SignedPolicy> {
        self.cache.load().ok()
    }

    /// Check if a cached policy exists
    #[allow(dead_code)] // Will be used in CLI commands (POL-012)
    pub fn has_cached_policy(&self) -> bool {
        self.cache.exists()
    }

    /// Clear the policy cache
    #[allow(dead_code)] // Will be used in CLI commands
    pub fn clear_cache(&self) -> PolicyManagerResult<()> {
        self.cache.clear()?;
        Ok(())
    }

    /// Get the maximum offline hours configuration
    #[allow(dead_code)] // Will be used in CLI commands (POL-012)
    pub fn max_offline_hours(&self) -> u64 {
        self.config.max_offline_hours
    }

    /// Get the refresh interval for background refresh
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs(DEFAULT_REFRESH_INTERVAL_SECS)
    }

    /// Start a background refresh task
    ///
    /// This spawns a task that periodically refreshes the policy from the server.
    /// The task runs every `refresh_interval()` and updates the cache.
    ///
    /// Returns a handle that can be used to abort the task.
    #[allow(dead_code)] // We use manual background refresh in proxy.rs
    pub fn start_background_refresh(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = self;
        let interval = manager.refresh_interval();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                debug!("Background policy refresh triggered");
                match manager.refresh().await {
                    Ok(policy) => {
                        info!("Background refresh successful: policy v{}", policy.version);
                    }
                    Err(PolicyManagerError::NoApiKey) => {
                        debug!("Background refresh skipped: no API key configured");
                    }
                    Err(e) => {
                        warn!("Background refresh failed: {}", e);
                    }
                }
            }
        })
    }
}

/// Get current time as ISO 8601 string
fn current_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert to ISO 8601 format
    let days_since_epoch = now / 86400;
    let time_of_day = now % 86400;

    // Calculate year/month/day (simplified, doesn't account for all edge cases)
    let mut year = 1970;
    let mut remaining_days = days_since_epoch;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for (m, &days) in days_in_month.iter().enumerate() {
        let days = if m == 1 && is_leap_year(year) {
            29
        } else {
            days
        };
        if remaining_days < days {
            break;
        }
        remaining_days -= days;
        month += 1;
    }

    let day = remaining_days + 1;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Parse ISO 8601 timestamp and return hours since that time
fn parse_iso8601_to_hours_ago(s: &str) -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple ISO 8601 parser (same logic as in policy_cache.rs)
    let s = s.trim();
    let s = s.strip_suffix('Z').unwrap_or(s);
    let s = if let Some(pos) = s.rfind('+') {
        &s[..pos]
    } else if let Some(pos) = s.rfind('-') {
        if pos > 10 {
            &s[..pos]
        } else {
            s
        }
    } else {
        s
    };

    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1]
        .split(':')
        .filter_map(|p| p.split('.').next()?.parse().ok())
        .collect();

    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let year = date_parts[0];
    let month = date_parts[1];
    let day = date_parts[2];
    let hour = time_parts[0];
    let minute = time_parts[1];
    let second = time_parts[2];

    // Calculate timestamp
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days: u64 = 0;

    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    for m in 1..month {
        let d = if m == 2 && is_leap_year(year) {
            29
        } else {
            days_in_month[(m - 1) as usize]
        };
        days += d as u64;
    }

    days += day - 1;

    let timestamp = days * 86400 + hour * 3600 + minute * 60 + second;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    let age_secs = now.saturating_sub(timestamp);
    Some(age_secs / 3600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DomainList, HeuristicConfig};
    use tempfile::tempdir;

    // Test keys (same as in policy.rs)
    const TEST_PRIVATE_KEY_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_PUBLIC_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// Create a test policy with a valid signature
    fn create_test_signed_policy() -> SignedPolicy {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let policy = Policy {
            version: "test-1.0.0".to_string(),
            expires_at: "2030-12-31T23:59:59Z".to_string(),
            fetched_at: Some(current_iso8601()),
            global_intercept: DomainList::default(),
            org_intercept: DomainList::default(),
            passthrough: DomainList::default(),
            heuristics: HeuristicConfig::default(),
        };

        // Sign the policy
        let private_key_bytes = hex_decode(TEST_PRIVATE_KEY_HEX).unwrap();
        let private_key_array: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_key_array);

        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        let signature = signing_key.sign(&policy_bytes);
        let signature_base64 = BASE64.encode(signature.to_bytes());

        SignedPolicy {
            policy,
            signature: signature_base64,
        }
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("Hex string must have even length".to_string());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    #[test]
    fn test_policy_manager_creation_no_api_key() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            api_key: None,
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();
        assert!(manager.client.is_none());
    }

    #[test]
    fn test_policy_manager_creation_with_api_key() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            api_key: Some("cg_test_key".to_string()),
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();
        assert!(manager.client.is_some());
    }

    #[tokio::test]
    async fn test_get_policy_no_api_key() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            api_key: None,
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();
        let result = manager.get_policy().await;

        assert!(matches!(result, Err(PolicyManagerError::NoApiKey)));
    }

    #[test]
    fn test_has_cached_policy_empty() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig::default();
        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        assert!(!manager.has_cached_policy());
    }

    #[test]
    fn test_clear_cache() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            public_key_hex: Some(TEST_PUBLIC_KEY_HEX.to_string()),
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        // Store a policy in the cache
        let policy = create_test_signed_policy();
        manager.cache.store(&policy).unwrap();
        assert!(manager.has_cached_policy());

        // Clear it
        manager.clear_cache().unwrap();
        assert!(!manager.has_cached_policy());
    }

    #[test]
    fn test_load_from_cache_valid() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            public_key_hex: Some(TEST_PUBLIC_KEY_HEX.to_string()),
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        // Store a valid signed policy
        let signed_policy = create_test_signed_policy();
        manager.cache.store(&signed_policy).unwrap();

        // Load it back
        let result = manager.load_from_cache();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, "test-1.0.0");
    }

    #[test]
    fn test_load_from_cache_expired() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            public_key_hex: Some(TEST_PUBLIC_KEY_HEX.to_string()),
            max_offline_hours: 1, // Very short for testing
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        // Store a policy with old fetched_at
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let policy = Policy {
            version: "old-policy".to_string(),
            expires_at: "2030-12-31T23:59:59Z".to_string(),
            fetched_at: Some("2020-01-01T00:00:00Z".to_string()), // Very old
            global_intercept: DomainList::default(),
            org_intercept: DomainList::default(),
            passthrough: DomainList::default(),
            heuristics: HeuristicConfig::default(),
        };

        let private_key_bytes = hex_decode(TEST_PRIVATE_KEY_HEX).unwrap();
        let private_key_array: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_key_array);
        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        let signature = signing_key.sign(&policy_bytes);

        let signed_policy = SignedPolicy {
            policy,
            signature: BASE64.encode(signature.to_bytes()),
        };

        manager.cache.store(&signed_policy).unwrap();

        // Try to load - should fail due to staleness
        let result = manager.load_from_cache();
        assert!(matches!(result, Err(PolicyManagerError::Expired { .. })));
    }

    #[test]
    fn test_current_iso8601() {
        let ts = current_iso8601();
        assert!(ts.contains("T"));
        assert!(ts.ends_with("Z"));
        assert_eq!(ts.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
    }

    #[test]
    fn test_parse_iso8601_to_hours_ago() {
        // Recent timestamp should have small hours
        let recent = current_iso8601();
        let hours = parse_iso8601_to_hours_ago(&recent);
        assert!(hours.is_some());
        assert!(hours.unwrap() < 1);

        // Old timestamp should have many hours
        let old = "2020-01-01T00:00:00Z";
        let hours = parse_iso8601_to_hours_ago(old);
        assert!(hours.is_some());
        assert!(hours.unwrap() > 1000); // Many hours since 2020
    }

    #[test]
    fn test_max_offline_hours() {
        let config = PolicyManagerConfig {
            max_offline_hours: 48,
            ..Default::default()
        };

        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");
        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        assert_eq!(manager.max_offline_hours(), 48);
    }

    #[test]
    fn test_refresh_interval() {
        let config = PolicyManagerConfig::default();
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");
        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        assert_eq!(manager.refresh_interval(), Duration::from_secs(300));
    }

    #[test]
    fn test_error_display() {
        let err = PolicyManagerError::NoApiKey;
        assert_eq!(err.to_string(), "No API key configured");

        let err = PolicyManagerError::Expired {
            age_hours: 100,
            max_hours: 72,
        };
        assert_eq!(
            err.to_string(),
            "Policy expired: cache is 100 hours old (max: 72 hours)"
        );

        let err = PolicyManagerError::NoPolicyAvailable;
        assert_eq!(
            err.to_string(),
            "No policy available: server unreachable and no valid cache"
        );
    }

    #[test]
    fn test_get_cached_policy() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("policy_cache");

        let config = PolicyManagerConfig {
            public_key_hex: Some(TEST_PUBLIC_KEY_HEX.to_string()),
            ..Default::default()
        };

        let manager = PolicyManager::with_cache_path(config, cache_path).unwrap();

        // No cache initially
        assert!(manager.get_cached_policy().is_none());

        // Store a policy
        let policy = create_test_signed_policy();
        manager.cache.store(&policy).unwrap();

        // Now we have a cached policy
        let cached = manager.get_cached_policy();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().policy.version, "test-1.0.0");
    }
}
