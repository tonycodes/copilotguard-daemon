//! Policy data structures for traffic classification
//!
//! This module defines the policy types used to determine which traffic
//! should be intercepted (for guardrail enforcement), passed through,
//! or logged for admin review.

// Allow dead code during incremental implementation - this module is being
// built up over multiple phases and will be integrated into the proxy later.
#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during policy verification
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Failed to decode base64 signature: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Failed to serialize policy: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

/// Production public key for CopilotGuard policy signing (Ed25519)
/// This key is embedded at compile time and cannot be modified by users.
///
/// Format: 32 bytes of the Ed25519 public key, hex-encoded
const PRODUCTION_PUBLIC_KEY_HEX: &str =
    "9625f800e9f21640d2e80ad01c7579fcb8a847043501828e136a05c98e4210d8";

/// A signed policy payload from the CopilotGuard API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// The policy payload
    #[serde(flatten)]
    pub policy: Policy,

    /// Ed25519 signature of the policy (base64-encoded)
    pub signature: String,
}

/// The policy configuration that controls traffic routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy version identifier (e.g., "2024.01.21.1")
    pub version: String,

    /// When this policy expires (ISO 8601 timestamp)
    pub expires_at: String,

    /// When this policy was fetched (set by daemon, not server)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,

    /// Global AI provider domains maintained by CopilotGuard
    pub global_intercept: DomainList,

    /// Organization-specific custom domains
    pub org_intercept: DomainList,

    /// Domains that should never be intercepted (safety valve)
    pub passthrough: DomainList,

    /// Heuristic detection settings for unknown AI traffic
    pub heuristics: HeuristicConfig,
}

/// A list of domain patterns with a description
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainList {
    /// Human-readable description of this list
    #[serde(default)]
    pub description: String,

    /// Domain patterns in this list
    pub domains: Vec<DomainPattern>,
}

/// A domain pattern for matching hostnames
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPattern {
    /// The pattern string (e.g., "api.anthropic.com" or "*.anthropic.com")
    pub pattern: String,

    /// The type of pattern matching to use
    #[serde(rename = "type")]
    pub pattern_type: PatternType,
}

/// The type of domain pattern matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    /// Exact match (e.g., "api.anthropic.com" matches only "api.anthropic.com")
    Exact,
    /// Wildcard match (e.g., "*.anthropic.com" matches "api.anthropic.com", "sub.api.anthropic.com")
    Wildcard,
}

/// Configuration for heuristic AI traffic detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicConfig {
    /// Whether heuristic detection is enabled
    pub enabled: bool,

    /// Action to take when heuristics match: "log_only", "block", "intercept"
    #[serde(default = "default_heuristic_action")]
    pub action: String,

    /// Heuristic rules
    #[serde(default)]
    pub rules: Vec<HeuristicRule>,
}

fn default_heuristic_action() -> String {
    "log_only".to_string()
}

/// A heuristic rule for detecting AI traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicRule {
    /// Rule name for identification
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: String,

    /// URL path patterns to match
    #[serde(default)]
    pub path_patterns: Vec<String>,

    /// Request body patterns to match (regex)
    #[serde(default)]
    pub body_patterns: Vec<String>,
}

/// The decision for how to handle traffic
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficDecision {
    /// Pass through without interception (no MITM)
    Passthrough,

    /// Intercept for full guardrail enforcement (MITM + API call)
    Intercept,

    /// Forward traffic but log for admin review (heuristic match)
    LogOnly {
        /// Reason why this traffic was flagged
        reason: String,
    },
}

impl SignedPolicy {
    /// Verify the signature of this policy using the production public key.
    ///
    /// The signature is verified against the JSON serialization of the policy
    /// (excluding the signature field itself).
    pub fn verify(&self) -> Result<(), PolicyError> {
        self.verify_with_key(PRODUCTION_PUBLIC_KEY_HEX)
    }

    /// Verify the signature of this policy using a specific public key (hex-encoded).
    ///
    /// This is useful for testing with test keys.
    pub fn verify_with_key(&self, public_key_hex: &str) -> Result<(), PolicyError> {
        // Decode the public key from hex
        let public_key_bytes = hex_decode(public_key_hex).map_err(|e| {
            PolicyError::InvalidPublicKey(format!("Failed to decode hex public key: {}", e))
        })?;

        if public_key_bytes.len() != 32 {
            return Err(PolicyError::InvalidPublicKey(format!(
                "Public key must be 32 bytes, got {}",
                public_key_bytes.len()
            )));
        }

        let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
            PolicyError::InvalidPublicKey("Failed to convert public key to array".to_string())
        })?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| PolicyError::InvalidPublicKey(format!("Invalid Ed25519 key: {}", e)))?;

        // Decode the signature from base64
        let signature_bytes = BASE64.decode(&self.signature)?;

        if signature_bytes.len() != 64 {
            return Err(PolicyError::InvalidSignature(format!(
                "Signature must be 64 bytes, got {}",
                signature_bytes.len()
            )));
        }

        let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            PolicyError::InvalidSignature("Failed to convert signature to array".to_string())
        })?;

        let signature = Signature::from_bytes(&signature_array);

        // Serialize the policy (without the signature) for verification
        let policy_bytes = serde_json::to_vec(&self.policy)?;

        // Verify the signature
        verifying_key
            .verify(&policy_bytes, &signature)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Get the production public key as bytes.
    ///
    /// This is useful for displaying the key in CLI commands.
    pub fn production_public_key() -> &'static str {
        PRODUCTION_PUBLIC_KEY_HEX
    }
}

/// Simple hex decoding function (no external dependency)
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
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

impl DomainPattern {
    /// Create a new exact-match pattern
    pub fn exact(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            pattern_type: PatternType::Exact,
        }
    }

    /// Create a new wildcard pattern
    pub fn wildcard(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            pattern_type: PatternType::Wildcard,
        }
    }

    /// Check if this pattern matches the given hostname
    ///
    /// # Exact matching
    /// - Pattern "api.anthropic.com" matches only "api.anthropic.com"
    ///
    /// # Wildcard matching
    /// - Pattern "*.anthropic.com" matches "api.anthropic.com"
    /// - Pattern "*.anthropic.com" matches "sub.api.anthropic.com"
    /// - Pattern "*.anthropic.com" does NOT match "anthropic.com" (no subdomain)
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        let pattern = self.pattern.to_lowercase();

        match self.pattern_type {
            PatternType::Exact => host == pattern,
            PatternType::Wildcard => {
                // Wildcard pattern must start with "*."
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    // Host must have at least one subdomain level before the suffix
                    // i.e., "api.anthropic.com" matches "*.anthropic.com"
                    // but "anthropic.com" does not match "*.anthropic.com"
                    if let Some(host_prefix) = host.strip_suffix(suffix) {
                        // Must have at least one character (the subdomain) plus a dot
                        // e.g., "api." or "sub.api."
                        host_prefix.len() > 1 && host_prefix.ends_with('.')
                    } else {
                        false
                    }
                } else {
                    // Invalid wildcard pattern, treat as exact match
                    host == pattern
                }
            }
        }
    }
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: default_heuristic_action(),
            rules: Vec::new(),
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: "0.0.0".to_string(),
            expires_at: String::new(),
            fetched_at: None,
            global_intercept: DomainList::default(),
            org_intercept: DomainList::default(),
            passthrough: DomainList {
                description: "Local development domains".to_string(),
                domains: vec![
                    DomainPattern::exact("localhost"),
                    DomainPattern::exact("127.0.0.1"),
                    DomainPattern::wildcard("*.local"),
                    DomainPattern::wildcard("*.test"),
                    DomainPattern::wildcard("*.localhost"),
                ],
            },
            heuristics: HeuristicConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = DomainPattern::exact("api.anthropic.com");

        assert!(pattern.matches("api.anthropic.com"));
        assert!(pattern.matches("API.ANTHROPIC.COM")); // Case-insensitive
        assert!(!pattern.matches("api.anthropic.com.evil.com"));
        assert!(!pattern.matches("sub.api.anthropic.com"));
        assert!(!pattern.matches("anthropic.com"));
    }

    #[test]
    fn test_wildcard_match() {
        let pattern = DomainPattern::wildcard("*.anthropic.com");

        // Should match subdomains
        assert!(pattern.matches("api.anthropic.com"));
        assert!(pattern.matches("sub.api.anthropic.com"));
        assert!(pattern.matches("a.b.c.anthropic.com"));

        // Should NOT match base domain (no subdomain)
        assert!(!pattern.matches("anthropic.com"));

        // Should NOT match unrelated domains
        assert!(!pattern.matches("notanthropic.com"));
        assert!(!pattern.matches("api.notanthropic.com"));
        assert!(!pattern.matches("anthropic.com.evil.com"));

        // Case insensitive
        assert!(pattern.matches("API.ANTHROPIC.COM"));
    }

    #[test]
    fn test_wildcard_requires_subdomain() {
        let pattern = DomainPattern::wildcard("*.localhost");

        assert!(pattern.matches("app.localhost"));
        assert!(pattern.matches("api.app.localhost"));
        assert!(!pattern.matches("localhost")); // No subdomain
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();

        assert_eq!(policy.version, parsed.version);
        assert_eq!(
            policy.passthrough.domains.len(),
            parsed.passthrough.domains.len()
        );
    }

    #[test]
    fn test_signed_policy_deserialization() {
        let json = r#"{
            "version": "2024.01.21.1",
            "expires_at": "2024-01-21T12:00:00Z",
            "signature": "test_signature_base64",
            "global_intercept": {
                "description": "AI providers",
                "domains": [
                    {"pattern": "api.anthropic.com", "type": "exact"},
                    {"pattern": "*.openai.azure.com", "type": "wildcard"}
                ]
            },
            "org_intercept": {
                "description": "Custom domains",
                "domains": []
            },
            "passthrough": {
                "description": "Local",
                "domains": [
                    {"pattern": "localhost", "type": "exact"}
                ]
            },
            "heuristics": {
                "enabled": true,
                "action": "log_only",
                "rules": []
            }
        }"#;

        let signed: SignedPolicy = serde_json::from_str(json).unwrap();

        assert_eq!(signed.policy.version, "2024.01.21.1");
        assert_eq!(signed.signature, "test_signature_base64");
        assert_eq!(signed.policy.global_intercept.domains.len(), 2);
        assert!(signed.policy.global_intercept.domains[0].matches("api.anthropic.com"));
        assert!(signed.policy.global_intercept.domains[1].matches("test.openai.azure.com"));
        assert!(!signed.policy.global_intercept.domains[1].matches("openai.azure.com"));
    }

    #[test]
    fn test_traffic_decision_variants() {
        let passthrough = TrafficDecision::Passthrough;
        let intercept = TrafficDecision::Intercept;
        let log_only = TrafficDecision::LogOnly {
            reason: "Suspicious path".to_string(),
        };

        assert_eq!(passthrough, TrafficDecision::Passthrough);
        assert_eq!(intercept, TrafficDecision::Intercept);
        assert_ne!(passthrough, intercept);

        if let TrafficDecision::LogOnly { reason } = log_only {
            assert_eq!(reason, "Suspicious path");
        } else {
            panic!("Expected LogOnly variant");
        }
    }

    #[test]
    fn test_domain_pattern_constructors() {
        let exact = DomainPattern::exact("example.com");
        assert_eq!(exact.pattern, "example.com");
        assert_eq!(exact.pattern_type, PatternType::Exact);

        let wildcard = DomainPattern::wildcard("*.example.com");
        assert_eq!(wildcard.pattern, "*.example.com");
        assert_eq!(wildcard.pattern_type, PatternType::Wildcard);
    }

    // ==========================================================================
    // Signature Verification Tests
    // ==========================================================================

    // Test keypair generated for unit testing only
    // DO NOT use these keys in production!
    //
    // Generated with:
    // ```
    // use ed25519_dalek::{SigningKey, VerifyingKey};
    // use rand::rngs::OsRng;
    // let signing_key = SigningKey::generate(&mut OsRng);
    // let verifying_key = signing_key.verifying_key();
    // ```
    const TEST_PRIVATE_KEY_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_PUBLIC_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// Helper function to create a signed policy for testing
    fn create_test_signed_policy(policy: &Policy, private_key_hex: &str) -> SignedPolicy {
        use ed25519_dalek::{Signer, SigningKey};

        // Decode private key
        let private_key_bytes = hex_decode(private_key_hex).unwrap();
        let private_key_array: [u8; 32] = private_key_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&private_key_array);

        // Serialize policy and sign
        let policy_bytes = serde_json::to_vec(policy).unwrap();
        let signature = signing_key.sign(&policy_bytes);

        // Base64 encode the signature
        let signature_base64 = BASE64.encode(signature.to_bytes());

        SignedPolicy {
            policy: policy.clone(),
            signature: signature_base64,
        }
    }

    #[test]
    fn test_signature_verification_valid() {
        let policy = Policy::default();
        let signed = create_test_signed_policy(&policy, TEST_PRIVATE_KEY_HEX);

        // Should verify successfully with the matching public key
        let result = signed.verify_with_key(TEST_PUBLIC_KEY_HEX);
        assert!(result.is_ok(), "Signature verification should pass");
    }

    #[test]
    fn test_signature_verification_tampered_policy() {
        let policy = Policy::default();
        let mut signed = create_test_signed_policy(&policy, TEST_PRIVATE_KEY_HEX);

        // Tamper with the policy after signing
        signed.policy.version = "tampered".to_string();

        // Should fail verification
        let result = signed.verify_with_key(TEST_PUBLIC_KEY_HEX);
        assert!(result.is_err(), "Tampered policy should fail verification");
        assert!(matches!(
            result,
            Err(PolicyError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_signature_verification_wrong_key() {
        let policy = Policy::default();
        let signed = create_test_signed_policy(&policy, TEST_PRIVATE_KEY_HEX);

        // Try to verify with a different public key (all zeros)
        let wrong_key = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = signed.verify_with_key(wrong_key);
        assert!(result.is_err(), "Wrong key should fail verification");
    }

    #[test]
    fn test_signature_verification_invalid_signature_base64() {
        let signed = SignedPolicy {
            policy: Policy::default(),
            signature: "not-valid-base64!!!".to_string(),
        };

        let result = signed.verify_with_key(TEST_PUBLIC_KEY_HEX);
        assert!(result.is_err(), "Invalid base64 should fail");
        assert!(matches!(result, Err(PolicyError::Base64DecodeError(_))));
    }

    #[test]
    fn test_signature_verification_invalid_signature_length() {
        let signed = SignedPolicy {
            policy: Policy::default(),
            signature: BASE64.encode(b"too short"), // Not 64 bytes
        };

        let result = signed.verify_with_key(TEST_PUBLIC_KEY_HEX);
        assert!(result.is_err(), "Wrong signature length should fail");
        assert!(matches!(result, Err(PolicyError::InvalidSignature(_))));
    }

    #[test]
    fn test_signature_verification_invalid_public_key_length() {
        let policy = Policy::default();
        let signed = create_test_signed_policy(&policy, TEST_PRIVATE_KEY_HEX);

        // Try with a public key that's too short
        let result = signed.verify_with_key("deadbeef");
        assert!(result.is_err(), "Short public key should fail");
        assert!(matches!(result, Err(PolicyError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_signature_verification_invalid_public_key_hex() {
        let policy = Policy::default();
        let signed = create_test_signed_policy(&policy, TEST_PRIVATE_KEY_HEX);

        // Try with invalid hex
        let result = signed.verify_with_key("not-hex-at-all!");
        assert!(result.is_err(), "Invalid hex should fail");
        assert!(matches!(result, Err(PolicyError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_hex_decode_valid() {
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_decode("DEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("odd").is_err()); // Odd length
        assert!(hex_decode("gg").is_err()); // Invalid chars
        assert!(hex_decode("0x00").is_err()); // Prefix not supported
    }

    #[test]
    fn test_production_public_key_accessor() {
        let key = SignedPolicy::production_public_key();
        assert_eq!(key.len(), 64); // 32 bytes hex-encoded = 64 chars
    }
}
