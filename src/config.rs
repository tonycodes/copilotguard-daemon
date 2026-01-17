use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the CopilotGuard daemon
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// API endpoint for the CopilotGuard service
    pub api_url: String,

    /// Organization API key (optional, can use OAuth session)
    pub api_key: Option<String>,

    /// Local proxy port
    pub proxy_port: u16,

    /// Domains to intercept
    pub intercept_domains: Vec<String>,

    /// Whether to log all requests (verbose mode)
    pub verbose: bool,

    /// Path to CA certificate
    pub ca_cert_path: Option<PathBuf>,

    /// Path to CA private key
    pub ca_key_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_url: "https://api.guard.tony.codes".to_string(),
            api_key: None,
            proxy_port: 8443,
            intercept_domains: vec![
                "api.github.com".to_string(),
                "copilot-proxy.githubusercontent.com".to_string(),
                "api.githubcopilot.com".to_string(),
                // Future: Add other AI assistants
                // "api.openai.com".to_string(),
                // "api.anthropic.com".to_string(),
            ],
            verbose: false,
            ca_cert_path: None,
            ca_key_path: None,
        }
    }
}

/// Check if running as root
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Get the config directory path
/// Uses /etc/copilotguard when running as root (for system service)
/// Uses ~/.config/copilotguard for regular user
pub fn config_dir() -> Result<PathBuf> {
    let dir = if is_root() {
        // System-wide config for daemon running as root
        PathBuf::from("/etc/copilotguard")
    } else {
        // User config
        dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("copilotguard")
    };

    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}

/// Get the config file path
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// Load configuration from file, or create default
pub fn load() -> Result<Config> {
    let path = config_path()?;

    if path.exists() {
        let contents = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    } else {
        let config = Config::default();
        save(&config)?;
        Ok(config)
    }
}

/// Save configuration to file
pub fn save(config: &Config) -> Result<()> {
    let path = config_path()?;
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(path, contents)?;
    Ok(())
}
