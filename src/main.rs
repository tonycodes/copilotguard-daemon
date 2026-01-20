use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod api;
mod api_client;
mod ca;
mod config;
mod hosts;
mod proxy;
mod service;

#[derive(Parser)]
#[command(name = "copilotguard")]
#[command(about = "Lightweight daemon for intercepting AI coding assistant traffic")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the daemon as a system service
    Install {
        /// Skip hosts file modification (manual setup required)
        #[arg(long)]
        skip_hosts: bool,
    },

    /// Uninstall the daemon and restore hosts file
    Uninstall,

    /// Start the daemon (usually called by system service)
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the running daemon
    Stop,

    /// Show daemon status
    Status,

    /// Generate or regenerate CA certificate
    GenerateCa {
        /// Force regeneration even if CA exists
        #[arg(long)]
        force: bool,
    },

    /// Trust the CA certificate in system keychain
    TrustCa,

    /// Show configuration
    Config,

    /// Login to CopilotGuard (interactive API key entry)
    Login {
        /// API key (if not provided, will prompt interactively)
        #[arg(long, short)]
        key: Option<String>,
    },

    /// Logout from CopilotGuard (clear credentials)
    Logout,

    /// Set CopilotGuard API key directly
    SetKey {
        /// API key (format: cg_xxxxx)
        key: String,
    },

    /// Test API connection and key validity
    Health,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider for rustls
    // This must be done before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Install { skip_hosts } => {
            info!("Installing CopilotGuard daemon...");

            // 1. Generate CA certificate if not exists
            ca::ensure_ca_exists()?;

            // 2. Trust CA in system keychain
            ca::trust_ca()?;

            // 3. Modify hosts file (unless skipped)
            if !skip_hosts {
                hosts::install()?;
            }

            // 4. Install system service
            service::install()?;

            // 5. Start the service
            service::start()?;

            info!("CopilotGuard installed and running!");
            println!("\n✓ CopilotGuard is now protecting your AI coding sessions.");
            println!("  Traffic from GitHub Copilot will be analyzed automatically.\n");
        }

        Commands::Uninstall => {
            info!("Uninstalling CopilotGuard daemon...");

            // 1. Stop the service
            service::stop()?;

            // 2. Remove system service
            service::uninstall()?;

            // 3. Restore hosts file
            hosts::uninstall()?;

            // 4. Optionally remove CA (leave for now, user can delete manually)

            info!("CopilotGuard uninstalled.");
            println!("\n✓ CopilotGuard has been removed.");
            println!("  Note: CA certificate remains in keychain. Remove manually if desired.\n");
        }

        Commands::Start { foreground } => {
            if foreground {
                info!("Starting CopilotGuard in foreground mode...");
                proxy::run().await?;
            } else {
                info!("Starting CopilotGuard daemon...");
                service::start()?;
            }
        }

        Commands::Stop => {
            info!("Stopping CopilotGuard daemon...");
            service::stop()?;
            println!("✓ CopilotGuard stopped.");
        }

        Commands::Status => {
            let status = service::status()?;
            println!("{}", status);
        }

        Commands::GenerateCa { force } => {
            if force {
                ca::generate_ca()?;
            } else {
                ca::ensure_ca_exists()?;
            }
            println!("✓ CA certificate ready at: {}", ca::ca_cert_path()?.display());
        }

        Commands::TrustCa => {
            ca::trust_ca()?;
            println!("✓ CA certificate trusted in system keychain.");
        }

        Commands::Config => {
            let config = config::load()?;
            println!("{}", toml::to_string_pretty(&config)?);
        }

        Commands::Login { key } => {
            // If API key provided directly, use it
            if let Some(api_key) = key {
                if api_key.is_empty() {
                    anyhow::bail!("API key cannot be empty");
                }

                // Validate key format
                if !api_key.starts_with("cg_") {
                    println!("Warning: API key doesn't match expected format (cg_xxxxx)");
                }

                // Save to config
                let mut config = config::load()?;
                config.api_key = Some(api_key.clone());
                config::save(&config)?;

                // Test the key
                let client = api_client::ApiClient::new(&config)?;
                match client.health_check().await {
                    Ok(health) => {
                        println!("✓ API key saved and verified");
                        println!("  API Status: {}", health.status);
                        if let Some(msg) = health.message {
                            println!("  Message: {}", msg);
                        }
                    }
                    Err(e) => {
                        println!("✓ API key saved");
                        println!("⚠ Could not verify key: {}", e);
                        println!("  The key will be used when the API becomes available.");
                    }
                }
            } else {
                // Use device authorization flow
                let config = config::load()?;
                let client = api_client::ApiClient::new(&config)?;

                println!("Starting device authorization...\n");

                // Start device flow
                let device_auth = match client.start_device_auth().await {
                    Ok(auth) => auth,
                    Err(e) => {
                        anyhow::bail!("Failed to start device authorization: {}", e);
                    }
                };

                // Display the code
                println!("┌─────────────────────────────────────────┐");
                println!("│                                         │");
                println!("│   Enter this code in your browser:      │");
                println!("│                                         │");
                println!("│            {}             │", device_auth.user_code);
                println!("│                                         │");
                println!("└─────────────────────────────────────────┘");
                println!();
                println!("Open: {}", device_auth.verification_url_complete);
                println!();

                // Try to open browser
                #[cfg(target_os = "macos")]
                {
                    let _ = std::process::Command::new("open")
                        .arg(&device_auth.verification_url_complete)
                        .spawn();
                }
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("xdg-open")
                        .arg(&device_auth.verification_url_complete)
                        .spawn();
                }
                #[cfg(target_os = "windows")]
                {
                    let _ = std::process::Command::new("cmd")
                        .args(["/c", "start", &device_auth.verification_url_complete])
                        .spawn();
                }

                println!("Waiting for authorization...");
                println!("(Press Ctrl+C to cancel)\n");

                // Poll for completion
                let poll_interval = std::time::Duration::from_secs(device_auth.interval);
                let timeout = std::time::Duration::from_secs(device_auth.expires_in);
                let start = std::time::Instant::now();

                loop {
                    if start.elapsed() > timeout {
                        anyhow::bail!("Authorization timed out. Please try again.");
                    }

                    tokio::time::sleep(poll_interval).await;

                    match client.poll_device_auth(&device_auth.device_code).await {
                        Ok(poll_response) => {
                            match poll_response.status.as_str() {
                                "authorized" => {
                                    if let Some(api_key) = poll_response.api_key {
                                        // Save the API key
                                        let mut config = config::load()?;
                                        config.api_key = Some(api_key);
                                        config::save(&config)?;

                                        println!("✓ Authorization successful!");
                                        println!("✓ API key saved to configuration");
                                        println!();
                                        println!("Restart the daemon to apply changes:");
                                        println!("  sudo launchctl bootout system/com.copilotguard.daemon");
                                        println!("  sudo launchctl bootstrap system /Library/LaunchDaemons/com.copilotguard.daemon.plist");
                                        break;
                                    } else {
                                        anyhow::bail!("Authorization succeeded but no API key received");
                                    }
                                }
                                "expired" => {
                                    anyhow::bail!("Authorization expired. Please try again.");
                                }
                                "pending" => {
                                    // Still waiting, continue polling
                                    print!(".");
                                    std::io::Write::flush(&mut std::io::stdout())?;
                                }
                                status => {
                                    anyhow::bail!("Unexpected authorization status: {}", status);
                                }
                            }
                        }
                        Err(e) => {
                            anyhow::bail!("Error checking authorization status: {}", e);
                        }
                    }
                }
            }
        }

        Commands::Logout => {
            let mut config = config::load()?;
            if config.api_key.is_some() {
                config.api_key = None;
                config::save(&config)?;
                println!("✓ API key removed from configuration");
            } else {
                println!("No API key was configured");
            }
        }

        Commands::SetKey { key } => {
            if key.is_empty() {
                anyhow::bail!("API key cannot be empty");
            }

            // Validate key format
            if !key.starts_with("cg_") {
                println!("Warning: API key doesn't match expected format (cg_xxxxx)");
            }

            // Save to config
            let mut config = config::load()?;
            config.api_key = Some(key);
            config::save(&config)?;

            println!("✓ API key saved to configuration");
        }

        Commands::Health => {
            let config = config::load()?;

            println!("CopilotGuard Health Check");
            println!("========================");
            println!();
            println!("API URL: {}", config.api_url);
            println!(
                "API Key: {}",
                if config.api_key.is_some() {
                    "Configured"
                } else {
                    "Not configured"
                }
            );
            println!("Fail Mode: {}", config.api_fail_mode);
            println!("Guardrail Timeout: {}ms", config.guardrail_timeout_ms);
            println!();

            if config.api_key.is_none() {
                println!("⚠ No API key configured - running in passthrough mode");
                println!("  Use 'copilotguard-daemon login' to configure an API key");
                return Ok(());
            }

            // Test API connection
            print!("Testing API connection... ");
            std::io::Write::flush(&mut std::io::stdout())?;

            let client = api_client::ApiClient::new(&config)?;
            match client.health_check().await {
                Ok(health) => {
                    println!("✓");
                    println!("  Status: {}", health.status);
                    if let Some(msg) = health.message {
                        println!("  Message: {}", msg);
                    }
                }
                Err(e) => {
                    println!("✗");
                    println!("  Error: {}", e);
                }
            }

            // Test API key validity
            print!("Validating API key... ");
            std::io::Write::flush(&mut std::io::stdout())?;

            match client.validate_api_key().await {
                Ok(true) => println!("✓ Valid"),
                Ok(false) => println!("✗ Invalid or not configured"),
                Err(e) => println!("✗ Error: {}", e),
            }
        }
    }

    Ok(())
}
