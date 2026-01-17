use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;

/// Get the path to the copilotguard binary
fn binary_path() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to get current executable path")
}

/// Install as a system service
pub fn install() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        install_launchd()?;
    }

    #[cfg(target_os = "linux")]
    {
        install_systemd()?;
    }

    #[cfg(target_os = "windows")]
    {
        install_windows_service()?;
    }

    Ok(())
}

/// Uninstall system service
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        uninstall_launchd()?;
    }

    #[cfg(target_os = "linux")]
    {
        uninstall_systemd()?;
    }

    #[cfg(target_os = "windows")]
    {
        uninstall_windows_service()?;
    }

    Ok(())
}

/// Start the daemon via system service
pub fn start() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("launchctl")
            .args(["load", "-w", "/Library/LaunchDaemons/com.copilotguard.daemon.plist"])
            .output()
            .context("Failed to start launchd service")?;

        if !output.status.success() {
            // Try bootstrap for newer macOS
            let _ = Command::new("sudo")
                .args(["launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.copilotguard.daemon.plist"])
                .output();
        }
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("sudo")
            .args(["systemctl", "start", "copilotguard"])
            .output()
            .context("Failed to start systemd service")?;
    }

    Ok(())
}

/// Stop the daemon
pub fn stop() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("launchctl")
            .args(["unload", "/Library/LaunchDaemons/com.copilotguard.daemon.plist"])
            .output();

        // Also try bootout for newer macOS
        let _ = Command::new("sudo")
            .args(["launchctl", "bootout", "system/com.copilotguard.daemon"])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("sudo")
            .args(["systemctl", "stop", "copilotguard"])
            .output()
            .context("Failed to stop systemd service")?;
    }

    Ok(())
}

/// Get daemon status
pub fn status() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("launchctl")
            .args(["list", "com.copilotguard.daemon"])
            .output()
            .context("Failed to get service status")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("com.copilotguard.daemon") {
                return Ok("✓ CopilotGuard is running".to_string());
            }
        }
        return Ok("✗ CopilotGuard is not running".to_string());
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("systemctl")
            .args(["is-active", "copilotguard"])
            .output()
            .context("Failed to get service status")?;

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if status == "active" {
            return Ok("✓ CopilotGuard is running".to_string());
        }
        return Ok(format!("✗ CopilotGuard is {}", status));
    }

    #[cfg(target_os = "windows")]
    {
        return Ok("Status check not implemented for Windows".to_string());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok("Unsupported platform".to_string())
    }
}

#[cfg(target_os = "macos")]
fn install_launchd() -> Result<()> {
    info!("Installing launchd service...");

    let binary = binary_path()?;
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.copilotguard.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/copilotguard.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/copilotguard.error.log</string>
    <key>WorkingDirectory</key>
    <string>/tmp</string>
</dict>
</plist>
"#,
        binary.display()
    );

    // Write plist to temp file first
    let temp_path = "/tmp/com.copilotguard.daemon.plist";
    fs::write(temp_path, &plist_content)?;

    // Copy with sudo
    let output = Command::new("sudo")
        .args(["cp", temp_path, "/Library/LaunchDaemons/com.copilotguard.daemon.plist"])
        .output()
        .context("Failed to copy plist file")?;

    if !output.status.success() {
        anyhow::bail!("Failed to install launchd plist");
    }

    // Set ownership
    Command::new("sudo")
        .args(["chown", "root:wheel", "/Library/LaunchDaemons/com.copilotguard.daemon.plist"])
        .output()?;

    fs::remove_file(temp_path)?;

    info!("launchd service installed");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> Result<()> {
    info!("Removing launchd service...");

    // Stop first
    let _ = stop();

    // Remove plist
    let _ = Command::new("sudo")
        .args(["rm", "-f", "/Library/LaunchDaemons/com.copilotguard.daemon.plist"])
        .output();

    info!("launchd service removed");
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd() -> Result<()> {
    info!("Installing systemd service...");

    let binary = binary_path()?;
    let service_content = format!(
        r#"[Unit]
Description=CopilotGuard AI Traffic Interceptor
After=network.target

[Service]
Type=simple
ExecStart={} start --foreground
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        binary.display()
    );

    // Write to temp file
    let temp_path = "/tmp/copilotguard.service";
    fs::write(temp_path, &service_content)?;

    // Copy with sudo
    Command::new("sudo")
        .args(["cp", temp_path, "/etc/systemd/system/copilotguard.service"])
        .output()
        .context("Failed to copy service file")?;

    // Reload systemd
    Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .output()?;

    // Enable service
    Command::new("sudo")
        .args(["systemctl", "enable", "copilotguard"])
        .output()?;

    fs::remove_file(temp_path)?;

    info!("systemd service installed");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> Result<()> {
    info!("Removing systemd service...");

    // Stop and disable
    let _ = Command::new("sudo")
        .args(["systemctl", "stop", "copilotguard"])
        .output();

    let _ = Command::new("sudo")
        .args(["systemctl", "disable", "copilotguard"])
        .output();

    // Remove service file
    let _ = Command::new("sudo")
        .args(["rm", "-f", "/etc/systemd/system/copilotguard.service"])
        .output();

    // Reload systemd
    let _ = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .output();

    info!("systemd service removed");
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows_service() -> Result<()> {
    info!("Windows service installation not yet implemented");
    // TODO: Implement Windows service using windows-service crate
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows_service() -> Result<()> {
    info!("Windows service removal not yet implemented");
    Ok(())
}
