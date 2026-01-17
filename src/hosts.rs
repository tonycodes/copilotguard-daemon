use anyhow::{Context, Result};
use std::fs;
use tracing::info;

const HOSTS_PATH: &str = if cfg!(windows) {
    r"C:\Windows\System32\drivers\etc\hosts"
} else {
    "/etc/hosts"
};

const HOSTS_MARKER_START: &str = "# BEGIN CopilotGuard";
const HOSTS_MARKER_END: &str = "# END CopilotGuard";

/// Domains to redirect to localhost for interception
const INTERCEPT_DOMAINS: &[&str] = &[
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    // Note: We don't intercept api.github.com as it would break git operations
    // Copilot uses the above domains for completions
];

/// Install hosts file entries for traffic interception
pub fn install() -> Result<()> {
    info!("Modifying hosts file...");

    let hosts_content = fs::read_to_string(HOSTS_PATH)
        .context("Failed to read hosts file. Are you running with sudo?")?;

    // Check if already installed
    if hosts_content.contains(HOSTS_MARKER_START) {
        info!("CopilotGuard entries already exist in hosts file");
        return Ok(());
    }

    // Build new entries
    let mut entries = String::new();
    entries.push_str(&format!("\n{}\n", HOSTS_MARKER_START));
    entries.push_str("# These entries redirect AI assistant traffic through CopilotGuard\n");
    for domain in INTERCEPT_DOMAINS {
        entries.push_str(&format!("127.0.0.1 {}\n", domain));
    }
    entries.push_str(&format!("{}\n", HOSTS_MARKER_END));

    // Append to hosts file
    let new_content = format!("{}{}", hosts_content, entries);

    #[cfg(unix)]
    {
        use std::process::Command;
        // Write to temp file first, then copy with sudo
        fs::write("/tmp/copilotguard_hosts", &new_content)?;
        let output = Command::new("sudo")
            .args(["cp", "/tmp/copilotguard_hosts", HOSTS_PATH])
            .output()
            .context("Failed to update hosts file")?;

        if !output.status.success() {
            anyhow::bail!("Failed to write hosts file");
        }
        fs::remove_file("/tmp/copilotguard_hosts")?;
    }

    #[cfg(windows)]
    {
        fs::write(HOSTS_PATH, &new_content)
            .context("Failed to write hosts file. Run as Administrator.")?;
    }

    info!("Hosts file updated successfully");
    Ok(())
}

/// Remove hosts file entries
pub fn uninstall() -> Result<()> {
    info!("Restoring hosts file...");

    let hosts_content = fs::read_to_string(HOSTS_PATH)
        .context("Failed to read hosts file. Are you running with sudo?")?;

    // Check if our entries exist
    if !hosts_content.contains(HOSTS_MARKER_START) {
        info!("CopilotGuard entries not found in hosts file");
        return Ok(());
    }

    // Remove our section
    let new_content = remove_section(&hosts_content, HOSTS_MARKER_START, HOSTS_MARKER_END);

    #[cfg(unix)]
    {
        use std::process::Command;
        fs::write("/tmp/copilotguard_hosts", &new_content)?;
        let output = Command::new("sudo")
            .args(["cp", "/tmp/copilotguard_hosts", HOSTS_PATH])
            .output()
            .context("Failed to restore hosts file")?;

        if !output.status.success() {
            anyhow::bail!("Failed to restore hosts file");
        }
        fs::remove_file("/tmp/copilotguard_hosts")?;
    }

    #[cfg(windows)]
    {
        fs::write(HOSTS_PATH, &new_content)
            .context("Failed to write hosts file. Run as Administrator.")?;
    }

    info!("Hosts file restored successfully");
    Ok(())
}

/// Remove a section between markers from a string
fn remove_section(content: &str, start_marker: &str, end_marker: &str) -> String {
    let mut result = String::new();
    let mut in_section = false;

    for line in content.lines() {
        if line.contains(start_marker) {
            in_section = true;
            continue;
        }
        if line.contains(end_marker) {
            in_section = false;
            continue;
        }
        if !in_section {
            result.push_str(line);
            result.push('\n');
        }
    }

    // Remove trailing newlines that might have accumulated
    result.trim_end().to_string() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_section() {
        let content = r#"# Some content
127.0.0.1 localhost

# BEGIN CopilotGuard
127.0.0.1 copilot-proxy.githubusercontent.com
# END CopilotGuard

# More content
"#;

        let result = remove_section(content, HOSTS_MARKER_START, HOSTS_MARKER_END);
        assert!(!result.contains("CopilotGuard"));
        assert!(result.contains("localhost"));
        assert!(result.contains("More content"));
    }
}
