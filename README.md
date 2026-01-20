# CopilotGuard Daemon

A lightweight, tool-agnostic daemon that intercepts and analyzes AI coding assistant traffic for compliance and security.

## Features

- **Tool-agnostic**: Works with any IDE or editor (VS Code, Cursor, PyCharm, Cline, etc.)
- **Lightweight**: Written in Rust for minimal resource usage (~2-5MB memory)
- **Transparent**: Uses hosts file modification for network-level interception
- **Secure**: Generates unique CA certificate per installation
- **Auto-start**: Runs as a system service (launchd/systemd)

## Installation

### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/tonycodes/copilotguard-daemon/main/install.sh | sh
```

This single command will:
1. Download the binary for your platform
2. Install the daemon (CA certificate, hosts file, system service)
3. **Open your browser to connect your CopilotGuard account**
4. Configure everything automatically

### Manual Installation

1. Download the binary for your platform from [Releases](https://github.com/tonycodes/copilotguard-daemon/releases)

2. Run the installer (requires sudo):
   ```bash
   sudo copilotguard-daemon install
   ```

3. Connect to your CopilotGuard account:
   ```bash
   copilotguard-daemon login
   ```
   This opens your browser where you'll enter a verification code to link your account.

4. Restart the daemon to apply your API key:
   ```bash
   sudo launchctl bootout system/com.copilotguard.daemon
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.copilotguard.daemon.plist
   ```

## Usage

```bash
# Check daemon status
copilotguard-daemon status

# Test API connection
copilotguard-daemon health

# Login or switch accounts
copilotguard-daemon login

# Logout (clear credentials)
copilotguard-daemon logout

# View configuration
copilotguard-daemon config

# Stop the daemon
sudo copilotguard-daemon stop

# Start the daemon
sudo copilotguard-daemon start

# Uninstall completely
sudo copilotguard-daemon uninstall
```

## How It Works

1. **Hosts File Modification**: Redirects AI assistant domains to localhost:
   - `copilot-proxy.githubusercontent.com`
   - `api.githubcopilot.com`
   - `api.individual.githubcopilot.com`
   - `api.business.githubcopilot.com`
   - `api.enterprise.githubcopilot.com`

2. **TLS Interception**: Generates certificates signed by a local CA to decrypt HTTPS traffic

3. **Traffic Analysis**: Inspects requests and responses for:
   - Sensitive data leakage
   - Policy violations
   - Usage metrics

4. **Forwarding**: Passes traffic to the real AI service after analysis

## Security

- **Local CA**: A unique CA certificate is generated for each installation
- **File Permissions**: Private keys are stored with 600 permissions
- **No Cloud**: All analysis happens locally; the daemon only sends metrics to your CopilotGuard dashboard
- **Open Source**: Full code transparency

## Configuration

Configuration is stored at:
- **macOS**: `~/Library/Application Support/copilotguard/config.toml`
- **Linux**: `~/.config/copilotguard/config.toml`
- **System (daemon)**: `/etc/copilotguard/config.toml`

```toml
# CopilotGuard API endpoint
api_url = "https://api.guard.tony.codes"

# API key (automatically set by 'copilotguard-daemon login')
api_key = "cg_xxxxx"

# Local proxy port (must be 443 for hosts file interception)
proxy_port = 443

# Domains to intercept
intercept_domains = [
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "api.business.githubcopilot.com",
    "api.enterprise.githubcopilot.com",
]

# Enable verbose logging
verbose = false
```

## Supported Platforms

| Platform | Status |
|----------|--------|
| macOS (Intel) | ✅ Supported |
| macOS (Apple Silicon) | ✅ Supported |
| Linux (x86_64) | ✅ Supported |
| Linux (ARM64) | ✅ Supported |
| Windows | 🚧 Coming Soon |

## Building from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone the repository
git clone https://github.com/tonycodes/copilotguard-daemon.git
cd copilotguard-daemon

# Build release binary
cargo build --release

# Binary will be at target/release/copilotguard-daemon
```

## GitHub Copilot CLI Support

The GitHub Copilot CLI (`@github/copilot`) bundles its own Node.js runtime and requires special handling for CA certificate trust.

### Option 1: Use the wrapper script (Recommended)

The installation includes a wrapper script that automatically handles CA trust:

```bash
# Install the wrapper (done automatically by copilotguard install)
sudo cp /path/to/copilotguard-daemon/scripts/copilot-wrapper.sh /usr/local/bin/copilot-guarded
sudo chmod +x /usr/local/bin/copilot-guarded

# Use the wrapper
copilot-guarded explain "what does git rebase do?"
```

### Option 2: Create an alias

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
alias copilot='NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot'
```

### Option 3: Manual invocation

```bash
NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot
```

This is necessary because the Copilot CLI bundles Node.js v24 which doesn't automatically trust macOS Keychain certificates for SSL connections.

## Troubleshooting

### Copilot not working after installation

1. Check the daemon is running: `copilotguard-daemon status`
2. Verify hosts file: `cat /etc/hosts | grep copilot`
3. Check CA is trusted: Look for "CopilotGuard Local CA" in Keychain (macOS) or certificates (Linux)
4. View logs: `tail -f /var/log/copilotguard.log` (macOS) or `journalctl -u copilotguard-daemon -f` (Linux)

### GitHub Copilot CLI showing "Failed to list models"

This usually means the CA certificate isn't being trusted. Make sure:
1. The CA has SSL trust policy: `security dump-trust-settings -d | grep -A15 "CopilotGuard"`
2. You're running with NODE_EXTRA_CA_CERTS: `NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot`

### Resetting CA Certificate

If you need to regenerate the CA certificate:

```bash
copilotguard-daemon generate-ca --force
sudo copilotguard-daemon trust-ca
```

### Complete Reset

```bash
sudo copilotguard-daemon uninstall
rm -rf ~/.config/copilotguard
rm -rf ~/Library/Application\ Support/copilotguard  # macOS only
# Then reinstall
curl -sSL https://raw.githubusercontent.com/tonycodes/copilotguard-daemon/main/install.sh | sh
```

## Development Documentation

See [LEARNINGS.md](LEARNINGS.md) for detailed technical documentation including:
- TLS interception architecture
- Certificate chain requirements
- macOS Keychain trust policies
- Debugging TLS issues

## License

MIT License - see [LICENSE](LICENSE)

## Related

- [CopilotGuard](https://github.com/tonycodes/copilotguard) - Main CopilotGuard platform
- [CopilotGuard CLI](https://github.com/tonycodes/copilotguard/tree/main/packages/cli) - Node.js CLI tool
