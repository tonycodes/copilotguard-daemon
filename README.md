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
# Download the latest release
curl -sSL https://get.copilotguard.com | sh

# Or with Homebrew (macOS)
brew install copilotguard/tap/copilotguard
```

### Manual Installation

1. Download the binary for your platform from [Releases](https://github.com/tonysnark/copilotguard-daemon/releases)

2. Run the installer (requires sudo):
   ```bash
   sudo copilotguard install
   ```

This will:
- Generate a local CA certificate
- Add the CA to your system trust store
- Modify `/etc/hosts` to redirect AI traffic
- Install and start the system service

## Usage

```bash
# Check status
copilotguard status

# View configuration
copilotguard config

# Stop the daemon
sudo copilotguard stop

# Start the daemon
sudo copilotguard start

# Uninstall completely
sudo copilotguard uninstall
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

Configuration is stored at `~/.config/copilotguard/config.toml`:

```toml
# CopilotGuard API endpoint
api_url = "https://api.guard.tony.codes"

# Your organization's API key (optional if using OAuth)
api_key = "cg_your_key_here"

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
git clone https://github.com/tonysnark/copilotguard-daemon.git
cd copilotguard-daemon

# Build release binary
cargo build --release

# Binary will be at target/release/copilotguard
```

## GitHub Copilot CLI Support

The GitHub Copilot CLI (`@github/copilot`) bundles its own Node.js runtime and requires special handling for CA certificate trust.

### Running Copilot CLI with CopilotGuard

```bash
# Required: Set NODE_EXTRA_CA_CERTS to trust the CopilotGuard CA
NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot
```

### Recommended: Create an alias

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
alias copilot='NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot'
```

This is necessary because the Copilot CLI bundles Node.js v24 which doesn't automatically trust macOS Keychain certificates for SSL connections.

## Troubleshooting

### Copilot not working after installation

1. Check the daemon is running: `copilotguard status`
2. Verify hosts file: `cat /etc/hosts | grep copilot`
3. Check CA is trusted: Look for "CopilotGuard Local CA" in Keychain (macOS) or certificates (Linux)
4. View logs: `tail -f /var/log/copilotguard.log` (macOS) or `journalctl -u copilotguard -f` (Linux)

### GitHub Copilot CLI showing "Failed to list models"

This usually means the CA certificate isn't being trusted. Make sure:
1. The CA has SSL trust policy: `security dump-trust-settings -d | grep -A15 "CopilotGuard"`
2. You're running with NODE_EXTRA_CA_CERTS: `NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot`

### Resetting CA Certificate

If you need to regenerate the CA certificate:

```bash
copilotguard generate-ca --force
sudo copilotguard trust-ca
```

### Complete Reset

```bash
sudo copilotguard uninstall
rm -rf ~/.config/copilotguard
# Then reinstall
sudo copilotguard install
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

- [CopilotGuard](https://github.com/tonysnark/copilotguard) - Main CopilotGuard platform
- [CopilotGuard CLI](https://github.com/tonysnark/copilotguard/tree/main/packages/cli) - Legacy Node.js CLI
