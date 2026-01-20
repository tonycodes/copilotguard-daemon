# CopilotGuard Daemon - Claude Code Instructions

## Known Issues & Solutions

### Status Check Requires SNI

The daemon's TLS proxy only accepts connections with a valid SNI (Server Name Indication) for Copilot domains. The status check must use `--resolve` to provide the correct SNI:

```bash
# CORRECT - provides SNI via --resolve
curl -k --resolve "api.githubcopilot.com:443:127.0.0.1" https://api.githubcopilot.com/

# WRONG - no SNI, proxy rejects with "tlsv1 alert access denied"
curl -k https://127.0.0.1:443/
```

### Rustls CryptoProvider Conflict (CRITICAL)

**Problem:** When using both `rustls` (for TLS proxy server) and `reqwest` with `rustls-tls` feature, there's a version conflict that causes a runtime panic:

```
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually...
```

**Solution:** Use `native-tls` feature for reqwest instead of `rustls-tls`:

```toml
# CORRECT - avoids rustls version conflicts
reqwest = { version = "0.12", default-features = false, features = ["native-tls", "stream", "json"] }

# WRONG - causes crypto provider conflicts with direct rustls dependency
reqwest = { version = "0.12", features = ["rustls-tls", "stream", "json"] }
```

**Why:** The daemon uses rustls directly for its TLS proxy server (intercepting HTTPS traffic). When reqwest also pulls in rustls with potentially different version/features, the crypto provider selection fails at runtime. Using native-tls for reqwest's outbound HTTP calls avoids this conflict entirely.

**Files affected:**
- `Cargo.toml` - reqwest dependency configuration
- `src/main.rs` - still needs `rustls::crypto::ring::default_provider().install_default()` for the proxy TLS

## Project Architecture

This is a **public repository** containing a lightweight daemon that intercepts AI coding assistant traffic. All business logic (guardrails, billing, user management) lives in the **private** `copilot-enterprise-extension` repository.

The daemon is intentionally "dumb" - it only:
1. Intercepts HTTPS traffic to Copilot domains
2. Asks the private API "should I allow this?"
3. Forwards or blocks based on the response
4. Logs responses asynchronously

## Build & Test

```bash
# Build release binary
cargo build --release

# Test locally (foreground mode)
sudo ./target/release/copilotguard-daemon start --foreground

# Install as system service
sudo ./target/release/copilotguard-daemon install

# Check status
./target/release/copilotguard-daemon status

# View logs
cat /var/log/copilotguard.log
cat /var/log/copilotguard.error.log
```

## Configuration

### Config File Locations (IMPORTANT)

The config file location depends on whether running as root or regular user:

| Context | Config Location |
|---------|-----------------|
| Daemon (runs as root) | `/etc/copilotguard/config.toml` |
| CLI commands (regular user) | `~/.config/copilotguard/config.toml` |

**Common Mistake:** Running `set-key` without sudo saves the API key to the user config, but the daemon (running as root) reads from `/etc/copilotguard/`. Always use sudo for config commands that affect the daemon:

```bash
# CORRECT - saves to /etc/copilotguard/ where daemon can read it
sudo ./target/release/copilotguard-daemon set-key cg_xxxxx

# WRONG - saves to ~/.config/copilotguard/ which daemon ignores
./target/release/copilotguard-daemon set-key cg_xxxxx
```

### Key Settings

- `api_url` - CopilotGuard API endpoint (default: https://api.guard.tony.codes)
- `api_key` - API key (format: `cg_xxxxx`)
- `api_fail_mode` - "open" (allow on error) or "closed" (block on error)
- `guardrail_timeout_ms` - Timeout for guardrail checks (default: 2000ms)

### Restarting the Daemon After Config Changes

After changing config in `/etc/copilotguard/config.toml`, restart the daemon:

```bash
sudo launchctl bootout system/com.copilotguard.daemon
sudo launchctl bootstrap system /Library/LaunchDaemons/com.copilotguard.daemon.plist
```
