# CopilotGuard Daemon - Development Learnings

This document captures key learnings and technical insights discovered during development.

## TLS Interception Architecture

### How It Works

1. **Hosts File Redirection**: Modify `/etc/hosts` to redirect AI domains to `127.0.0.1`
2. **TLS Proxy**: Listen on port 443, terminate TLS, inspect traffic, forward to real servers
3. **SNI-Based Certificates**: Dynamically generate certificates based on the Server Name Indication (SNI) from the client
4. **DNS Bypass**: Use hardcoded IPs to reach real servers (bypass our own hosts file redirect)

### Key Domains Intercepted

```
copilot-proxy.githubusercontent.com     # Copilot completions
api.githubcopilot.com                   # Copilot API
api.individual.githubcopilot.com        # Individual plans
api.business.githubcopilot.com          # Business/Enterprise plans
api.enterprise.githubcopilot.com        # Enterprise plans
```

**Note**: We do NOT intercept `api.github.com` as it would break git operations. Copilot uses this for authentication but the actual AI traffic goes through the Copilot-specific domains.

## GitHub Copilot CLI Specifics

### Bundled Node.js Binary

The GitHub Copilot CLI (`@github/copilot`) is NOT a simple Node.js script. It's a **compiled native binary** that bundles Node.js:

- Location: `~/.copilot/pkg/*/copilot-darwin-arm64/copilot`
- Type: Mach-O 64-bit executable (native ARM64 binary)
- Node version: v24.x (bundled, not system Node.js)
- TLS: Uses OpenSSL with system certificate support

### Certificate Trust Requirements

The bundled Node.js respects:
1. **macOS System Keychain** - but only when certificates have explicit SSL trust policy
2. **NODE_EXTRA_CA_CERTS** - environment variable for additional CA certificates

**Critical**: Simply adding a certificate to the keychain is NOT enough. You must set the SSL trust policy:

```bash
# WRONG - just adds certificate
sudo security add-trusted-cert -k /Library/Keychains/System.keychain ca.crt

# CORRECT - adds with SSL trust policy
sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain ca.crt
```

### Running Copilot with Interception

Until we implement automatic CA trust, users must run:

```bash
NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot
```

Or create an alias in `.zshrc`/`.bashrc`:

```bash
alias copilot='NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot'
```

## Rust Implementation Details

### Crypto Provider

rustls requires explicit crypto provider installation before any TLS operations:

```rust
rustls::crypto::aws_lc_rs::default_provider()
    .install_default()
    .expect("Failed to install crypto provider");
```

This MUST be called at the start of `main()` before any TLS operations.

### SNI-Based Certificate Resolution

Implemented `ResolvesServerCert` trait for dynamic certificate generation:

```rust
impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        self.get_or_create_cert(&sni.to_string())
    }
}
```

### Certificate Chain

The TLS handshake requires the **full certificate chain** (domain cert + CA cert):

```rust
// Return full certificate chain: domain cert + CA cert
let cert_chain = format!("{}{}", domain_cert.pem(), ca_cert_pem);
```

### DNS Resolution Bypass

Since we modify `/etc/hosts`, we need to bypass it for outbound connections:

```rust
struct BypassResolver {
    overrides: HashMap<String, Vec<IpAddr>>,
}

// Hardcoded real IPs for GitHub Copilot domains
// (GitHub CDN: 140.82.112.x, 140.82.113.x, 140.82.114.x)
```

## Debugging TLS Issues

### Common Errors

1. **"tls handshake eof"** - Client rejected certificate (CA not trusted)
2. **"no server certificate chain resolved"** - SNI domain not in allowed list
3. **"The certificate was not trusted"** - Missing CA in client's trust store

### Verification Commands

```bash
# Check CA in keychain
security find-certificate -a -c "CopilotGuard" /Library/Keychains/System.keychain

# Check trust settings (must show "Policy OID: SSL")
security dump-trust-settings -d | grep -A15 "CopilotGuard"

# Test TLS with curl
curl -v https://api.business.githubcopilot.com/

# Test with explicit CA
curl -v --cacert /etc/copilotguard/ca.crt https://api.business.githubcopilot.com/

# Test Node.js CA handling
NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt node -e "
const https = require('https');
https.get('https://api.business.githubcopilot.com/', (res) => {
  console.log('Status:', res.statusCode);
}).on('error', console.error);
"
```

### Viewing Proxy Logs

```bash
tail -f /var/log/copilotguard.log
```

## macOS Keychain Gotchas

### Duplicate Certificates

Each `security add-trusted-cert` call adds a NEW certificate, even if one with the same name exists. Clean up with:

```bash
# List all CopilotGuard certs
security find-certificate -a -Z -c "CopilotGuard" /Library/Keychains/System.keychain

# Delete by SHA-1 hash
sudo security delete-certificate -Z <SHA1_HASH> /Library/Keychains/System.keychain
```

### Trust Settings

- `-d` = domain trust settings (used by most apps)
- `-s` = admin trust settings (for system-wide defaults)
- `-p ssl` = specifically trust for SSL/TLS connections

## Future Improvements

1. **Automatic NODE_EXTRA_CA_CERTS**: Create a wrapper script or shell integration
2. **Dynamic DNS Resolution**: Query real DNS servers instead of hardcoded IPs
3. **HTTP/2 Support**: Currently only HTTP/1.1; may need HTTP/2 for some clients
4. **Request/Response Logging**: Add detailed logging with body inspection
5. **Policy Engine**: Implement guardrails and content filtering
6. **Metrics Collection**: Send usage data to CopilotGuard API
