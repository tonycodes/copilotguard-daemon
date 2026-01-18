#!/bin/bash
# CopilotGuard wrapper for GitHub Copilot CLI
# Automatically sets NODE_EXTRA_CA_CERTS to trust the CopilotGuard CA certificate

CA_CERT="/etc/copilotguard/ca.crt"
REAL_COPILOT="${HOME}/.copilot/pkg/latest/copilot"

# Check if CA certificate exists
if [[ ! -f "$CA_CERT" ]]; then
    echo "Warning: CopilotGuard CA certificate not found at $CA_CERT" >&2
    echo "Running copilot without CopilotGuard interception..." >&2
    exec "$REAL_COPILOT" "$@"
fi

# Find the real copilot binary
if [[ ! -f "$REAL_COPILOT" ]]; then
    # Try to find it in the versioned directories
    REAL_COPILOT=$(find "${HOME}/.copilot/pkg" -name "copilot" -type f -executable 2>/dev/null | head -1)
    if [[ -z "$REAL_COPILOT" ]]; then
        echo "Error: GitHub Copilot CLI not found" >&2
        echo "Install it with: gh extension install github/copilot-cli" >&2
        exit 1
    fi
fi

# Run copilot with the CA certificate
export NODE_EXTRA_CA_CERTS="$CA_CERT"
exec "$REAL_COPILOT" "$@"
