#!/bin/bash
# CopilotGuard wrapper for GitHub Copilot CLI
# Automatically sets NODE_EXTRA_CA_CERTS to trust the CopilotGuard CA certificate

CA_CERT="/etc/copilotguard/ca.crt"

# Check if CA certificate exists
if [[ ! -f "$CA_CERT" ]]; then
    echo "Warning: CopilotGuard CA certificate not found at $CA_CERT" >&2
    echo "Running copilot without CopilotGuard interception..." >&2
    exec copilot "$@"
fi

# Find the real copilot command (exclude this script if it's named 'copilot')
SCRIPT_PATH="$(realpath "$0")"
REAL_COPILOT=""

# Search PATH for copilot, excluding our wrapper
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    candidate="$dir/copilot"
    if [[ -x "$candidate" && "$(realpath "$candidate" 2>/dev/null)" != "$SCRIPT_PATH" ]]; then
        REAL_COPILOT="$candidate"
        break
    fi
done

if [[ -z "$REAL_COPILOT" ]]; then
    echo "Error: GitHub Copilot CLI not found in PATH" >&2
    echo "Install it with: npm install -g @github/copilot" >&2
    exit 1
fi

# Run copilot with the CA certificate
export NODE_EXTRA_CA_CERTS="$CA_CERT"
exec "$REAL_COPILOT" "$@"
