#!/bin/sh
set -e

# CopilotGuard Daemon Installer
# Usage: curl -sSL https://raw.githubusercontent.com/tonycodes/copilotguard-daemon/main/install.sh | sh

VERSION="${COPILOTGUARD_VERSION:-latest}"
INSTALL_DIR="${COPILOTGUARD_INSTALL_DIR:-/usr/local/bin}"
GITHUB_REPO="tonycodes/copilotguard-daemon"
BINARY_NAME="copilotguard-daemon"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { printf "${BLUE}==>${NC} %s\n" "$1"; }
success() { printf "${GREEN}==>${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}==>${NC} %s\n" "$1"; }
error() { printf "${RED}==>${NC} %s\n" "$1"; exit 1; }

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin) OS="darwin" ;;
        Linux) OS="linux" ;;
        *) error "Unsupported operating system: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac

    # Check for unsupported combinations
    if [ "$OS" = "linux" ] && [ "$ARCH" = "arm64" ]; then
        error "Linux ARM64 is not yet supported. Please use x86_64."
    fi

    PLATFORM="${OS}-${ARCH}"
    info "Detected platform: $PLATFORM"
}

# Get the latest version from GitHub
get_latest_version() {
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(curl -sSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -z "$VERSION" ]; then
            error "Failed to fetch latest version"
        fi
    fi
    info "Installing CopilotGuard Daemon $VERSION"
}

# Download and install binary
install_binary() {
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/copilotguard-${PLATFORM}.tar.gz"

    info "Downloading from $DOWNLOAD_URL"

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    if ! curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/copilotguard-daemon.tar.gz"; then
        error "Failed to download CopilotGuard Daemon"
    fi

    info "Extracting..."
    tar -xzf "$TMP_DIR/copilotguard-daemon.tar.gz" -C "$TMP_DIR"

    if [ ! -f "$TMP_DIR/$BINARY_NAME" ]; then
        error "Binary not found in archive"
    fi

    info "Installing to $INSTALL_DIR (requires sudo)"
    sudo mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"

    success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
}

# Run copilotguard-daemon install to set up CA, hosts, and daemon
setup_daemon() {
    info "Setting up CopilotGuard Daemon (CA certificate, hosts file, daemon)..."

    if ! sudo "$INSTALL_DIR/$BINARY_NAME" install; then
        error "Failed to complete CopilotGuard Daemon setup"
    fi

    success "CopilotGuard Daemon is running"
}

# Configure shell alias for Copilot CLI
setup_shell_alias() {
    ALIAS_LINE='alias copilot="NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot"'

    # Detect shell config file
    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.profile"
    fi

    # Check if alias already exists
    if grep -q "NODE_EXTRA_CA_CERTS=/etc/copilotguard" "$SHELL_RC" 2>/dev/null; then
        info "Copilot CLI alias already configured in $SHELL_RC"
    else
        info "Adding Copilot CLI alias to $SHELL_RC"
        printf "\n# CopilotGuard: Enable CA trust for GitHub Copilot CLI\n%s\n" "$ALIAS_LINE" >> "$SHELL_RC"
        success "Alias added to $SHELL_RC"
    fi
}

# Verify everything is working
verify_setup() {
    printf "\n"
    info "Verifying installation..."

    # Check binary
    if command -v $BINARY_NAME > /dev/null 2>&1; then
        INSTALLED_VERSION=$($BINARY_NAME --version 2>/dev/null || echo "unknown")
        success "Binary: $INSTALLED_VERSION"
    else
        warn "Binary not in PATH"
    fi

    # Check daemon
    if pgrep -f "$BINARY_NAME" > /dev/null 2>&1; then
        success "Daemon: running"
    else
        warn "Daemon: not running"
    fi

    # Check CA
    if [ -f "/etc/copilotguard/ca.crt" ]; then
        success "CA certificate: installed"
    else
        warn "CA certificate: not found"
    fi

    # Check hosts file
    if grep -q "copilot" /etc/hosts 2>/dev/null; then
        success "Hosts file: configured"
    else
        warn "Hosts file: not configured"
    fi
}

# Print completion message
print_complete() {
    printf "\n"
    printf "${GREEN}===========================================${NC}\n"
    printf "${GREEN}  CopilotGuard Daemon installation complete! ${NC}\n"
    printf "${GREEN}===========================================${NC}\n"
    printf "\n"
    printf "To activate the Copilot CLI alias, run:\n"
    printf "  ${YELLOW}source ~/.zshrc${NC}  (or restart your terminal)\n"
    printf "\n"
    printf "Then test with:\n"
    printf "  ${YELLOW}copilot -p \"hello\"${NC}\n"
    printf "\n"
    printf "Useful commands:\n"
    printf "  ${BLUE}copilotguard-daemon status${NC}   - Check daemon status\n"
    printf "  ${BLUE}sudo copilotguard-daemon stop${NC} - Stop the daemon\n"
    printf "  ${BLUE}sudo copilotguard-daemon uninstall${NC} - Remove completely\n"
    printf "\n"
    printf "For more information: https://github.com/${GITHUB_REPO}\n"
    printf "\n"
}

# Main
main() {
    printf "\n"
    printf "${BLUE}====================================${NC}\n"
    printf "${BLUE}  CopilotGuard Daemon Installer${NC}\n"
    printf "${BLUE}====================================${NC}\n"
    printf "\n"

    detect_platform
    get_latest_version
    install_binary
    setup_daemon
    setup_shell_alias
    verify_setup
    print_complete
}

main "$@"
