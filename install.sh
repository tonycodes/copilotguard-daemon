#!/bin/sh
set -e

# CopilotGuard Installer
# Usage: curl -sSL https://raw.githubusercontent.com/tonycodes/copilotguard-daemon/main/install.sh | sh

VERSION="${COPILOTGUARD_VERSION:-latest}"
INSTALL_DIR="${COPILOTGUARD_INSTALL_DIR:-/usr/local/bin}"
GITHUB_REPO="tonycodes/copilotguard-daemon"

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
    if [[ "$OS" == "linux" && "$ARCH" == "arm64" ]]; then
        error "Linux ARM64 is not yet supported. Please use x86_64."
    fi

    PLATFORM="${OS}-${ARCH}"
    info "Detected platform: $PLATFORM"
}

# Get the latest version from GitHub
get_latest_version() {
    if [[ "$VERSION" == "latest" ]]; then
        VERSION=$(curl -sSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "$VERSION" ]]; then
            error "Failed to fetch latest version"
        fi
    fi
    info "Installing CopilotGuard $VERSION"
}

# Download and install
install_binary() {
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/copilotguard-${PLATFORM}.tar.gz"

    info "Downloading from $DOWNLOAD_URL"

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    if ! curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/copilotguard.tar.gz"; then
        error "Failed to download CopilotGuard"
    fi

    info "Extracting..."
    tar -xzf "$TMP_DIR/copilotguard.tar.gz" -C "$TMP_DIR"

    if [[ ! -f "$TMP_DIR/copilotguard" ]]; then
        error "Binary not found in archive"
    fi

    info "Installing to $INSTALL_DIR (requires sudo)"
    sudo mv "$TMP_DIR/copilotguard" "$INSTALL_DIR/copilotguard"
    sudo chmod +x "$INSTALL_DIR/copilotguard"

    success "Binary installed to $INSTALL_DIR/copilotguard"
}

# Verify installation
verify_install() {
    if command -v copilotguard &> /dev/null; then
        INSTALLED_VERSION=$(copilotguard --version 2>/dev/null || echo "unknown")
        success "CopilotGuard installed successfully: $INSTALLED_VERSION"
    else
        warn "Binary installed but not in PATH. Add $INSTALL_DIR to your PATH."
    fi
}

# Print next steps
print_next_steps() {
    printf "\n"
    printf "${GREEN}Installation complete!${NC}\n"
    printf "\n"
    printf "Next steps:\n"
    printf "\n"
    printf "  1. Complete setup (generates CA, configures hosts file, starts daemon):\n"
    printf "     ${YELLOW}sudo copilotguard install${NC}\n"
    printf "\n"
    printf "  2. For GitHub Copilot CLI support, add this alias to your shell profile:\n"
    printf "     ${YELLOW}echo 'alias copilot=\"NODE_EXTRA_CA_CERTS=/etc/copilotguard/ca.crt copilot\"' >> ~/.zshrc${NC}\n"
    printf "\n"
    printf "  3. Reload your shell and test:\n"
    printf "     ${YELLOW}source ~/.zshrc${NC}\n"
    printf "     ${YELLOW}copilot -p \"hello\"${NC}\n"
    printf "\n"
    printf "For more information: https://github.com/${GITHUB_REPO}\n"
}

# Main
main() {
    printf "\n"
    printf "${BLUE}CopilotGuard Installer${NC}\n"
    printf "\n"

    detect_platform
    get_latest_version
    install_binary
    verify_install
    print_next_steps
}

main "$@"
