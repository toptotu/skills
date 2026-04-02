#!/usr/bin/env bash
# install_tools.sh — Install Go security audit helper tools
#
# Usage:
#   bash skills/go-security-audit/scripts/install_tools.sh
#
# Requirements:
#   - Go 1.18+ installed and on PATH
#   - Internet access (or a configured GOPROXY)
#
# Offline environments: see references/offline-setup.md

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_go() {
    if ! command -v go &>/dev/null; then
        error "Go not found. Please install Go 1.18 or later."
        error "Download: https://go.dev/dl/"
        exit 1
    fi
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    info "Detected Go version: ${GO_VERSION}"
}

install_tool() {
    local name="$1"
    local pkg="$2"
    local bin_name="$3"

    if command -v "${bin_name}" &>/dev/null; then
        warn "${name} already installed, skipping ($(command -v ${bin_name}))"
        return 0
    fi

    info "Installing ${name} ..."
    if GOFLAGS="" go install "${pkg}@latest" 2>&1; then
        info "${name} installed successfully"
    else
        error "${name} installation failed. Check network access or see references/offline-setup.md"
        return 1
    fi
}

check_go

GOBIN_DIR="$(go env GOPATH)/bin"
info "Tools will be installed to: ${GOBIN_DIR}"

FAILED=0

install_tool "govulncheck" "golang.org/x/vuln/cmd/govulncheck" "govulncheck" || FAILED=$((FAILED+1))
install_tool "gosec"       "github.com/securego/gosec/v2/cmd/gosec" "gosec"  || FAILED=$((FAILED+1))
install_tool "staticcheck" "honnef.co/go/tools/cmd/staticcheck"  "staticcheck" || FAILED=$((FAILED+1))

echo ""
if [ "${FAILED}" -eq 0 ]; then
    info "All tools installed successfully."
    echo ""
    echo "  govulncheck  $(govulncheck --version 2>/dev/null | head -1)"
    echo "  gosec        $(gosec --version 2>/dev/null | head -1)"
    echo "  staticcheck  $(staticcheck --version 2>/dev/null | head -1)"
else
    warn "${FAILED} tool(s) failed to install. The skill will continue with manual code audit only."
    warn "For offline installation options, see: references/offline-setup.md"
fi

# Warn if GOBIN is not on PATH
if [[ ":$PATH:" != *":${GOBIN_DIR}:"* ]]; then
    warn "${GOBIN_DIR} is not in PATH. Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    warn "  export PATH=\"\$PATH:${GOBIN_DIR}\""
fi
