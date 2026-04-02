#!/usr/bin/env bash
# install_tools.sh — 安装 Go 安全审计辅助工具
#
# 用法:
#   bash skills/go-security-audit-cn/scripts/install_tools.sh
#
# 需要:
#   - Go 1.18+（已安装并在 PATH 中）
#   - 公网访问（或已配置内网 GOPROXY）
#
# 离线环境请参阅: references/offline-setup.md

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
        error "未找到 Go。请先安装 Go 1.18 或更高版本。"
        error "下载地址: https://go.dev/dl/"
        exit 1
    fi
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    info "检测到 Go 版本: ${GO_VERSION}"
}

install_tool() {
    local name="$1"
    local pkg="$2"
    local bin_name="$3"

    if command -v "${bin_name}" &>/dev/null; then
        warn "${name} 已安装，跳过（$(command -v ${bin_name})）"
        return 0
    fi

    info "正在安装 ${name} ..."
    if GOFLAGS="" go install "${pkg}@latest" 2>&1; then
        info "${name} 安装成功"
    else
        error "${name} 安装失败。请检查网络连接或参阅 references/offline-setup.md"
        return 1
    fi
}

check_go

GOBIN_DIR="$(go env GOPATH)/bin"
info "工具将安装至: ${GOBIN_DIR}"

FAILED=0

install_tool "govulncheck" "golang.org/x/vuln/cmd/govulncheck" "govulncheck" || FAILED=$((FAILED+1))
install_tool "gosec"       "github.com/securego/gosec/v2/cmd/gosec" "gosec"  || FAILED=$((FAILED+1))
install_tool "staticcheck" "honnef.co/go/tools/cmd/staticcheck"  "staticcheck" || FAILED=$((FAILED+1))

echo ""
if [ "${FAILED}" -eq 0 ]; then
    info "所有工具安装完成。"
    echo ""
    echo "  govulncheck  $(govulncheck --version 2>/dev/null | head -1)"
    echo "  gosec        $(gosec --version 2>/dev/null | head -1)"
    echo "  staticcheck  $(staticcheck --version 2>/dev/null | head -1)"
else
    warn "${FAILED} 个工具安装失败。技能将在没有这些工具的情况下继续进行手动代码审计。"
    warn "离线安装方法请参阅: references/offline-setup.md"
fi

# 检查 GOBIN 是否在 PATH 中
if [[ ":$PATH:" != *":${GOBIN_DIR}:"* ]]; then
    warn "${GOBIN_DIR} 不在 PATH 中。请将以下内容添加到你的 shell 配置文件（~/.bashrc 或 ~/.zshrc）："
    warn "  export PATH=\"\$PATH:${GOBIN_DIR}\""
fi
