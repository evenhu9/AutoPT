#!/usr/bin/env bash
# install_tools.sh - 安装 AutoPT 运行所需的二进制工具
# 包含：masscan、httpx、xray
# 运行要求：Ubuntu 20.04/22.04，需要 root 权限（sudo）
#
# 使用方法：
#   chmod +x install_tools.sh
#   sudo ./install_tools.sh

set -e

XRAY_VERSION="1.9.11"
HTTPX_VERSION="1.6.10"
INSTALL_DIR="/usr/local/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; exit 1; }
ok()      { echo -e "${GREEN}[✓]${NC} $1 already installed, skipping."; }

# 检测架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH_STR="amd64" ; ARCH_XRAY="linux-amd64" ;;
    aarch64) ARCH_STR="arm64" ; ARCH_XRAY="linux-arm64" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac

# ── 1. masscan ────────────────────────────────────────────────────────────────
install_masscan() {
    if command -v masscan &>/dev/null; then
        ok "masscan"
        return
    fi
    info "Installing masscan..."
    apt-get update -qq
    apt-get install -y -qq masscan
    info "masscan installed: $(masscan --version 2>&1 | head -1)"
}

# ── 2. httpx (projectdiscovery) ───────────────────────────────────────────────
install_httpx() {
    if command -v httpx &>/dev/null; then
        ok "httpx"
        return
    fi
    info "Installing httpx v${HTTPX_VERSION}..."
    TMP=$(mktemp -d)
    HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH_STR}.zip"
    wget -q "$HTTPX_URL" -O "$TMP/httpx.zip" || error "Failed to download httpx from $HTTPX_URL"
    unzip -q "$TMP/httpx.zip" -d "$TMP"
    install -m 755 "$TMP/httpx" "$INSTALL_DIR/httpx"
    rm -rf "$TMP"
    info "httpx installed: $(httpx -version 2>&1 | head -1)"
}

# ── 3. xray ───────────────────────────────────────────────────────────────────
install_xray() {
    if command -v xray &>/dev/null; then
        ok "xray"
        return
    fi
    info "Installing xray v${XRAY_VERSION}..."
    TMP=$(mktemp -d)
    XRAY_URL="https://github.com/chaitin/xray/releases/download/${XRAY_VERSION}/xray_${ARCH_XRAY}.zip"
    wget -q "$XRAY_URL" -O "$TMP/xray.zip" || error "Failed to download xray from $XRAY_URL"
    unzip -q "$TMP/xray.zip" -d "$TMP"

    # xray 解压后二进制名称可能带版本后缀，统一重命名
    XRAY_BIN=$(find "$TMP" -maxdepth 1 -type f -name "xray*" | head -1)
    [ -z "$XRAY_BIN" ] && error "xray binary not found in zip"
    install -m 755 "$XRAY_BIN" "$INSTALL_DIR/xray"
    rm -rf "$TMP"

    # 生成默认配置（xray 首次运行需要）
    if [ ! -f "$HOME/.config/xray/config.yml" ]; then
        warn "Generating xray default config..."
        xray genca &>/dev/null || true
    fi

    info "xray installed: $(xray version 2>&1 | head -1)"
}

# ── 主流程 ────────────────────────────────────────────────────────────────────
echo "=============================="
echo "  AutoPT Tool Installer"
echo "=============================="
echo "Arch: $ARCH ($ARCH_STR)"
echo ""

[ "$EUID" -ne 0 ] && error "Please run as root: sudo ./install_tools.sh"

apt-get install -y -qq wget unzip curl

install_masscan
install_httpx
install_xray

echo ""
echo "=============================="
info "All tools installed successfully!"
echo ""
echo "Verify:"
echo "  masscan --version"
echo "  httpx -version"
echo "  xray version"
echo "=============================="
