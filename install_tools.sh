#!/usr/bin/env bash
# install_tools.sh - 安装 AutoPT 运行所需的二进制工具
# 包含：xray
# 运行要求：Ubuntu 20.04/22.04，需要 root 权限（sudo）
#
# 使用方法：
#   chmod +x install_tools.sh
#   sudo ./install_tools.sh

set -e

XRAY_VERSION="1.9.11"
INSTALL_DIR="/usr/local/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }
ok()    { echo -e "${GREEN}[✓]${NC} $1 already installed, skipping."; }

# 检测架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH_XRAY="linux-amd64" ;;
    aarch64) ARCH_XRAY="linux-arm64" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac

# ── xray ──────────────────────────────────────────────────────────────────────
install_xray() {
    if command -v xray &>/dev/null; then
        ok "xray"
        return
    fi
    info "Installing xray v${XRAY_VERSION}..."
    apt-get install -y -qq wget unzip curl

    TMP=$(mktemp -d)
    XRAY_URL="https://github.com/chaitin/xray/releases/download/${XRAY_VERSION}/xray_${ARCH_XRAY}.zip"
    wget -q "$XRAY_URL" -O "$TMP/xray.zip" || error "Failed to download xray from $XRAY_URL"
    unzip -q "$TMP/xray.zip" -d "$TMP"

    # 找到解压出的二进制（名称可能带版本后缀）
    XRAY_BIN=$(find "$TMP" -maxdepth 1 -type f ! -name "*.zip" ! -name "*.yml" | head -1)
    [ -z "$XRAY_BIN" ] && error "xray binary not found in zip"
    install -m 755 "$XRAY_BIN" "$INSTALL_DIR/xray"
    rm -rf "$TMP"

    # 生成默认配置（首次运行需要）
    warn "Generating xray default config..."
    xray genca &>/dev/null || true

    info "xray installed: $(xray version 2>&1 | head -1)"
}

# ── 主流程 ─────────────────────────────────────────────────────────────────────
echo "=============================="
echo "  AutoPT Tool Installer"
echo "=============================="
echo "Arch: $ARCH"
echo ""

[ "$EUID" -ne 0 ] && error "Please run as root: sudo ./install_tools.sh"

install_xray

echo ""
echo "=============================="
info "All tools installed successfully!"
echo ""
echo "Verify:"
echo "  xray version"
echo "=============================="
