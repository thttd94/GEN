#!/bin/sh
set -eu
APP_DIR="${1:-/opt/proxy-manager-v1}"
VERSION="0.61.1"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) PKG_ARCH="amd64" ;;
  aarch64|arm64) PKG_ARCH="arm64" ;;
  armv7l|armv7) PKG_ARCH="arm" ;;
  *)
    echo "[WARN] Unsupported arch for auto frpc install: $ARCH"
    exit 0
    ;;
esac
URL="https://github.com/fatedier/frp/releases/download/v${VERSION}/frp_${VERSION}_linux_${PKG_ARCH}.tar.gz"
TMP_DIR="/tmp/frpc-install.$$"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"
rm -f frp.tgz
wget --no-check-certificate -O frp.tgz "$URL"
tar -xzf frp.tgz
FRPC_PATH="$(find . -type f -name frpc | head -n1)"
[ -n "$FRPC_PATH" ]
mkdir -p "$APP_DIR"
cp "$FRPC_PATH" "$APP_DIR/frpc"
chmod 755 "$APP_DIR/frpc"
cd /
rm -rf "$TMP_DIR"
echo "[OK] frpc installed to $APP_DIR/frpc"
