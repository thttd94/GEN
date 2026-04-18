#!/bin/sh
set -eu
APP_DIR="/opt/proxy-manager-v1"
cd "$APP_DIR"
DOMAIN="$(python3 frpc_setup.py)"
echo "[FRP] custom_domain=$DOMAIN"
exec ./frpc -c "$APP_DIR/frpc.generated.toml"
