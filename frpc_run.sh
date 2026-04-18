#!/bin/sh
set -eu
APP_DIR="/opt/proxy-manager-v1"
cd "$APP_DIR"
PORT="$(python3 frpc_setup.py)"
echo "[FRP] remote_port=$PORT"
exec ./frpc -c "$APP_DIR/frpc.generated.toml"
