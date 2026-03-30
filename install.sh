#!/bin/sh
set -eu

APP_DIR="/opt/proxy-manager-v1"
SERVICE_NAME="proxy-manager-v1"
PORT="18123"
# Đổi pass này trước khi đưa lên GitHub
INSTALL_PASSWORD="CHANGE_ME_INSTALL_PASS"

printf 'Enter install password: '
stty -echo
read -r INPUT_PASS
stty echo
printf '\n'

if [ "$INPUT_PASS" != "$INSTALL_PASSWORD" ]; then
  echo "[ERR] Wrong password"
  exit 1
fi

mkdir -p "$APP_DIR"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cp "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
mkdir -p "$APP_DIR/static"
cp "$SCRIPT_DIR/static/index.html" "$APP_DIR/static/index.html"
chmod 755 "$APP_DIR/app.py"

cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command python3 $APP_DIR/app.py
  procd_set_param respawn
  procd_close_instance
}
EOF

chmod +x "/etc/init.d/$SERVICE_NAME"
/etc/init.d/$SERVICE_NAME enable || true
/etc/init.d/$SERVICE_NAME restart || /etc/init.d/$SERVICE_NAME start

echo "[OK] Installed"
echo "[OK] Open: http://$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1):$PORT"
