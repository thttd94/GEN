#!/bin/sh
set -eu

APP_DIR="/opt/proxy-manager-v1"
SERVICE_NAME="proxy-manager-v1"
PORT="18123"
# Đổi pass này trước khi đưa lên GitHub
INSTALL_PASSWORD="123123@qq"

INPUT_PASS="$(python3 - <<'PY'
import getpass
print(getpass.getpass('Enter install password: '), end='')
PY
)"

if [ "$INPUT_PASS" != "$INSTALL_PASSWORD" ]; then
  echo "[ERR] Wrong password"
  exit 1
fi

LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)"
LAN_CIDR="$(ip -4 -o addr show br-lan 2>/dev/null | awk '{print $4}' | head -n1)"
[ -n "$LAN_CIDR" ] || LAN_CIDR="${LAN_IP}/24"

mkdir -p "$APP_DIR"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cp "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
cp "$SCRIPT_DIR/admanager_gui_config.json" "$APP_DIR/admanager_gui_config.json"
cp "$SCRIPT_DIR/admanager_gui.local.json" "$APP_DIR/admanager_gui.local.json"
[ -f "$SCRIPT_DIR/collector_config.json" ] && cp "$SCRIPT_DIR/collector_config.json" "$APP_DIR/collector_config.json"
[ -f "$SCRIPT_DIR/reverse_tunnel_config.json" ] && cp "$SCRIPT_DIR/reverse_tunnel_config.json" "$APP_DIR/reverse_tunnel_config.json"
[ -f "$SCRIPT_DIR/reverse_tunnel.sh" ] && cp "$SCRIPT_DIR/reverse_tunnel.sh" "$APP_DIR/reverse_tunnel.sh"
[ -f "$SCRIPT_DIR/frpc_config.json" ] && cp "$SCRIPT_DIR/frpc_config.json" "$APP_DIR/frpc_config.json"
[ -f "$SCRIPT_DIR/frpc_template.toml" ] && cp "$SCRIPT_DIR/frpc_template.toml" "$APP_DIR/frpc_template.toml"
[ -f "$SCRIPT_DIR/frpc_setup.py" ] && cp "$SCRIPT_DIR/frpc_setup.py" "$APP_DIR/frpc_setup.py"
[ -f "$SCRIPT_DIR/frpc_run.sh" ] && cp "$SCRIPT_DIR/frpc_run.sh" "$APP_DIR/frpc_run.sh"
[ -f "$SCRIPT_DIR/frp_registry.json" ] && cp "$SCRIPT_DIR/frp_registry.json" "$APP_DIR/frp_registry.json"
rm -rf "$APP_DIR/static"
mkdir -p "$APP_DIR/static"
cp -r "$SCRIPT_DIR/static/." "$APP_DIR/static/"
mkdir -p "$APP_DIR/xxtouch_jobs/data" "$APP_DIR/xxtouch_jobs/log" "$APP_DIR/xxtouch_jobs/tmp"
chmod 755 "$APP_DIR/app.py"
[ -f "$APP_DIR/reverse_tunnel.sh" ] && chmod 755 "$APP_DIR/reverse_tunnel.sh"
[ -f "$APP_DIR/frpc_run.sh" ] && chmod 755 "$APP_DIR/frpc_run.sh"

cat > "$APP_DIR/apply_xxtouch_bypass.sh" <<EOF
#!/bin/sh
set -eu
LAN_IP="${LAN_IP}"
LAN_CIDR="${LAN_CIDR}"
if iptables -t mangle -C GENROUTER -s "$LAN_CIDR" -d "$LAN_IP/32" -p tcp -j RETURN 2>/dev/null; then
  exit 0
fi
iptables -t mangle -I GENROUTER 1 -s "$LAN_CIDR" -d "$LAN_IP/32" -p tcp -j RETURN
EOF
chmod 755 "$APP_DIR/apply_xxtouch_bypass.sh"
"$APP_DIR/apply_xxtouch_bypass.sh" || true

cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
  $APP_DIR/apply_xxtouch_bypass.sh || true
  procd_open_instance
  procd_set_param command python3 $APP_DIR/app.py
  procd_set_param respawn
  procd_close_instance
}
EOF

chmod +x "/etc/init.d/$SERVICE_NAME"
/etc/init.d/$SERVICE_NAME enable || true
/etc/init.d/$SERVICE_NAME restart || /etc/init.d/$SERVICE_NAME start

if [ -f "$SCRIPT_DIR/reverse_tunnel_service.txt" ]; then
  cp "$SCRIPT_DIR/reverse_tunnel_service.txt" /etc/init.d/genrouter-reverse-tunnel
  chmod +x /etc/init.d/genrouter-reverse-tunnel
  /etc/init.d/genrouter-reverse-tunnel enable || true
  /etc/init.d/genrouter-reverse-tunnel restart || /etc/init.d/genrouter-reverse-tunnel start || true
fi

if [ -f "$SCRIPT_DIR/frpc_service.txt" ]; then
  cp "$SCRIPT_DIR/frpc_service.txt" /etc/init.d/genrouter-frpc
  chmod +x /etc/init.d/genrouter-frpc
  /etc/init.d/genrouter-frpc enable || true
  /etc/init.d/genrouter-frpc restart || /etc/init.d/genrouter-frpc start || true
fi

echo "[OK] Installed"
echo "[OK] Open: http://$LAN_IP:$PORT"
echo "[OK] XXTouch assets synced to: $APP_DIR/static/xxtouch"
echo "[OK] XXTouch admin LAN bypass ensured for router $LAN_IP"
