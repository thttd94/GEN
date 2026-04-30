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

if [ -f "$SCRIPT_DIR/setup_data_disk.sh" ]; then
  echo "[INFO] Checking data disk..."
  sh "$SCRIPT_DIR/setup_data_disk.sh" /dev/nvme0n1 || echo "[WARN] setup_data_disk.sh skipped/failed, continue install"
fi

cp "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
[ -f "$SCRIPT_DIR/VERSION.txt" ] && cp "$SCRIPT_DIR/VERSION.txt" "$APP_DIR/VERSION.txt"
[ ! -f "$APP_DIR/admanager_gui_config.json" ] && cp "$SCRIPT_DIR/admanager_gui_config.json" "$APP_DIR/admanager_gui_config.json"
[ ! -f "$APP_DIR/admanager_gui.local.json" ] && cp "$SCRIPT_DIR/admanager_gui.local.json" "$APP_DIR/admanager_gui.local.json"
[ -f "$SCRIPT_DIR/collector_config.json" ] && [ ! -f "$APP_DIR/collector_config.json" ] && cp "$SCRIPT_DIR/collector_config.json" "$APP_DIR/collector_config.json"
[ -f "$SCRIPT_DIR/setup_data_disk.sh" ] && cp "$SCRIPT_DIR/setup_data_disk.sh" "$APP_DIR/setup_data_disk.sh"
rm -f "$APP_DIR/reverse_tunnel.sh" "$APP_DIR/reverse_tunnel_config.json"
rm -f "$APP_DIR/frpc" "$APP_DIR/frpc_config.json" "$APP_DIR/frpc_template.toml" "$APP_DIR/frpc_setup.py" "$APP_DIR/frpc_run.sh" "$APP_DIR/frpc_boot_loop.sh" "$APP_DIR/frpc.generated.toml" "$APP_DIR/install_frpc_binary.sh"
rm -rf "$APP_DIR/static"
mkdir -p "$APP_DIR/static"
cp -r "$SCRIPT_DIR/static/." "$APP_DIR/static/"
rm -rf "$APP_DIR/xxtouch_jobs"
mkdir -p "$APP_DIR/xxtouch_jobs"
if [ -d "$SCRIPT_DIR/xxtouch_jobs" ]; then
  cp -r "$SCRIPT_DIR/xxtouch_jobs/." "$APP_DIR/xxtouch_jobs/"
fi
mkdir -p "$APP_DIR/xxtouch_jobs/data" "$APP_DIR/xxtouch_jobs/log" "$APP_DIR/xxtouch_jobs/tmp"
chmod 755 "$APP_DIR/app.py"
[ -f "$APP_DIR/setup_data_disk.sh" ] && chmod 755 "$APP_DIR/setup_data_disk.sh"

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

for svc in genrouter-reverse-tunnel genrouter-frpc; do
  if [ -f "/etc/init.d/$svc" ]; then
    /etc/init.d/$svc stop || true
    /etc/init.d/$svc disable || true
    rm -f "/etc/init.d/$svc"
  fi
done

if [ -f /etc/rc.local ]; then
  cp /etc/rc.local /etc/rc.local.bak.gen_no_frpc 2>/dev/null || true
fi
cat > /etc/rc.local <<'EOF'
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.

exit 0
EOF
chmod +x /etc/rc.local
killall frpc >/dev/null 2>&1 || true
killall start_frpc_loop.sh >/dev/null 2>&1 || true
killall ssh >/dev/null 2>&1 || true
rm -f /tmp/genrouter-frpc.log /tmp/genrouter-frpc-domain.log

echo "[OK] Installed"
echo "[OK] Open: http://$LAN_IP:$PORT"
echo "[OK] XXTouch assets synced to: $APP_DIR/static/xxtouch"
echo "[OK] XXTouch admin LAN bypass ensured for router $LAN_IP"
echo "[OK] FRPC and reverse tunnel removed/disabled"
