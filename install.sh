#!/bin/sh
set -eu

APP_DIR="/opt/proxy-manager-v1"
SERVICE_NAME="proxy-manager-v1"
PORT="18123"

# ---------------------------------------------------------------------------
# Mat khau cai dat - Ver 2.41: KHONG con luu dang chu ro trong repo.
#
# VI SAO: repo nay PUBLIC. Mat khau cu (dat trong install.sh tu ban dau) da nam
# trong git history tu lau => phai coi nhu DA LO. Doi mat khau khong du, vi nguoi
# ta van doc duoc trong commit cu; nen o day chi luu SHA-256, va chan thang hash
# cua mat khau cu do.
#
# CACH DOI MAT KHAU (khong can sua file nay):
#   INSTALL_PASSWORD_SHA256="$(printf '%s' 'genrouter-install-v241<matkhaumoi>' | sha256sum | awk '{print $1}')" sh install.sh
# CACH CHAY KHONG CAN NHAP TAY (CI / script):
#   INSTALL_PASSWORD='<matkhau>' sh install.sh
# CACH BO QUA HOAN TOAN (khi da o trong mang tin cay):
#   INSTALL_SKIP_PASSWORD=1 sh install.sh
# ---------------------------------------------------------------------------
INSTALL_PASSWORD_SALT="${INSTALL_PASSWORD_SALT:-genrouter-install-v241}"
INSTALL_PASSWORD_SHA256="${INSTALL_PASSWORD_SHA256:-766e02e383489ff92139960e5234d59d5b5aad3d4cc9992bace9749148125a91}"
# hash cua mat khau da lo, luon bi tu choi du co ai co tinh dat lai
INSTALL_PASSWORD_LEAKED_SHA256="5c2f0dbb47d419e2daae234516f6aeba0627d2d6446705921b6ce03a89c03fef"

_hash_pass() {
  # $1 = mat khau tho -> in ra sha256 cua salt+pass
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "${INSTALL_PASSWORD_SALT}$1" | sha256sum | awk '{print $1}'
  else
    INSTALL_PASSWORD_SALT="$INSTALL_PASSWORD_SALT" _P="$1" python3 - <<'PY'
import hashlib, os
print(hashlib.sha256((os.environ['INSTALL_PASSWORD_SALT'] + os.environ['_P']).encode()).hexdigest())
PY
  fi
}

if [ "${INSTALL_SKIP_PASSWORD:-0}" = "1" ]; then
  echo "[WARN] Bo qua kiem tra mat khau (INSTALL_SKIP_PASSWORD=1)"
else
  if [ -n "${INSTALL_PASSWORD:-}" ]; then
    INPUT_PASS="$INSTALL_PASSWORD"
  else
    INPUT_PASS="$(python3 - <<'PY'
import getpass
print(getpass.getpass('Enter install password: '), end='')
PY
)"
  fi

  INPUT_HASH="$(_hash_pass "$INPUT_PASS")"
  if [ "$INPUT_HASH" = "$INSTALL_PASSWORD_LEAKED_SHA256" ]; then
    echo "[ERR] Mat khau nay da bi lo trong git history cong khai - khong dung lai duoc."
    echo "      Dat mat khau moi: xem huong dan o dau file install.sh"
    exit 1
  fi
  if [ "$INPUT_HASH" != "$INSTALL_PASSWORD_SHA256" ]; then
    echo "[ERR] Wrong password"
    exit 1
  fi
  unset INPUT_PASS INPUT_HASH
fi

LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)"
LAN_CIDR="$(ip -4 -o addr show br-lan 2>/dev/null | awk '{print $4}' | head -n1)"
[ -n "$LAN_CIDR" ] || LAN_CIDR="${LAN_IP}/24"

mkdir -p "$APP_DIR"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GENROUTER_VERSION_RAW="${GENROUTER_VERSION:-$(cat "$SCRIPT_DIR/VERSION.txt" 2>/dev/null || echo 1.1)}"
GENROUTER_VERSION="$(printf '%s' "$GENROUTER_VERSION_RAW" | sed 's/^[Vv]//')"
if [ -d /data ] && mount | grep -q ' /data '; then
  BACKUP_ROOT="${BACKUP_ROOT:-/data/genrouter_backups/versions}"
else
  BACKUP_ROOT="${BACKUP_ROOT:-/root/genrouter_backups/versions}"
fi
VERSION_BACKUP_BASE="$BACKUP_ROOT/$GENROUTER_VERSION"
VERSION_BACKUP_DIR="$VERSION_BACKUP_BASE/package"
VERSION_SYSTEM_DIR="$VERSION_BACKUP_BASE/system"
GEN_EMBEDDED_VERSION_DIR="$SCRIPT_DIR/gen_backup/versions/$GENROUTER_VERSION"
GEN_EMBEDDED_BACKUP_DIR="$GEN_EMBEDDED_VERSION_DIR/package"
GEN_EMBEDDED_SYSTEM_DIR="$GEN_EMBEDDED_VERSION_DIR/system"
mkdir -p "$BACKUP_ROOT"
if [ ! -d "$VERSION_BACKUP_DIR" ]; then
  mkdir -p "$VERSION_BACKUP_DIR"
  if [ -d "$GEN_EMBEDDED_BACKUP_DIR" ]; then
    cp -a "$GEN_EMBEDDED_BACKUP_DIR/." "$VERSION_BACKUP_DIR/"
  else
    cp -a "$SCRIPT_DIR/." "$VERSION_BACKUP_DIR/"
  fi
  echo "[OK] Saved router package backup: $VERSION_BACKUP_DIR"
else
  echo "[OK] Router package backup exists: $VERSION_BACKUP_DIR"
fi
if [ -d "$GEN_EMBEDDED_SYSTEM_DIR" ]; then
  rm -rf "$VERSION_SYSTEM_DIR"
  mkdir -p "$VERSION_SYSTEM_DIR"
  cp -a "$GEN_EMBEDDED_SYSTEM_DIR/." "$VERSION_SYSTEM_DIR/"
  echo "[OK] Saved router system snapshot: $VERSION_SYSTEM_DIR"
fi

if [ -f "$SCRIPT_DIR/setup_data_disk.sh" ]; then
  echo "[INFO] Checking data disk..."
  sh "$SCRIPT_DIR/setup_data_disk.sh" /dev/nvme0n1 || echo "[WARN] setup_data_disk.sh skipped/failed, continue install"
fi

cp "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
[ -f "$SCRIPT_DIR/rollback_version.sh" ] && cp "$SCRIPT_DIR/rollback_version.sh" "$APP_DIR/rollback_version.sh"
[ -f "$SCRIPT_DIR/VERSION.txt" ] && cp "$SCRIPT_DIR/VERSION.txt" "$APP_DIR/VERSION.txt"
[ ! -f "$APP_DIR/admanager_gui_config.json" ] && cp "$SCRIPT_DIR/admanager_gui_config.json" "$APP_DIR/admanager_gui_config.json"
[ ! -f "$APP_DIR/admanager_gui.local.json" ] && cp "$SCRIPT_DIR/admanager_gui.local.json" "$APP_DIR/admanager_gui.local.json"
[ -f "$SCRIPT_DIR/collector_config.json" ] && [ ! -f "$APP_DIR/collector_config.json" ] && cp "$SCRIPT_DIR/collector_config.json" "$APP_DIR/collector_config.json"
[ -f "$SCRIPT_DIR/setup_data_disk.sh" ] && cp "$SCRIPT_DIR/setup_data_disk.sh" "$APP_DIR/setup_data_disk.sh"
rm -f "$APP_DIR/reverse_tunnel.sh" "$APP_DIR/reverse_tunnel_config.json" "$APP_DIR/reverse_tunnel_service.txt"
rm -f "$APP_DIR/frpc" "$APP_DIR/frpc_config.json" "$APP_DIR/frpc_template.toml" "$APP_DIR/frpc_setup.py" "$APP_DIR/frpc_run.sh" "$APP_DIR/frpc_boot_loop.sh" "$APP_DIR/frpc.generated.toml" "$APP_DIR/install_frpc_binary.sh" "$APP_DIR/frpc_service.txt" "$APP_DIR/frp_registry.json"
rm -rf "$APP_DIR/static"
mkdir -p "$APP_DIR/static"
cp -r "$SCRIPT_DIR/static/." "$APP_DIR/static/"
rm -rf "$APP_DIR/xxtouch_jobs"
mkdir -p "$APP_DIR/xxtouch_jobs"
if [ -d "$SCRIPT_DIR/xxtouch_jobs" ]; then
  cp -r "$SCRIPT_DIR/xxtouch_jobs/." "$APP_DIR/xxtouch_jobs/"
fi
# tools/ (vpn_mgr.sh, gen_vpn_guard.sh, gen_vpn_guard_install.sh) - app.py tu phuc hoi tu day
if [ -d "$SCRIPT_DIR/tools" ]; then
  mkdir -p "$APP_DIR/tools"
  cp -r "$SCRIPT_DIR/tools/." "$APP_DIR/tools/"
  chmod 755 "$APP_DIR/tools"/*.sh 2>/dev/null || true
fi
[ -f "$SCRIPT_DIR/gen_fw_fix.sh" ] && cp "$SCRIPT_DIR/gen_fw_fix.sh" "$APP_DIR/gen_fw_fix.sh"
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

if [ -f "/etc/init.d/proxy-manager" ]; then
  /etc/init.d/proxy-manager enable || true
  /etc/init.d/proxy-manager restart || /etc/init.d/proxy-manager start || true
fi
if [ -f "/etc/init.d/genrouter-old-gui" ]; then
  /etc/init.d/genrouter-old-gui enable || true
  /etc/init.d/genrouter-old-gui restart || /etc/init.d/genrouter-old-gui start || true
fi

for svc in genrouter-reverse-tunnel genrouter-frpc; do
  if [ -f "/etc/init.d/$svc" ]; then
    /etc/init.d/$svc stop || true
    /etc/init.d/$svc disable || true
    rm -f "/etc/init.d/$svc"
  fi
done

# ---- rc.local: GIU NGUYEN cac dong custom, chi bo dong frpc/reverse-tunnel ----
# BUG CU (truoc Ver 2.31): doan nay 'cat > /etc/rc.local' ghi de ca file bang
# template trong -> XOA MAT cac dong boot quan trong da co san tren router dang
# chay, vi du:
#   /etc/gen_runtime_tune.sh ...
#   /etc/genrouter/dyn24-runtime/start_dyn24.sh ...
#   /etc/genrouter_fix_fw.sh
# Hau qua: sau moi lan chay lai install.sh, router mat tune runtime + mat 24 shard
# gencore + mat firewall fix cho tan lan reboot sau. Gio chuyen sang MERGE.
if [ -f /etc/rc.local ]; then
  cp /etc/rc.local "/etc/rc.local.bak.gen_install.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
  # bo cac dong frpc / reverse-tunnel cu (khong dung nua)
  sed -i '/frpc/d; /reverse_tunnel/d; /start_frpc_loop/d' /etc/rc.local 2>/dev/null || true
else
  printf '%s\n' \
    '# Put your custom commands here that should be executed once' \
    '# the system init finished. By default this file does nothing.' \
    '' \
    'exit 0' > /etc/rc.local
fi
grep -q '^exit 0' /etc/rc.local 2>/dev/null || printf 'exit 0\n' >> /etc/rc.local
# dam bao firewall fix chay luc boot (guard duoc goi ben trong file nay)
if ! grep -q 'genrouter_fix_fw' /etc/rc.local 2>/dev/null; then
  sed -i '/^exit 0/i /etc/genrouter_fix_fw.sh' /etc/rc.local
fi
chmod +x /etc/rc.local

# ---- firewall + VPN guard: chay SAU khi rc.local da on dinh ----
[ -f "$APP_DIR/gen_fw_fix.sh" ] && sh "$APP_DIR/gen_fw_fix.sh" || true
# gen_vpn_guard: chua duong br-lan -> tun* (ipset genrouter_vpn + fw4 include),
# self-heal moi phut qua cron + hook trong genrouter_fix_fw.sh. Idempotent.
if [ -f "$APP_DIR/tools/gen_vpn_guard_install.sh" ]; then
  sh "$APP_DIR/tools/gen_vpn_guard_install.sh" "$APP_DIR/tools/gen_vpn_guard.sh" || true
fi

# ---- [Ver 2.44] etc/: kill-switch + tproxy da sua + cron watchdog ----
# Truoc Ver 2.44, install.sh CHI trien khai app dir va tools/, nen router moi
# pull source ve bi THIEU 3 thanh phan nam ngoai app dir:
#   /etc/genrouter_killswitch.sh          (chan may khong qua proxy/VPN ra WAN)
#   /etc/genrouter/core/tproxy + /etc/shm/tproxy  (ban da sua rt_tables 200/201)
#   dong cron */5 goi tools/dataplane_guard.py    (watchdog data-plane VPN)
# etc_install.sh idempotent va APPEND cron, khong ghi de crontab cua vendor.
if [ -f "$APP_DIR/tools/etc_install.sh" ] && [ -d "$SCRIPT_DIR/etc" ]; then
  sh "$APP_DIR/tools/etc_install.sh" "$SCRIPT_DIR/etc" || echo "[WARN] etc_install.sh that bai, tiep tuc"
fi

killall frpc >/dev/null 2>&1 || true
killall frpc_boot_loop.sh >/dev/null 2>&1 || true
killall start_frpc_loop.sh >/dev/null 2>&1 || true
pkill -f '/opt/proxy-manager-v1/frpc_boot_loop.sh' >/dev/null 2>&1 || true
pkill -f 'frpc.generated.toml' >/dev/null 2>&1 || true
killall ssh >/dev/null 2>&1 || true
rm -f /tmp/genrouter-frpc.log /tmp/genrouter-frpc-domain.log

if [ -f /etc/genrouter/core/run_server.sh ]; then
  cp /etc/genrouter/core/run_server.sh /etc/genrouter/core/run_server.sh.bak.gen_install 2>/dev/null || true
  cat > /etc/genrouter/core/run_server.sh <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x /etc/genrouter/core/run_server.sh
fi
if [ -f /etc/init.d/genrouter_server ]; then
  /etc/init.d/genrouter_server stop || true
  /etc/init.d/genrouter_server disable || true
  rm -f /etc/rc.d/S99genrouter_server /etc/rc.d/K10genrouter_server
fi
killall server >/dev/null 2>&1 || true
pkill -f '/etc/genrouter/server' >/dev/null 2>&1 || true

echo "[OK] Installed"
echo "[OK] Open: http://$LAN_IP:$PORT"
echo "[OK] XXTouch assets synced to: $APP_DIR/static/xxtouch"
echo "[OK] XXTouch admin LAN bypass ensured for router $LAN_IP"
echo "[OK] Old FRPC/reverse-tunnel cleanup completed (not installed)"
