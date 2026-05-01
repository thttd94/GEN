#!/bin/sh
set -eu

VERSION="${1:-1.1}"
APP_DIR="${APP_DIR:-/opt/proxy-manager-v1}"
BACKUP_ROOT="${BACKUP_ROOT:-/root/genrouter_backups/versions}"
PKG_DIR="$BACKUP_ROOT/$VERSION/package"

if [ ! -d "$PKG_DIR" ]; then
  echo "[ERR] backup version not found: $VERSION ($PKG_DIR)"
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo now)"
mkdir -p "$BACKUP_ROOT/_pre_rollback"
if [ -d "$APP_DIR" ]; then
  cp -a "$APP_DIR" "$BACKUP_ROOT/_pre_rollback/app_before_${VERSION}_${TS}"
fi

/etc/init.d/proxy-manager-v1 stop 2>/dev/null || true
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
cp -a "$PKG_DIR/." "$APP_DIR/"
chmod +x "$APP_DIR"/*.sh 2>/dev/null || true
chmod +x /etc/init.d/proxy-manager-v1 2>/dev/null || true
/etc/init.d/proxy-manager-v1 enable 2>/dev/null || true
/etc/init.d/proxy-manager-v1 restart 2>/dev/null || /etc/init.d/proxy-manager-v1 start 2>/dev/null || python3 "$APP_DIR/app.py" >/tmp/proxy-manager-v1.log 2>&1 &

echo "[OK] rolled back to version $VERSION"
