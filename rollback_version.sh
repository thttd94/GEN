#!/bin/sh
set -eu

VERSION="${1:-1.1}"
VERSION="$(printf '%s' "$VERSION" | sed 's/^[Vv]//')"
APP_DIR="${APP_DIR:-/opt/proxy-manager-v1}"

if [ -n "${BACKUP_ROOT:-}" ]; then
  CANDIDATE_ROOTS="$BACKUP_ROOT"
else
  CANDIDATE_ROOTS="/data/genrouter_backups/versions /root/genrouter_backups/versions"
fi

PKG_DIR=""
SYSTEM_DIR=""
BACKUP_ROOT=""
for root in $CANDIDATE_ROOTS; do
  if [ -d "$root/$VERSION/package" ]; then
    PKG_DIR="$root/$VERSION/package"
    SYSTEM_DIR="$root/$VERSION/system"
    BACKUP_ROOT="$root"
    break
  fi
done

if [ -z "$PKG_DIR" ]; then
  echo "[ERR] backup version not found: $VERSION"
  echo "[ERR] searched: $CANDIDATE_ROOTS"
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo now)"
mkdir -p "$BACKUP_ROOT/_pre_rollback"
if [ -d "$APP_DIR" ]; then
  cp -a "$APP_DIR" "$BACKUP_ROOT/_pre_rollback/app_before_${VERSION}_${TS}"
fi

restore_tar() {
  tarfile="$1"
  label="$2"
  if [ -f "$tarfile" ]; then
    echo "[INFO] restoring $label from $tarfile"
    tar -C / -xzf "$tarfile"
  fi
}

/etc/init.d/proxy-manager-v1 stop 2>/dev/null || true
/etc/init.d/proxy-manager stop 2>/dev/null || true
/etc/init.d/genrouter-old-gui stop 2>/dev/null || true

# Full system restore first when the version contains system snapshots.
# Version backups themselves are never inside these tarballs.
if [ -d "$SYSTEM_DIR" ]; then
  restore_tar "$SYSTEM_DIR/etc_config.tgz" /etc/config
  restore_tar "$SYSTEM_DIR/etc_genrouter.tgz" /etc/genrouter
  restore_tar "$SYSTEM_DIR/etc_init_d.tgz" /etc/init.d
  restore_tar "$SYSTEM_DIR/etc_rc_local.tgz" /etc/rc.local
  restore_tar "$SYSTEM_DIR/etc_crontabs.tgz" /etc/crontabs
  restore_tar "$SYSTEM_DIR/etc_shm.tgz" /etc/shm
  restore_tar "$SYSTEM_DIR/opt_proxy_manager_v1.tgz" /opt/proxy-manager-v1
fi

# Always restore package app cleanly as final source of truth for this version.
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
cp -a "$PKG_DIR/." "$APP_DIR/"
chmod +x "$APP_DIR"/*.sh 2>/dev/null || true
chmod +x /etc/init.d/proxy-manager-v1 2>/dev/null || true
chmod +x /etc/init.d/proxy-manager 2>/dev/null || true
chmod +x /etc/init.d/genrouter-old-gui 2>/dev/null || true
chmod +x /etc/rc.local 2>/dev/null || true

/etc/init.d/network reload 2>/dev/null || true
/etc/init.d/cron restart 2>/dev/null || true
/etc/init.d/proxy-manager-v1 enable 2>/dev/null || true
/etc/init.d/proxy-manager-v1 restart 2>/dev/null || /etc/init.d/proxy-manager-v1 start 2>/dev/null || python3 "$APP_DIR/app.py" >/tmp/proxy-manager-v1.log 2>&1 &

if [ -f /etc/init.d/genrouter ]; then /etc/init.d/genrouter restart 2>/dev/null || true; fi
if [ -f /etc/init.d/genrouter_server ]; then /etc/init.d/genrouter_server restart 2>/dev/null || true; fi
if [ -f /etc/init.d/proxy-manager ]; then /etc/init.d/proxy-manager restart 2>/dev/null || true; fi
if [ -f /etc/init.d/genrouter-old-gui ]; then /etc/init.d/genrouter-old-gui restart 2>/dev/null || true; fi

echo "[OK] rolled back full GEN system/app to version $VERSION"
