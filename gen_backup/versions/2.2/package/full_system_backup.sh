#!/bin/sh
set -eu
VERSION_RAW="${1:-$(cat /opt/proxy-manager-v1/VERSION.txt 2>/dev/null || cat ./VERSION.txt 2>/dev/null || echo 1.1)}"
VERSION="$(printf '%s' "$VERSION_RAW" | sed 's/^[Vv]//')"
if [ -d /data ] && mount | grep -q ' /data '; then BACKUP_ROOT="${BACKUP_ROOT:-/data/genrouter_backups/versions}"; else BACKUP_ROOT="${BACKUP_ROOT:-/root/genrouter_backups/versions}"; fi
DEST="$BACKUP_ROOT/$VERSION"; SNAP="$DEST/system"; PKG="$DEST/package"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rm -rf "$PKG" "$SNAP"; mkdir -p "$PKG" "$SNAP"
# Copy package without nested backups/cache/VCS. BusyBox compatible.
for item in "$SCRIPT_DIR"/* "$SCRIPT_DIR"/.[!.]*; do
  [ -e "$item" ] || continue
  base="$(basename "$item")"
  case "$base" in .git|__pycache__|gen_backup) continue;; esac
  cp -a "$item" "$PKG/"
done
find "$PKG" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$PKG" -type f -name '*.pyc' -delete 2>/dev/null || true
backup_path(){ src="$1"; name="$2"; if [ -e "$src" ]; then tar -C / -czf "$SNAP/$name.tgz" "${src#/}"; echo "[OK] snapshot $src"; else echo "[SKIP] missing $src"; fi; }
backup_path /opt/proxy-manager-v1 opt_proxy_manager_v1
backup_path /etc/genrouter etc_genrouter
backup_path /etc/config etc_config
backup_path /etc/init.d etc_init_d
backup_path /etc/rc.local etc_rc_local
backup_path /etc/crontabs etc_crontabs
backup_path /etc/shm etc_shm
{
 echo "VERSION=$VERSION"; echo "DATE=$(date 2>/dev/null || true)"; echo "UNAME=$(uname -a 2>/dev/null || true)";
 echo "--- mount"; mount 2>/dev/null || true; echo "--- df"; df -h 2>/dev/null || true; echo "--- blkid"; blkid 2>/dev/null || true; echo "--- lsblk"; lsblk 2>/dev/null || true; echo "--- fdisk"; fdisk -l 2>/dev/null || true; echo "--- ip addr"; ip addr 2>/dev/null || true; echo "--- ip route"; ip route 2>/dev/null || true; echo "--- services"; ls -l /etc/init.d 2>/dev/null || true;
} > "$SNAP/system_manifest.txt"
[ -f "$SCRIPT_DIR/rollback_version.sh" ] && cp "$SCRIPT_DIR/rollback_version.sh" "$PKG/rollback_version.sh" 2>/dev/null || true
chmod +x "$PKG"/*.sh 2>/dev/null || true
echo "[OK] full system backup saved: $DEST"
