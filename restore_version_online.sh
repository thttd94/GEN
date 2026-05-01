#!/bin/sh
set -e
VERSION="${1:-2.2}"
VERSION="$(printf '%s' "$VERSION" | sed 's/^[Vv]//')"
URL="${GEN_FULL_URL:-https://github.com/thttd94/GEN/releases/download/v${VERSION}/genrouter-v${VERSION}-full.tar.gz}"

pick_workdir() {
  for d in /data /mnt/nvme0n1p4 /mnt/nvme0n1p3 /mnt/nvme0n1p2 /tmp /root; do
    [ -d "$d" ] || continue
    avail="$(df -k "$d" 2>/dev/null | awk 'NR==2{print $4}')"
    [ -n "$avail" ] || continue
    if [ "$avail" -gt 51200 ]; then
      echo "$d/genrouter_restore_work"
      return 0
    fi
  done
  echo /tmp/genrouter_restore_work
}

WORKDIR="${GEN_WORKDIR:-$(pick_workdir)}"
BACKUP_BASE="${GEN_BACKUP_BASE:-}"
if [ -z "$BACKUP_BASE" ]; then
  if [ -d /data ] && df -k /data 2>/dev/null | awk 'NR==2{exit !($4>51200)}'; then
    BACKUP_BASE=/data/genrouter_backups/versions
  else
    BACKUP_BASE=/root/genrouter_backups/versions
  fi
fi
DEST="$BACKUP_BASE/$VERSION"
ARCHIVE="$WORKDIR/genrouter-v${VERSION}-full.tar.gz"
EXTRACT="$WORKDIR/extract"

mkdir -p "$WORKDIR" "$BACKUP_BASE"
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"

echo "[INFO] version=$VERSION"
echo "[INFO] url=$URL"
echo "[INFO] workdir=$WORKDIR"
echo "[INFO] backup=$DEST"

if command -v curl >/dev/null 2>&1; then
  curl -L --insecure -o "$ARCHIVE" "$URL"
else
  wget --no-check-certificate -O "$ARCHIVE" "$URL"
fi

tar -xzf "$ARCHIVE" -C "$EXTRACT"
SRC="$EXTRACT/genrouter_v${VERSION}_full"
if [ ! -d "$SRC" ]; then
  SRC="$(find "$EXTRACT" -maxdepth 1 -type d -name 'genrouter_*_full' | head -n1)"
fi
[ -d "$SRC/package" ] || { echo "[ERR] package missing in artifact"; exit 1; }
[ -d "$SRC/system" ] || { echo "[ERR] system missing in artifact"; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"
cp -a "$SRC/package" "$DEST/package"
cp -a "$SRC/system" "$DEST/system"

# Use the bootstrap rollback script from current Git when available because it
# contains the latest restore safety logic (network preservation, service fixes).
if [ -f "./rollback_version.sh" ]; then
  cp ./rollback_version.sh "$DEST/package/rollback_version.sh"
elif [ -f "/opt/proxy-manager-v1/rollback_version.sh" ]; then
  cp /opt/proxy-manager-v1/rollback_version.sh "$DEST/package/rollback_version.sh"
fi

if [ -f "$DEST/package/rollback_version.sh" ]; then
  chmod +x "$DEST/package/rollback_version.sh"
  PRESERVE_NETWORK="${PRESERVE_NETWORK:-1}" SKIP_PRE_ROLLBACK="${SKIP_PRE_ROLLBACK:-1}" sh "$DEST/package/rollback_version.sh" "$VERSION"
else
  echo "[ERR] rollback_version.sh missing in artifact package"
  exit 1
fi

echo "[OK] restored GEN router version $VERSION from full artifact"
