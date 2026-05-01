#!/bin/sh
set -eu

ROOT_DIR="/root"
APP_NAME="GEN"
TARGET_DIR="${ROOT_DIR}/${APP_NAME}"
ARG="${1:-}"

if [ -z "$ARG" ]; then
  echo "Usage: ./rollback.sh <backup_folder_name|git_tag>"
  echo "Example backup: ./rollback.sh GEN_bak_20260418_104500"
  echo "Example tag:    ./rollback.sh v2026.04.18-01"
  exit 1
fi

case "$ARG" in
  GEN_bak_*)
    BACKUP_PATH="${ROOT_DIR}/${ARG}"
    [ -d "$BACKUP_PATH" ] || { echo "[ERR] Backup not found: $BACKUP_PATH"; exit 1; }
    rm -rf "$TARGET_DIR"
    mv "$BACKUP_PATH" "$TARGET_DIR"
    cd "$TARGET_DIR"
    chmod +x install.sh start.sh update.sh rollback.sh
    sh install.sh
    echo "[OK] Rolled back from backup: $ARG"
    ;;
  v*)
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    exec "$SCRIPT_DIR/update.sh" "$ARG"
    ;;
  *)
    echo "[ERR] Invalid argument: $ARG"
    echo "Use backup folder name like GEN_bak_YYYYMMDD_HHMMSS or tag like v2026.04.18-01"
    exit 1
    ;;
esac
