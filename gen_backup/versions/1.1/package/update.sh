#!/bin/sh
set -eu

ROOT_DIR="/root"
APP_NAME="GEN"
REPO_OWNER="thttd94"
REPO_NAME="GEN"
REF="${1:-main}"
ARCHIVE="${APP_NAME}-${REF}.tar.gz"
BACKUP_DIR="${ROOT_DIR}/${APP_NAME}_bak_$(date +%Y%m%d_%H%M%S)"
TARGET_DIR="${ROOT_DIR}/${APP_NAME}"
WORK_DIR="${ROOT_DIR}/${APP_NAME}__extract_${REF}_$$"

case "$REF" in
  v*)
    URL="https://codeload.github.com/${REPO_OWNER}/${REPO_NAME}/tar.gz/refs/tags/${REF}"
    EXPECTED_DIR="${REPO_NAME}-${REF}"
    ;;
  *)
    URL="https://codeload.github.com/${REPO_OWNER}/${REPO_NAME}/tar.gz/refs/heads/${REF}"
    EXPECTED_DIR="${REPO_NAME}-${REF}"
    ;;
esac

echo "[INFO] Download ref: $REF"
rm -f "${ROOT_DIR}/${ARCHIVE}"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$ROOT_DIR"
wget --no-check-certificate -O "$ARCHIVE" "$URL"
tar -xzf "$ARCHIVE" -C "$WORK_DIR"

EXTRACTED_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -n "$EXTRACTED_DIR" ] || { echo "[ERR] Extract failed"; exit 1; }

if [ -d "$TARGET_DIR" ]; then
  mv "$TARGET_DIR" "$BACKUP_DIR"
  echo "[INFO] Backup current app to: $BACKUP_DIR"
fi

mv "$EXTRACTED_DIR" "$TARGET_DIR"
rm -rf "$WORK_DIR"

echo "$REF" > "$TARGET_DIR/VERSION.txt"
chmod +x "$TARGET_DIR/install.sh" "$TARGET_DIR/start.sh" "$TARGET_DIR/update.sh" "$TARGET_DIR/rollback.sh"
cd "$TARGET_DIR"
sh install.sh

echo "[OK] Deployed ref: $REF"
echo "[OK] Version file: $TARGET_DIR/VERSION.txt"
