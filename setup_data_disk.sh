#!/bin/sh
set -eu

DISK="${1:-/dev/nvme0n1}"
PART_NUM="4"
PART="${DISK}p${PART_NUM}"
MOUNT_POINT="${DATA_MOUNT_POINT:-/data}"
BACKUP_DIR="$MOUNT_POINT/genrouter_backups"

if [ ! -b "$DISK" ]; then
  echo "[WARN] disk not found: $DISK; skip data partition setup"
  exit 0
fi

if mount | grep -q " $MOUNT_POINT "; then
  echo "[OK] $MOUNT_POINT already mounted"
  mkdir -p "$BACKUP_DIR" "$MOUNT_POINT/proxy-manager" "$MOUNT_POINT/log"
  df -h "$MOUNT_POINT" || true
  exit 0
fi

if [ -b "$PART" ]; then
  echo "[OK] data partition exists: $PART"
else
  START_SECTOR="$(fdisk -l "$DISK" 2>/dev/null | awk -v disk="$DISK" '
    $1 ~ "^" disk "p?[0-9]+$" { if ($3+0 > max) max=$3+0 }
    END { if (max>0) print max+2048 }
  ')"
  if [ -z "$START_SECTOR" ]; then
    echo "[WARN] cannot detect free partition start on $DISK; skip data partition setup"
    exit 0
  fi
  END_SECTOR="$(fdisk -l "$DISK" 2>/dev/null | awk '/sectors$/ {print $7; exit}')"
  if [ -n "$END_SECTOR" ] && [ "$START_SECTOR" -ge "$END_SECTOR" ]; then
    echo "[WARN] no free space for partition $PART on $DISK; skip data partition setup"
    exit 0
  fi
  echo "[INFO] creating data partition $PART from sector $START_SECTOR"
  if ! printf "n\n${PART_NUM}\n${START_SECTOR}\n\nw\n" | fdisk "$DISK"; then
    echo "[WARN] failed to create $PART; skip data partition setup"
    exit 0
  fi
  sync
  sleep 2
fi

if [ ! -b "$PART" ]; then
  echo "[WARN] partition still missing after create attempt: $PART; skip data partition setup"
  exit 0
fi

if ! blkid "$PART" 2>/dev/null | grep -qi 'ext4'; then
  echo "[INFO] formatting $PART as ext4"
  mkfs.ext4 -F "$PART"
fi

mkdir -p "$MOUNT_POINT"
if ! mount "$PART" "$MOUNT_POINT"; then
  echo "[WARN] failed to mount $PART at $MOUNT_POINT; skip data partition setup"
  exit 0
fi

grep -q "^$PART $MOUNT_POINT ext4 " /etc/fstab 2>/dev/null || echo "$PART $MOUNT_POINT ext4 defaults 0 0" >> /etc/fstab
mkdir -p "$BACKUP_DIR" "$MOUNT_POINT/proxy-manager" "$MOUNT_POINT/log"

echo "[OK] data partition ready: $PART -> $MOUNT_POINT"
df -h "$MOUNT_POINT" || true
