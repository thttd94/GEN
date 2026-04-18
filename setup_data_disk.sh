#!/bin/sh
set -eu

DISK="${1:-/dev/nvme0n1}"
PART_NUM="4"
START_SECTOR="680448"
PART="${DISK}p${PART_NUM}"
MOUNT_POINT="/data"

if [ ! -b "$DISK" ]; then
  echo "[ERR] disk not found: $DISK"
  exit 1
fi

if mount | grep -q " $MOUNT_POINT "; then
  echo "[OK] $MOUNT_POINT already mounted"
  df -h "$MOUNT_POINT" || true
  exit 0
fi

echo "=== CHECK DISK ==="
fdisk -l "$DISK"
df -h

if [ ! -b "$PART" ]; then
  echo
  echo "=== CREATE PARTITION ${PART_NUM} ==="
  printf "n\n${PART_NUM}\n${START_SECTOR}\n\nw\n" | fdisk "$DISK"
  sync
  sleep 2
fi

if ! blkid "$PART" 2>/dev/null | grep -qi 'ext4'; then
  echo
  echo "=== FORMAT ${PART} EXT4 ==="
  mkfs.ext4 "$PART"
fi

echo
 echo "=== MOUNT ${MOUNT_POINT} ==="
mkdir -p "$MOUNT_POINT"
mount "$PART" "$MOUNT_POINT"

grep -q "^$PART $MOUNT_POINT ext4 " /etc/fstab 2>/dev/null || echo "$PART $MOUNT_POINT ext4 defaults 0 0" >> /etc/fstab
mkdir -p "$MOUNT_POINT/proxy-manager" "$MOUNT_POINT/frp" "$MOUNT_POINT/log"

echo
 echo "=== DONE ==="
df -h "$MOUNT_POINT"
fdisk -l "$DISK"
