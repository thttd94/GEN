#!/bin/sh
# ============================================================
# disk_expand.sh - tu mo rong phan vung root toi da theo disk trong
#
# Vi sao can: moi con Gen co o cung khac nhau, phan vung trong khac nhau.
# Script tu detect: disk nao, root nam o partition may, con bao nhieu
# sector trong sau partition cuoi, roi mo rong toi da co the.
#
# Nguyen tac:
#   - DRY-RUN mac dinh: chi in ke hoach, KHONG lam gi.
#   - --apply moi lam that. Co backup bang phan vung (sfdisk dump).
#   - Chi mo rong partition root khi free space LIEN KE ngay sau no.
#     Neu free nam sau partition khac (vd p4 chua GEN repo) thi BAO,
#     khong tu dong xoa/di doi du lieu nguoi khac.
#   - resize2fs online duoc (ext4 mounted) nen khong can reboot.
#   - DUNG khi: khong co free space, khong co fdisk/resize2fs,
#     root khong phai ext2/3/4, khong phai GPT/MBR doc duoc.
#
# Cach dung:
#   sh disk_expand.sh              # xem ke hoach (dry-run)
#   sh disk_expand.sh --apply      # lam that
#   sh disk_expand.sh --apply --target /dev/nvme0n1   # chi dinh disk
#
# Tich hop: install.sh hoac cron goi o che do dry-run de canh bao,
#           nguoi van hanh duyet roi chay --apply tay.
# ============================================================
set -u

APPLY=0
TARGET_DISK=""

for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --target) shift ;;
    --target=*) TARGET_DISK="${a#--target=}" ;;
    -h|--help)
      sed -n '2,/^# ===/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) [ -z "$TARGET_DISK" ] && case "$a" in /dev/*) TARGET_DISK="$a" ;; esac ;;
  esac
done

log()  { echo "[$1] $2"; }
die()  { log ERR "$1"; exit 1; }

# --- 1) tim root device + disk ---
ROOT_SRC="$(cat /proc/mounts 2>/dev/null | awk '$2=="/" {print $1; exit}')"
[ -n "$ROOT_SRC" ] || die "khong xac dinh duoc root device"
# /dev/root -> giai root that (nhieu Gen boot bang PARTUUID nen mount hien /dev/root ao)
# thu tu: mountinfo (major:minor) -> sysfs -> readlink
if [ "$ROOT_SRC" = "/dev/root" ]; then
  # cach 1: /proc/self/mountinfo cot 3 la major:minor cua mountpoint /
  MM="$(awk '$5=="/" {print $3; exit}' /proc/self/mountinfo 2>/dev/null)"
  if [ -n "$MM" ]; then
    for ue in /sys/block/*/dev /sys/block/*/*/dev; do
      [ -f "$ue" ] || continue
      if [ "$(cat "$ue" 2>/dev/null)" = "$MM" ]; then
        # /sys/block/nvme0n1/nvme0n1p3/dev -> /dev/nvme0n1p3
        bn="$(basename "$(dirname "$ue")")"
        ROOT_SRC="/dev/$bn"
        break
      fi
    done
  fi
  # cach 2: readlink (khi co udev)
  if [ "$ROOT_SRC" = "/dev/root" ]; then
    RL="$(readlink -f /dev/root 2>/dev/null)"
    [ -n "$RL" ] && [ "$RL" != "/dev/root" ] && ROOT_SRC="$RL"
  fi
  if [ "$ROOT_SRC" = "/dev/root" ]; then
    # doan qua sysfs: tim device co mountpoint /
    for d in /sys/block/*/; do
      bn="$(basename "$d")"
      for p in "$d$bn"p* "$d$bn"*; do :; done
    done
    # fallback: lay tu /proc/cmdline (root=PARTUUID=...) khong giai duoc -> bao loi
    die "root la /dev/root ao, hay chay voi --target /dev/XXX (vd --target /dev/nvme0n1)"
  fi
fi

DISK="$TARGET_DISK"
if [ -z "$DISK" ]; then
  # cat so cuoi cua partition: /dev/nvme0n1p3 -> /dev/nvme0n1 ; /dev/sda3 -> /dev/sda
  case "$ROOT_SRC" in
    *p[0-9]*) DISK="${ROOT_SRC%p[0-9]*}" ;;
    *[0-9])   DISK="$(echo "$ROOT_SRC" | sed 's/[0-9]*$//')" ;;
    *) die "khong doan duoc disk tu $ROOT_SRC, hay dung --target" ;;
  esac
fi
[ -b "$DISK" ] || die "disk khong ton tai: $DISK"

ROOT_PART="$ROOT_SRC"
log INFO "root=$ROOT_PART disk=$DISK che do=$([ $APPLY = 1 ] && echo APPLY || echo DRY-RUN)"

# --- 2) cong cu ---
for t in fdisk resize2fs; do
  if ! which "$t" >/dev/null 2>&1; then
    # thu trong chroot ubuntu neu co (Gen mang theo /data/ubroot)
    if [ -x /data/ubroot/sbin/$t ]; then
      log INFO "dung $t tu chroot /data/ubroot"
      alias $t="chroot /data/ubroot /sbin/$t" 2>/dev/null || true
    else
      die "thieu cong cu: $t"
    fi
  fi
done

# --- 3) doc bang phan vung ---
command -v fdisk >/dev/null 2>&1 || die "thieu fdisk"
PTABLE="$(fdisk -l "$DISK" 2>/dev/null)" || die "khong doc duoc bang phan vung $DISK"
echo "$PTABLE" | head -12

DISK_SECTORS="$(echo "$PTABLE" | grep -oE '[0-9]+ sectors' | head -1 | awk '{print $1}')"
[ -n "$DISK_SECTORS" ] || die "khong doc duoc tong sectors"

# dong cua root partition: lay End hien tai + so thu tu
ROOT_LINE="$(echo "$PTABLE" | grep -E "^$ROOT_PART[[:space:]]")"
[ -n "$ROOT_LINE" ] || die "khong thay $ROOT_PART trong bang phan vung"
ROOT_END="$(echo "$ROOT_LINE" | awk '{print $3}')"
ROOT_NUM="$(echo "$ROOT_PART" | grep -oE '[0-9]+$')"
log INFO "root la partition so $ROOT_NUM, End hien tai = sector $ROOT_END, tong disk = $DISK_SECTORS sectors"

# partition co End lon nhat (tinh ca root)
MAX_END=0
LAST_DEV=""
echo "$PTABLE" | grep -E "^$DISK" | while read -r dev start end rest; do
  echo "$end $dev"
done | sort -rn | head -5 > /tmp/disk_expand.parts 2>/dev/null
if [ ! -s /tmp/disk_expand.parts ]; then
  echo "$PTABLE" | awk -v d="$DISK" '$1 ~ "^"d {print $3, $1}' | sort -rn | head -5 > /tmp/disk_expand.parts
fi
read -r MAX_END LAST_DEV < /tmp/disk_expand.parts
log INFO "partition ket thuc muon nhat: $LAST_DEV (End=$MAX_END)"

FREE_AFTER=$((DISK_SECTORS - MAX_END - 34))
# tru 34 sectors GPT backup o cuoi disk
[ "$FREE_AFTER" -lt 0 ] && FREE_AFTER=0
FREE_MB=$((FREE_AFTER * 512 / 1024 / 1024))
log INFO "free space sau partition cuoi: ~${FREE_MB}MB ($FREE_AFTER sectors)"

if [ "$FREE_AFTER" -lt 2048 ]; then
  log INFO "khong con cho trong dang ke (<1MB). Khong mo rong duoc."
  log INFO "goi y: neu muon gop partition data (vd p4 GEN repo) vao root,"
  log INFO "      hay backup du lieu p4, xoa p4, roi chay lai script nay."
  rm -f /tmp/disk_expand.parts
  exit 0
fi

if [ "$LAST_DEV" != "$ROOT_PART" ]; then
  log WARN "free space nam sau $LAST_DEV, KHONG lien ke root ($ROOT_PART)."
  log WARN "script khong tu dong xoa/di doi $LAST_DEV."
  log WARN "muon mo rong root: backup $LAST_DEV -> xoa no (fdisk) -> chay lai script."
  rm -f /tmp/disk_expand.parts
  exit 0
fi

# --- 4) ke hoach mo rong root ---
NEW_END=$((DISK_SECTORS - 34))
ADD_MB=$(((NEW_END - ROOT_END) * 512 / 1024 / 1024))
log INFO "ke hoach: mo rong $ROOT_PART tu sector $ROOT_END -> $NEW_END (+~${ADD_MB}MB)"

if [ "$APPLY" -ne 1 ]; then
  log INFO "DRY-RUN: chua lam gi. Chay voi --apply de thuc hien."
  rm -f /tmp/disk_expand.parts
  exit 0
fi

# --- 5) backup + lam that ---
BK="/data/genrouter_backups/disk_expand_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BK" 2>/dev/null
if which sfdisk >/dev/null 2>&1; then
  sfdisk -d "$DISK" > "$BK/partition.dump" 2>/dev/null && log INFO "backup bang phan vung: $BK/partition.dump"
else
  echo "$PTABLE" > "$BK/fdisk-l.txt" 2>/dev/null && log INFO "backup fdisk -l: $BK/fdisk-l.txt"
fi

log INFO "xoa + tao lai partition $ROOT_NUM giu nguyen Start, End moi = $NEW_END ..."
ROOT_START="$(echo "$ROOT_LINE" | awk '{print $2}')"
(
echo d
echo "$ROOT_NUM"
echo n
echo "$ROOT_NUM"
echo "$ROOT_START"
echo "$NEW_END"
echo w
) | fdisk "$DISK" 2>&1 | tail -3

log INFO "resize filesystem online ..."
if [ -x /data/ubroot/sbin/resize2fs ] && ! which resize2fs >/dev/null 2>&1; then
  chroot /data/ubroot /sbin/resize2fs "$ROOT_PART" 2>&1 | tail -3
else
  resize2fs "$ROOT_PART" 2>&1 | tail -3
fi

log INFO "ket qua:"
df -h / | tail -1
rm -f /tmp/disk_expand.parts
log INFO "xong. backup o $BK"
