#!/bin/sh
# ============================================================
# disk_expand.sh (Ver 2.77) - mo rong phan vung root (p3) toi het o dia
#
# Vi sao: Gen14 root p3 chi 300M (dung 84%), p4 13G rong nam ngay sau.
# Gen15/17 p3 da 6.1G => khong can, script tu bo qua.
#
# Che do:
#   sh disk_expand.sh            # DRY-RUN: in ke hoach, KHONG thay doi gi
#   sh disk_expand.sh --apply    # lam that ngay (bo qua nguong dung %, van du kiem an toan)
#   sh disk_expand.sh --auto     # tu dong: chi lam khi root dung >=70% hoac con <100MB
#   sh disk_expand.sh --auto-bg  # etc_install goi: chay nen --auto sau 90s, khong chan update
#
# An toan (ly do ban 2.51 bi bo: fdisk d+n tao PARTUUID MOI => kernel
# root=PARTUUID=... khong thay root => router KHONG BOOT):
#   - Dung sfdisk -N <so> ", +" => GIU NGUYEN start + PARTUUID + type cua p3.
#     Ghi xong doc lai: UUID/start khac => tu khoi phuc bang cu, KHONG reboot.
#   - PARTUUID p3 phai khop root=PARTUUID trong /proc/cmdline, khac => dung.
#   - Chi GPT. Sau root toi da 1 partition (p4), phai la partition cuoi.
#   - p4 chi duoc chua: lost+found log proxy-manager genrouter_backups GEN
#     GEN-main.tar.gz gen_update_work genrouter_restore_work; tong <=30MB.
#     Co thu khac => dung, ghi disk_expand.blocked, khong tu thu lai.
#   - p4 dang co tien trinh dung / dang update => hoan (lan boot sau thu lai).
#   - Backup: bang phan vung (sfdisk dump) + 34 sector dau/33 sector cuoi
#     + noi dung p4 (tgz) vao /data/genrouter_backups/disk_expand_<time>/.
#   - Loi truoc resize2fs => ghi lai bang cu, mount lai p4, dung.
#   - resize2fs online (ext4 dang mount), khong reboot. Kernel khong nhan bang
#     moi => ghi disk_expand.pending, lan boot sau tu resize.
#   - Chi chay 1 lan: disk_expand.done. Muon thu lai sau khi blocked: xoa
#     /opt/proxy-manager-v1/logs/disk_expand.blocked.
# Log: /opt/proxy-manager-v1/logs/disk_expand.log
# ============================================================
set -u

MODE=dry
DELAY=0
for a in "$@"; do
  case "$a" in
    --apply) MODE=apply ;;
    --auto) MODE=auto ;;
    --auto-bg) MODE=autobg ;;
    --dry-run) MODE=dry ;;
    --delay=*) DELAY="${a#--delay=}" ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

SELF="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")"
APP=/opt/proxy-manager-v1
TEST="${DX_TEST:-0}"
if [ "$TEST" = 1 ]; then
  STATE_DIR="${DX_STATE_DIR:?}"; BK_ROOT="${DX_BK_DIR:?}"
else
  STATE_DIR="$APP/logs"; BK_ROOT=/data/genrouter_backups
fi
LOG="$STATE_DIR/disk_expand.log"
DONE="$STATE_DIR/disk_expand.done"
BLOCKED="$STATE_DIR/disk_expand.blocked"
PENDING="$STATE_DIR/disk_expand.pending"
TOOLS="${DX_TOOLS:-/tmp/disk_expand_tools}"
USE_PCT_MIN="${DX_USE_PCT:-70}"
FREE_MB_MIN="${DX_FREE_MB:-100}"
GAIN_MB_MIN="${DX_GAIN_MB:-64}"
P4_MAX_KB="${DX_P4_MAX_KB:-30720}"
FAIL_AT=""; [ "$TEST" = 1 ] && FAIL_AT="${DX_FAIL_AT:-}"
STAMP="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$STATE_DIR" 2>/dev/null

log() {
  echo "[$1] $2"
  [ "$MODE" = dry ] && return 0
  echo "$(date '+%F %T') [$MODE] [$1] $2" >> "$LOG" 2>/dev/null
}
# ket thuc: SKIP/DEFER = khong lam gi, lan sau thu lai; BLOCK = dung han
finish() { # $1 kind $2 msg
  log "$1" "$2"
  if [ "$1" = BLOCK ] && [ "$MODE" != dry ]; then
    echo "$(date '+%F %T') $2" > "$BLOCKED" 2>/dev/null
  fi
  [ "$1" = BLOCK ] && exit 2
  exit 0
}
if [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 262144 ]; then
  tail -n 500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# ---------- --auto-bg: hen chay nen, tra ve ngay ----------
if [ "$MODE" = autobg ]; then
  if [ -f "$DONE" ]; then echo "[=] disk_expand da xong truoc do ($(head -c 80 "$DONE"))"; exit 0; fi
  if [ -f "$BLOCKED" ]; then echo "[=] disk_expand dang bi chan: $(head -c 160 "$BLOCKED")"; exit 0; fi
  # router KHONG co nohup/setsid (BusyBox) => subshell bo HUP, tach stdin/stdout
  ( trap '' HUP; exec sh "$SELF" --auto --delay="${DX_DELAY:-90}" >/dev/null 2>&1 </dev/null ) &
  echo "[i] disk_expand --auto se chay nen sau ${DX_DELAY:-90}s (log: $LOG)"
  exit 0
fi

if [ "$MODE" = auto ]; then
  [ -f "$DONE" ] && exit 0
  [ -f "$BLOCKED" ] && exit 0
fi
exec 9>/tmp/disk_expand.lock
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { echo "[=] disk_expand dang chay o tien trinh khac"; exit 0; }
fi
[ "$DELAY" -gt 0 ] 2>/dev/null && sleep "$DELAY"
if [ "$MODE" = auto ]; then
  n=0
  while ps w 2>/dev/null | grep -v grep | grep -qE 'gen_update\.sh|restore_version_online\.sh'; do
    n=$((n+1)); [ $n -gt 40 ] && finish DEFER "update dang chay qua 10 phut, de lan boot sau"
    sleep 15
  done
fi

# ---------- 1) root partition + disk ----------
if [ "$TEST" = 1 ]; then
  ROOT_PART="${DX_ROOT_PART:?}"; ROOT_MNT="${DX_ROOT_MNT:?}"
else
  ROOT_MNT=/
  MM="$(awk '$5=="/" {print $3; exit}' /proc/self/mountinfo 2>/dev/null)"
  ROOT_PART=""
  for f in /sys/class/block/*/dev; do
    [ "$(cat "$f" 2>/dev/null)" = "$MM" ] && { ROOT_PART="/dev/$(basename "$(dirname "$f")")"; break; }
  done
  [ -n "$ROOT_PART" ] || finish BLOCK "khong tim duoc partition root (major:minor=$MM)"
fi
RB="$(basename "$ROOT_PART")"
[ -f "/sys/class/block/$RB/partition" ] || finish BLOCK "root $ROOT_PART khong phai partition"
ROOT_NUM="$(cat "/sys/class/block/$RB/partition")"
DISK_B=""
for d in /sys/block/*/"$RB"; do [ -d "$d" ] && DISK_B="$(basename "$(dirname "$d")")"; done
[ -n "$DISK_B" ] || finish BLOCK "khong tim duoc disk chua $RB"
DISK="/dev/$DISK_B"
if [ "$TEST" = 1 ]; then
  case "$DISK_B" in loop*) ;; *) echo "[ERR] DX_TEST chi cho phep /dev/loop*"; exit 3 ;; esac
fi
pdev() { case "$DISK_B" in *[0-9]) echo "${DISK}p$1" ;; *) echo "${DISK}$1" ;; esac; }
log INFO "root=$ROOT_PART (so $ROOT_NUM) disk=$DISK che do=$MODE"

# ---------- 2) partition sau root (kernel view) ----------
R_START="$(cat "/sys/class/block/$RB/start")"; R_SIZE="$(cat "/sys/class/block/$RB/size")"
R_END=$((R_START + R_SIZE - 1))
DISK_SEC="$(cat "/sys/block/$DISK_B/size")"
LBS="$(cat "/sys/block/$DISK_B/queue/logical_block_size" 2>/dev/null || echo 512)"
[ "$LBS" = 512 ] || finish BLOCK "logical sector $LBS != 512, script chua ho tro"
AFTER=""; AFTER_N=0
for p in /sys/block/"$DISK_B"/"$DISK_B"*; do
  [ -f "$p/partition" ] || continue
  s="$(cat "$p/start")"
  if [ "$s" -gt "$R_START" ]; then AFTER="$(cat "$p/partition")"; AFTER_N=$((AFTER_N+1)); fi
done
[ "$AFTER_N" -le 1 ] || finish BLOCK "sau root co $AFTER_N partition, chi ho tro toi da 1 (p4)"
DATA_NUM="$AFTER"; DATA_PART=""; [ -n "$DATA_NUM" ] && DATA_PART="$(pdev "$DATA_NUM")"

# ---------- 3) tinh trang + nguong ----------
set -- $(df -kP "$ROOT_MNT" 2>/dev/null | awk 'NR==2{print $2, $3, $4, $5}')
FS_TOTAL_KB="${1:-0}"; FS_AVAIL_KB="${3:-0}"; FS_PCT="${4:-0%}"; FS_PCT="${FS_PCT%\%}"
GAIN_MB=$(( (DISK_SEC - 34 - 1 - R_END) / 2048 ))
log INFO "root ${FS_TOTAL_KB}KB dung ${FS_PCT}% con ${FS_AVAIL_KB}KB; partition sau root: ${DATA_PART:-khong}; co the them ~${GAIN_MB}MB"
FSTYPE="$(awk -v m="$ROOT_MNT" '$2==m {t=$3} END{print t}' /proc/mounts)"
case "$FSTYPE" in ext4|ext3|ext2) ;; *) finish BLOCK "root la $FSTYPE, chi ho tro ext2/3/4" ;; esac

if [ -f "$PENDING" ] && [ "$MODE" != dry ]; then
  RESUME=1
else
  RESUME=0
  [ "$GAIN_MB" -ge "$GAIN_MB_MIN" ] || finish SKIP "khong con cho mo rong (<${GAIN_MB_MIN}MB)"
  if [ "$MODE" = auto ]; then
    if [ "$FS_PCT" -lt "$USE_PCT_MIN" ] && [ "$FS_AVAIL_KB" -ge $((FREE_MB_MIN * 1024)) ]; then
      finish SKIP "root moi dung ${FS_PCT}% (<${USE_PCT_MIN}%), chua can mo rong"
    fi
  fi
fi

# ---------- 4) cong cu: sfdisk, partx, resize2fs ----------
export LD_LIBRARY_PATH="$TOOLS/usr/lib:$TOOLS/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
find_bin() {
  for d in "$TOOLS/usr/sbin" "$TOOLS/sbin" "$TOOLS/usr/bin" /usr/sbin /sbin /usr/bin /bin; do
    [ -x "$d/$1" ] && { echo "$d/$1"; return 0; }
  done; return 1
}
feed_bases() {
  grep -v '^#' /etc/opkg/distfeeds.conf 2>/dev/null | awk '$3 ~ /\/base\/?$/ {print $3}'
  ARCH="$(. /etc/openwrt_release 2>/dev/null; echo "${DISTRIB_ARCH:-x86_64}")"
  echo "https://downloads.openwrt.org/releases/23.05.5/packages/$ARCH/base"
}
fetch_pkg() { # $1 = ten goi opkg; giai nen vao $TOOLS (tmpfs), KHONG cai vao rootfs
  mkdir -p "$TOOLS/dl" || return 1
  i=0
  for B in $(feed_bases); do
    i=$((i+1)); PK="$TOOLS/dl/Packages.$i"
    [ -s "$PK" ] || wget -q -T 20 -O - "$B/Packages.gz" 2>/dev/null | gunzip > "$PK" 2>/dev/null
    F="$(awk -v p="$1" '$1=="Package:"{x=($2==p)} x && $1=="Filename:"{print $2; exit}' "$PK" 2>/dev/null)"
    [ -n "$F" ] || continue
    wget -q -T 60 -O "$TOOLS/dl/$1.ipk" "$B/$F" 2>/dev/null || continue
    X="$TOOLS/dl/x.$1"; rm -rf "$X"; mkdir -p "$X"
    if ( cd "$X" && { tar -xzf "../$1.ipk" 2>/dev/null || ar x "../$1.ipk" 2>/dev/null; } ) \
       && [ -f "$X/data.tar.gz" ] && tar -xzf "$X/data.tar.gz" -C "$TOOLS" 2>/dev/null; then
      rm -rf "$X"; log INFO "lay $1 tu $B (tam o $TOOLS)"; return 0
    fi
  done
  return 1
}
need() { # $1 bin $2 pkg
  b="$(find_bin "$1")" && { echo "$b"; return 0; }
  fetch_pkg "$2" >&2 && b="$(find_bin "$1")" && { echo "$b"; return 0; }
  return 1
}
SFDISK="$(need sfdisk sfdisk)" || finish DEFER "khong co sfdisk va tai khong duoc (mang/feed), lan sau thu lai"
"$SFDISK" --version >/dev/null 2>&1 || finish DEFER "sfdisk khong chay duoc (thieu thu vien?)"
PARTX="$(need partx partx-utils)" || finish DEFER "khong co partx"
RESIZE2FS="$(need resize2fs resize2fs)" || finish DEFER "khong co resize2fs va tai khong duoc"
"$RESIZE2FS" 2>&1 | grep -q resize2fs || finish DEFER "resize2fs khong chay duoc"

dump_to() { "$SFDISK" --dump "$DISK" 2>/dev/null | sed 's/= */=/g' > "$1"; }
dfield() { # $1 dumpfile $2 partdev $3 key
  awk -v d="$2" -v k="$3" '$1==d { for (i=2;i<=NF;i++) { f=$i; sub(/,$/,"",f); if (index(f, k"=")==1) { print substr(f, length(k)+2); exit } } }' "$1"
}
lc() { echo "$1" | tr 'A-F' 'a-f'; }

# ---------- 5) PENDING: bang da ghi, chi con resize ----------
do_resize() {
  if [ "$(cat "/sys/class/block/$RB/size")" -le "$R_SIZE_OLD" ]; then
    "$PARTX" -u --nr "$ROOT_NUM" "$DISK" 2>&1 | sed 's/^/    /'
  fi
  NEW_K="$(cat "/sys/class/block/$RB/size")"
  if [ "$FAIL_AT" = partx ] || [ "$NEW_K" -le "$R_SIZE_OLD" ]; then
    echo "$(date '+%F %T') bang moi da ghi, kernel chua nhan (size $NEW_K)" > "$PENDING"
    finish DEFER "kernel chua nhan kich thuoc moi cua $ROOT_PART; da ghi pending, lan boot sau tu resize2fs"
  fi
  log INFO "kernel da nhan $ROOT_PART = $((NEW_K / 2048))MB; resize2fs online ..."
  if [ "$FAIL_AT" = resize ] || ! "$RESIZE2FS" "$ROOT_PART" > /tmp/disk_expand.rs 2>&1; then
    log ERR "resize2fs loi: $(tail -n 3 /tmp/disk_expand.rs 2>/dev/null | tr '\n' ' ')"
    echo "$(date '+%F %T') resize2fs loi" > "$PENDING"
    finish BLOCK "resize2fs loi (filesystem van nguyen ven, partition da lon). Xem log; chay tay: resize2fs $ROOT_PART"
  fi
  rm -f "$PENDING" /tmp/disk_expand.rs
  set -- $(df -kP "$ROOT_MNT" | awk 'NR==2{print $2, $4, $5}')
  echo "$(date '+%F %T') root $ROOT_PART ${FS_TOTAL_KB}KB -> ${1}KB (con ${2}KB, dung $3) backup=${BK:-}" > "$DONE"
  finish OK "XONG: root ${FS_TOTAL_KB}KB -> ${1}KB, con trong ${2}KB ($3). Backup: ${BK:-khong}"
}
if [ "$RESUME" = 1 ]; then
  R_SIZE_OLD=$(( FS_TOTAL_KB * 2 ))   # partition cu ~ kich thuoc fs
  log INFO "co pending tu lan truoc: chi chay buoc resize"
  do_resize
fi

# ---------- 6) kiem GPT + PARTUUID ----------
T=/tmp/disk_expand_$STAMP; mkdir -p "$T"
dump_to "$T/before.dump"
grep -q '^label: gpt' "$T/before.dump" || finish BLOCK "bang phan vung khong phai GPT"
RPD="$(pdev "$ROOT_NUM")"
OLD_UUID="$(dfield "$T/before.dump" "$RPD" uuid)"
OLD_START="$(dfield "$T/before.dump" "$RPD" start)"
[ -n "$OLD_UUID" ] && [ "$OLD_START" = "$R_START" ] || finish BLOCK "bang tren dia khac kernel (start $OLD_START vs $R_START) - khong dam dong"
if [ "$TEST" = 1 ]; then
  CMD_UUID="${DX_CMDLINE_UUID:-}"
else
  CMD_UUID="$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^root=PARTUUID=//p' | head -n 1)"
fi
if [ -n "$CMD_UUID" ] && [ "$(lc "$CMD_UUID")" != "$(lc "$OLD_UUID")" ]; then
  finish BLOCK "PARTUUID root ($OLD_UUID) khong khop kernel cmdline ($CMD_UUID)"
fi
log INFO "GPT OK, PARTUUID root $OLD_UUID khop cmdline${CMD_UUID:+ }"

# ---------- 7) kiem p4 ----------
DATA_MNT=""; P4_KB=0
if [ -n "$DATA_PART" ]; then
  grep -q "^$DATA_PART " /proc/swaps 2>/dev/null && finish BLOCK "$DATA_PART dang lam swap"
  DATA_MNT="$(awk -v d="$DATA_PART" '$1==d {print $2; exit}' /proc/mounts)"
  [ "$(awk -v d="$DATA_PART" '$1==d' /proc/mounts | wc -l)" -le 1 ] || finish BLOCK "$DATA_PART mount nhieu cho"
  INSPECT="$DATA_MNT"
  if [ -z "$DATA_MNT" ]; then
    INSPECT="$T/p4ro"; mkdir -p "$INSPECT"
    mount -o ro "$DATA_PART" "$INSPECT" 2>/dev/null || finish BLOCK "$DATA_PART khong mount duoc de kiem (khong ro du lieu) - khong xoa"
  fi
  BAD=""
  for e in "$INSPECT"/* "$INSPECT"/.[!.]*; do
    [ -e "$e" ] || continue
    n="$(basename "$e")"
    case "$n" in
      lost+found|log|proxy-manager|genrouter_backups|GEN|GEN-main.tar.gz|gen_update_work|genrouter_restore_work) ;;
      *) BAD="$BAD $n" ;;
    esac
  done
  P4_KB="$(du -sk "$INSPECT" 2>/dev/null | awk '{print $1}')"
  [ -z "$DATA_MNT" ] && umount "$INSPECT" 2>/dev/null
  [ -z "$BAD" ] || finish BLOCK "$DATA_PART co du lieu la:$BAD - khong tu xoa. Kiem tay roi xoa $BLOCKED de thu lai"
  [ "$P4_KB" -le "$P4_MAX_KB" ] || finish BLOCK "$DATA_PART dung ${P4_KB}KB (> ${P4_MAX_KB}KB) - khong tu xoa"
  [ $((P4_KB * 2)) -lt "$FS_AVAIL_KB" ] || finish BLOCK "root khong du cho backup p4 (${P4_KB}KB)"
  if [ -n "$DATA_MNT" ]; then
    BUSY="$(ls -l /proc/[0-9]*/cwd /proc/[0-9]*/fd/ 2>/dev/null | grep -cE -- "-> $DATA_MNT(/|\$)")"
    [ "$BUSY" -eq 0 ] || finish DEFER "$DATA_MNT dang co $BUSY file/thu muc mo, de lan sau"
  fi
  log INFO "$DATA_PART (${P4_KB}KB, mount ${DATA_MNT:-khong}) chi co du lieu an toan => se xoa de mo rong root"
fi

PLAN_MB=$(( (DISK_SEC - 34 - R_START) / 2048 ))
log INFO "ke hoach: ${DATA_PART:+xoa $DATA_PART, }mo rong $ROOT_PART giu start=$R_START uuid=$OLD_UUID, ${R_SIZE} -> ~$((PLAN_MB))MB"
[ "$MODE" = dry ] && { rm -rf "$T"; log INFO "DRY-RUN: chua lam gi. --apply de lam that"; exit 0; }

# ---------- 8) backup ----------
BK="$BK_ROOT/disk_expand_$STAMP"
mkdir -p "$BK" || finish DEFER "khong tao duoc $BK"
cp "$T/before.dump" "$BK/ptable.dump" && cp "$T/before.dump" "$T/ptable.dump" || finish DEFER "khong ghi duoc backup"
"$SFDISK" --dump "$DISK" > "$BK/ptable.raw.dump" 2>/dev/null
dd if="$DISK" of="$BK/gpt_head.bin" bs=512 count=34 2>/dev/null
dd if="$DISK" of="$BK/gpt_tail.bin" bs=512 skip=$((DISK_SEC - 33)) count=33 2>/dev/null
cp "$BK/ptable.raw.dump" "$T/ptable.raw.dump" 2>/dev/null
if [ -n "$DATA_MNT" ]; then
  ( cd "$DATA_MNT" && L="$(ls -A | grep -v '^lost+found$')"; [ -z "$L" ] || tar -czf "$BK/p4_content.tgz" $L ) \
    || finish DEFER "backup noi dung p4 loi"
fi
log INFO "backup: $BK (bang phan vung + GPT head/tail${DATA_MNT:+ + noi dung p4})"

restore_table() { # $1 ly do
  log ERR "$1 => khoi phuc bang phan vung cu"
  if "$SFDISK" --no-reread --no-tell-kernel --wipe never "$DISK" < "$T/ptable.raw.dump" > "$T/restore.out" 2>&1; then
    dump_to "$T/after_restore.dump"
    if [ "$(dfield "$T/after_restore.dump" "$RPD" uuid)" = "$OLD_UUID" ] && \
       [ "$(dfield "$T/after_restore.dump" "$RPD" size)" = "$(dfield "$T/before.dump" "$RPD" size)" ]; then
      log INFO "da khoi phuc bang cu (uuid/size root khop)"
    else
      log ERR "khoi phuc xong nhung doc lai KHONG khop - KHONG REBOOT, goi ky thuat. Backup: $BK"
    fi
  else
    log ERR "ghi lai bang cu LOI: $(tail -n 2 "$T/restore.out" | tr '\n' ' ') - KHONG REBOOT. Backup: $BK"
  fi
  if [ -n "$DATA_PART" ] && [ ! -b "$DATA_PART" ]; then "$PARTX" -a --nr "$DATA_NUM" "$DISK" 2>/dev/null; fi
  if [ -n "$DATA_MNT" ]; then mount "$DATA_PART" "$DATA_MNT" 2>/dev/null && log INFO "da mount lai $DATA_PART -> $DATA_MNT"; fi
  finish BLOCK "$1 (da khoi phuc). Chi tiet: $LOG"
}

# ---------- 9) umount p4 ----------
if [ -n "$DATA_MNT" ]; then
  umount "$DATA_MNT" 2>/dev/null || finish DEFER "umount $DATA_MNT that bai (dang ban), de lan sau"
  log INFO "da umount $DATA_MNT"
fi

# ---------- 10) ghi bang moi: xoa p4, keo p3 toi het ----------
SF="--no-reread --no-tell-kernel --wipe never --wipe-partitions never"
if [ -n "$DATA_NUM" ]; then
  "$SFDISK" $SF --delete "$DISK" "$DATA_NUM" > "$T/del.out" 2>&1 || restore_table "sfdisk --delete $DATA_NUM loi: $(tail -n 2 "$T/del.out" | tr '\n' ' ')"
  [ "$FAIL_AT" = after_delete ] && restore_table "gia lap loi sau khi xoa p4"
fi
echo ", +" | "$SFDISK" $SF -N "$ROOT_NUM" "$DISK" > "$T/grow.out" 2>&1 || restore_table "sfdisk -N $ROOT_NUM loi: $(tail -n 2 "$T/grow.out" | tr '\n' ' ')"
[ "$FAIL_AT" = after_grow ] && restore_table "gia lap loi sau khi keo p3"

dump_to "$T/after.dump"
cp "$T/after.dump" "$BK/ptable.after.dump" 2>/dev/null
NU="$(dfield "$T/after.dump" "$RPD" uuid)"; NS="$(dfield "$T/after.dump" "$RPD" start)"; NZ="$(dfield "$T/after.dump" "$RPD" size)"
[ "$NU" = "$OLD_UUID" ] || restore_table "PARTUUID doi ($OLD_UUID -> $NU)"
[ "$NS" = "$OLD_START" ] || restore_table "start doi ($OLD_START -> $NS)"
[ -n "$NZ" ] && [ "$NZ" -gt "$R_SIZE" ] || restore_table "size khong tang ($R_SIZE -> $NZ)"
if [ -n "$DATA_NUM" ] && grep -q "^$(pdev "$DATA_NUM") " "$T/after.dump"; then restore_table "p$DATA_NUM van con trong bang"; fi
for k in type attrs name; do
  [ "$(dfield "$T/after.dump" "$RPD" $k)" = "$(dfield "$T/before.dump" "$RPD" $k)" ] || restore_table "$k cua root bi doi"
done
log INFO "bang moi OK: $RPD start=$NS size=$NZ ($((NZ / 2048))MB) uuid giu nguyen $NU"

# ---------- 11) bao kernel + resize2fs ----------
if [ -n "$DATA_NUM" ]; then "$PARTX" -d --nr "$DATA_NUM" "$DISK" 2>&1 | sed 's/^/    /'; fi
R_SIZE_OLD="$R_SIZE"
rm -rf "$T"
do_resize
