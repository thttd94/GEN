#!/bin/sh
# gen_update.sh - GEN router manual update via SSH (single command)
#
# Usage:
#   sh /root/gen_update.sh              update app to latest main (backup + restart + verify)
#   sh /root/gen_update.sh --check      check for new version only, change nothing
#   sh /root/gen_update.sh <ref>        update a specific branch/tag, e.g. v2.4
#
# Safe by design:
#   - never touches runtime state: update_codes.json, admanager_gui_config.json,
#     admanager_gui.local.json, collector_config.json, xxtouch_jobs data/log/tmp
#   - small tar backup of current app before applying (keeps newest 2, GEN_NO_BACKUP=1 to skip)
#   - verifies SSH(886) + GUI(9001) after restart; on failure prints rollback hint
set -u

REPO="thttd94/GEN"
APP_DIR="/opt/proxy-manager-v1"
SERVICE="proxy-manager-v1"
MODE="apply"
REF="main"
if [ $# -ge 1 ]; then
  if [ "$1" = "--check" ]; then MODE="check"; else REF="$1"; fi
fi

log(){ echo "[INFO] $*"; }
err(){ echo "[ERR] $*" >&2; }

fetch(){ # $1=url $2=outfile ; returns non-zero on failure
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --insecure -T 30 -o "$2" "$1" && return 0
  fi
  wget --no-check-certificate -q -T 30 -O "$2" "$1"
}

pick_workdir(){
  for d in /mnt/nvme0n1p4 /data /mnt/nvme0n1p3 /tmp; do
    [ -d "$d" ] || continue
    avail="$(df -k "$d" 2>/dev/null | awk 'NR==2{print $4}')"
    [ -n "${avail:-}" ] || continue
    if [ "$avail" -gt 51200 ]; then echo "$d"; return 0; fi
  done
  echo /tmp
}

WORK="${GEN_WORKDIR:-$(pick_workdir)}/gen_update_work"
PKG="$WORK/GEN-${REF}"
rm -rf "$WORK"
mkdir -p "$PKG"

cleanup(){ rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

case "$REF" in
  v*) URL="https://codeload.github.com/${REPO}/tar.gz/refs/tags/${REF}" ;;
  *)  URL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${REF}" ;;
esac

log "workdir: $WORK"
log "downloading ${REPO}@${REF} ..."
fetch "$URL" "$WORK/gen.tar.gz" || { err "download failed: $URL"; exit 1; }
tar -xzf "$WORK/gen.tar.gz" -C "$WORK" || { err "extract failed"; exit 1; }
SRC="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -n "$SRC" ] || { err "package empty"; exit 1; }
mv "$SRC" "$PKG" 2>/dev/null || PKG="$SRC"

# ---- resolve version label (GitHub API best-effort, same rule as web updater) ----
LABEL=""
SHORT=""
api="$(fetch 'https://api.github.com/repos/thttd94/GEN/commits/main' /dev/stdout 2>/dev/null || true)"
if [ -n "${api:-}" ]; then
  SHORT="$(printf '%s' "$api" | grep -o '"sha": *"[0-9a-f]\{40\}"' | head -n1 | sed 's/.*"\([0-9a-f]\{40\}\)"$/\1/' | cut -c1-7)"
  SUBJ="$(printf '%s' "$api" | grep -o '"message": *"[^"]*"' | head -n1 | sed 's/^"message": *"//; s/"$//')"
  LABEL="$(printf '%s' "$SUBJ" | sed -n 's/.*\([Vv]er[ ][0-9][0-9.]*\).*/\1/p' | sed 's/^v/V/' )"
fi
[ -n "$LABEL" ] || LABEL="$(cat "$PKG/VERSION.txt" 2>/dev/null || echo unknown)"
VT="$LABEL"
[ -n "$SHORT" ] && VT="$LABEL ($SHORT)"

md5f(){ md5sum "$1" 2>/dev/null | awk '{print $1}'; }

# ============================== CHECK MODE ==============================
if [ "$MODE" = "check" ]; then
  log "remote : $REF @ ${SHORT:-?} — ${LABEL}"
  log "local  : $(cat "$APP_DIR/VERSION.txt" 2>/dev/null || echo unknown)"
  diff_cnt=0
  for f in app.py static/index.html; do
    a="$(md5f "$APP_DIR/$f")"; b="$(md5f "$PKG/$f")"
    if [ "$a" != "$b" ]; then echo "[DIFF] $f  local=${a:-none} remote=${b:-none}"; diff_cnt=$((diff_cnt+1)); fi
  done
  if [ "$diff_cnt" -eq 0 ]; then
    echo "[OK] may da la ban moi nhat ($REF)"
    exit 0
  else
    echo "[UPDATE] co $diff_cnt file khac voi $REF -> chay: sh /root/gen_update.sh"
    exit 3
  fi
fi

# ============================== APPLY MODE ==============================
[ -d "$APP_DIR" ] || { err "$APP_DIR not found"; exit 1; }
OLD_V="$(cat "$APP_DIR/VERSION.txt" 2>/dev/null || echo unknown)"
log "current: $OLD_V -> target: $VT"

# backup current app (small tgz), keep newest 2
if [ "${GEN_NO_BACKUP:-0}" != "1" ]; then
  BK_BASE=""
  for d in /data/genrouter_backups /root/genrouter_backups; do
    [ -d "$(dirname "$d")" ] || continue
    avail="$(df -k "$(dirname "$d")" 2>/dev/null | awk 'NR==2{print $4}')"
    if [ -n "${avail:-}" ] && [ "$avail" -gt 20480 ]; then BK_BASE="$d"; break; fi
  done
  [ -z "$BK_BASE" ] && BK_BASE="/root/genrouter_backups"
  if mkdir -p "$BK_BASE" 2>/dev/null; then
    TS="$(date +%Y%m%d_%H%M%S)"
    BK="$BK_BASE/gen_app_pre_${TS}.tgz"
    if tar -czf "$BK" -C "$APP_DIR" app.py VERSION.txt static rollback_version.sh 2>/dev/null; then
      log "backup: $BK ($(du -k "$BK" | awk '{print $1}') KB)"
      ls -1t "$BK_BASE"/gen_app_pre_*.tgz 2>/dev/null | tail -n +3 | while read -r old; do rm -f "$old"; done
    else
      err "backup failed (disk?) -> tiep tuc KHONG backup"
    fi
  else
    err "khong tao duoc backup dir -> tiep tuc KHONG backup"
  fi
else
  log "GEN_NO_BACKUP=1 -> bo qua backup"
fi

# apply code files (targeted, preserve runtime state)
for f in app.py rollback_version.sh setup_data_disk.sh update.sh install.sh start.sh full_system_backup.sh gen_update.sh restore_version_online.sh; do
  [ -f "$PKG/$f" ] && cp "$PKG/$f" "$APP_DIR/$f"
done
rm -rf "$APP_DIR/static"
mkdir -p "$APP_DIR/static"
cp -r "$PKG/static/." "$APP_DIR/static/" || { err "copy static failed"; exit 1; }
mkdir -p "$APP_DIR/xxtouch_jobs"
[ -d "$PKG/xxtouch_jobs" ] && cp -a "$PKG/xxtouch_jobs/." "$APP_DIR/xxtouch_jobs/" 2>/dev/null
mkdir -p "$APP_DIR/xxtouch_jobs/data" "$APP_DIR/xxtouch_jobs/log" "$APP_DIR/xxtouch_jobs/tmp"
chmod +x "$APP_DIR"/*.sh 2>/dev/null
# firewall sync (hide 8000/9000 + udp fast-reject) - idempotent, adaptive per-router
[ -f "$APP_DIR/gen_fw_fix.sh" ] && sh "$APP_DIR/gen_fw_fix.sh" || true
# keep canonical label with commit sha (same format as key-update)
echo "$VT" > "$APP_DIR/VERSION.txt"
cp "$APP_DIR/gen_update.sh" /root/gen_update.sh 2>/dev/null || true

log "restarting $SERVICE ..."
/etc/init.d/$SERVICE restart >/dev/null 2>&1 || /etc/init.d/$SERVICE start >/dev/null 2>&1

ok=0
i=0
while [ "$i" -lt 15 ]; do
  sleep 2
  i=$((i+1))
  if wget -qO /dev/null -T 3 http://127.0.0.1:9001/api/pm/router-info 2>/dev/null; then ok=1; break; fi
done

if ! netstat -lnt 2>/dev/null | grep -q ':886'; then
  err "port 886 (SSH) khong lang nghe?!"
fi
if [ "$ok" = "1" ]; then
  echo "[OK] update xong: $(cat "$APP_DIR/VERSION.txt")"
  echo "[OK] GUI 9001: HTTP OK | backup moi nhat: $(ls -1t ${BK_BASE:-/root/genrouter_backups}/gen_app_pre_*.tgz 2>/dev/null | head -n1)"
  exit 0
else
  err "GUI 9001 chua len sau restart"
  err "kiem tra: logread | tail -40 ; thu lai: /etc/init.d/$SERVICE restart"
  err "rollback: dung ban gan nhat trong /data/genrouter_backups|/root/genrouter_backups (gen_app_pre_*.tgz):"
  err "  tar -xzf <file.tgz> -C $APP_DIR && /etc/init.d/$SERVICE restart"
  exit 2
fi
