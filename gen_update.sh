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
# Parse bang cut -d'"' de chay dung tren moi busybox (grep -o + sed \{40\} bat cap tren mot so build)
LABEL=""
SHORT=""
api="$(fetch 'https://api.github.com/repos/thttd94/GEN/commits/main' /dev/stdout 2>/dev/null || true)"
if [ -n "${api:-}" ]; then
  SHORT="$(printf '%s\n' "$api" | grep '"sha"' | head -n1 | cut -d'"' -f4 | cut -c1-7)"
  case "$SHORT" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) SHORT="" ;;
  esac
  SUBJ="$(printf '%s\n' "$api" | grep '"message"' | head -n1 | cut -d'"' -f4)"
  LABEL="$(printf '%s' "$SUBJ" | tr ',' '\n' | sed -n 's/.*\([Vv]er[ ][0-9][0-9.]*\).*/\1/p' | head -n1 | sed 's/^v/V/')"
fi
[ -n "$LABEL" ] || LABEL="$(cat "$PKG/VERSION.txt" 2>/dev/null || echo unknown)"
VT="$LABEL"
[ -n "$SHORT" ] && VT="$LABEL ($SHORT)"

# ---- self-install: chay tu dau (pipe wget / tmp / GUI package) cung tu dong vao /root ----
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
if [ "$SELF" != "/root/gen_update.sh" ]; then
  if fetch 'https://raw.githubusercontent.com/thttd94/GEN/main/gen_update.sh' /root/.gen_update.sh.new 2>/dev/null && mv /root/.gen_update.sh.new /root/gen_update.sh; then
    chmod 755 /root/gen_update.sh
    log "self-install: /root/gen_update.sh (lan sau chi can go: sh /root/gen_update.sh)"
  fi
fi

md5f(){ md5sum "$1" 2>/dev/null | awk '{print $1}'; }

# ============================== CHECK MODE ==============================
if [ "$MODE" = "check" ]; then
  log "remote : $REF @ ${SHORT:-?} â€” ${LABEL}"
  log "local  : $(cat "$APP_DIR/VERSION.txt" 2>/dev/null || echo unknown)"
  diff_cnt=0
  for f in app.py static/index.html tools/etc_install.sh tools/dataplane_guard.py; do
    a="$(md5f "$APP_DIR/$f")"; b="$(md5f "$PKG/$f")"
    if [ "$a" != "$b" ]; then echo "[DIFF] $f  local=${a:-none} remote=${b:-none}"; diff_cnt=$((diff_cnt+1)); fi
  done
  # [Ver 2.47] file NGOAI app dir: bao cao rieng vi etc_install.sh moi dat chung vao cho
  for pair in "etc/genrouter_killswitch.sh:/etc/genrouter_killswitch.sh" \
              "etc/genrouter/core/tproxy:/etc/genrouter/core/tproxy" \
              "etc/genrouter/core/tproxy:/etc/shm/tproxy" \
              "etc/gen_vpn_guard.sh:/etc/gen_vpn_guard.sh"; do
    src="$PKG/${pair%%:*}"; dst="${pair##*:}"
    [ -f "$src" ] || continue
    a="$(md5f "$dst")"; b="$(md5f "$src")"
    if [ "$a" != "$b" ]; then echo "[DIFF] $dst  local=${a:-none} remote=${b:-none}"; diff_cnt=$((diff_cnt+1)); fi
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
# Ver 2.19+: XXTouch da duoc loai bo - khong can tao/copy xxtouch_jobs nua
# (giu lai neu package cu van con - idempotent)
if [ -d "$PKG/xxtouch_jobs" ]; then
  log "(!) package cu van con xxtouch_jobs/ - se khong copy (Ver 2.19+ loai bo XXTouch)"
fi
chmod +x "$APP_DIR"/*.sh 2>/dev/null
# tools/ (vpn_mgr.sh, gen_vpn_guard.sh, gen_vpn_guard_install.sh)
if [ -d "$PKG/tools" ]; then
  mkdir -p "$APP_DIR/tools"
  cp -r "$PKG/tools/." "$APP_DIR/tools/" || err "copy tools failed"
  chmod +x "$APP_DIR/tools"/*.sh 2>/dev/null
fi
[ -f "$PKG/gen_fw_fix.sh" ] && cp "$PKG/gen_fw_fix.sh" "$APP_DIR/gen_fw_fix.sh"
# firewall sync (hide 8000/9000 + udp fast-reject) - idempotent, adaptive per-router
[ -f "$APP_DIR/gen_fw_fix.sh" ] && sh "$APP_DIR/gen_fw_fix.sh" || true
# gen_vpn_guard: chua duong br-lan -> tun* + self-heal (cron 1 phut + hook fix_fw)
[ -f "$APP_DIR/tools/gen_vpn_guard_install.sh" ] && sh "$APP_DIR/tools/gen_vpn_guard_install.sh" "$APP_DIR/tools/gen_vpn_guard.sh" >/dev/null 2>&1 || true

# ---- [Ver 2.47] etc/: kill-switch + tproxy da sua + cron watchdog ----
# Truoc Ver 2.47, script nay CHI dong bo app dir + tools/, nen may update qua duong
# nay bi THIEU 3 thanh phan nam NGOAI app dir (chi install.sh moi trien khai):
#   /etc/genrouter_killswitch.sh                   khong qua proxy/VPN => khong ra WAN
#   /etc/genrouter/core/tproxy + /etc/shm/tproxy   ban da sua rt_tables 200/201 + FIX07
#   cron */5 goi tools/dataplane_guard.py          watchdog data-plane
# => day la ly do ban va tay tren 1 may khong bao gio lan ra ca dan may.
# Phai COPY etc/ vao APP_DIR TRUOC roi moi goi: etc_install.sh auto-detect tim
# "$APP_DIR/etc", khong copy thi no truot va bo qua IM LANG (khong bao loi).
if [ -d "$PKG/etc" ]; then
  rm -rf "$APP_DIR/etc"
  mkdir -p "$APP_DIR/etc"
  if cp -r "$PKG/etc/." "$APP_DIR/etc/"; then
    if [ -f "$APP_DIR/tools/etc_install.sh" ]; then
      log "etc_install: kill-switch + tproxy + cron watchdog ..."
      if sh "$APP_DIR/tools/etc_install.sh" "$APP_DIR/etc" > "$WORK/etc_install.out" 2>&1; then
        sed 's/^/  /' "$WORK/etc_install.out"
      else
        err "etc_install.sh tra ve loi (log duoi), van tiep tuc update"
        sed 's/^/  /' "$WORK/etc_install.out" >&2
      fi
    else
      err "thieu $APP_DIR/tools/etc_install.sh -> KHONG trien khai duoc kill-switch/tproxy"
    fi
  else
    err "copy etc/ that bai -> KHONG trien khai duoc kill-switch/tproxy"
  fi
else
  err "package $REF khong co etc/ -> bo qua (ban truoc Ver 2.44?)"
fi

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
