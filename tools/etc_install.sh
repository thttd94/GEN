#!/bin/sh
# ============================================================
# etc_install.sh - trien khai cac file trong etc/ vao he thong
#
# Vi sao can: truoc Ver 2.44, install.sh CHI trien khai app dir
# (/opt/proxy-manager-v1) va tools/. Cac file duoi day nam NGOAI app dir
# nhung LA MOT PHAN cua he thong, va khong co script nao dat chung vao dung cho:
#
#   etc/genrouter_killswitch.sh   -> /etc/genrouter_killswitch.sh  + cron 1 phut
#   etc/genrouter/core/tproxy     -> /etc/genrouter/core/tproxy    + /etc/shm/tproxy
#   etc/crontabs/root (dong */5)  -> /etc/crontabs/root            (APPEND)
#
# => router moi pull source ve se KHONG co kill-switch, KHONG co ban tproxy da sua,
#    KHONG co watchdog data-plane. Day la khoang trong cua yeu cau "full final".
#
# Nguyen tac:
#   - IDEMPOTENT: chay bao nhieu lan cung ra mot ket qua.
#   - KHONG GHI DE ca file crontab: chi APPEND dong con thieu (vendor co dong rieng).
#   - Backup truoc khi thay file dang co noi dung khac.
#   - KHONG tu dong sua rc.local (duong boot) - viec do install.sh da lam rieng.
#
# Cach dung: sh etc_install.sh [duong-dan-thu-muc-etc]
#            mac dinh lay thu muc etc/ nam canh script nay hoac o repo root.
# ============================================================
set -u

SRC_ETC="${1:-}"
if [ -z "$SRC_ETC" ]; then
  D="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
  for c in "$D/etc" "$D/../etc" /opt/proxy-manager-v1/etc; do
    [ -d "$c" ] && { SRC_ETC="$c"; break; }
  done
fi
[ -n "$SRC_ETC" ] && [ -d "$SRC_ETC" ] || {
  echo "[ERR] khong thay thu muc etc/ (truyen duong dan lam tham so 1)"; exit 1; }

STAMP=$(date '+%Y%m%d_%H%M%S')
CRONF=/etc/crontabs/root
CHANGED=0

# copy giu quyen thuc thi, chi ghi khi noi dung KHAC, co backup
_put() {
  src="$1"; dst="$2"; mode="${3:-755}"
  [ -f "$src" ] || { echo "[--] khong co nguon: $src"; return 0; }
  if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
    echo "[=] $dst da dung ban moi nhat"
    return 0
  fi
  mkdir -p "$(dirname "$dst")" 2>/dev/null
  [ -f "$dst" ] && cp -p "$dst" "$dst.bak.$STAMP" 2>/dev/null
  cp "$src" "$dst" || { echo "[ERR] copy that bai: $dst"; return 1; }
  chmod "$mode" "$dst" 2>/dev/null
  CHANGED=$((CHANGED+1))
  if [ -f "$dst.bak.$STAMP" ]; then
    echo "[OK] cap nhat $dst (backup: $dst.bak.$STAMP)"
  else
    echo "[OK] cai moi $dst"
  fi
}

echo "=== 1) kill-switch ==="
_put "$SRC_ETC/genrouter_killswitch.sh" /etc/genrouter_killswitch.sh 755

echo "=== 2) cron: APPEND cac dong con thieu (khong ghi de) ==="
mkdir -p /etc/crontabs 2>/dev/null
[ -f "$CRONF" ] || : > "$CRONF"
CRON_TOUCHED=0
_add_cron() {
  pattern="$1"; line="$2"
  if grep -q "$pattern" "$CRONF" 2>/dev/null; then
    echo "[=] crontab da co: $pattern"
  else
    [ "$CRON_TOUCHED" = 0 ] && cp "$CRONF" "$CRONF.bak.$STAMP" 2>/dev/null
    CRON_TOUCHED=1
    printf '%s\n' "$line" >> "$CRONF"
    echo "[OK] them cron: $line"
  fi
}
_add_cron 'genrouter_killswitch' '* * * * * /etc/genrouter_killswitch.sh >/dev/null 2>&1'
if [ -f /opt/proxy-manager-v1/tools/dataplane_guard.py ]; then
  _add_cron 'dataplane_guard' '*/5 * * * * /usr/bin/python3 /opt/proxy-manager-v1/tools/dataplane_guard.py >/dev/null 2>&1'
else
  echo "[--] chua co tools/dataplane_guard.py, bo qua cron watchdog"
fi
if [ "$CRON_TOUCHED" = 1 ]; then
  /etc/init.d/cron reload >/dev/null 2>&1 || /etc/init.d/cron restart >/dev/null 2>&1 || true
  echo "[OK] reload cron (backup: $CRONF.bak.$STAMP)"
fi

echo "=== 3) tproxy da sua (vendor script) ==="
# QUAN TRONG: /etc/shm/ov.sh chay MOI PHUT va copy /etc/shm/<file> ->
# /etc/genrouter/core/<file> khi mtime cua target != 2025-05-05.
# => phai ghi CA HAI cho, va giu mtime 2025-05-05, neu khong ban da sua se bi
#    ghi de trong vong 60 giay.
TP_SRC="$SRC_ETC/genrouter/core/tproxy"
if [ -f "$TP_SRC" ]; then
  for dst in /etc/shm/tproxy /etc/genrouter/core/tproxy; do
    [ -d "$(dirname "$dst")" ] || { echo "[--] khong co $(dirname "$dst"), bo qua $dst"; continue; }
    if [ -f "$dst" ] && cmp -s "$TP_SRC" "$dst"; then
      echo "[=] $dst da dung ban moi nhat"
    else
      [ -f "$dst" ] && cp -p "$dst" "$dst.bak.$STAMP" 2>/dev/null
      cp "$TP_SRC" "$dst" && chmod 755 "$dst" && CHANGED=$((CHANGED+1)) \
        && echo "[OK] cap nhat $dst"
    fi
    # moc thoi gian ma ov.sh coi la "ban chuan" -> khong bi phuc hoi ve ban vendor
    touch -t 202505051200 "$dst" 2>/dev/null
  done
  echo "[i] da dat mtime 2025-05-05 12:00 cho tproxy (khop EXPECTED_DATE cua /etc/shm/ov.sh)"
else
  echo "[--] khong co $TP_SRC, bo qua"
fi

echo ""
echo "=== KIEM TRA LAI ==="
for f in /etc/genrouter_killswitch.sh /etc/genrouter/core/tproxy /etc/shm/tproxy; do
  if [ -f "$f" ]; then
    echo "  $(md5sum "$f" | cut -d' ' -f1)  mtime=$(date -r "$f" '+%F')  $f"
  else
    echo "  THIEU: $f"
  fi
done
echo "  cron:"
grep -n 'killswitch\|dataplane_guard\|gen_vpn_guard\|ov.sh' "$CRONF" 2>/dev/null | sed 's/^/    /'
echo ""
echo "[OK] etc_install.sh xong ($CHANGED file thay doi)"
echo "[i] KHONG tu chay kill-switch: no thay doi routing/iptables. Chay tay khi san sang:"
echo "    /etc/genrouter_killswitch.sh   (hoac doi cron 1 phut)"
