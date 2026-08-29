#!/bin/sh
# ============================================================
# gen_vpn_guard_install.sh - cai dat gen_vpn_guard.sh vao he thong
#
# Lam 4 viec, tat ca IDEMPOTENT + KHONG GHI DE cai co san:
#   1. copy gen_vpn_guard.sh -> /etc/gen_vpn_guard.sh (chmod 755)
#   2. them dong goi guard vao CUOI /etc/genrouter_fix_fw.sh  (marker gen_vpn_guard_v1)
#      -> moi lan gen_fw_fix / rc.local chay xong la guard chay ngay sau
#   3. them cron 1 phut (APPEND, giu nguyen cac dong cu nhu ov.sh)
#   4. rc.local: dam bao co dong /etc/genrouter_fix_fw.sh (gen_fw_fix da lam,
#      day chi la kiem tra bo sung)
#
# Backup: /etc/genrouter_fix_fw.sh va crontab duoc backup truoc khi sua.
# ============================================================
set -u

SRC="${1:-}"
GUARD="/etc/gen_vpn_guard.sh"
FIXFW="/etc/genrouter_fix_fw.sh"
MARK="gen_vpn_guard_v1"
CRONF="/etc/crontabs/root"
STAMP=$(date '+%Y%m%d_%H%M%S')

if [ -z "$SRC" ]; then
  for c in /opt/proxy-manager-v1/tools/gen_vpn_guard.sh \
           "$(dirname "$0")/gen_vpn_guard.sh" \
           /tmp/gen_vpn_guard.sh; do
    [ -f "$c" ] && { SRC="$c"; break; }
  done
fi
[ -n "$SRC" ] && [ -f "$SRC" ] || { echo "[ERR] khong thay gen_vpn_guard.sh (truyen duong dan lam tham so 1)"; exit 1; }

# ---------- 1) copy ----------
if [ ! -f "$GUARD" ] || ! cmp -s "$SRC" "$GUARD"; then
  cp "$SRC" "$GUARD" && chmod 755 "$GUARD" && echo "[OK] cai $GUARD"
else
  echo "[=] $GUARD da dung ban moi nhat"
fi

# ---------- 2) hook vao genrouter_fix_fw.sh ----------
[ -f "$FIXFW" ] || printf '#!/bin/sh\n' > "$FIXFW"
chmod 755 "$FIXFW"
if grep -q "$MARK" "$FIXFW" 2>/dev/null; then
  echo "[=] $FIXFW da co hook guard"
else
  cp "$FIXFW" "$FIXFW.bak.$STAMP" 2>/dev/null || true
  cat >> "$FIXFW" <<XEOF
# $MARK - chua duong VPN sau khi cac rule -i br-lan duoc chen lai
[ -x $GUARD ] && $GUARD fix >/dev/null 2>&1
XEOF
  echo "[OK] them hook guard vao $FIXFW (backup: $FIXFW.bak.$STAMP)"
fi

# ---------- 3) cron 1 phut (APPEND, khong ghi de) ----------
mkdir -p /etc/crontabs 2>/dev/null
[ -f "$CRONF" ] || : > "$CRONF"
if grep -q 'gen_vpn_guard' "$CRONF" 2>/dev/null; then
  echo "[=] crontab da co gen_vpn_guard"
else
  cp "$CRONF" "$CRONF.bak.$STAMP" 2>/dev/null || true
  printf '* * * * * %s fix >/dev/null 2>&1\n' "$GUARD" >> "$CRONF"
  /etc/init.d/cron reload >/dev/null 2>&1 || /etc/init.d/cron restart >/dev/null 2>&1 || true
  echo "[OK] them cron 1 phut (backup: $CRONF.bak.$STAMP)"
fi

# ---------- 4) rc.local ----------
if [ -f /etc/rc.local ] && ! grep -q 'genrouter_fix_fw' /etc/rc.local 2>/dev/null; then
  cp /etc/rc.local "/etc/rc.local.bak.$STAMP" 2>/dev/null || true
  sed -i '/exit 0/i /etc/genrouter_fix_fw.sh' /etc/rc.local
  echo "[OK] them /etc/genrouter_fix_fw.sh vao rc.local"
else
  echo "[=] rc.local da goi genrouter_fix_fw.sh"
fi

echo ""
echo "--- chay guard lan dau ---"
"$GUARD" fix
