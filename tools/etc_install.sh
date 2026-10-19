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
#   etc/config/dhcp.tpl           -> /etc/config/dhcp (CHI THEM section thieu:
#                                    dnsmasq DHCP-only + dhcp.lan + dhcp.wan)
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

echo "=== 2b) client-isolate (tach client L2, giu router) ==="
_put "$SRC_ETC/init.d/client-isolate" /etc/init.d/client-isolate 755
_put "$SRC_ETC/client-isolate.nft.tpl" /etc/client-isolate.nft.tpl 644
if [ -x /etc/init.d/client-isolate ]; then
  /etc/init.d/client-isolate enable 2>/dev/null || ln -sf /etc/init.d/client-isolate /etc/rc.d/S99client-isolate 2>/dev/null
  _add_cron 'client-isolate' '* * * * * nft list table bridge client_isolate >/dev/null 2>&1 || /etc/init.d/client-isolate start >/dev/null 2>&1'
  /etc/init.d/client-isolate start 2>/dev/null || true
else
  echo "[--] thieu client-isolate, bo qua"
fi

echo "=== 2c) DHCP server LAN (dnsmasq) - dam bao Gen nao cung co ==="
# Gen17 tung mat: /etc/config/dhcp rong 0 byte -> client cam LAN khong duoc cap IP.
# Template: $SRC_ETC/config/dhcp.tpl (__LAN_IP__ -> IP lan hien tai).
# Nguyen tac: chi them section THIEU (dnsmasq/lan/wan), KHONG ghi de cau hinh san co.
DHCP_TPL="$SRC_ETC/config/dhcp.tpl"
if [ -f "$DHCP_TPL" ]; then
  LAN_IP="$(uci get network.lan.ipaddr 2>/dev/null || echo 192.17.0.1)"
  [ -n "$LAN_IP" ] || LAN_IP="192.17.0.1"
  # backup file goc neu co noi dung
  if [ -f /etc/config/dhcp ] && [ -s /etc/config/dhcp ]; then
    cp -p /etc/config/dhcp "/etc/config/dhcp.bak.$STAMP" 2>/dev/null
  fi
  # them section dnsmasq neu thieu
  if ! uci show dhcp.@dnsmasq[0] >/dev/null 2>&1; then
    echo "[OK] them section dnsmasq (DHCP-only, port=0, nghe br-lan)"
    uci add dhcp dnsmasq >/dev/null 2>&1
    for kv in "domainneeded=1" "boguspriv=1" "filterwin2k=0" "localise_queries=1" \
      "rebind_protection=1" "rebind_localhost=1" "local=/lan/" "expandhosts=1" \
      "authoritative=1" "readethers=1" "leasefile=/tmp/dhcp.leases" \
      "localservice=1" "cachesize=8000" "min_cache_ttl=3600" \
      "port=0" "noresolv=1"; do
      k="${kv%%=*}"; v="${kv#*=}"
      uci set "dhcp.@dnsmasq[0].$k=$v" 2>/dev/null
    done
    uci add_list dhcp.@dnsmasq[0].interface='br-lan' 2>/dev/null
    uci add_list dhcp.@dnsmasq[0].notinterface='eth0' 2>/dev/null
    uci add_list dhcp.@dnsmasq[0].notinterface='tun*' 2>/dev/null
    uci add_list dhcp.@dnsmasq[0].notinterface='wg*' 2>/dev/null
  else
    echo "[=] da co section dnsmasq"
  fi
  # them/sua section lan neu thieu
  if ! uci show dhcp.lan >/dev/null 2>&1; then
    echo "[OK] them section dhcp.lan (start=10 limit=1000 lease=30d)"
    uci set dhcp.lan=dhcp 2>/dev/null
    uci set dhcp.lan.interface='lan' 2>/dev/null
    uci set dhcp.lan.start='10' 2>/dev/null
    uci set dhcp.lan.limit='1000' 2>/dev/null
    uci set dhcp.lan.leasetime='30d' 2>/dev/null
    uci set dhcp.lan.dhcpv4='server' 2>/dev/null
    uci set dhcp.lan.dhcpv6='disabled' 2>/dev/null
    uci set dhcp.lan.ra='disabled' 2>/dev/null
    uci add_list dhcp.lan.dhcp_option="6,$LAN_IP" 2>/dev/null
  else
    echo "[=] da co section dhcp.lan"
  fi
  # wan ignore
  if ! uci show dhcp.wan >/dev/null 2>&1; then
    uci set dhcp.wan=dhcp 2>/dev/null
    uci set dhcp.wan.interface='wan' 2>/dev/null
    uci set dhcp.wan.ignore='1' 2>/dev/null
    echo "[OK] them section dhcp.wan (ignore)"
  fi
  uci commit dhcp 2>/dev/null
  /etc/init.d/dnsmasq enable 2>/dev/null
  /etc/init.d/dnsmasq restart 2>/dev/null || true
  sleep 3
  if ps | grep -v grep | grep -q '[d]nsmasq -C'; then
    echo "[OK] dnsmasq dang chay (DHCP dải tu $LAN_IP.10)"
  else
    echo "[WARN] dnsmasq chua chay - kiem tra: logread | grep dnsmasq"
  fi
else
  echo "[--] khong co $DHCP_TPL, bo qua"
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
