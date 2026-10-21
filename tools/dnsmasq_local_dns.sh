#!/bin/sh
# ============================================================
# dnsmasq_local_dns.sh - [Ver 2.71] dam bao dnsmasq nghe DNS 127.0.0.1:5353
#
# Vi sao BAT BUOC: gencore.json dung dnsmasq 127.0.0.1:5353 lam
#   - loop breaker: rule dns 'as.lumiproxy.io -> server dnsmasq'
#   - dns.final = dnsmasq
# Khong ai nghe 5353 => gencore khong resolve duoc as.lumiproxy.io => TOAN BO
# outbound lumi chet, DNS client (hijack qua gencore :53) chet => gan proxy lumi
# hay gan VPN deu "khong vao duoc mang".
#
# Do that 2026-10-21 Gen17 (len 2.70 tu 2.52): uci dhcp.@dnsmasq[0].port='0'
# (do etc_install.sh Ver 2.52 tao section "DHCP-only port=0") va /etc/dnsmasq.conf
# KHONG co 'port=5353'. Gen15 chay tot: uci KHONG dat port, /etc/dnsmasq.conf co
# 'port=5353'. Update chi thay code, giu /etc/config => loi nam lai mai mai.
# Script nay dua moi router ve dung mau Gen15:
#   1) uci port='0' -> xoa (port khac 0/5353 do nguoi dat: KHONG dong, chi canh bao)
#   2) /etc/dnsmasq.conf phai co 'port=5353' (KHONG duoc de dnsmasq chiem :53 cua gencore)
#   3) noresolv=1 ma khong co upstream nao -> them server=8.8.8.8/8.8.4.4
# Chi restart dnsmasq khi THAT SU co thay doi. Sau restart tu kiem
# (nghe 127.0.0.1:5353 + nslookup qua 5353); FAIL => tra lai backup + restart.
#
# Cach dung: sh dnsmasq_local_dns.sh          (sua neu can)
#            sh dnsmasq_local_dns.sh --check  (chi in, KHONG sua)
# Exit: 0 = dung/da sua OK, 1 = can sua (--check), 2 = sua that bai (da rollback)
# ============================================================
set -u
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1
CONF=/etc/dnsmasq.conf
LOG=/opt/proxy-manager-v1/logs/dnsmasq_local_dns.log
STAMP=$(date '+%Y%m%d_%H%M%S')
mkdir -p "$(dirname "$LOG")" 2>/dev/null

_log() { echo "$*"; [ "$CHECK" = 1 ] || echo "$(date '+%F %T') $*" >> "$LOG" 2>/dev/null; }

_listen5353() { netstat -lnu 2>/dev/null | grep -q '127\.0\.0\.1:5353 \|0\.0\.0\.0:5353 '; }
_resolve5353() { nslookup google.com 127.0.0.1:5353 >/dev/null 2>&1; }

command -v uci >/dev/null 2>&1 || { _log "[--] khong co uci, bo qua"; exit 0; }
uci -q get dhcp.@dnsmasq[0] >/dev/null 2>&1 || { _log "[--] chua co section dnsmasq, bo qua"; exit 0; }

NEED=""
UPORT="$(uci -q get dhcp.@dnsmasq[0].port || true)"
case "$UPORT" in
  "") ;;
  0) NEED="$NEED uci_port0" ;;
  5353) ;;
  *) _log "[WARN] uci dnsmasq port='$UPORT' (khong phai 0/5353) - KHONG tu sua" ;;
esac

[ -f "$CONF" ] || : > "$CONF"
CPORT="$(grep -E '^[[:space:]]*port=' "$CONF" 2>/dev/null | tail -n 1 | sed 's/.*port=//; s/[[:space:]]//g')"
if [ -z "$CPORT" ]; then
  # uci da tu dat 5353 thi khong can them vao conf
  [ "$UPORT" = "5353" ] || NEED="$NEED conf_port"
elif [ "$CPORT" != "5353" ]; then
  _log "[WARN] $CONF co port=$CPORT (khong phai 5353) - KHONG tu sua"
fi

NORES="$(uci -q get dhcp.@dnsmasq[0].noresolv || true)"
if [ "$NORES" = "1" ]; then
  USRV="$(uci -q get dhcp.@dnsmasq[0].server || true)"
  if [ -z "$USRV" ] && ! grep -qE '^[[:space:]]*server=' "$CONF" 2>/dev/null; then
    NEED="$NEED upstream"
  fi
fi

if [ -z "$NEED" ]; then
  if _listen5353 && _resolve5353; then
    _log "[=] dnsmasq 5353 OK"
    exit 0
  fi
  _log "[WARN] cau hinh dung nhung 5353 chua tra loi - KHONG restart (de watchdog/nguoi xem)"
  exit 0
fi

if [ "$CHECK" = 1 ]; then
  _log "[CHECK] can sua:$NEED (uci port='$UPORT' conf port='$CPORT' noresolv='$NORES')"
  exit 1
fi

cp -p /etc/config/dhcp "/etc/config/dhcp.bak.dns5353.$STAMP" 2>/dev/null
cp -p "$CONF" "$CONF.bak.dns5353.$STAMP" 2>/dev/null
_log "[i] backup /etc/config/dhcp.bak.dns5353.$STAMP + $CONF.bak.dns5353.$STAMP"

for n in $NEED; do
  case "$n" in
    uci_port0) uci -q delete dhcp.@dnsmasq[0].port; _log "[OK] xoa uci dhcp.@dnsmasq[0].port='0'" ;;
    conf_port) echo "port=5353" >> "$CONF"; _log "[OK] them port=5353 vao $CONF" ;;
    upstream) printf 'server=8.8.8.8\nserver=8.8.4.4\n' >> "$CONF"; _log "[OK] them server=8.8.8.8/8.8.4.4 vao $CONF" ;;
  esac
done
uci commit dhcp 2>/dev/null
/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true

OK=0
for i in 1 2 3 4 5 6 7 8; do
  sleep 2
  if _listen5353 && _resolve5353; then OK=1; break; fi
done
if [ "$OK" = 1 ]; then
  _log "[OK] dnsmasq nghe 127.0.0.1:5353, resolve OK (sua:$NEED)"
  exit 0
fi

_log "[FAIL] sau khi sua 5353 van khong tra loi -> ROLLBACK"
cp -p "/etc/config/dhcp.bak.dns5353.$STAMP" /etc/config/dhcp 2>/dev/null
cp -p "$CONF.bak.dns5353.$STAMP" "$CONF" 2>/dev/null
/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
_log "[FAIL] da tra lai backup $STAMP + restart dnsmasq"
exit 2
