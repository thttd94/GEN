#!/bin/sh
# GENROUTER KILL-SWITCH GUARD  (tao 2026-09-03)
# Nguyen tac: thiet bi KHONG qua proxy/VPN thi KHONG duoc ra WAN.
# Idempotent. Goi tu rc.local (boot) + cron (moi phut).
#
# [Ver 2.44 2026-09-05] BO HET HARDCODE. Truoc day file nay dong dinh
# LAN_NET=192.14.0.0/20 va dia chi router 192.14.0.1, nen router khac subnet
# pull source ve la kill-switch chan SAI dai mang (hoac khong chan gi).
# Cac tham so duoi day suy ra tu chinh he thong dang chay:
#   LAN_IF     <- uci network.lan.device  (fallback br-lan)
#   LAN_IP     <- dia chi IPv4 that cua LAN_IF
#   LAN_NET    <- route proto kernel cua LAN_IF (dung prefix that: /20, /24...)
#   TPROXY_PORT/FW_MARK <- doc tu chinh script vendor /etc/genrouter/core/tproxy
# Rule TPROXY catch-all duoc xoa bang CHINH spec lay tu `iptables -S`,
# khong doan tham so, nen khong the lech port/mark.

# ---------- suy tham so tu he thong (KHONG hardcode) ----------
LAN_IF="$(uci -q get network.lan.device 2>/dev/null)"
[ -n "$LAN_IF" ] || LAN_IF="$(uci -q get network.lan.ifname 2>/dev/null)"
[ -n "$LAN_IF" ] || LAN_IF=br-lan

LAN_CIDR="$(ip -o -4 addr show dev "$LAN_IF" 2>/dev/null | awk '{print $4; exit}')"
LAN_IP="${LAN_CIDR%%/*}"
LAN_PLEN="${LAN_CIDR##*/}"
[ -n "$LAN_IP" ] || LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null)"
case "$LAN_PLEN" in ''|*[!0-9]*) LAN_PLEN=24 ;; esac

# dai LAN: uu tien route 'proto kernel' cua chinh interface do (chinh xac tuyet doi),
# neu khong co thi tinh bang awk tu IP + prefix.
LAN_NET="$(ip -o -4 route show dev "$LAN_IF" 2>/dev/null \
  | awk -v p="/$LAN_PLEN" '$1 ~ p"$" && /proto kernel/ {print $1; exit}')"
[ -n "$LAN_NET" ] || LAN_NET="$(ip -o -4 route show dev "$LAN_IF" 2>/dev/null \
  | awk -v p="/$LAN_PLEN" '$1 ~ p"$" {print $1; exit}')"
[ -n "$LAN_NET" ] || LAN_NET="$(echo "$LAN_IP" | awk -F. -v m="$LAN_PLEN" \
  '{if(m>=24){print $1"."$2"."$3".0/"m} \
    else if(m>=16){b=int($3/(2^(24-m)))*(2^(24-m)); print $1"."$2"."b".0/"m} \
    else if(m>=8){b=int($2/(2^(16-m)))*(2^(16-m)); print $1"."b".0.0/"m} \
    else {print $1".0.0.0/"m}}')"

BLOCK_TABLE=201
PROXY_TABLE=200
UDP_TABLE=202
LOG=/tmp/killswitch.log
_log(){ echo "$(date '+%F %T') $*" >> $LOG; }

# thieu tham so co ban thi DUNG NGAY: chan sai con hai hon khong chan.
if [ -z "$LAN_IF" ] || [ -z "$LAN_IP" ] || [ -z "$LAN_NET" ]; then
  _log "ABORT khong suy duoc LAN (LAN_IF='$LAN_IF' LAN_IP='$LAN_IP' LAN_NET='$LAN_NET')"
  exit 0
fi

# --- table 200: local delivery cho packet TPROXY-mark 0x4d2 ---
ip route show table $PROXY_TABLE | grep -q '^local default' || {
  ip route replace local default dev lo table $PROXY_TABLE 2>/dev/null && _log "FIX t$PROXY_TABLE local default"; }

# --- table 202: local delivery cho UDP mark 0x4d3 ---
ip route show table $UDP_TABLE | grep -q '^local default' || {
  ip route replace local default dev lo table $UDP_TABLE 2>/dev/null && _log "FIX t$UDP_TABLE local default"; }

# --- table 201: giu intra-LAN + link-local + multicast, con lai UNREACHABLE ---
ip route show table $BLOCK_TABLE | grep -q "^$LAN_NET " || {
  ip route replace $LAN_NET dev $LAN_IF table $BLOCK_TABLE 2>/dev/null && _log "FIX t$BLOCK_TABLE keep intra-LAN"; }
ip route show table $BLOCK_TABLE | grep -q '^169.254.0.0/16 ' || {
  ip route replace 169.254.0.0/16 dev $LAN_IF table $BLOCK_TABLE 2>/dev/null && _log "FIX t$BLOCK_TABLE keep link-local"; }
ip route show table $BLOCK_TABLE | grep -q '^224.0.0.0/4 ' || {
  ip route replace 224.0.0.0/4 dev $LAN_IF table $BLOCK_TABLE 2>/dev/null && _log "FIX t$BLOCK_TABLE keep multicast"; }
ip route show table $BLOCK_TABLE | grep -q '^unreachable default' || {
  ip route replace unreachable default table $BLOCK_TABLE 2>/dev/null && _log "FIX t$BLOCK_TABLE unreachable default"; }

# --- ip rule: dung SO, khong dung ten ---
ip rule show | grep -q 'fwmark 0x4d2' || {
  ip rule add fwmark 0x4d2 table $PROXY_TABLE priority 100 2>/dev/null && _log "FIX rule 0x4d2->$PROXY_TABLE"; }
ip rule show | grep -q 'fwmark 0x4d3' || {
  ip rule add fwmark 0x4d3 table $UDP_TABLE priority 150 2>/dev/null && _log "FIX rule 0x4d3->$UDP_TABLE"; }
ip rule show | grep -q "iif $LAN_IF" || {
  ip rule add iif $LAN_IF table $BLOCK_TABLE priority 1000 2>/dev/null && _log "FIX rule iif $LAN_IF->$BLOCK_TABLE"; }

# --- rt_tables: xoa dong trung ten neu vendor tproxy append lai ---
if [ "$(awk '{if($1 ~ /^[0-9]+$/) print $2}' /etc/iproute2/rt_tables | sort | uniq -d | wc -l)" -gt 0 ]; then
  sed -i -e '/^100 proxy$/d' -e '/^200 block$/d' /etc/iproute2/rt_tables
  _log "FIX rt_tables xoa dong trung ten"
fi
# --- L1: chan DNS cua may CHUA MAP (cache cua sing-box khong the lach) ---
# sing-box tra loi tu CACHE truoc khi xet dns.rules => rule reject khong du.
# Chan tai INPUT theo ipset dong bo tu chinh config runtime.
#
# [Ver 2.44 2026-09-05] SUA LOI IM LANG: ban truoc dung `comm -23` / `comm -13`,
# nhung BusyBox tren router KHONG CO `comm` (da kiem: comm, join, paste, diff,
# timeout, base64, fold deu thieu). Cron chay voi `>/dev/null 2>&1` nen loi
# "comm: not found" bi nuot => khoi dong bo nay CHUA BAO GIO chay ke tu 2026-09-03
# (log /tmp/killswitch.log: 0 dong SYNC, 0 dong MK trong suot 17 dong log).
# 322 entry hien co la do lan tao dau tien, khong phai do dong bo.
# Hau qua neu khong sua: doi danh sach may (them/bot/doi IP) thi ipset dung yen
# => may MOI bi chan DNS oan, may DA BO van duoc phep hoi DNS.
#
# [Ver 2.45 2026-09-05] SUA TIEP: ban 2.44 thay `comm` bang
# `awk 'NR==FNR{s[$1];next} ...'`. Cach do SAI khi file thu nhat RONG: awk khong
# mo duoc block NR==FNR nen coi luon file thu HAI la "tap hien co" => 0 dong add.
# Do that 7 to hop: NR==FNR 6/7, sai dung o "set rong, cfg co 3 IP" (tra 0, dung 3).
# Nghia la tren router MOI (ipset chua co entry nao) thi ipset se MAI MAI RONG
# va lop chan DNS khong bao gio bat - dung loai loi im lang vua chua.
# Nay dung `getline` trong BEGIN: 7/7 dung, va la cach `vpn_mgr.sh:496` da dung san.
RT_CFG=/etc/genrouter/gencore.json
ipset list genrouter_mapped >/dev/null 2>&1 || {
  ipset create genrouter_mapped hash:ip maxelem 4096 2>/dev/null && _log "MK ipset genrouter_mapped"; }
if [ -f "$RT_CFG" ]; then
  awk -F'"source_ip_cidr":"' '{for(i=2;i<=NF;i++){split($i,a,"\"");print a[1]}}' "$RT_CFG" \
    | sed 's#/32##' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > /tmp/ks_mapped.txt
  if [ -s /tmp/ks_mapped.txt ]; then
    ipset list genrouter_mapped | sed -n '/Members/,$p' | tail -n +2 \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > /tmp/ks_cur.txt
    # co trong config ma chua co trong set -> add ; co trong set ma khong con trong config -> del
    { awk -v LF=/tmp/ks_cur.txt   'BEGIN{while((getline l < LF)>0) s[l]=1} !($1 in s){print "add genrouter_mapped "$1}' /tmp/ks_mapped.txt
      awk -v LF=/tmp/ks_mapped.txt 'BEGIN{while((getline l < LF)>0) s[l]=1} !($1 in s){print "del genrouter_mapped "$1}' /tmp/ks_cur.txt
    } > /tmp/ks_batch.txt
    if [ -s /tmp/ks_batch.txt ]; then
      ipset restore -! < /tmp/ks_batch.txt 2>/dev/null && _log "SYNC ipset genrouter_mapped ($(wc -l < /tmp/ks_batch.txt) thay doi)"
    fi
    rm -f /tmp/ks_cur.txt /tmp/ks_batch.txt
  fi
  rm -f /tmp/ks_mapped.txt
fi
# Chi chan khi ipset CO du lieu: set rong = chan sach moi may trong LAN.
if [ "$(ipset list genrouter_mapped 2>/dev/null | grep -c '^[0-9]')" -gt 0 ]; then
  DNSU="-i $LAN_IF -p udp --dport 53 -m set ! --match-set genrouter_mapped src -j REJECT --reject-with icmp-port-unreachable"
  DNST="-i $LAN_IF -p tcp --dport 53 -m set ! --match-set genrouter_mapped src -j REJECT --reject-with tcp-reset"
  iptables -C INPUT $DNSU 2>/dev/null || { iptables -I INPUT 1 $DNSU && _log "FIX INPUT chan DNS udp may chua map"; }
  iptables -C INPUT $DNST 2>/dev/null || { iptables -I INPUT 1 $DNST && _log "FIX INPUT chan DNS tcp may chua map"; }
fi

# [fix09] exit 0 da chuyen xuong cuoi file: khoi guard fix06 (bao ve IP router + xoa TPROXY catch-all LAN) bi dead-code

# --- [fix06 2026-09-03] bao ve duong LAN -> router + chong TPROXY catch-all LAN ---
# Vendor tproxy quet source_ip_cidr trong gencore.json de dung CLIENT_IPS, nen rule
# deny-by-default {"action":"reject","source_ip_cidr":"<LAN>/20"} bi bien thanh
# TPROXY cho ca dai LAN; dong thoi `tproxy -s` rebuild chain lam MAT rule RETURN
# intra-LAN => LAN mat duong vao 886/9001/19123 (RST). Guard tu don.
_ks6_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> /tmp/killswitch.log; }
if ! iptables -t mangle -S GENROUTER 2>/dev/null | grep -q -- "-d $LAN_IP/32 -j RETURN"; then
  iptables -t mangle -I GENROUTER 1 -s "$LAN_NET" -d "$LAN_IP/32" -j RETURN 2>/dev/null \
    && _ks6_log "FIX GENROUTER tra lai RETURN intra-LAN ($LAN_NET -> $LAN_IP)"
fi
# Xoa rule TPROXY catch-all bang CHINH spec cua no (khong doan port/mark).
# `iptables -S` sinh spec dung de nap lai, nen dua thang vao -D la khop tuyet doi.
iptables -t mangle -S GENROUTER 2>/dev/null \
  | grep -- "-s $LAN_NET " | grep -- '-j TPROXY' \
  | sed 's/^-A GENROUTER //' > /tmp/ks_catchall.txt
if [ -s /tmp/ks_catchall.txt ]; then
  while read -r spec; do
    [ -n "$spec" ] || continue
    iptables -t mangle -D GENROUTER $spec 2>/dev/null \
      && _ks6_log "FIX GENROUTER xoa TPROXY catch-all $LAN_NET"
  done < /tmp/ks_catchall.txt
fi
rm -f /tmp/ks_catchall.txt

# --- [Ver 2.45 2026-09-05] CHONG RO IP THAT khi chay che do VPN ---
#
# LOI: trong che do VPN, moi may co mot outbound rieng trong gencore.json dat la
# {"tag":"proxy_N","type":"direct"} - nghia la "cu di thang, routing se day vao tunnel".
# Viec day vao tunnel do `ip rule from <IP> lookup <table>` lam, va rule do chi
# duoc tao khi `vpn_mgr.sh assign-many` chay thanh cong.
#
# Nhung `sync_vpn_state_on_apply` (app.py:2296) BO QUA may co tunnel khong chay:
#     summary['skipped'].append({'ip': ip, 'account': acc, 'reason': 'tunnel khong chay'})
# May bi bo qua thi khong vao `ipset genrouter_vpn`, khong co `ip rule` rieng
# => bi TPROXY hijack vao sing-box => gap outbound `direct` => RA WAN BANG IP THAT.
# Day la fail-OPEN: dung ra phai chan (fail-closed).
#
# CHUA: may nao KHAI BAO che do VPN ma CHUA duoc gan tunnel thi cho RETURN khoi
# chain GENROUTER truoc cac rule TPROXY. Da do: `ip route get 1.1.1.1 from <IP>
# iif br-lan` cua may khong co ip rule rieng tra ve "Host is unreachable"
# (nho `ip rule iif br-lan lookup 201` + `unreachable default` trong table 201)
# => RETURN = CHAN THAT, khong phai tha ra WAN.
#
# Hai tap hop:
#   genrouter_vpn_want  = may KHAI BAO VPN (outbound proxy_* type=direct trong runtime)
#   genrouter_vpn       = may DA duoc gan tunnel that (gen_vpn_guard.sh dong bo tu map.txt)
# Rule chi match phan hieu: want MA khong co trong vpn.
#
# Che do proxy: khong outbound nao type=direct => want RONG => rule duoc XOA => vo hai.
# Che do VPN gan du: want == vpn => phan hieu rong => rule khong match gi => vo hai.
# Chi khi co may khai VPN ma chua gan thi rule moi chan - dung luc can chan.
VPN_WANT_SET=genrouter_vpn_want
if [ -f "$RT_CFG" ]; then
  ipset list "$VPN_WANT_SET" >/dev/null 2>&1 || {
    ipset create "$VPN_WANT_SET" hash:ip maxelem 4096 2>/dev/null && _log "MK ipset $VPN_WANT_SET"; }

  # Trich tap IP khai bao VPN. Dung python3 (co san, 0 ms cho file 128 KB) vi
  # gencore.json la MOT dong dai va can doi chieu tag outbound <-> route rule -
  # viec nay bang sed/awk se rat de sai am tham.
  /usr/bin/python3 - "$RT_CFG" > /tmp/ks_vpnwant.txt 2>/dev/null <<'PYEOF'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
direct = set()
for o in (doc.get('outbounds') or []):
    if not isinstance(o, dict):
        continue
    tag = str(o.get('tag') or '')
    if tag.startswith('proxy_') and str(o.get('type') or '') == 'direct':
        direct.add(tag)
out = set()
for r in ((doc.get('route') or {}).get('rules') or []):
    if not isinstance(r, dict):
        continue
    if str(r.get('outbound') or '') not in direct:
        continue
    ip = str(r.get('source_ip_cidr') or '').strip()
    if not ip:
        continue
    ip = ip.split('/')[0]
    p = ip.split('.')
    if len(p) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in p):
        out.add(ip)
for ip in sorted(out):
    print(ip)
PYEOF

  if [ -f /tmp/ks_vpnwant.txt ]; then
    ipset list "$VPN_WANT_SET" | sed -n '/Members/,$p' | tail -n +2 \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > /tmp/ks_wcur.txt
    sort -u /tmp/ks_vpnwant.txt > /tmp/ks_wwant.txt
    # dung `getline` trong BEGIN, KHONG dung NR==FNR: NR==FNR sai khi file thu
    # nhat rong (do that 7 to hop, xem ghi chu o khoi genrouter_mapped ben tren).
    { awk -v LF=/tmp/ks_wcur.txt  -v S="$VPN_WANT_SET" 'BEGIN{while((getline l < LF)>0) s[l]=1} !($1 in s){print "add "S" "$1}' /tmp/ks_wwant.txt
      awk -v LF=/tmp/ks_wwant.txt -v S="$VPN_WANT_SET" 'BEGIN{while((getline l < LF)>0) s[l]=1} !($1 in s){print "del "S" "$1}' /tmp/ks_wcur.txt
    } > /tmp/ks_wbatch.txt
    if [ -s /tmp/ks_wbatch.txt ]; then
      ipset restore -! < /tmp/ks_wbatch.txt 2>/dev/null \
        && _log "SYNC ipset $VPN_WANT_SET ($(wc -l < /tmp/ks_wbatch.txt) thay doi, tong $(wc -l < /tmp/ks_wwant.txt) may che do VPN)"
    fi
    rm -f /tmp/ks_wcur.txt /tmp/ks_wwant.txt /tmp/ks_wbatch.txt
  fi
  rm -f /tmp/ks_vpnwant.txt

  # Rule chan: chi giu khi tap want CO du lieu (dang o che do VPN).
  # Chen o vi tri 2 vi gen_vpn_guard.sh ep rule cua no ve vi tri 1 moi phut;
  # dat o 2 thi hai ben khong tranh cho, va van dung TRUOC rule TPROXY dau tien
  # (do duoc: TPROXY som nhat o vi tri 15 cua chain GENROUTER).
  KS_LEAK="-m set --match-set $VPN_WANT_SET src -m set ! --match-set genrouter_vpn src -j RETURN"
  if [ "$(ipset list "$VPN_WANT_SET" 2>/dev/null | grep -c '^[0-9]')" -gt 0 ]; then
    if ! iptables -t mangle -C GENROUTER $KS_LEAK 2>/dev/null; then
      iptables -t mangle -I GENROUTER 2 $KS_LEAK 2>/dev/null \
        && _log "FIX GENROUTER chan may khai VPN nhung chua gan tunnel (chong ro IP that)"
    fi
  else
    while iptables -t mangle -C GENROUTER $KS_LEAK 2>/dev/null; do
      iptables -t mangle -D GENROUTER $KS_LEAK 2>/dev/null || break
      _log "CLEAN GENROUTER bo rule chong ro IP (khong con may nao che do VPN)"
    done
  fi
fi

# [fix09] exit cuoi file
exit 0
