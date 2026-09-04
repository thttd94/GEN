#!/bin/sh
# GENROUTER KILL-SWITCH GUARD  (tao 2026-09-03)
# Nguyen tac: thiet bi KHONG qua proxy/VPN thi KHONG duoc ra WAN.
# Idempotent. Goi tu rc.local (boot) + cron (moi phut).
LAN_IF=br-lan
LAN_NET=192.14.0.0/20
BLOCK_TABLE=201
PROXY_TABLE=200
UDP_TABLE=202
LOG=/tmp/killswitch.log
_log(){ echo "$(date '+%F %T') $*" >> $LOG; }

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
RT_CFG=/etc/genrouter/gencore.json
ipset list genrouter_mapped >/dev/null 2>&1 || {
  ipset create genrouter_mapped hash:ip maxelem 4096 2>/dev/null && _log "MK ipset genrouter_mapped"; }
if [ -f "$RT_CFG" ]; then
  awk -F'"source_ip_cidr":"' '{for(i=2;i<=NF;i++){split($i,a,"\"");print a[1]}}' "$RT_CFG" \
    | sed 's#/32##' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > /tmp/ks_mapped.txt
  if [ -s /tmp/ks_mapped.txt ]; then
    ipset list genrouter_mapped | sed -n '/Members/,$p' | tail -n +2 | sort -u > /tmp/ks_cur.txt
    { comm -23 /tmp/ks_mapped.txt /tmp/ks_cur.txt | sed 's/^/add genrouter_mapped /'
      comm -13 /tmp/ks_mapped.txt /tmp/ks_cur.txt | sed 's/^/del genrouter_mapped /'; } > /tmp/ks_batch.txt
    if [ -s /tmp/ks_batch.txt ]; then
      ipset restore -! < /tmp/ks_batch.txt 2>/dev/null && _log "SYNC ipset genrouter_mapped ($(wc -l < /tmp/ks_batch.txt) thay doi)"
    fi
    rm -f /tmp/ks_cur.txt /tmp/ks_batch.txt
  fi
  rm -f /tmp/ks_mapped.txt
fi
# Chi chan khi ipset CO du lieu: set rong = chan sach 322 may.
if [ "$(ipset list genrouter_mapped 2>/dev/null | grep -c '^[0-9]')" -gt 0 ]; then
  DNSU="-i $LAN_IF -p udp --dport 53 -m set ! --match-set genrouter_mapped src -j REJECT --reject-with icmp-port-unreachable"
  DNST="-i $LAN_IF -p tcp --dport 53 -m set ! --match-set genrouter_mapped src -j REJECT --reject-with tcp-reset"
  iptables -C INPUT $DNSU 2>/dev/null || { iptables -I INPUT 1 $DNSU && _log "FIX INPUT chan DNS udp may chua map"; }
  iptables -C INPUT $DNST 2>/dev/null || { iptables -I INPUT 1 $DNST && _log "FIX INPUT chan DNS tcp may chua map"; }
fi

# [fix09] exit 0 da chuyen xuong cuoi file: khoi guard fix06 (bao ve 192.14.0.1 + xoa TPROXY catch-all /20) bi dead-code

# --- [fix06 2026-09-03] bao ve duong LAN -> router + chong TPROXY catch-all /20 ---
# Vendor tproxy quet source_ip_cidr trong gencore.json de dung CLIENT_IPS, nen rule
# deny-by-default {"action":"reject","source_ip_cidr":"192.14.0.0/20"} bi bien thanh
# TPROXY cho ca /20; dong thoi `tproxy -s` rebuild chain lam MAT rule RETURN intra-LAN
# => LAN mat duong vao 886/9001/19123 (RST). Guard tu don.
_ks6_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> /tmp/killswitch.log; }
if ! iptables -t mangle -S GENROUTER 2>/dev/null | grep -q -- "-d 192.14.0.1/32 -j RETURN"; then
  iptables -t mangle -I GENROUTER 1 -s 192.14.0.0/20 -d 192.14.0.1/32 -j RETURN 2>/dev/null \
    && _ks6_log "FIX GENROUTER tra lai RETURN intra-LAN (LAN -> router)"
fi
while iptables -t mangle -S GENROUTER 2>/dev/null | grep -q -- "-s 192.14.0.0/20 -p tcp -j TPROXY"; do
  iptables -t mangle -D GENROUTER -s 192.14.0.0/20 -p tcp -j TPROXY \
    --on-port 9888 --on-ip 0.0.0.0 --tproxy-mark 0x4d2/0x4d2 2>/dev/null || break
  _ks6_log "FIX GENROUTER xoa TPROXY catch-all 192.14.0.0/20"
done

# [fix09] exit cuoi file
exit 0
