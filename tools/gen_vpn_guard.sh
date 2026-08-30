#!/bin/sh
# ============================================================
# gen_vpn_guard.sh - tu phat hien + tu chua duong di VPN (tun*)
#
# VAN DE GOC
#   Router GEN co HAI duong ra khac nhau:
#     - proxy socks5 : ipset genrouter_clients -> TPROXY 9888 -> INPUT (local socket)
#     - vpn tunnel   : map.txt -> ip rule lookup 30x -> FORWARD -> tun*
#   Cac rule do /etc/genrouter/core/tproxy va gen_fw_fix.sh sinh ra chan theo
#   INTERFACE (-i br-lan) chu khong theo client, nen chung chan luon ca may VPN:
#     iptables -I FORWARD 1 -i br-lan -p udp -j DROP            (tproxy:50)
#     iptables -I FORWARD 1 -i br-lan -p tcp --dport 53 -j DROP (tproxy:51)
#     iptables -t mangle -I PREROUTING 1 -i br-lan -p udp -j GEN_FW_UDP
#   Cong them: chain nft `accept_to_wan` cua fw4 RONG trong khi chain `forward`
#   co policy drop -> moi goi br-lan -> tun* roi xuong handle_reject.
#   Proxy khong bi anh huong vi no di qua INPUT, khong qua FORWARD.
#
# CACH CHUA (khong sua tproxy vi /etc/shm/ov.sh cp de lai moi phut)
#   1. ipset genrouter_vpn  <- dong bo tu /data/vpn/map.txt
#   2. 4 diem thoat theo ipset, luon bi ep ve dau chain:
#        mangle PREROUTING 1 : match-set genrouter_vpn src -j RETURN
#        mangle GENROUTER   1 : match-set genrouter_vpn src -j RETURN
#        mangle GEN_FW_UDP  1 : match-set genrouter_vpn src -j RETURN
#        filter FORWARD     1 : match-set genrouter_vpn src -j ACCEPT
#   3. fw4 include persist: forward_lan accept oifname tun* + MSS clamp
#   Them/bo may VPN = ipset add/del, KHONG sinh rule moi -> khong lech thu tu.
#
# IDEMPOTENT. Chay bao nhieu lan cung duoc. Chi ghi log khi co thay doi.
#
# Dung:
#   gen_vpn_guard.sh            kiem tra + tu chua (mac dinh)
#   gen_vpn_guard.sh check      chi bao cao, khong sua gi
#   gen_vpn_guard.sh sync       chi dong bo ipset tu map.txt
#   gen_vpn_guard.sh status     in trang thai hien tai
# ============================================================
set -u

VPN_SET="genrouter_vpn"
MAPF="/data/vpn/map.txt"
LOGF="/data/vpn/logs/guard.log"
LOG_MAX=200000
NFT_DIR="/usr/share/nftables.d/chain-pre"
LAN_IF="br-lan"
MODE="${1:-fix}"

CHANGED=0
REPORT=""

# Neu router chua co ipset (ban firmware toi gian) -> tu chuyen sang che do
# per-IP: sinh rule theo tung IP trong map.txt thay vi match-set. Cham hon va
# de lech thu tu hon nhung van chua duoc duong VPN, khong bao gio bo trong.
# GUARD_FORCE_NO_IPSET=1 chi dung de test nhanh nhanh per-IP tren may co ipset.
HAVE_IPSET=1
command -v ipset >/dev/null 2>&1 || HAVE_IPSET=0
[ "${GUARD_FORCE_NO_IPSET:-0}" = 1 ] && HAVE_IPSET=0


_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { # chi ghi khi co thay doi that
  REPORT="$REPORT$1
"
  [ "$MODE" = check ] && return 0
  mkdir -p "$(dirname "$LOGF")" 2>/dev/null
  if [ -f "$LOGF" ]; then
    sz=$(wc -c < "$LOGF" 2>/dev/null || echo 0)
    [ "$sz" -gt "$LOG_MAX" ] 2>/dev/null && { tail -c 100000 "$LOGF" > "$LOGF.tmp" 2>/dev/null && mv "$LOGF.tmp" "$LOGF"; }
  fi
  echo "$(_ts) $1" >> "$LOGF" 2>/dev/null
  return 0
}

note() { CHANGED=$((CHANGED+1)); log "$1"; }

is_ipv4() {
  printf '%s' "$1" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
}

# ---------- 1) ipset ----------
ensure_set() {
  [ "$HAVE_IPSET" = 1 ] || return 1
  if ! ipset list -n "$VPN_SET" >/dev/null 2>&1; then
    [ "$MODE" = check ] && { log "[MISS] ipset $VPN_SET chua ton tai"; return 1; }
    ipset create "$VPN_SET" hash:ip family inet hashsize 256 maxelem 2000 2>/dev/null \
      && note "[FIX] tao ipset $VPN_SET"
  fi
  ipset list -n "$VPN_SET" >/dev/null 2>&1
}

sync_set() {
  if [ "$HAVE_IPSET" != 1 ]; then
    log "[SKIP] khong co ipset -> dung che do per-IP"
    return 1
  fi
  ensure_set || return 1
  want="/tmp/.vpnguard_want.$$"
  have="/tmp/.vpnguard_have.$$"
  : > "$want"; : > "$have"
  if [ -f "$MAPF" ]; then
    while read -r ip acc rest; do
      [ -n "${ip:-}" ] || continue
      [ -n "${acc:-}" ] || continue
      case "$ip" in \#*) continue ;; esac
      is_ipv4 "$ip" || continue
      echo "$ip" >> "$want"
    done < "$MAPF"
  fi
  ipset list "$VPN_SET" 2>/dev/null | sed -n '/^Members:/,$p' | sed '1d' \
    | while read -r m rest; do [ -n "${m:-}" ] && echo "$m"; done > "$have"

  # them thieu
  while read -r ip; do
    [ -n "${ip:-}" ] || continue
    grep -qxF "$ip" "$have" 2>/dev/null && continue
    if [ "$MODE" = check ]; then
      log "[MISS] ipset thieu $ip"
    else
      ipset add "$VPN_SET" "$ip" -exist 2>/dev/null && note "[FIX] ipset + $ip"
    fi
  done < "$want"
  # bo thua
  while read -r ip; do
    [ -n "${ip:-}" ] || continue
    grep -qxF "$ip" "$want" 2>/dev/null && continue
    if [ "$MODE" = check ]; then
      log "[EXTRA] ipset con $ip (khong trong map)"
    else
      ipset del "$VPN_SET" "$ip" 2>/dev/null && note "[FIX] ipset - $ip"
    fi
  done < "$have"
  rm -f "$want" "$have"
  return 0
}

# ---------- 2) rule, ep ve dau chain ----------
# top_rule <table> <chain> <spec...>
# Dam bao rule ton tai VA nam o vi tri 1. Neu sai vi tri -> xoa het roi chen lai 1.
top_rule() {
  tbl="$1"; ch="$2"; shift 2
  iptables -t "$tbl" -nL "$ch" >/dev/null 2>&1 || {
    log "[SKIP] chain $tbl/$ch chua ton tai"
    return 0
  }
  first=$(iptables -t "$tbl" -S "$ch" 2>/dev/null | sed -n '2p')
  want="-A $ch $*"
  if [ "$first" = "$want" ]; then
    return 0
  fi
  if [ "$MODE" = check ]; then
    if iptables -t "$tbl" -C "$ch" "$@" 2>/dev/null; then
      log "[ORDER] $tbl/$ch: rule co nhung KHONG o vi tri 1 (vi tri 1 dang la: ${first:-<rong>})"
    else
      log "[MISS] $tbl/$ch: thieu rule: $*"
    fi
    return 0
  fi
  while iptables -t "$tbl" -D "$ch" "$@" 2>/dev/null; do :; done
  iptables -t "$tbl" -I "$ch" 1 "$@" 2>/dev/null \
    && note "[FIX] $tbl/$ch <- vi tri 1: $*"
  return 0
}

ensure_rules() {
  if [ "$HAVE_IPSET" != 1 ]; then
    # che do per-IP: doc map.txt, ep rule cua tung IP ve dau chain.
    # Duyet nguoc de IP dau file cuoi cung nam tren cung (thu tu khong quan trong
    # vi cac rule nay doc lap nhau, chi can dung TRUOC rule chan cua tproxy).
    [ -f "$MAPF" ] || return 0
    while read -r ip acc rest; do
      [ -n "${ip:-}" ] && [ -n "${acc:-}" ] || continue
      case "$ip" in \#*) continue ;; esac
      is_ipv4 "$ip" || continue
      top_rule mangle PREROUTING -s "$ip" -j RETURN
      top_rule mangle GENROUTER  -s "$ip" -j RETURN
      top_rule mangle GEN_FW_UDP -s "$ip" -j RETURN
      top_rule filter FORWARD    -s "$ip" -j ACCEPT
    done < "$MAPF"
    return 0
  fi
  M="-m set --match-set $VPN_SET src"
  # thoat toan bo pipeline gencore/tproxy
  top_rule mangle PREROUTING $M -j RETURN
  # phong tuyen 2: ngay trong chain con, khong phu thuoc thu tu PREROUTING
  top_rule mangle GENROUTER  $M -j RETURN
  top_rule mangle GEN_FW_UDP $M -j RETURN
  # cho phep forward (vuot rule DROP udp / DROP tcp:53 cua tproxy)
  top_rule filter FORWARD    $M -j ACCEPT
}

# ---------- 3) fw4 include (persist qua fw4 reload) ----------
# Dat o chain-pre/forward_lan chu KHONG phai accept_to_wan: fw4 bo qua include
# cua chain rong, ma accept_to_wan dang rong.
NFT_FWD="$NFT_DIR/forward_lan/99-genrouter-vpn.nft"
NFT_MSS="$NFT_DIR/mangle_forward/99-genrouter-vpn-mss.nft"
NFT_FWD_BODY='oifname "tun*" counter accept comment "genrouter-vpn-fwd"'
NFT_MSS_BODY='oifname "tun*" tcp flags syn / syn,rst tcp option maxseg size set rt mtu counter comment "genrouter-vpn-mss"'

ensure_file() { # <path> <body>
  d=$(dirname "$1")
  if [ -f "$1" ] && [ "$(cat "$1" 2>/dev/null)" = "$2" ]; then
    return 0
  fi
  if [ "$MODE" = check ]; then
    log "[MISS] file include sai/thieu: $1"
    return 0
  fi
  mkdir -p "$d" 2>/dev/null
  printf '%s\n' "$2" > "$1" && note "[FIX] ghi $1"
}

ensure_nft() {
  command -v nft >/dev/null 2>&1 || { log "[SKIP] khong co nft"; return 0; }
  ensure_file "$NFT_FWD" "$NFT_FWD_BODY"
  ensure_file "$NFT_MSS" "$NFT_MSS_BODY"

  # rule dang chay trong nhan (file chi co hieu luc sau fw4 reload).
  # Kiem tra tren CA table vi rule co the dang nam o accept_to_wan (ban chen tay
  # truoc day) hoac o forward_lan (sau khi fw4 nap file include).
  if ! nft list table inet fw4 2>/dev/null | grep -q 'genrouter-vpn-fwd'; then
    if [ "$MODE" = check ]; then
      log "[MISS] fw4 thieu accept oifname tun* (forward_lan/accept_to_wan)"
    else
      nft insert rule inet fw4 forward_lan oifname '"tun*"' counter accept comment '"genrouter-vpn-fwd"' 2>/dev/null \
        && note "[FIX] nft insert forward_lan accept tun*"
    fi
  fi
  if ! nft list table inet fw4 2>/dev/null | grep -q 'genrouter-vpn-mss'; then
    if [ "$MODE" = check ]; then
      log "[MISS] nft mangle_forward thieu MSS clamp cho tun*"
    else
      nft add rule inet fw4 mangle_forward oifname '"tun*"' tcp flags syn / syn,rst \
        tcp option maxseg size set rt mtu counter comment '"genrouter-vpn-mss"' 2>/dev/null \
        && note "[FIX] nft add mangle_forward MSS clamp tun*"
    fi
  fi
}

# ---------- 4) route/rule cua tung tunnel ----------
# TOI UU (Ver 2.32): ban cu spawn ~6 process cho MOI dong map.txt
# (grep meta x3 + ip link + ip route show + ip rule show + iptables -C).
# Voi 114 may = ~700 process moi lan goi guard -> ~1s, va vpn_mgr.sh goi
# guard sau TUNG IP nen gan all bi chi phi binh phuong (gan all ~5 phut).
#
# Ban nay: snapshot 1 lan (ip rule / nat / net devices / meta cua tat ca
# account) roi dung DUNG 1 LUOT awk de tinh ra danh sach viec CAN LAM.
# Shell chi chay dung so lenh thuc su can -> khi moi thu da dung thi
# tong chi phi la ~5 process, khong phu thuoc so may.
# Logic quyet dinh giu Y NGUYEN nhu ban cu.
ensure_routes() {
  [ -f "$MAPF" ] || return 0
  acct=/data/vpn/accounts
  _t="/tmp/.vpnguard_er.$$"

  # ---- snapshot: 4 lenh, khong phu thuoc so may ----
  ip rule show 2>/dev/null                 > "$_t.rules"
  iptables -t nat -S POSTROUTING 2>/dev/null > "$_t.nat"
  ls /sys/class/net 2>/dev/null            > "$_t.devs"
  ip route show table all 2>/dev/null      > "$_t.routes"
  # meta cua moi account, dinh dang: <ten> <key>=<val>
  for _d in "$acct"/*/meta; do
    [ -f "$_d" ] || continue
    _n=${_d%/meta}; _n=${_n##*/}
    sed -n "s/^/$_n /p" "$_d" 2>/dev/null
  done > "$_t.meta"

  # ---- 1 luot awk: sinh danh sach viec can lam ----
  # Moi dong ket qua: <loai>|<tham so...>
  awk -v METAF="$_t.meta" -v RULEF="$_t.rules" -v NATF="$_t.nat" \
      -v DEVF="$_t.devs" -v RTF="$_t.routes" '
    BEGIN {
      while ((getline l < METAF) > 0) {
        n = l; sub(/ .*$/, "", n)
        kv = l; sub(/^[^ ]+ /, "", kv)
        k = kv; sub(/=.*$/, "", k)
        v = kv; sub(/^[^=]*=/, "", v)
        if (k == "dev")   DEV[n] = v
        if (k == "table") TBL[n] = v
        if (k == "prio")  PRI[n] = v
      }
      close(METAF)
      while ((getline l < RULEF) > 0) {
        if (match(l, /from [0-9.]+ lookup [0-9a-zA-Z_]+/))
          HAVERULE[substr(l, RSTART, RLENGTH)] = 1
      }
      close(RULEF)
      while ((getline l < NATF) > 0)  NAT = NAT "\n" l
      close(NATF)
      while ((getline l < DEVF) > 0)  HAVEDEV[l] = 1
      close(DEVF)
      while ((getline l < RTF) > 0) {
        # "default dev tunN table 3NN" hoac "default dev tunN" (table main)
        if (l !~ /^default/) continue
        t = "main"
        if (match(l, /table [0-9a-zA-Z_]+/)) t = substr(l, RSTART + 6, RLENGTH - 6)
        HAVEDEF[t] = 1
      }
      close(RTF)
    }
    /^[ 	]*#/ { next }
    {
      ip = $1; acc = $2
      if (ip == "" || acc == "") next
      if (ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
      if (!(acc in DEV) || !(acc in TBL) || !(acc in PRI)) next
      d = DEV[acc]; t = TBL[acc]; p = PRI[acc]
      if (d == "" || t == "" || p == "") next
      if (!(d in HAVEDEV)) { print "DOWN|" acc "|" d "|" ip; next }

      if (!(t in HAVEDEF) && !("def" t in DONE)) {
        print "DEF|" t "|" d; DONE["def" t] = 1
      }
      found = (("from " ip " lookup " t) in HAVERULE)
      if (!found && !("rule" ip "_" t in DONE)) {
        print "RULE|" ip "|" t "|" p; DONE["rule" ip "_" t] = 1
      }
      if (!index(NAT, "-o " d " -j MASQUERADE") && !("masq" d in DONE)) {
        print "MASQ|" d; DONE["masq" d] = 1
      }
    }
  ' "$MAPF" > "$_t.todo" 2>/dev/null

  # ---- thuc thi (hoac bao cao khi MODE=check) ----
  while IFS='|' read -r kind a b cc; do
    case "$kind" in
      DOWN) log "[DOWN] tunnel $a ($b) khong ton tai - bo qua $cc" ;;
      DEF)
        if [ "$MODE" = check ]; then
          log "[MISS] table $a thieu default dev $b"
        else
          ip route replace default dev "$b" table "$a" 2>/dev/null \
            && note "[FIX] table $a <- default dev $b"
        fi ;;
      RULE)
        if [ "$MODE" = check ]; then
          log "[MISS] thieu ip rule from $a lookup $b"
        else
          ip rule add from "$a" table "$b" priority "$cc" 2>/dev/null \
            && note "[FIX] ip rule from $a -> table $b"
        fi ;;
      MASQ)
        if [ "$MODE" = check ]; then
          log "[MISS] thieu MASQUERADE -o $a"
        else
          iptables -t nat -A POSTROUTING -o "$a" -j MASQUERADE 2>/dev/null \
            && note "[FIX] MASQUERADE -o $a"
        fi ;;
    esac
  done < "$_t.todo"

  rm -f "$_t.rules" "$_t.nat" "$_t.devs" "$_t.routes" "$_t.meta" "$_t.todo"
  return 0
}

# ---------- status ----------
cmd_status() {
  echo "== ipset $VPN_SET"
  if ipset list -n "$VPN_SET" >/dev/null 2>&1; then
    ipset list "$VPN_SET" 2>/dev/null | sed -n '/^Members:/,$p' | sed 's/^/   /'
  else
    echo "   (chua ton tai)"
  fi
  echo "== map.txt"
  sed 's/^/   /' "$MAPF" 2>/dev/null || echo "   (khong co)"
  echo "== mangle PREROUTING (5 dong dau)"
  iptables -t mangle -L PREROUTING -n -v --line-numbers 2>/dev/null | sed -n '3,7p' | sed 's/^/   /'
  echo "== filter FORWARD (7 dong dau)"
  iptables -L FORWARD -n -v --line-numbers 2>/dev/null | sed -n '3,9p' | sed 's/^/   /'
  echo "== nft forward_lan"
  nft list chain inet fw4 forward_lan 2>/dev/null | sed 's/^/   /'
  echo "== nft mangle_forward"
  nft list chain inet fw4 mangle_forward 2>/dev/null | sed 's/^/   /'
  echo "== tun devices"
  for d in $(ls /sys/class/net 2>/dev/null | grep '^tun'); do
    echo "   $d tx=$(cat /sys/class/net/$d/statistics/tx_packets 2>/dev/null) rx=$(cat /sys/class/net/$d/statistics/rx_packets 2>/dev/null)"
  done
}

case "$MODE" in
  status) cmd_status; exit 0 ;;
  sync)   sync_set; exit 0 ;;
  check|fix)
    sync_set
    ensure_rules
    ensure_nft
    ensure_routes
    ;;
  *) echo "dung: $0 [fix|check|sync|status]"; exit 1 ;;
esac

if [ "$MODE" = check ]; then
  # [SKIP]/[DOWN] chi la thong tin (khong co ipset, tunnel dang down) -> khong tinh lech.
  PROBLEMS=$(printf '%s' "$REPORT" | grep -c -e '^\[MISS\]' -e '^\[ORDER\]' -e '^\[EXTRA\]')
  [ -n "$REPORT" ] && printf '%s' "$REPORT"
  if [ "${PROBLEMS:-0}" -eq 0 ] 2>/dev/null; then
    echo "[OK] duong VPN dung chuan, khong can sua"
    exit 0
  fi
  echo "[WARN] co $PROBLEMS diem lech - chay '$0 fix' de chua"
  exit 1
fi

if [ "$CHANGED" -gt 0 ]; then
  printf '%s' "$REPORT"
  echo "[OK] gen_vpn_guard: da chua $CHANGED diem"
else
  echo "[OK] gen_vpn_guard: khong co gi phai chua"
fi
exit 0
