#!/bin/sh
# ============================================================
# vpn_mgr.sh - VPN manager DA DUNG cho router GEN (.14)
# Viet lai tu vpn_ctl.sh + tham khao kien truc genrouter cu:
#   - moi tai khoan VPN = 1 thu muc /data/vpn/accounts/<ten>/
#       config.ovpn | wg-strip.conf   : cau hinh
#       auth                          : 2 dong user\npass (neu co)
#       meta                          : type/idx/dev/table/prio/auto
#   - tunnel song song: dev tun<idx>, table 300+idx, rule prio 90+idx
#   - client gan VPN: RETURN dau mangle PREROUTING (thoat gencore +
#     thoat UDP-reject) + ip rule from <IP> table <T>
#
# LENH:
#   vpn_mgr.sh list                        : danh sach tai khoan
#   vpn_mgr.sh status                      : trang thai moi tunnel
#   vpn_mgr.sh add-openvpn <ten> </duoc/file.ovpn> [user] [pass]
#   vpn_mgr.sh add-express <ten> <location-hoac-hostname> <user> <pass>
#   vpn_mgr.sh add-wg <ten> </duoc/wg.conf>      (can wireguard-tools)
#   vpn_mgr.sh import-old                  : don cac ovpn cu trong configs/
#   vpn_mgr.sh up|down <ten>               : bat/tat 1 tunnel
#   vpn_mgr.sh assign <ten> <IP>           : gan client vao 1 VPN
#   vpn_mgr.sh clean-stale                 : don rule/map rac khi tunnel chet hoac IP khong con trong map
#   vpn_mgr.sh unassign <IP>               : bo gan client
#   vpn_mgr.sh test <ten>                  : xem exit-IP qua tunnel
#   vpn_mgr.sh autostart <ten> on|off      : up khi goi startall
#   vpn_mgr.sh startall|stopall            : loat theo flag auto
#   vpn_mgr.sh del <ten>                   : xoa tai khoan
# ============================================================

BASE=/data/vpn
ACCT=$BASE/accounts
MAPF=$BASE/map.txt
LOGS=$BASE/logs
TPL=$BASE/express_template.ovpn
HOSTS=$BASE/express_hosts.txt
OLD_AUTH=$BASE/auth.txt

mkdir -p "$ACCT" "$LOGS"
[ -f "$MAPF" ] || : > "$MAPF"

err()  { echo "[ERR] $*" >&2; exit 1; }
ok()   { echo "[OK] $*"; }
die_use() { sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

meta_get() { # meta_get <ten> <key>
  grep -o "^$2=.*" "$ACCT/$1/meta" 2>/dev/null | head -n1 | cut -d= -f2-
}
meta_set() { # meta_set <ten> <key> <val>
  touch "$ACCT/$1/meta"
  grep -v "^$2=" "$ACCT/$1/meta" > "$ACCT/$1/meta.new" 2>/dev/null
  echo "$2=$3" >> "$ACCT/$1/meta.new"
  mv "$ACCT/$1/meta.new" "$ACCT/$1/meta"
}
exists() { [ -d "$ACCT/$1" ]; }
next_idx() {
  m=0
  for f in "$ACCT"/*/meta; do
    [ -f "$f" ] || continue
    i=$(grep -o '^idx=[0-9]*' "$f" | cut -d= -f2)
    [ -n "$i" ] && [ "$i" -gt "$m" ] 2>/dev/null && m=$i
  done
  echo $((m+1))
}
running() { # running <ten>
  p="/tmp/vpn_$1.pid"
  [ -f "$p" ] && kill -0 "$(cat "$p")" 2>/dev/null && return 0
  # wireguard khong co daemon: kiem tra link con ton tai
  [ "$(meta_get "$1" type)" = "wireguard" ] || return 1
  dev=$(meta_get "$1" dev)
  [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1
}

# ---------- them tai khoan ----------
norm_ovpn() { # norm_ovpn <src.ovpn> <dst.ovpn> <dev> <authpath|->
  awk -v D="$3" -v A="$4" '
    {
      gsub("\r","");
      if ($0 ~ /^ns-cert-type server/) { print "remote-cert-tls server"; next }
      if ($0 ~ /^dev /)                { print "dev " D; next }
      if ($0 ~ /^auth-user-pass/) {
        if (A == "-") { next }
        print "auth-user-pass " A; next
      }
      print
    }' "$1" > "$2"
}

cmd_add_openvpn() {
  name="$2"; src="$3"; user="$4"; pass="$5"
  [ -n "$name" ] && [ -n "$src" ] || die_use
  exists "$name" && err "tai khoan '$name' da co"
  [ -f "$src" ] || err "khong thay file $src"
  d="$ACCT/$name"; mkdir -p "$d"
  idx=$(next_idx)
  dev="tun$idx"; tbl=$((300+idx)); pri=$((90+idx))
  if [ -n "$user" ]; then
    printf '%s\n%s\n' "$user" "$pass" > "$d/auth"; chmod 600 "$d/auth"
    norm_ovpn "$src" "$d/config.ovpn" "$dev" "$d/auth"
  else
    norm_ovpn "$src" "$d/config.ovpn" "$dev" "-"
  fi
  cat > "$d/meta" <<EOF
type=openvpn
idx=$idx
dev=$dev
table=$tbl
prio=$pri
auto=0
EOF
  ok "da them openvpn '$name' ($dev table $tbl)"
}

resolve_express_host() {
  arg="$1"
  case "$arg" in *expressnetw.com*) echo "$arg"; return 0;; esac
  [ -f "$HOSTS" ] || err "thieu $HOSTS (chua upload danh sach host)"
  n=$(grep -ci -- "$arg" "$HOSTS")
  [ "$n" -eq 0 ] && { echo "[ERR] khong tim thay host cho '$arg'. Vi du:"; grep -i -e singapore -e japan -e us-new "$HOSTS" | head -5 >&2; return 1; }
  if [ "$n" -gt 1 ]; then
    echo "[ERR] '$arg' trung $n host, chon ro hon:" >&2
    grep -i -- "$arg" "$HOSTS" | head -8 >&2
    return 1
  fi
  grep -i -- "$arg" "$HOSTS" | head -n1
}

cmd_add_express() {
  name="$2"; loc="$3"; user="$4"; pass="$5"
  [ -n "$name" ] && [ -n "$loc" ] && [ -n "$user" ] || die_use
  exists "$name" && err "tai khoan '$name' da co"
  [ -f "$TPL" ] || err "thieu template $TPL (chua upload express_template.ovpn)"
  host=$(resolve_express_host "$loc") || exit 1
  d="$ACCT/$name"; mkdir -p "$d"
  idx=$(next_idx)
  dev="tun$idx"; tbl=$((300+idx)); pri=$((90+idx))
  printf '%s\n%s\n' "$user" "$pass" > "$d/auth"; chmod 600 "$d/auth"
  tr -d '\r' < "$TPL" | awk -v D="$dev" -v H="$host" -v A="$d/auth" '
    {
      gsub("dev tun%d", "dev " D)
      gsub("remote %s 1195", "remote " H " 1195")
      gsub("/etc/genrouter/openvpn/%d.auth", A)
      if ($0 == "ns-cert-type server") $0 = "remote-cert-tls server"
      print
    }' > "$d/config.ovpn"
  cat > "$d/meta" <<EOF
type=openvpn
provider=expressvpn
host=$host
idx=$idx
dev=$dev
table=$tbl
prio=$pri
auto=0
EOF
  ok "da them expressvpn '$name' -> $host:1195 ($dev table $tbl)"
}

cmd_import_old() {
  [ -d "$BASE/configs" ] || err "khong co $BASE/configs"
  au=""
  [ -f "$OLD_AUTH" ] && au=$(head -c 4000 "$OLD_AUTH")
  found=0
  for f in "$BASE"/configs/*.ovpn; do
    [ -f "$f" ] || continue
    found=1
    b=$(basename "$f" .ovpn)
    exists "$b" && { echo "bo qua $b (da co)"; continue; }
    if [ -n "$au" ]; then
      u=$(printf '%s' "$au" | sed -n 1p); p=$(printf '%s' "$au" | sed -n 2p)
      cmd_add_openvpn "" x "$f" "$u" "$p"
    else
      cmd_add_openvpn "" x "$f"
    fi
    mv "$ACCT/x" "$ACCT/$b"
  done
  [ "$found" = 1 ] && ok "import xong" || err "khong thay ovn nao trong configs/"
}

# ------------------------------------------------------------
wireguard_ok() {
  command -v wg >/dev/null 2>&1 || { echo "[ERR] thieu 'wg'. Cai: opkg update && opkg install wireguard-tools kmod-wireguard (chu y disk root it cho trong)"; return 1; }
  return 0
}
cmd_add_wg() {
  name="$2"; src="$3"
  [ -n "$name" ] && [ -n "$src" ] || die_use
  wireguard_ok || exit 1
  exists "$name" && err "tai khoan '$name' da co"
  [ -f "$src" ] || err "khong thay $src"
  d="$ACCT/$name"; mkdir -p "$d"
  # lay value sau dau '=' DAU TIEN, giu nguyen padding base64 (dung sed, khong dung awk -F'=')
  priv=$(sed -n 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//p' "$src" | head -n1 | tr -d '\r')
  addr=$(sed -n 's/^[[:space:]]*Address[[:space:]]*=[[:space:]]*//p' "$src" | head -n1 | tr -d '\r')
  peer=$(sed -n '/^\[Peer\]/,$p' "$src" | sed -n 's/^[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*//p' | head -n1 | tr -d '\r')
  ep=$(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$src" | head -n1 | tr -d '\r')
  psk=$(sed -n 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//p' "$src" | head -n1 | tr -d '\r')
  [ -n "$priv" ] && [ -n "$peer" ] && [ -n "$addr" ] || err "wg.conf thieu PrivateKey/Address/Peer.PublicKey"
  {
    echo "[Interface]"; echo "PrivateKey = $priv"
    echo ""; echo "[Peer]"
    echo "PublicKey = $peer"; echo "Endpoint = $ep"
    echo "AllowedIPs = 0.0.0.0/0,::/0"
    [ -n "$psk" ] && echo "PresharedKey = $psk"
  } > "$d/wg-strip.conf"
  chmod 600 "$d/wg-strip.conf"
  idx=$(next_idx)
  cat > "$d/meta" <<EOF
type=wireguard
idx=$idx
dev=wg$idx
table=$((300+idx))
prio=$((90+idx))
addr=$addr
endpoint=$ep
auto=0
EOF
  cp "$src" "$d/wg-original.conf"; chmod 600 "$d/wg-original.conf"
  ok "da them wireguard '$name' (wg$idx)"
}

# ---------- routing helpers ----------
ensure_route() { # <dev> <tbl> - dam bao table co default route (openvpn reset tun lam mat route)
  ip route show table "$2" 2>/dev/null | grep -q '^default' || \
    ip route replace default dev "$1" table "$2" 2>/dev/null
}
# ---------- guard: duong thoat theo ipset thay vi rule per-IP ----------
# Ly do: /etc/genrouter/core/tproxy chen 'iptables -I FORWARD 1 -i br-lan -p udp
# -j DROP' va gen_fw_fix.sh chen 'mangle -I PREROUTING 1 -i br-lan -p udp -j
# GEN_FW_UDP' MOI LAN apply cau hinh -> rule per-IP bi day xuong duoi va het tac
# dung. Dung ipset genrouter_vpn + 4 rule co dinh do gen_vpn_guard.sh ep ve dau
# chain thi them/bo may VPN chi la ipset add/del, khong bao gio lech thu tu.
VPN_GUARD=/etc/gen_vpn_guard.sh
VPN_SET=genrouter_vpn

guard_run() { [ -x "$VPN_GUARD" ] && "$VPN_GUARD" fix >/dev/null 2>&1; return 0; }
guard_set_ok() { ipset list -n "$VPN_SET" >/dev/null 2>&1; }

assign_rules_on() { # <IP> <tbl> <pri> [dev]
  if guard_set_ok; then
    ipset add "$VPN_SET" "$1" -exist 2>/dev/null
  else
    # fallback khi chua cai guard: giu nguyen hanh vi cu
    iptables -t mangle -C PREROUTING -s "$1" -j RETURN 2>/dev/null || \
      iptables -t mangle -I PREROUTING 1 -s "$1" -j RETURN
  fi
  ip rule show | grep -q "from $1 lookup $2" || \
    ip rule add from "$1" table "$2" priority "$3"
  [ -n "$4" ] && ensure_route "$4" "$2"
  guard_run
  return 0
}
assign_rules_off() { # <IP> <tbl> <pri>
  guard_set_ok && ipset del "$VPN_SET" "$1" 2>/dev/null
  # don ca rule per-IP cu (ban truoc guard) de khong con rac
  while iptables -t mangle -D PREROUTING -s "$1" -j RETURN 2>/dev/null; do :; done
  while ip rule del from "$1" table "$2" priority "$3" 2>/dev/null; do :; done
  return 0
}
masq_on()  { iptables -t nat -C POSTROUTING -o "$1" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$1" -j MASQUERADE; }
masq_off() { while iptables -t nat -D POSTROUTING -o "$1" -j MASQUERADE 2>/dev/null; do :; done; }

restore_clients() { # restore_clients <ten>
  tbl=$(meta_get "$1" table); pri=$(meta_get "$1" prio); dev=$(meta_get "$1" dev)
  awk -v N="$1" '$2==N{print $1}' "$MAPF" | while read -r ip; do
    [ -n "$ip" ] || continue
    assign_rules_on "$ip" "$tbl" "$pri" "$dev"
    echo "  restored: $ip"
  done
}

do_up() {
  name="$2"; [ -n "$name" ] || die_use
  exists "$name" || err "khong co tai khoan '$name'"
  running "$name" && err "'$name' dang chay roi"
  type=$(meta_get "$name" type); dev=$(meta_get "$name" dev)
  tbl=$(meta_get "$name" table)
  log="$LOGS/$name.log"
  if [ "$type" = wireguard ]; then
    wireguard_ok || exit 1
    ip link del "$dev" 2>/dev/null
    ip link add "$dev" type wireguard || err "tao $dev that bai"
    wg setconf "$dev" "$ACCT/$name/wg-strip.conf" || { ip link del "$dev"; err "wg setconf loi"; }
    addr=$(meta_get "$name" addr)
    for a in $(echo "$addr" | tr ',' ' '); do ip addr add "$a" dev "$dev" 2>/dev/null; done
    ip link set "$dev" mtu 1420 up
  else
    rm -f "$log"
    extra=""
    [ -f "$ACCT/$name/auth" ] && extra="--auth-user-pass $ACCT/$name/auth"
    openvpn --config "$ACCT/$name/config.ovpn" \
      $extra \
      --daemon --writepid "/tmp/vpn_$name.pid" --log "$log" \
      --route-nopull \
      --pull-filter ignore "redirect-gateway" \
      --pull-filter ignore "dhcp-options" || err "openvpn khong chay duoc"
  fi
  i=0
  while [ $i -lt 45 ]; do
    ip link show "$dev" >/dev/null 2>&1 && break
    sleep 1; i=$((i+1))
  done
  if ! ip link show "$dev" >/dev/null 2>&1; then
    [ -f "/tmp/vpn_$name.pid" ] && kill "$(cat /tmp/vpn_$name.pid)" 2>/dev/null
    rm -f "/tmp/vpn_$name.pid"
    err "$dev khong len - xem log: tail -30 $log"
  fi
  # doi tunnel co IP (openvpn gan addr sau handshake) truoc khi dat route
  j=0
  while [ $j -lt 30 ]; do
    ip -4 addr show "$dev" 2>/dev/null | grep -q inet && break
    sleep 1; j=$((j+1))
  done
  ip route replace default dev "$dev" table "$tbl"
  masq_on "$dev"
  ( sleep 5; ensure_route "$dev" "$tbl" ) &
  guard_run
  ok "'$name' UP ($dev):"
  ip -4 addr show "$dev" | grep inet
  restore_clients "$name"
}

do_down() {
  name="$2"; [ -n "$name" ] || die_use
  exists "$name" || err "khong co tai khoan '$name'"
  dev=$(meta_get "$name" dev); tbl=$(meta_get "$name" table); pri=$(meta_get "$name" prio)
  [ -f "/tmp/vpn_$name.pid" ] && { kill "$(cat /tmp/vpn_$name.pid)" 2>/dev/null; rm -f "/tmp/vpn_$name.pid"; }
  ip link del "$dev" 2>/dev/null
  masq_off "$dev"
  ip route flush table "$tbl" 2>/dev/null
  awk -v N="$name" '$2==N{print $1}' "$MAPF" | while read -r ip; do
    [ -n "$ip" ] || continue
    assign_rules_off "$ip" "$tbl" "$pri"
    grep -v "^$ip $name\$" "$MAPF" > "$MAPF.tmp" 2>/dev/null; mv "$MAPF.tmp" "$MAPF"
    echo "  unassigned: $ip"
  done
  ok "'$name' DOWN"
}

cmd_clean_stale() {
  # Quet ip rule lookup 300-399:
  #   - IP khong co trong map.txt -> xoa rule (rac)
  #   - tunnel cua map da chet (mat dev / mat default route) -> xoa rule + go map
  #   - table thieu default ma dev con song -> tu v?a ensure_route thay vi xoa
  rules="/tmp/vpn_rules.$$"
  ip rule show 2>/dev/null | awk '/lookup 3[0-9][0-9]/' > "$rules"
  [ -s "$rules" ] || { rm -f "$rules"; ok "khong co rule vpn nao"; return 0; }
  while IFS= read -r line; do
    prio=$(printf '%s\n' "$line" | awk '{gsub(/:/,"",$1);print $1}')
    fromip=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="from"){print $(i+1);exit}}')
    tbl=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lookup"){print $(i+1);exit}}')
    [ -n "$prio" ] && [ -n "$fromip" ] && [ -n "$tbl" ] || continue
    printf '%s' "$fromip" | grep -qE '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$' || continue
    case "$tbl" in 3[0-9][0-9]) ;; *) continue ;; esac
    name=$(awk -v I="$fromip" '$1==I{print $2; exit}' "$MAPF")
    if [ -z "$name" ]; then
      ip rule del priority "$prio" from "$fromip" lookup "$tbl" >/dev/null 2>&1 \
        && echo "[CLEAN] bo rule rac: $fromip -> table $tbl (khong trong map)"
      continue
    fi
    dev=$(meta_get "$name" dev)
    alive=1
    ip link show "$dev" >/dev/null 2>&1 || alive=0
    if [ "$alive" = 1 ]; then
      ip route show table "$tbl" 2>/dev/null | grep -q '^default' || {
        ensure_route "$dev" "$tbl"
        ip route show table "$tbl" 2>/dev/null | grep -q '^default' || alive=0
      }
    fi
    if [ "$alive" = 0 ]; then
      ip rule del priority "$prio" from "$fromip" lookup "$tbl" >/dev/null 2>&1
      awk -v I="$fromip" '$1!=I' "$MAPF" > "$MAPF.tmp" 2>/dev/null && mv "$MAPF.tmp" "$MAPF"
      echo "[CLEAN] $fromip -> table $tbl (tunnel '$name' chet/mat)"
    fi
  done < "$rules"
  rm -f "$rules"
  ok "clean-stale xong"
}

case "$1" in
  add-openvpn) cmd_add_openvpn "$@" ;;
  add-express) cmd_add_express "$@" ;;
  add-wg)      cmd_add_wg "$@" ;;
  import-old)  cmd_import_old ;;
  clean-stale) cmd_clean_stale ;;
  up)          do_up "$@" ;;
  down)        do_down "$@" ;;
  startall)
    for d in "$ACCT"/*/meta; do
      [ -f "$d" ] || continue
      n=$(dirname "$d" | xargs basename)
      [ "$(meta_get "$n" auto)" = "1" ] || continue
      running "$n" || { echo "== start $n"; do_up x "$n"; }
    done ;;
  stopall)
    for d in "$ACCT"/*/meta; do
      [ -f "$d" ] || continue
      n=$(dirname "$d" | xargs basename)
      running "$n" && do_down x "$n"
    done ;;
  assign)
    name="$2"; ip="$3"
    [ -n "$name" ] && [ -n "$ip" ] || die_use
    exists "$name" || err "khong co tai khoan '$name'"
    dev=$(meta_get "$name" dev)
    ip link show "$dev" >/dev/null 2>&1 || err "tunnel '$name' chua bat - chay: vpn_mgr.sh up $name"
    tbl=$(meta_get "$name" table); pri=$(meta_get "$name" prio)
    # gan lai sang VPN khac: go duong cu truoc (1 IP chi thuoc 1 VPN)
    old=$(awk -v I="$ip" '$1==I{print $2; exit}' "$MAPF")
    if [ -n "$old" ] && [ "$old" != "$name" ]; then
      otbl=$(meta_get "$old" table); opri=$(meta_get "$old" prio)
      [ -n "$otbl" ] && assign_rules_off "$ip" "$otbl" "$opri"
      grep -v "^$ip $old\$" "$MAPF" > "$MAPF.tmp" 2>/dev/null; mv "$MAPF.tmp" "$MAPF"
    fi
    assign_rules_on "$ip" "$tbl" "$pri" "$dev"
    grep -q "^$ip $name\$" "$MAPF" || echo "$ip $name" >> "$MAPF"
    ok "$ip di qua VPN '$name'" ;;
  unassign)
    ip="$2"; [ -n "$ip" ] || die_use
    name=$(awk -v I="$ip" '$1==I{print $2; exit}' "$MAPF")
    [ -n "$name" ] || err "$ip chua duoc gan cho VPN nao"
    tbl=$(meta_get "$name" table); pri=$(meta_get "$name" prio)
    assign_rules_off "$ip" "$tbl" "$pri"
    grep -v "^$ip $name\$" "$MAPF" > "$MAPF.tmp" 2>/dev/null; mv "$MAPF.tmp" "$MAPF"
    ok "da bo gan $ip (tu '$name')" ;;
  test)
    name="$2"; [ -n "$name" ] || die_use
    dev=$(meta_get "$name" dev)
    lip=$(ip -4 addr show "$dev" 2>/dev/null | awk '/inet/{split($2,a,"/");print a[1];exit}')
    [ -n "$lip" ] || err "tunnel '$name' chua UP"
    echo "local-in-tunnel: $lip"
    echo "route-get: $(ip route get 198.54.65.98 from "$lip" 2>/dev/null | head -n1)"
    if command -v curl >/dev/null 2>&1; then
      echo "exit-ip: $(curl -4 -s --max-time 10 --interface "$lip" https://api.ipify.org)"
    else
      echo "(khong co curl - xem 'route-get' o tren de ket luan)"
    fi ;;
  autostart)
    name="$2"; v="$3"
    exists "$name" || err "khong co '$name'"
    case "$v" in on) meta_set "$name" auto 1 ;; off) meta_set "$name" auto 0 ;; *) die_use ;; esac
    ok "autostart('$name')=$v" ;;
  del)
    name="$2"; exists "$name" || err "khong co '$name'"
    running "$name" && err "'$name' dang chay - down truoc"
    tbl=$(meta_get "$name" table); pri=$(meta_get "$name" prio)
    awk -v N="$name" '$2==N{print $1}' "$MAPF" | while read -r ip; do
      [ -n "$ip" ] && assign_rules_off "$ip" "$tbl" "$pri"
    done
    grep -v " $name\$" "$MAPF" > "$MAPF.tmp" 2>/dev/null; mv "$MAPF.tmp" "$MAPF"
    rm -rf "$ACCT/$name"
    ok "da xoa '$name'" ;;
  json)
    out="["
    sep=""
    for d in "$ACCT"/*/meta; do
      [ -f "$d" ] || continue
      n=$(dirname "$d" | xargs basename)
      r=false; running "$n" && r=true
      c=0
      ips=$(awk -v N="$n" '$2==N{printf "%s%s", sep, $1; sep=","}' "$MAPF")
      cl=""
      [ -n "$ips" ] && cl="\"$(echo "$ips" | sed 's/,/","/g')\""
      cc=$(awk -v N="$n" '$2==N' "$MAPF" | wc -l)
      pv=$(meta_get "$n" provider); [ -z "$pv" ] && pv=$(meta_get "$n" host)
      out="$out$sep{\"name\":\"$n\",\"type\":\"$(meta_get "$n" type)\",\"dev\":\"$(meta_get "$n" dev)\",\"table\":$(meta_get "$n" table),\"prio\":$(meta_get "$n" prio),\"running\":$r,\"auto\":$(meta_get "$n" auto),\"clients\":[$cl],\"client_count\":$cc,\"host\":\"$pv\"}"
      sep=","
    done
    echo "$out]"
    ;;
  list)
    echo "NAME              TYPE       DEV    RUN  AUTO  CLIENTS  PROVIDER/HOST"
    for d in "$ACCT"/*/meta; do
      [ -f "$d" ] || continue
      n=$(dirname "$d" | xargs basename)
      r="-"; running "$n" && r="UP"
      c=$(awk -v N="$n" '$2==N' "$MAPF" | wc -l)
      pv=$(meta_get "$n" provider); [ -z "$pv" ] && pv=$(meta_get "$n" host)
      printf '%-17s %-10s %-6s %-4s %-5s %-8s %s\n' "$n" "$(meta_get "$n" type)" "$(meta_get "$n" dev)" "$r" "$(meta_get "$n" auto)" "$c" "$pv"
    done ;;
  status)
    any=0
    for d in "$ACCT"/*/meta; do
      [ -f "$d" ] || continue
      any=1; n=$(dirname "$d" | xargs basename)
      echo "== $n ($(meta_get "$n" type))"
      if running "$n"; then
        dev=$(meta_get "$n" dev)
        echo "   state: UP  $(ip -4 addr show $dev 2>/dev/null | awk '/inet/{print $2}')"
        echo "   table: $(ip route show table $(meta_get "$n" table) 2>/dev/null)"
      else
        echo "   state: down"
      fi
    done
    [ "$any" = 1 ] || echo "(chua co tai khoan nao - xem help)"
    echo "-- map client->vpn:"; sed 's/^/   /' "$MAPF" ;;
  *)
    die_use ;;
esac
