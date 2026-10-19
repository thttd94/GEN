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
#   vpn_mgr.sh set-auth <ten|--all> <u> <p>: gan/sua username-password OpenVPN
#   vpn_mgr.sh assign <ten> <IP>           : gan client vao 1 VPN
#   vpn_mgr.sh assign-many <ten> <IP...>   : gan NHIEU client 1 luot (nhanh)
#   vpn_mgr.sh unassign-many <IP...>       : bo gan NHIEU client 1 luot
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

# Kiem tra IPv4 that su: 4 octet, moi octet 0-255, khong co ky tu la.
# (glob '[0-9]*.[0-9]*.[0-9]*.[0-9]*' cu chap nhan ca 999.1.1.1)
is_ipv4() {
  case "${1:-}" in
    *[!0-9.]*|''|.*|*.|*..*) return 1 ;;
  esac
  IFS_OLD=$IFS; IFS=.; set -- $1; IFS=$IFS_OLD
  [ $# -eq 4 ] || return 1
  for o in "$@"; do
    [ -n "$o" ] || return 1
    [ "${#o}" -le 3 ] || return 1
    [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}
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
# [Ver 2.48] Config .ovpn CAN username/password khi khong co chung chi client.
# openvpn tu choi chay ngay neu thieu ca 3 (--cert/--key, --pkcs12, --auth-user-pass):
#   "Options error: No client-side authentication method is specified."
# Dung cho CA 2 thoi diem: luc `add` (kiem file nguon) va luc `up` (kiem config da chuan hoa).
# Tra 0 = CAN auth-user-pass.
ovpn_needs_auth() {
  [ -f "${1:-}" ] || return 1
  grep -qE '^[[:space:]]*(cert|pkcs12)[[:space:]]|^[[:space:]]*<(cert|pkcs12)>' "$1" && return 1
  return 0
}

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
  # [Ver 2.48] KHONG tao tai khoan hong roi de no chet luc UP.
  # Truoc ban nay: norm_ovpn() XOA IM LANG dong 'auth-user-pass' khi khong co user,
  # van in [OK], den luc UP moi bao "openvpn khong chay duoc" ma khong noi ly do.
  if [ -z "$user" ] && [ "${VPN_ALLOW_NOAUTH:-0}" != "1" ] && ovpn_needs_auth "$src"; then
    echo "[ERR] file .ovpn nay YEU CAU username/password (khong co chung chi client)." >&2
    echo "      Hay dien 2 o username/password roi them lai tai khoan '$name'." >&2
    echo "      ProtonVPN: lay o trang Account, muc 'OpenVPN / IKEv2 username'" >&2
    echo "      (KHONG phai email + mat khau dang nhap website)." >&2
    exit 1
  fi
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
      # [Ver 2.48] khong co auth.txt: bo qua file can dang nhap thay vi tao tai khoan hong
      if ovpn_needs_auth "$f"; then
        echo "bo qua $b: can username/password (thieu $OLD_AUTH)"
        continue
      fi
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

guard_run() {
  # VPN_NO_GUARD=1 -> bo qua guard (dung cho assign-many/unassign-many:
  # guard chi chay DUNG 1 LAN o cuoi thay vi sau tung IP)
  [ "${VPN_NO_GUARD:-0}" = "1" ] && return 0
  [ -x "$VPN_GUARD" ] && "$VPN_GUARD" fix >/dev/null 2>&1; return 0
}
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
    # [Ver 2.48] chan som + noi RO ly do (truoc day chi in "openvpn khong chay duoc")
    if [ -z "$extra" ] && ovpn_needs_auth "$ACCT/$name/config.ovpn"; then
      echo "[ERR] tai khoan '$name' THIEU username/password OpenVPN." >&2
      echo "      Config can dang nhap nhung luc them tai khoan da de trong 2 o" >&2
      echo "      username/password, nen dong 'auth-user-pass' bi bo." >&2
      echo "      SUA NGAY: sh $0 set-auth $name '<username>' '<password>'" >&2
      echo "      (ProtonVPN: trang Account > 'OpenVPN / IKEv2 username'," >&2
      echo "       KHONG phai email + mat khau dang nhap website)" >&2
      exit 1
    fi
    # [Ver 2.48] 'dhcp-option' (so IT) moi la ten option ProtonVPN push. Ban truoc viet
    # 'dhcp-options' (so nhieu) nen filter khong khop gi => 49/59 log day dong
    # "Options error: option 'dhcp-option' cannot be used in this context".
    if ! openvpn --config "$ACCT/$name/config.ovpn" \
      $extra \
      --daemon --writepid "/tmp/vpn_$name.pid" --log "$log" \
      --route-nopull \
      --pull-filter ignore "redirect-gateway" \
      --pull-filter ignore "dhcp-option"; then
      echo "[ERR] openvpn khong chay duoc - LY DO THAT:" >&2
      if [ -s "$log" ]; then
        tail -6 "$log" | sed 's/^/      /' >&2
      else
        echo "      (log rong hoac khong ghi duoc: $log)" >&2
      fi
      echo "      xem day du: tail -30 $log" >&2
      exit 1
    fi
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

# [Ver 2.46 2026-09-05] DONG CUA SO RO IP THAT khi apply mode VPN.
# Kill-switch dong bo `ipset genrouter_vpn_want` (may KHAI BAO VPN, trich tu
# /etc/genrouter/gencore.json) roi chen rule chan "khai VPN ma chua gan tunnel".
# Cron goi no moi 1 phut, nen sau khi apply co cua so <=60 s ma may khai VPN
# nhung tunnel chet van RA WAN BANG IP THAT. clean-stale la buoc CUOI cua
# sync_vpn_state_on_apply (app.py:2305, dung 1 lan/apply, sau moi assign-many),
# va luc do gencore.json DA la cau hinh moi (ghi o app.py:2557) => goi ngay tai
# day thi cua so ve ~0 s. Kill-switch idempotent, do duoc 0 ms, va KHONG goi
# vpn_mgr.sh nen khong de quy.
ks_refresh() {
  [ -x /etc/genrouter_killswitch.sh ] && /etc/genrouter_killswitch.sh >/dev/null 2>&1
  return 0
}

cmd_clean_stale() {
  # Quet ip rule lookup 300-399:
  #   - IP khong co trong map.txt -> xoa rule (rac)
  #   - tunnel cua map da chet (mat dev / mat default route) -> xoa rule + go map
  #   - table thieu default ma dev con song -> tu v?a ensure_route thay vi xoa
  rules="/tmp/vpn_rules.$$"
  ip rule show 2>/dev/null | awk '/lookup 3[0-9][0-9]/' > "$rules"
  [ -s "$rules" ] || { rm -f "$rules"; ks_refresh; ok "khong co rule vpn nao"; return 0; }
  while IFS= read -r line; do
    prio=$(printf '%s\n' "$line" | awk '{gsub(/:/,"",$1);print $1}')
    fromip=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="from"){print $(i+1);exit}}')
    tbl=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lookup"){print $(i+1);exit}}')
    [ -n "$prio" ] && [ -n "$fromip" ] && [ -n "$tbl" ] || continue
    # Ver 2.33: sua regex kiem IP. Ban cu dung '\\.' - trong ERE nghia la
    # "mot dau backslash roi mot ky tu bat ky", tuc doi IP phai CHUA backslash
    # nen KHONG IP NAO khop => moi dong deu continue => clean-stale luon bao OK
    # ma khong don gi. Do la ly do 210 rule mo coi ton tai duoc sau khi map.txt
    # bi xoa. Dung '[.]' de khop dau cham that.
    printf '%s' "$fromip" | grep -qE '^[0-9]{1,3}([.][0-9]{1,3}){3}$' || continue
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
  ks_refresh
  ok "clean-stale xong"
}

# [Ver 2.48] gan/sua username-password OpenVPN cho tai khoan DA tao.
# Chua chuc nang cua ban va tay: ghi file auth + bao dam config.ovpn tro DUNG vao no
# (them lai dong 'auth-user-pass <path>' neu truoc do bi norm_ovpn xoa).
# Idempotent, backup config.ovpn mot lan (.bak_setauth), KHONG tu bam UP.
cmd_set_auth() { # cmd_set_auth x <ten|--all> <user> <pass>
  target="$2"; u="$3"; p="$4"
  [ -n "$target" ] && [ -n "$u" ] && [ -n "$p" ] || \
    err "dung: $0 set-auth <ten-tai-khoan|--all> '<username>' '<password>'"
  n_ok=0
  for d in "$ACCT"/*/; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    [ "$target" = "--all" ] || [ "$target" = "$n" ] || continue
    if [ "$(meta_get "$n" type)" = "wireguard" ]; then
      echo "[-] $n: wireguard, bo qua"; continue
    fi
    [ -f "$d/config.ovpn" ] || { echo "[!] $n: khong co config.ovpn, bo qua"; continue; }
    printf '%s\n%s\n' "$u" "$p" > "$d/auth"; chmod 600 "$d/auth"
    [ -f "$d/config.ovpn.bak_setauth" ] || cp "$d/config.ovpn" "$d/config.ovpn.bak_setauth"
    if grep -q '^auth-user-pass' "$d/config.ovpn"; then
      sed -i "s|^auth-user-pass.*|auth-user-pass $d/auth|" "$d/config.ovpn"
      echo "[=] $n: cap nhat auth"
    else
      printf 'auth-user-pass %s\n' "$d/auth" >> "$d/config.ovpn"
      echo "[+] $n: THEM lai dong auth-user-pass (tai khoan nay dang bi loi)"
    fi
    n_ok=$((n_ok+1))
  done
  [ "$n_ok" -gt 0 ] || err "khong khop tai khoan nao ('$target')"
  ok "da gan credential cho $n_ok tai khoan - gio bam UP hoac: $0 up <ten>"
}

case "$1" in
  add-openvpn) cmd_add_openvpn "$@" ;;
  add-express) cmd_add_express "$@" ;;
  add-wg)      cmd_add_wg "$@" ;;
  import-old)  cmd_import_old ;;
  clean-stale) cmd_clean_stale ;;
  set-auth)    cmd_set_auth "$@" ;;
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
  assign-many)
    # assign-many <ten> <IP1> <IP2> ...
    # Nhanh hon N lan 'assign' vi:
    #   - guard chi chay DUNG 1 LAN o cuoi (VPN_NO_GUARD=1)
    #   - map.txt duoc ghi 1 lan bang awk thay vi grep/mv moi IP
    #   - ip rule show doc 1 lan
    name="$2"; shift 2
    [ -n "$name" ] && [ -n "$1" ] || die_use
    exists "$name" || err "khong co tai khoan '$name'"
    dev=$(meta_get "$name" dev)
    ip link show "$dev" >/dev/null 2>&1 || err "tunnel '$name' chua bat - chay: vpn_mgr.sh up $name"
    tbl=$(meta_get "$name" table); pri=$(meta_get "$name" prio)
    ensure_route "$dev" "$tbl"

    VPN_NO_GUARD=1
    export VPN_NO_GUARD
    RULES="/tmp/vpn_am_rules.$$"
    NEWMAP="/tmp/vpn_am_map.$$"
    IPLIST="/tmp/vpn_am_ips.$$"
    ip rule show 2>/dev/null > "$RULES"
    : > "$IPLIST"
    okn=0; badn=0

    for ip in "$@"; do
      if ! is_ipv4 "$ip"; then
        echo "[SKIP] IP khong hop le: $ip"; badn=$((badn+1)); continue
      fi
      # bo trung lap trong chinh danh sach dau vao
      if grep -qxF "$ip" "$IPLIST" 2>/dev/null; then
        continue
      fi
      # go duong VPN cu neu dang thuoc tunnel khac
      old=$(awk -v I="$ip" '$1==I{print $2; exit}' "$MAPF")
      if [ -n "$old" ] && [ "$old" != "$name" ]; then
        otbl=$(meta_get "$old" table); opri=$(meta_get "$old" prio)
        [ -n "$otbl" ] && assign_rules_off "$ip" "$otbl" "$opri"
      fi
      # ipset + ip rule (khong goi guard)
      if guard_set_ok; then
        ipset add "$VPN_SET" "$ip" -exist 2>/dev/null
      else
        iptables -t mangle -C PREROUTING -s "$ip" -j RETURN 2>/dev/null || \
          iptables -t mangle -I PREROUTING 1 -s "$ip" -j RETURN
      fi
      grep -q "from $ip lookup $tbl" "$RULES" 2>/dev/null || \
        ip rule add from "$ip" table "$tbl" priority "$pri" 2>/dev/null
      echo "$ip" >> "$IPLIST"
      okn=$((okn+1))
    done

    # ghi map.txt 1 lan: bo cac dong cua IP trong danh sach, roi them lai
    awk -v LF="$IPLIST" 'BEGIN{while((getline l < LF)>0) d[l]=1} !($1 in d)' "$MAPF" > "$NEWMAP" 2>/dev/null
    while read -r ip; do
      [ -n "$ip" ] && echo "$ip $name" >> "$NEWMAP"
    done < "$IPLIST"
    mv "$NEWMAP" "$MAPF"
    rm -f "$RULES" "$IPLIST"

    # guard DUNG 1 LAN cho ca loat
    unset VPN_NO_GUARD
    guard_run
    ok "gan $okn may vao VPN '$name'$([ "$badn" -gt 0 ] && echo " ($badn IP bo qua)")" ;;
  unassign-many)
    # unassign-many <IP1> <IP2> ...
    shift
    [ -n "$1" ] || die_use
    VPN_NO_GUARD=1
    export VPN_NO_GUARD
    IPLIST="/tmp/vpn_um_ips.$$"
    NEWMAP="/tmp/vpn_um_map.$$"
    : > "$IPLIST"
    okn=0
    for ip in "$@"; do
      is_ipv4 "$ip" || continue
      grep -qxF "$ip" "$IPLIST" 2>/dev/null && continue
      nm=$(awk -v I="$ip" '$1==I{print $2; exit}' "$MAPF")
      [ -n "$nm" ] || continue
      tbl=$(meta_get "$nm" table); pri=$(meta_get "$nm" prio)
      assign_rules_off "$ip" "$tbl" "$pri"
      echo "$ip" >> "$IPLIST"
      okn=$((okn+1))
    done
    awk -v LF="$IPLIST" 'BEGIN{while((getline l < LF)>0) d[l]=1} !($1 in d)' "$MAPF" > "$NEWMAP" 2>/dev/null
    mv "$NEWMAP" "$MAPF"
    rm -f "$IPLIST"
    unset VPN_NO_GUARD
    guard_run
    ok "da bo gan $okn may" ;;
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
