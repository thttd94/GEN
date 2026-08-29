#!/bin/sh
# gen_fw_fix.sh - dong bo firewall fix GEN cho moi router (thay the hide_gen_ports.sh don le)
#
# Goi gom:
#  1. An port legacy 8000/9000 voi mang ngoai (giu 9001 GUI + loopback) - nhu TT04/TT07.
#  2. Anti QUIC-lag: UDP client khong con bi nuot im lang (blackhole) mà duoc REJECT
#     bang icmp-port-unreachable -> browser/OS fallback TCP ngay (<50ms).
#     Thich ung ca 2 kien truc: co hoac khong chain/ipset GENROUTER (TT04/TT07 dung ipset,
#     .14 dung TPROXY per-IP). Bao ve: DNS(53), DHCP(67:68), multicast/mDNS/SSDP, IP router.
#
# Idempotent; persist vao /etc/genrouter_fix_fw.sh (marker gen_fw_fix_v1) + rc.local.
set -u

FIXFW="/etc/genrouter_fix_fw.sh"
MARK_ALL="gen_fw_fix_v1"
MARK_HIDE="hide_gen_ports_8000_9000"

LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)"

# ---------- 1) an port 8000/9000 ----------
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT
iptables -C INPUT -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
  || iptables -I INPUT 2 -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable
iptables -C INPUT -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
  || iptables -I INPUT 3 -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable

# ---------- 2a) FORWARD: uu tien DHCP/DNS + DROP->REJECT cho UDP truc tiep ----------
fa() { iptables -C FORWARD "$@" 2>/dev/null || iptables -I FORWARD 1 "$@"; }
fa -i br-lan -p udp --dport 67:68 -j ACCEPT
fa -i br-lan -p tcp --dport 53 -j ACCEPT
iptables -S FORWARD 2>/dev/null | grep -F -- '-p udp' | grep -F -- '-j DROP' \
  | sed -e 's/^-A FORWARD //' -e 's/-j DROP$/-j REJECT --reject-with icmp-port-unreachable/' \
  | while read -r ins; do iptables -C FORWARD $ins 2>/dev/null || iptables -I FORWARD 3 $ins; done
if iptables -L GENROUTER_NODIRECT -n >/dev/null 2>&1; then
  iptables -S GENROUTER_NODIRECT 2>/dev/null | grep -F -- '-p udp' | grep -F -- '-j DROP' \
    | sed -e 's/^-A GENROUTER_NODIRECT //' -e 's/-j DROP$/-j REJECT --reject-with icmp-port-unreachable/' \
    | while read -r ins; do iptables -C GENROUTER_NODIRECT $ins 2>/dev/null || iptables -I GENROUTER_NODIRECT 1 $ins; done
fi

# ---------- 2b) UDP fast-reject qua mark 0x4d3 (chain rieng, khong phu thuoc ipset) ----------
ip route replace local default dev lo table 202 2>/dev/null
ip rule show | grep -q 'fwmark 0x4d3' || ip rule add fwmark 0x4d3 table 202 priority 150
if ! iptables -t mangle -nL GEN_FW_UDP >/dev/null 2>&1; then
  iptables -t mangle -N GEN_FW_UDP 2>/dev/null
fi
# tra ve ngay voi luong can bao ve (khong danh dau)
gr() { iptables -t mangle -C GEN_FW_UDP "$@" 2>/dev/null || iptables -t mangle -A GEN_FW_UDP "$@"; }
gr -p udp --dport 67:68 -j RETURN
gr -p udp --dport 53 -j RETURN
gr -d 224.0.0.0/4 -j RETURN
gr -d 255.255.255.255 -j RETURN
gr -d "$LAN_IP/32" -j RETURN
gr -j MARK --set-xmark 0x4d3/0xffffffff
if ! iptables -t mangle -C PREROUTING -i br-lan -p udp -j GEN_FW_UDP 2>/dev/null; then
  iptables -t mangle -I PREROUTING 1 -i br-lan -p udp -j GEN_FW_UDP
fi
iptables -C INPUT -i br-lan -p udp -m mark --mark 0x4d3 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
  || iptables -I INPUT 4 -i br-lan -p udp -m mark --mark 0x4d3 -j REJECT --reject-with icmp-port-unreachable

# ---------- persist ----------
[ -f "$FIXFW" ] || printf '#!/bin/sh\n' > "$FIXFW"
chmod 755 "$FIXFW"
if ! grep -q "$MARK_ALL" "$FIXFW" 2>/dev/null; then
  cat >> "$FIXFW" <<XEOF
# $MARK_ALL (hide ports + udp fast-reject, adaptive)
fa() { iptables -C FORWARD "\$@" 2>/dev/null || iptables -I FORWARD 1 "\$@"; }
fa -i br-lan -p udp --dport 67:68 -j ACCEPT
fa -i br-lan -p tcp --dport 53 -j ACCEPT
iptables -S FORWARD | grep -F -- '-p udp' | grep -F -- '-j DROP' | sed -e 's/^-A FORWARD //' -e 's/-j DROP\$/-j REJECT --reject-with icmp-port-unreachable/' | while read -r ins; do iptables -C FORWARD \$ins 2>/dev/null || iptables -I FORWARD 3 \$ins; done
iptables -t mangle -nL GEN_FW_UDP >/dev/null 2>&1 || iptables -t mangle -N GEN_FW_UDP
iptables -t mangle -C GEN_FW_UDP -p udp --dport 67:68 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -p udp --dport 67:68 -j RETURN
iptables -t mangle -C GEN_FW_UDP -p udp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -p udp --dport 53 -j RETURN
iptables -t mangle -C GEN_FW_UDP -d 224.0.0.0/4 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -d 224.0.0.0/4 -j RETURN
iptables -t mangle -C GEN_FW_UDP -d 255.255.255.255 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -d 255.255.255.255 -j RETURN
iptables -t mangle -C GEN_FW_UDP -d \$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)/32 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -d \$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)/32 -j RETURN
iptables -t mangle -C GEN_FW_UDP -j MARK --set-xmark 0x4d3/0xffffffff 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -j MARK --set-xmark 0x4d3/0xffffffff
iptables -t mangle -C PREROUTING -i br-lan -p udp -j GEN_FW_UDP 2>/dev/null || iptables -t mangle -I PREROUTING 1 -i br-lan -p udp -j GEN_FW_UDP
ip route replace local default dev lo table 202 2>/dev/null
ip rule show | grep -q 'fwmark 0x4d3' || ip rule add fwmark 0x4d3 table 202 priority 150
iptables -C INPUT -i br-lan -p udp -m mark --mark 0x4d3 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || iptables -I INPUT 4 -i br-lan -p udp -m mark --mark 0x4d3 -j REJECT --reject-with icmp-port-unreachable
XEOF
fi
if ! grep -q "$MARK_HIDE" "$FIXFW" 2>/dev/null; then
  cat >> "$FIXFW" <<XEOF
# $MARK_HIDE
if ! iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; then iptables -I INPUT 1 -i lo -j ACCEPT; fi
if ! iptables -C INPUT -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then iptables -I INPUT 2 -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable; fi
if ! iptables -C INPUT -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then iptables -I INPUT 3 -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable; fi
XEOF
fi
if [ -f /etc/rc.local ] && ! grep -q genrouter_fix_fw /etc/rc.local 2>/dev/null; then
  cp /etc/rc.local /etc/rc.local.bak.gen_fw_fix 2>/dev/null || true
  sed -i '/exit 0/i /etc/genrouter_fix_fw.sh' /etc/rc.local
fi

# ---------- 3) chua lai duong VPN (tun*) ----------
# Cac rule o buoc 2 chan theo INTERFACE (-i br-lan) nen chan luon may di VPN.
# gen_vpn_guard.sh ep 4 rule thoat theo ipset genrouter_vpn ve dau chain, va
# nap 2 file include cho fw4 (chain accept_to_wan cua fw4 rong + forward co
# policy drop -> br-lan->tun* bi reject neu khong co accept nay).
# Phai chay SAU buoc 2, vi buoc 2 vua chen rule -i br-lan len dau.
MARK_VPN="gen_vpn_guard_v1"
GUARD="/etc/gen_vpn_guard.sh"
if [ ! -x "$GUARD" ]; then
  for c in "$(dirname "$0")/tools/gen_vpn_guard.sh" \
           "$(dirname "$0")/gen_vpn_guard.sh" \
           /opt/proxy-manager-v1/tools/gen_vpn_guard.sh; do
    [ -f "$c" ] && { cp "$c" "$GUARD" && chmod 755 "$GUARD"; break; }
  done
fi
if ! grep -q "$MARK_VPN" "$FIXFW" 2>/dev/null; then
  cat >> "$FIXFW" <<XEOF
# $MARK_VPN - chua duong VPN sau khi rule -i br-lan duoc chen lai
[ -x $GUARD ] && $GUARD fix >/dev/null 2>&1
XEOF
fi
if [ -x "$GUARD" ]; then
  # cron 1 phut: APPEND, giu nguyen cac dong san co (vi du /etc/shm/ov.sh)
  CRONF=/etc/crontabs/root
  mkdir -p /etc/crontabs 2>/dev/null
  [ -f "$CRONF" ] || : > "$CRONF"
  if ! grep -q 'gen_vpn_guard' "$CRONF" 2>/dev/null; then
    cp "$CRONF" "$CRONF.bak.gen_fw_fix" 2>/dev/null || true
    printf '* * * * * %s fix >/dev/null 2>&1\n' "$GUARD" >> "$CRONF"
    /etc/init.d/cron reload >/dev/null 2>&1 || /etc/init.d/cron restart >/dev/null 2>&1 || true
  fi
  "$GUARD" fix >/dev/null 2>&1
  echo "[OK] gen_vpn_guard active (ipset genrouter_vpn + fw4 include tun*)"
else
  echo "[WARN] khong tim thay gen_vpn_guard.sh - may di VPN co the bi chan UDP/FORWARD"
fi

echo "[OK] gen_fw_fix applied: ports 8000/9000 hidden, udp fast-reject active (DNS/DHCP/mDNS guarded)"
