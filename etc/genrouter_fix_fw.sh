#!/bin/sh
# hide_gen_ports_8000_9000
if ! iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; then iptables -I INPUT 1 -i lo -j ACCEPT; fi
if ! iptables -C INPUT -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then iptables -I INPUT 2 -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable; fi
if ! iptables -C INPUT -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then iptables -I INPUT 3 -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable; fi
# gen_fw_fix_v1 (hide ports + udp fast-reject, adaptive)
fa() { iptables -C FORWARD "$@" 2>/dev/null || iptables -I FORWARD 1 "$@"; }
fa -i br-lan -p udp --dport 67:68 -j ACCEPT
fa -i br-lan -p tcp --dport 53 -j ACCEPT
iptables -S FORWARD | grep -F -- '-p udp' | grep -F -- '-j DROP' | sed -e 's/^-A FORWARD //' -e 's/-j DROP$/-j REJECT --reject-with icmp-port-unreachable/' | while read -r ins; do iptables -C FORWARD $ins 2>/dev/null || iptables -I FORWARD 3 $ins; done
iptables -t mangle -nL GEN_FW_UDP >/dev/null 2>&1 || iptables -t mangle -N GEN_FW_UDP
iptables -t mangle -C GEN_FW_UDP -p udp --dport 67:68 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -p udp --dport 67:68 -j RETURN
iptables -t mangle -C GEN_FW_UDP -p udp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -p udp --dport 53 -j RETURN
iptables -t mangle -C GEN_FW_UDP -d 224.0.0.0/4 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -d 224.0.0.0/4 -j RETURN
iptables -t mangle -C GEN_FW_UDP -d 255.255.255.255 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -d 255.255.255.255 -j RETURN
iptables -t mangle -C GEN_FW_UDP -d $(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)/32 -j RETURN 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -d $(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.1.1)/32 -j RETURN
iptables -t mangle -C GEN_FW_UDP -j MARK --set-xmark 0x4d3/0xffffffff 2>/dev/null || iptables -t mangle -A GEN_FW_UDP -j MARK --set-xmark 0x4d3/0xffffffff
iptables -t mangle -C PREROUTING -i br-lan -p udp -j GEN_FW_UDP 2>/dev/null || iptables -t mangle -I PREROUTING 1 -i br-lan -p udp -j GEN_FW_UDP
ip route replace local default dev lo table 202 2>/dev/null
ip rule show | grep -q 'fwmark 0x4d3' || ip rule add fwmark 0x4d3 table 202 priority 150
iptables -C INPUT -i br-lan -p udp -m mark --mark 0x4d3 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || iptables -I INPUT 4 -i br-lan -p udp -m mark --mark 0x4d3 -j REJECT --reject-with icmp-port-unreachable
# gen_vpn_guard_v1 - chua duong VPN sau khi rule -i br-lan duoc chen lai
[ -x /etc/gen_vpn_guard.sh ] && /etc/gen_vpn_guard.sh fix >/dev/null 2>&1
