#!/bin/sh
set -eu
# Bypass quan tri LAN -> IP router truoc TPROXY. Tu suy ra subnet, khong hardcode.
LAN_IF="$(uci -q get network.lan.device || uci -q get network.lan.ifname || echo br-lan)"
LAN_IP="$(ip -4 -o addr show dev "$LAN_IF" scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')"
LAN_PREFIX="$(ip -4 -o addr show dev "$LAN_IF" scope global | awk 'NR==1{print $4}')"
[ -n "$LAN_IP" ] && [ -n "$LAN_PREFIX" ] || exit 0
if iptables -t mangle -C GENROUTER -s "$LAN_PREFIX" -d "$LAN_IP/32" -p tcp -j RETURN 2>/dev/null; then
  exit 0
fi
iptables -t mangle -I GENROUTER 1 -s "$LAN_PREFIX" -d "$LAN_IP/32" -p tcp -j RETURN
