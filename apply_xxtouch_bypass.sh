#!/bin/sh
set -eu
# LAN management bypass; derive subnet, never hardcode.
LAN_IF="$(uci -q get network.lan.device || uci -q get network.lan.ifname || echo br-lan)"
LAN_IP="$(ip -4 -o addr show dev "$LAN_IF" scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')"
LAN_PREFIX="$(ip -4 -o addr show dev "$LAN_IF" scope global | awk 'NR==1{print $4}')"
[ -n "$LAN_IP" ] && [ -n "$LAN_PREFIX" ] || exit 0

# Keep exactly one LAN -> GENROUTER hook.
while iptables -t mangle -C PREROUTING -i br-lan -j GENROUTER 2>/dev/null; do
  iptables -t mangle -D PREROUTING -i br-lan -j GENROUTER 2>/dev/null || break
done
iptables -t mangle -I PREROUTING 2 -i br-lan -j GENROUTER

# Router management traffic bypasses TPROXY.
if iptables -t mangle -C GENROUTER -s "$LAN_PREFIX" -d "$LAN_IP/32" -p tcp -j RETURN 2>/dev/null; then
  exit 0
fi
iptables -t mangle -I GENROUTER 1 -s "$LAN_PREFIX" -d "$LAN_IP/32" -p tcp -j RETURN
