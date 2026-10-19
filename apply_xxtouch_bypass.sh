#!/bin/sh
set -eu
LAN_IP="192.14.0.1"
LAN_CIDR="192.14.0.1/20"
if iptables -t mangle -C GENROUTER -s "192.14.0.1/20" -d "192.14.0.1/32" -p tcp -j RETURN 2>/dev/null; then
  exit 0
fi
iptables -t mangle -I GENROUTER 1 -s "192.14.0.1/20" -d "192.14.0.1/32" -p tcp -j RETURN
