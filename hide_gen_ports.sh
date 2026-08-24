#!/bin/sh
# hide_gen_ports.sh - an port legacy 8000/9000 khoi mang ngoai, giu 9001 (GUI chinh) va loopback.
# 9000 = old GUI root (GUI 9001 goi noi bo qua 127.0.0.1:9000) -> KHONG tat process, chi an.
# 8000 = flask /etc/shm/app.py, khong app noi bo nao goi.
# Idempotent; persist qua /etc/genrouter_fix_fw.sh (marker hide_gen_ports_8000_9000) + rc.local.
set -u

MARK="hide_gen_ports_8000_9000"

# --- apply ngay (thu tu cuoi cung: lo ACCEPT, 9000 REJECT, 8000 REJECT nhu TT07) ---
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT
iptables -C INPUT -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
  || iptables -I INPUT 2 -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable
iptables -C INPUT -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
  || iptables -I INPUT 3 -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable

# --- persist ---
F="/etc/genrouter_fix_fw.sh"
[ -f "$F" ] || printf '#!/bin/sh\n' > "$F"
chmod 755 "$F"
if ! grep -q "$MARK" "$F" 2>/dev/null; then
  cat >> "$F" <<XEOF
# $MARK
if ! iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; then iptables -I INPUT 1 -i lo -j ACCEPT; fi
if ! iptables -C INPUT -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then iptables -I INPUT 2 -p tcp --dport 9000 -j REJECT --reject-with icmp-port-unreachable; fi
if ! iptables -C INPUT -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then iptables -I INPUT 3 -p tcp --dport 8000 -j REJECT --reject-with icmp-port-unreachable; fi
XEOF
fi

# --- hook rc.local (song qua reboot) ---
if [ -f /etc/rc.local ] && ! grep -q genrouter_fix_fw /etc/rc.local 2>/dev/null; then
  cp /etc/rc.local /etc/rc.local.bak.hideports 2>/dev/null || true
  sed -i '/exit 0/i /etc/genrouter_fix_fw.sh' /etc/rc.local
fi

echo "[OK] hidden ports 8000/9000 (loopback + 9001 kept)"
