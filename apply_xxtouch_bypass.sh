#!/bin/sh
# [Ver 2.68] Chay moi lan proxy-manager-v1 start.
# 1) Doc IP LAN LUC CHAY (truoc day install.sh ghi cung IP luc cai => doi
#    192.14 -> 192.15 thi rule RETURN quan tri sai dai, GUI bi TPROXY bat).
# 2) Mien fw4 syn_flood cho SYN tu br-lan (gioi han rieng theo tung IP nguon).
#    syn_flood mac dinh 25 SYN/s burst 50 la bucket CHUNG cho ca router; luu
#    luong nen cua fleet ~28 SYN/s (do 2026-10-21) => bucket can, SYN LAN->GUI
#    va client TPROXY bi drop ngau nhien => treo 1/3/7/21s (SYN retransmit).
#    WAN van giu nguyen syn_flood. Moi IP LAN toi da 200 SYN/s burst 400, vuot
#    thi roi xuong syn_flood cu.
LAN_IP="$(uci -q get network.lan.ipaddr 2>/dev/null)"
LAN_CIDR="$(ip -4 -o addr show br-lan 2>/dev/null | awk '{print $4}' | head -n1)"
[ -n "$LAN_CIDR" ] || { [ -n "$LAN_IP" ] && LAN_CIDR="$LAN_IP/24"; }

if [ -n "$LAN_IP" ] && iptables -t mangle -L GENROUTER -n >/dev/null 2>&1; then
  iptables -t mangle -C GENROUTER -s "$LAN_CIDR" -d "$LAN_IP/32" -p tcp -j RETURN 2>/dev/null || \
    iptables -t mangle -I GENROUTER 1 -s "$LAN_CIDR" -d "$LAN_IP/32" -p tcp -j RETURN
fi

RULE='iifname "br-lan" tcp flags syn / fin,syn,rst,ack meter gen_lan_syn { ip saddr limit rate 200/second burst 400 packets } jump input_lan comment "genrouter-lan-syn"'
SNIP=/usr/share/nftables.d/chain-pre/input/10-genrouter-lan-syn.nft
mkdir -p "${SNIP%/*}"
printf '%s\n' "$RULE" > "$SNIP.tmp"
if cmp -s "$SNIP.tmp" "$SNIP" 2>/dev/null; then rm -f "$SNIP.tmp"; else mv "$SNIP.tmp" "$SNIP"; fi
# Ap dung ngay khong can fw4 reload; fw4 reload/boot sau nay se tu nap tu $SNIP.
if nft list chain inet fw4 input >/dev/null 2>&1; then
  nft list chain inet fw4 input | grep -q 'genrouter-lan-syn' || nft "insert rule inet fw4 input $RULE"
fi
exit 0
