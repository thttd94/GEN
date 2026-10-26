#!/bin/sh
# [Ver 2.94] Cau hinh ket noi cho MAY VPN (may VPN RETURN khoi gencore o mangle nen rule gencore khong ap).
# Dung: gen_conn_vpn.sh apply|status|off
# Tham so qua env (app.py ghi /data/vpn/gen_conn.env de cron/boot chay lai):
#   CONN_BYPASS  "ten-mien|IP ..."  -> ra WAN goc (fwmark 0x4d5 -> table main, prio 80 truoc rule VPN 90+)
#   CONN_BLOCK   "ten-mien|IP ..."  -> chan
#   CONN_UDP     1|0                -> chan UDP (giu 53, 67-68)
#   CONN_WEBRTC  block|off          -> chan STUN 3478, 5349, 19302-19309
# Ten mien: dnsmasq nftset (/tmp/dnsmasq.d/gen_conn.conf) dien IP vao set khi resolve.
# Tap may VPN: set vpn_clients dong bo tu /data/vpn/map.txt moi lan chay.
ENVF=/data/vpn/gen_conn.env
MAPF=/data/vpn/map.txt
DNSF=/tmp/dnsmasq.d/gen_conn.conf
NFT=/tmp/gen_conn.nft
MARK=0x4d5
[ -f "$ENVF" ] && [ -z "${CONN_WEBRTC:-}" ] && . "$ENVF"
CONN_UDP=${CONN_UDP:-0}; CONN_WEBRTC=${CONN_WEBRTC:-block}

is_ip() { printf '%s' "$1" | grep -qE '^[0-9]{1,3}([.][0-9]{1,3}){3}(/[0-9]{1,2})?$'; }
ips_of() { for t in $1; do is_ip "$t" && echo "$t"; done; }
doms_of() { for t in $1; do is_ip "$t" || echo "${t#\*.}"; done | sort -u; }
csv() { tr '\n' ',' | sed -e 's/,$//' -e 's/,/, /g'; }
el() { v=$(printf '%s\n' "$1" | grep . | csv); [ -n "$v" ] && printf 'elements = { %s }' "$v"; }

do_off() {
	nft delete table inet gen_conn 2>/dev/null
	while ip rule del fwmark $MARK lookup main priority 80 2>/dev/null; do :; done
	if [ -f "$DNSF" ]; then rm -f "$DNSF"; /etc/init.d/dnsmasq restart >/dev/null 2>&1; fi
	echo "[OK] gen_conn off"
}

do_apply() {
	VPN=$(awk 'NF>=2{print $1}' "$MAPF" 2>/dev/null | grep -E '^[0-9.]+$' | sort -u)
	BYI=$(ips_of "$CONN_BYPASS"); BLI=$(ips_of "$CONN_BLOCK")
	BYD=$(doms_of "$CONN_BYPASS"); BLD=$(doms_of "$CONN_BLOCK")
	{
	echo "table inet gen_conn {"
	echo "  set vpn_clients { type ipv4_addr; $(el "$VPN") }"
	echo "  set bypass4 { type ipv4_addr; flags interval; auto-merge; $(el "$BYI") }"
	echo "  set block4 { type ipv4_addr; flags interval; auto-merge; $(el "$BLI") }"
	# ten chain KHONG duoc trung tu khoa nft (fwd, pre... la keyword) => dung gc_*
	echo "  chain gc_pre {"
	echo "    type filter hook prerouting priority mangle - 5; policy accept;"
	echo "    iifname \"br-lan\" ip saddr @vpn_clients ip daddr @bypass4 meta mark set $MARK"
	echo "  }"
	echo "  chain gc_fwd {"
	echo "    type filter hook forward priority filter - 5; policy accept;"
	echo "    iifname \"br-lan\" ip saddr @vpn_clients ip daddr @block4 counter reject"
	if [ "$CONN_WEBRTC" = block ]; then
		echo "    iifname \"br-lan\" ip saddr @vpn_clients udp dport { 3478, 5349, 19302-19309 } counter drop"
		echo "    iifname \"br-lan\" ip saddr @vpn_clients tcp dport { 3478, 5349 } counter reject with tcp reset"
	fi
	if [ "$CONN_UDP" = 1 ]; then
		echo "    iifname \"br-lan\" ip saddr @vpn_clients udp dport != { 53, 67, 68 } counter reject"
	fi
	echo "  }"
	echo "}"
	} > "$NFT"
	nft -c -f "$NFT" || { echo "[ERR] nft file loi, giu cau hinh cu"; return 1; }
	nft delete table inet gen_conn 2>/dev/null
	nft -f "$NFT" || { echo "[ERR] nap nft that bai"; return 1; }
	ip rule show | grep -q "fwmark $MARK lookup main" || ip rule add fwmark $MARK lookup main priority 80
	# dnsmasq nftset cho ten mien (chi restart khi noi dung doi)
	NEW=/tmp/gen_conn.dns.$$
	: > "$NEW"
	[ -n "$BYD" ] && echo "nftset=/$(printf '%s\n' "$BYD" | tr '\n' '/' | sed 's#/$##')/4#inet#gen_conn#bypass4" >> "$NEW"
	[ -n "$BLD" ] && echo "nftset=/$(printf '%s\n' "$BLD" | tr '\n' '/' | sed 's#/$##')/4#inet#gen_conn#block4" >> "$NEW"
	mkdir -p /tmp/dnsmasq.d
	if [ -s "$NEW" ]; then
		if ! cmp -s "$NEW" "$DNSF"; then mv "$NEW" "$DNSF"; /etc/init.d/dnsmasq restart >/dev/null 2>&1; echo "dnsmasq: nap lai ten mien"; fi
	elif [ -f "$DNSF" ]; then rm -f "$DNSF"; /etc/init.d/dnsmasq restart >/dev/null 2>&1; fi
	rm -f "$NEW"
	echo "[OK] gen_conn: vpn=$(printf '%s\n' "$VPN" | grep -c .) bypass=$(printf '%s\n%s\n' "$BYI" "$BYD" | grep -c .) block=$(printf '%s\n%s\n' "$BLI" "$BLD" | grep -c .) udp=$CONN_UDP webrtc=$CONN_WEBRTC"
}

case "${1:-apply}" in
	apply) do_apply ;;
	off) do_off ;;
	status) nft list table inet gen_conn 2>/dev/null | grep -E 'counter|elements' | head -20; ip rule | grep "$MARK" ;;
	*) echo "dung: $0 apply|status|off"; exit 1 ;;
esac
