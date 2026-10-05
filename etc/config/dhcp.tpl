# ============================================================
# etc/config/dhcp.tpl - mau cau hinh DHCP/DNS cho Gen (dnsmasq)
#
# Vi sao can: Gen17 tung mat DHCP (file /etc/config/dhcp rong 0 byte),
# client cam LAN khong duoc cap IP. Template nay dam bao moi Gen update
# code deu co DHCP server chuan nhu Gen14.
#
# Placeholders (etc_install.sh se thay khi trien khai):
#   __LAN_IP__   : IP router (vd 192.17.0.1)
#
# Dac diem (hoc tu Gen14 + sua loi Gen17):
#   - port=0 + noresolv: dnsmasq he thong CHI lam DHCP, KHONG giu port 53.
#     Port 53 do gencore giu (DNS chan/filter client). Tranh xung dot
#     "failed to create listening socket ... Address in use".
#   - interface br-lan + notinterface eth0/tun*/wg*: chi nghe LAN,
#     khong bind IP tunnel VPN (tun22, wg*) gay crash loop.
#   - start=10 limit=1000 leasetime=30d, DNS client tro ve router.
#
# Trien khai: tools/etc_install.sh muc 2c (idempotent: chi them section
# thieu, khong ghi de cau hinh san co).
# ============================================================
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option expandhosts '1'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option localservice '1'
	option cachesize '8000'
	option min_cache_ttl '3600'
	option port '0'
	option noresolv '1'
	list interface 'br-lan'
	list notinterface 'eth0'
	list notinterface 'tun*'
	list notinterface 'wg*'

config dhcp 'lan'
	option interface 'lan'
	option start '10'
	option limit '1000'
	option leasetime '30d'
	option dhcpv4 'server'
	option dhcpv6 'disabled'
	option ra 'disabled'
	list dhcp_option '6,__LAN_IP__'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'
