# etc/ - file he thong NGOAI /opt/proxy-manager-v1

Cac file nay nam ngoai app dir nhung LA MOT PHAN cua he thong. Truoc day chung khong
duoc luu vao git => router chet la mat sach cong sua loi thang 8-9/2026.

| file | vai tro |
|---|---|
| `genrouter_killswitch.sh` | cron moi phut. Khong qua proxy/VPN => khong ra WAN. Chua fix06 (bao ve RETURN intra-LAN + xoa TPROXY catch-all /20) va fix09 (dua `exit 0` xuong cuoi file) |
| `gen_vpn_guard.sh` | cron moi phut. Chua duong `br-lan -> tun*` (ipset `genrouter_vpn` + fw4 include) |
| `genrouter_fix_fw.sh` | chay luc boot tu `rc.local`. An port 8000/9000, UDP fast-reject, chain `GEN_FW_UDP` + fwmark 0x4d3 -> table 202 |
| `rc.local` | duong boot. **Da don 74 dong dead-code ngay 04/09/2026** (co `exit 0` o dong 20 nen phan sau chua bao gio chay, va chua `ip rule ... priority 50` sai so voi vendor 100) |
| `init.d/proxy-manager-v1` | procd service cua app |
| `crontabs/root` | **4 dong cron**: `ov.sh`, `gen_vpn_guard.sh fix`, `genrouter_killswitch.sh` (moi 1 phut) + `dataplane_guard.py` (moi 5 phut, them 2026-09-05). Tu Ver 2.43 guard nay kiem ca phan bo may/tunnel (`[SPREAD]`) |
| `genrouter/core/tproxy` | **script cua VENDOR nhung DA SUA**: FIX 2026-09-03 dang ky `rt_tables` dung theo bien (`200 proxy` / `201 block`, truoc day vendor ghi sai `100 proxy` / `200 block`), va sua `unreachable default` cho table 201 (ban vendor dung cu phap sai nen table 201 LUON RONG = kill-switch chet im lang) |

## Cach trien khai lai (KHONG co script tu dong - co y)
Copy tay tung file, `chmod 755`, roi reboot hoac chay lai `rc.local`. Khong tu dong hoa
vi day la duong boot: sai la router mat mang, phai co nguoi xac nhan tung buoc.

**Luu y `crontabs/root`**: 3 dong dau la cua VENDOR. Khi trien khai lai phai **APPEND**
dong `dataplane_guard.py`, khong ghi de ca file, vi vendor co the da them dong khac.
