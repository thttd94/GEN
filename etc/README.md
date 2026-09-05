# etc/ - file he thong NGOAI /opt/proxy-manager-v1

Cac file nay nam ngoai app dir nhung LA MOT PHAN cua he thong. Truoc day chung khong
duoc luu vao git => router chet la mat sach cong sua loi thang 8-9/2026.

| file | vai tro |
|---|---|
| `genrouter_killswitch.sh` | cron moi phut. Khong qua proxy/VPN => khong ra WAN. Chua fix06 (bao ve RETURN intra-LAN + xoa TPROXY catch-all dai LAN) va fix09 (dua `exit 0` xuong cuoi file). **Tu Ver 2.44: khong con hardcode dai LAN** (suy tu `uci network.lan.*` + `ip addr/route`). **Tu Ver 2.45: them lop chong ro IP that o che do VPN** - dong bo ipset `genrouter_vpn_want` (may KHAI BAO VPN, trich tu runtime `gencore.json`) roi chen rule `want && !genrouter_vpn -j RETURN` vao vi tri 2 chain `GENROUTER`, nen may khai VPN ma tunnel chet thi bi CHAN chu khong ra WAN bang IP that. Doi chieu tap hop dung `getline` trong `BEGIN`, KHONG dung `awk 'NR==FNR'` (sai khi tap hien tai rong) |
| `gen_vpn_guard.sh` | cron moi phut. Chua duong `br-lan -> tun*` (ipset `genrouter_vpn` + fw4 include) |
| `genrouter_fix_fw.sh` | chay luc boot tu `rc.local`. An port 8000/9000, UDP fast-reject, chain `GEN_FW_UDP` + fwmark 0x4d3 -> table 202 |
| `rc.local` | duong boot. **Da don 74 dong dead-code ngay 04/09/2026** (co `exit 0` o dong 20 nen phan sau chua bao gio chay, va chua `ip rule ... priority 50` sai so voi vendor 100) |
| `init.d/proxy-manager-v1` | procd service cua app |
| `crontabs/root` | **4 dong cron**: `ov.sh`, `gen_vpn_guard.sh fix`, `genrouter_killswitch.sh` (moi 1 phut) + `dataplane_guard.py` (moi 5 phut, them 2026-09-05). Tu Ver 2.43 guard nay kiem ca phan bo may/tunnel (`[SPREAD]`) |
| `genrouter/core/tproxy` | **script cua VENDOR nhung DA SUA**: FIX 2026-09-03 dang ky `rt_tables` dung theo bien (`200 proxy` / `201 block`, truoc day vendor ghi sai `100 proxy` / `200 block`), va sua `unreachable default` cho table 201 (ban vendor dung cu phap sai nen table 201 LUON RONG = kill-switch chet im lang) |

## Cach trien khai lai

**Tu Ver 2.44 da co script: `tools/etc_install.sh`.** `install.sh` tu goi no, hoac chay tay:

```sh
sh tools/etc_install.sh ./etc
```

Script lam 3 viec, tat ca IDEMPOTENT:

1. `genrouter_killswitch.sh` -> `/etc/` (chi ghi khi noi dung khac, co backup `.bak.<timestamp>`).
2. Cron: **APPEND** dong con thieu (`genrouter_killswitch.sh`, `dataplane_guard.py`), **khong ghi de**
   ca file vi 3 dong dau la cua VENDOR. Da thu nghiem: xoa dong `*/5` roi chay lai -> them dung
   1 dong, file giong nguyen ban tuyet doi.
3. `genrouter/core/tproxy` -> ghi CA HAI cho `/etc/shm/tproxy` va `/etc/genrouter/core/tproxy`,
   roi `touch -t 202505051200`.

**Vi sao buoc 3 phai lam nhu vay:** `/etc/shm/ov.sh` chay **moi phut** (cron dong 3) va copy
`/etc/shm/<file>` -> `/etc/genrouter/core/<file>` **khi mtime cua target khac `2025-05-05`**.
Neu chi sua `/etc/genrouter/core/tproxy` ma khong sua `/etc/shm/tproxy` va khong giu mtime,
ban da sua se bi ghi de bang ban vendor **trong vong 60 giay** ma khong co log nao.

`etc_install.sh` **khong tu chay kill-switch** (no doi routing/iptables) va **khong tu sua
`rc.local`** (duong boot - sai la mat mang). Hai viec do do `install.sh`/nguoi van hanh quyet dinh.

## Khong luu vao git (co y)

`genrouter/core/genrunner` va `/etc/shm/genrunner` la binary/script vendor **chua sua gi**,
khong dua vao repo. `ov.sh` cung la cua vendor, giu nguyen.
