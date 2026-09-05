# CHANGELOG

## Ver 2.46 (2026-09-05) - dong cua so ro IP tu <=60 s ve ~0 s

Ver 2.45 dung lop `[VPN_WANT]` trong `etc/genrouter_killswitch.sh` de chan may khai bao VPN
ma chua duoc gan tunnel. Nhung kill-switch chi chay theo **cron moi 1 phut**, nen ngay sau khi
apply cau hinh VPN van con mot cua so **<= 60 giay** ma may khai VPN + tunnel chet **ra WAN
bang IP that**. Ban nay dong cua so do.

### Diem hook: cuoi `cmd_clean_stale()` trong `tools/vpn_mgr.sh`

Da doc lai duong apply de tim mot diem chay **dung 1 lan moi apply** va **sau khi moi thu da xong**:

| buoc | dong | viec |
|---|---|---|
| 1 | app.py:2544 | ghi preset -> `/etc/genrouter/config/gencore.json` |
| 2 | app.py:2557 | ghi runtime -> `/etc/genrouter/gencore.json` (day la file kill-switch doc) |
| 3 | app.py:2561 | `sync_vpn_state_on_apply()` |
| 3a | app.py:2287 | `vpn_mgr.sh unassign-many ...` (may khong con khai VPN) |
| 3b | app.py:2300 | `vpn_mgr.sh assign-many <acc> <ip...>` (moi account 1 lan) |
| 3c | **app.py:2305** | **`vpn_mgr.sh clean-stale`** <- chay 1 lan, sau cung |
| 4 | app.py:2564 | `genrunner check` |

`clean-stale` la ung vien duy nhat thoa ca ba: chay dung 1 lan/apply, chay sau khi
`gencore.json` da la cau hinh moi **va** `map.txt` da phan anh tunnel that duoc gan,
va **nam ngoai nhanh `if saved_text`** (thut le 8 ky tu, cung cap voi `if`) nen luon chay.

Them ham `ks_refresh()` goi `/etc/genrouter_killswitch.sh`:

```sh
ks_refresh() {
  [ -x /etc/genrouter_killswitch.sh ] && /etc/genrouter_killswitch.sh >/dev/null 2>&1
  return 0
}
```

Khong de quy: kill-switch khong goi `vpn_mgr.sh` (da kiem: 2 hit `vpn_mgr` trong file nhung
**0 hit trong code**, ca 2 deu la comment). Kill-switch idempotent va do duoc **0 ms** nen goi
them vo hai.

### Bay da tranh duoc: `cmd_clean_stale` co HAI duong ra

Ban dau chi chen `ks_refresh` truoc `ok "clean-stale xong"`. Thu nghiem nguoc **truot ngay ca A**:
dong 369 co `return` som:

```sh
[ -s "$rules" ] || { rm -f "$rules"; ok "khong co rule vpn nao"; return 0; }
```

Khong co `ip rule lookup 3xx` nao thi ham **return truoc khi toi cuoi**. Ma day chinh la
**tinh huong nguy hiem nhat**: apply mode VPN trong khi *moi* tunnel chet => 0 rule duoc tao =>
`clean-stale` return som => kill-switch khong duoc goi => cua so ro IP van 60 s. Da goi
`ks_refresh` o **ca hai** duong ra.

### Thu nghiem nguoc 5/5 PASS (kill-switch STUB, khong cham `/etc`)

| | tinh huong | ket qua |
|---|---|---|
| A | khong co `ip rule` vpn nao (nhanh return som) | goi 1 lan - **ca ban dau truot** |
| B | chay lai lan 2 | goi 1 lan - idempotent |
| C | co `ip rule` rac (nhanh day du) | goi 1 lan, rule rac bi don dung |
| D | ban CU | **0 lan** o ca hai nhanh |
| E | kiem de quy: kill-switch goi `vpn_mgr` | **0 hit trong code** |

### Cai vao ca hai ban

`ensure_vpn_mgr()` (app.py:2821) copy `tools/vpn_mgr.sh` -> `/data/vpn/vpn_mgr.sh` khi **khac size**,
va `vpn_run()` chay ban `/data/vpn/`. Cai 1 ban thoi thi app se dap lai. Da ghi **ca hai**,
cung md5 `ce1841a2e54b3abad267773925c39038` (24794 B).

Chay that sau khi cai: ca hai nhanh `clean-stale` deu rc=0, stderr sach, `/api/vpn/status`
tra ve dung 33 account, app **khong restart** (pid nguyen), toan ven runtime khong doi
(TPROXY 644, GENROUTER 657, `ip rule` 6, ipset 322/0/0, map.txt 0).

### Thu nghiem end-to-end ca ro IP (chain + ipset + gencore.json GIA)

Mo phong dung tinh huong that: 3 may khai VPN + 1 may proxy, nhung chi 1 may duoc gan tunnel.

| IP | trong `want` | trong `vpn` | ket qua |
|---|---|---|---|
| .101 | co | co | qua tunnel that (rule chan khong match) |
| .102 | co | khong | **CHAN** - `ip route get` = `Host is unreachable` |
| .103 | co | khong | **CHAN** - `ip route get` = `Host is unreachable` |
| .109 | khong | khong | may proxy, TPROXY -> sing-box, khong bi anh huong |

Truoc khi chay kill-switch: `want`=0, 0 rule chan => .102/.103 bi TPROXY hijack => ra WAN IP that.
Sau khi chay: `want`=3, rule chan o vi tri 2, .102/.103 unreachable. Da don sach chain/ipset gia.

## Ver 2.45 (2026-09-05) - chong RO IP THAT khi chay che do VPN (fail-open -> fail-closed)

Ban 2.44 tro xuong co mot lo fail-open trong che do VPN. Trong che do nay moi may khach
co mot outbound rieng trong `gencore.json`:

```json
{"tag": "proxy_7", "type": "direct"}
```

`type: direct` nghia la "cu di thang, routing se day vao tunnel". Viec day vao tunnel do
`ip rule from <IP> lookup <table>` lam, va rule do **chi ton tai khi `vpn_mgr.sh assign-many`
chay thanh cong**. Nhung `sync_vpn_state_on_apply` (app.py:2296) BO QUA may co tunnel khong chay:

```python
summary['skipped'].append({'ip': ip, 'account': acc, 'reason': 'tunnel khong chay'})
```

May bi bo qua thi khong vao `ipset genrouter_vpn`, khong co `ip rule` rieng, nen bi TPROXY
hijack vao sing-box, gap outbound `direct` va **ra WAN bang IP that**. Dung ra phai chan.
Rui ro nay chi hien hinh khi co tunnel chet dung luc apply - nhung do la dung luc no nguy hiem
nhat, vi khong co canh bao nao va may khach van "chay binh thuong".

### Vi sao khong sua bang `type: block`

Da thu va do: `gencore check` (sing-box 1.11.6) CHAP NHAN ca `{"type":"block"}` (chi WARN
legacy) va ca bien the route `{"action":"reject"}`. Nhung `extract_rows` (app.py:1770) nhan dien
"may nay dang o che do VPN" **chinh bang `ob_type == 'direct'`**. Doi sang `block` se lam GUI mat
nhan dien VPN, keo theo phai sua dong bo `extract_rows` + `build_old_gui_update_proxy_payload_from_rows`
(app.py:2183) + `config_doc_stats`. Sua 3 cho trong app dung sinh menh GUI de doi lay mot viec ma
tang iptables lam duoc gon hon => chon chan o tang iptables.

### Lop `[VPN_WANT]` trong `etc/genrouter_killswitch.sh`

Them mot ipset thu hai va mot rule hieu tap hop:

| ipset | y nghia | ai dong bo |
|---|---|---|
| `genrouter_vpn_want` | may **KHAI BAO** che do VPN (outbound `proxy_*` co `type: direct` trong runtime) | `genrouter_killswitch.sh` (moi phut), trich tu `/etc/genrouter/gencore.json` |
| `genrouter_vpn` | may **DA duoc gan tunnel that** | `gen_vpn_guard.sh` dong bo tu `/data/vpn/map.txt` |

```sh
iptables -t mangle -I GENROUTER 2 \
  -m set --match-set genrouter_vpn_want src \
  -m set ! --match-set genrouter_vpn src -j RETURN
```

Rule chi match **phan hieu**: khai VPN MA chua duoc gan tunnel.

- Che do proxy: khong outbound nao `type: direct` => `want` RONG => rule **bi xoa** => vo hai.
- Che do VPN gan du: `want == vpn` => phan hieu rong => rule khong match gi => vo hai.
- Chi khi co may khai VPN ma chua gan thi rule moi chan - dung luc can chan.

**RETURN o day la CHAN THAT, khong phai tha ra WAN.** Da do: may khong co `ip rule` rieng thi roi
vao `ip rule iif br-lan lookup 201`, va table 201 co `unreachable default`
(ban `tproxy` da sua tu 2026-09-03). `ip route get 1.1.1.1 from <IP> iif br-lan` tra ve
`Host is unreachable`. Chen o **vi tri 2** vi `gen_vpn_guard.sh` ep 4 rule cua no ve vi tri 1
moi phut - dat o 2 thi hai ben khong tranh cho, va van dung truoc rule TPROXY dau tien
(do duoc: TPROXY som nhat o vi tri 15 cua chain).

Trich tap IP bang `python3` + `json` chu khong bang `sed`/`awk`: `gencore.json` la MOT dong dai
va can doi chieu tag outbound <-> route rule; lam bang sed/awk rat de sai am tham. Da do:
python3 ~0,4 s cho 322 may, ban shell `grep -o` ~1,4 s va phu thuoc thu tu khoa JSON.

### Sua tiep mot LOI IM LANG vua sinh ra o Ver 2.44: `awk 'NR==FNR'` sai khi file thu nhat RONG

Ver 2.44 thay `comm` (BusyBox khong co) bang `awk 'NR==FNR{s[$1];next} !($1 in s)'`. Cach do
**sai khi file thu nhat rong**: awk khong doc duoc ban ghi nao tu file rong, nen `NR==FNR` van
DUNG voi moi dong cua file thu HAI; toan bo file thu hai bi nap vao mang `s` roi `next` bo qua
=> **0 dong ket qua**.

Do that tren router, 7 to hop:

| tinh huong | `NR==FNR` | `getline` trong BEGIN | dung |
|---|---|---|---|
| set RONG, cfg 3 IP | **0 SAI** | 3 | 3 |
| set 3 IP, cfg rong | 0 | 0 | 0 |
| ca hai rong | 0 | 0 | 0 |
| set{a,b} cfg{a,b,c} | 1 | 1 | 1 |
| set{a,b,c} cfg{a} | 0 | 0 | 0 |
| khong giao nhau | 2 | 2 | 2 |
| 1 phan tu moi | 1 | 1 | 1 |
| **tong** | **6/7** | **7/7** | |

Hau qua neu de nguyen: tren router MOI (hoac sau khi `ipset destroy`), `genrouter_mapped` rong
=> sync add 0 IP => ipset **mai mai rong** => nhanh "chi chan khi ipset co du lieu" khong bao gio
bat => **lop chan DNS chet im lang**, dung loai loi ma 2.44 vua chua. Dang la loi ngu, chua phat
tac vi set hien co 322 entry tu lan tao dau tien.

Nay dung `while ((getline l < LF) > 0) s[l]=1` trong `BEGIN` - doc tuong minh file thu nhat, rong
thi mang rong, dung ngu nghia tap hop. Day cung la cach `tools/vpn_mgr.sh:496` da dung san.
Ca **4 cho** trong file (2 cho `genrouter_mapped` + 2 cho `genrouter_vpn_want`) deu doi.

### Thu nghiem nguoc 6/6 PASS

Chay tren chain `GR428` + ipset gia, khong cham traffic that:

| | tinh huong | ket qua |
|---|---|---|
| A | 5 may khai VPN, chua gan tunnel nao (`vpn` rong) | `want`=5, rule o vi tri 2, **khong lay may proxy** |
| B | chay lai lan 2 | `want`=5, vi tri 2, tong rule 4 - idempotent |
| C | gan du 5 may (`vpn` == `want`) | rule con nhung phan hieu rong => vo hai |
| D | chi 2/5 may duoc gan | **dung 3 may bi chan** |
| E | doi sang toan proxy => `want` rong | rule **bi xoa**, tong rule ve 3 |
| F | quay lai VPN tu trang thai `want` rong | `want`=2 - **dung ca loi `NR==FNR`** |

Ca F la ca ma ban `NR==FNR` truot; ca A/C/D cung truot vi cung nguyen nhan.

### Nghiem thu tren router that

Chay o che do proxy dang phuc vu 322 may: **stderr rong**, snapshot
`iptables -t mangle -S GENROUTER` + `iptables -S INPUT` + `ip rule` + `ip route show table 201`
+ `ipset genrouter_mapped` truoc-sau **0 dong khac** (do bang `difflib`, khong dung `diff` vi
BusyBox khong co), chay lan 2 cung 0 dong khac.

Sau khi cai: TPROXY 644 | GENROUTER 657 | `ip rule` 6 | `genrouter_mapped` 322 |
`genrouter_vpn_want` **0** (dung, dang che do proxy) | INPUT chan DNS 2 | openvpn 32 / tun 32 / wg 1
| `gencore.json` md5 khong doi | app pid + gencore pid nguyen | log killswitch tang dung 1 dong
`MK ipset genrouter_vpn_want`.

### Bai hoc do luong (noi tiep 2.44)

- **`awk 'NR==FNR'` la bay khi file thu nhat co the rong.** Dung `while ((getline l < F) > 0)`.
  Thu nghiem nguoc **phai co ca "tap hien tai rong"** - khong co ca do thi loi nay lot.
- Harness thu nghiem cung phai **bat stderr** va **khong `rm` file trung gian** truoc khi kiem.
  Mat 5 vong chan doan chi vi `2>/dev/null` + `rm -f` nam trong doan ma dang thu.

## Ver 2.44 (2026-09-05) - "FULL FINAL" thuc su: pull source ve la co du he thong

Ban 2.43 tro xuong co mot khoang trong lang le: `install.sh` **chi trien khai app dir**
(`/opt/proxy-manager-v1`) va `tools/`. Ba thanh phan nam NGOAI app dir - dung ra la mot phan
cua he thong - khong co script nao dat chung vao dung cho:

| Thanh phan | Vai tro | Hau qua khi thieu |
|---|---|---|
| `/etc/genrouter_killswitch.sh` | may khong qua proxy/VPN thi khong ra WAN | mat kill-switch: may chua map van ra Internet bang IP that |
| `/etc/genrouter/core/tproxy` + `/etc/shm/tproxy` | ban vendor DA SUA `rt_tables` 200/201 | table 201 rong => kill-switch chet im lang |
| dong cron `*/5` goi `tools/dataplane_guard.py` | watchdog data-plane VPN | tunnel chet data-plane khong ai phat hien |

=> router moi `pull` source ve **chay duoc nhung khong an toan**, va khong ai biet vi khong co
thong bao loi nao. Ver 2.44 dong khoang trong nay.

### 1. `tools/etc_install.sh` (moi)

`install.sh` tu goi. Idempotent, 3 viec:

- Cai `etc/genrouter_killswitch.sh` -> `/etc/` (chi ghi khi noi dung khac, backup `.bak.<timestamp>`).
- Cron: **APPEND** dong con thieu, **khong ghi de** ca file vi 3 dong dau la cua VENDOR.
  Da thu nghiem: xoa dong `*/5` roi chay lai -> them dung 1 dong, file **giong nguyen ban tuyet doi**.
- `tproxy`: ghi **CA HAI** `/etc/shm/tproxy` va `/etc/genrouter/core/tproxy`, roi `touch -t 202505051200`.

Diem thu ba khong hien nhien: `/etc/shm/ov.sh` chay **moi phut** va copy
`/etc/shm/<file>` -> `/etc/genrouter/core/<file>` **khi mtime cua target khac `2025-05-05`**.
Sua mot cho hoac khong giu mtime thi ban da sua **bi ghi de bang ban vendor trong vong 60 giay**,
khong co log nao.

`etc_install.sh` khong tu chay kill-switch (doi routing/iptables) va khong tu sua `rc.local`
(duong boot): hai viec do can nguoi xac nhan.

### 2. `etc/genrouter_killswitch.sh` - bo hardcode dai LAN

Truoc: `LAN_NET=192.14.0.0/20` va dia chi router `192.14.0.1` dong dinh trong file
=> **router khac subnet pull source ve la kill-switch chan sai dai mang** (hoac khong chan gi).

Nay suy tu chinh he thong dang chay: `LAN_IF` <- `uci network.lan.device`;
`LAN_IP`/`LAN_PLEN` <- dia chi IPv4 that cua interface; `LAN_NET` <- route `proto kernel`
cua interface do (fallback tinh bang `awk` tu IP + prefix). Thieu tham so co ban thi **dung ngay**
thay vi chan bua. Rule TPROXY catch-all duoc xoa bang **chinh spec lay tu `iptables -S`**
(khong doan port/mark).

Do dac:

- **Hanh vi y nguyen** ban cu tren router that: snapshot `iptables`/`ip rule`/`ip route`/`ipset`
  truoc va sau = **0 dong khac**, chay lan 2 cung 0 dong khac (idempotent).
- **Thu nghiem nguoc 5 subnet gia** (chen stub `uci`/`ip`): `10.77.5.1/24`, `172.20.130.1/17`,
  `192.168.44.1/22` tren interface ten khac, `10.9.35.1/20` khong co route (fallback), `10.0.0.1/8`
  -> **5/5 suy dung ca IP va dai mang**. Cung tinh huong do, ban cu van tra ve `192.14.0.0/20`.

### 3. `etc/genrouter_killswitch.sh` - sua LOI IM LANG: BusyBox khong co `comm`

Khoi dong bo `ipset genrouter_mapped` (lop chan DNS cua may chua map) dung `comm -23`/`comm -13`.
Router **khong co `comm`**. Cron chay voi `>/dev/null 2>&1` nen `comm: not found` bi nuot
=> **khoi nay chua bao gio chay ke tu 2026-09-03**: `/tmp/killswitch.log` co **0 dong `SYNC`,
0 dong `MK`** trong suot 17 dong log. 322 entry hien co la tu lan tao dau tien, khong phai dong bo.

Hau qua neu khong sua: doi danh sach may (them/bot/doi IP) thi ipset dung yen => may **moi** bi
chan DNS oan, may **da bo** van duoc phep hoi DNS.

Chua bang `awk` (BusyBox co san), cung ngu nghia tap hop, khong them phu thuoc.
Thu nghiem nguoc tren ipset gia: tap hien tai `{1,2,9}`, config `{1,2,3,4}` ->
sinh dung `add 3`, `add 4`, `del 9`; `ipset restore` xong ra dung `{1,2,3,4}`; chay lan 2
batch **rong** (idempotent). Chay ban da cai tren router: **stderr sach**.

Da quet toan bo 35 script tren router de tim loai loi nay: `comm` con 2 cho (da sua),
`curl` 7 cho nhung deu co nhanh `command -v` du phong. Cac lenh khac khong co tren router:
`join`, `paste`, `diff`, `timeout`, `base64`, `fold`, `logrotate`, `unshare`, `xxd`, `realpath`,
`column`, `shuf`, `tac`, `rev`, `nproc`, `stdbuf`, `getopt`, `envsubst`, `openssl`, `ss`.

### 4. Doi chieu repo <-> router

33 thanh phan (app, static, tools, etc): **33/33 khop md5**, 0 thieu, 0 lech.

---

## Ver 2.43 (2026-09-05) - FIX GOC: ca dan may khach bi don vao DUNG 1 tunnel VPN + tools/vpn_spread.py

**Su co that:** preset VPN gan **TOAN BO may khach vao dung 1 tai khoan VPN** (do duoc:
322/322 may -> `proton-jp-171` -> `tun1`). Tat ca chi so cua watchdog deu "xanh" vi 33/33 tunnel
deu song va ra Internet duoc - khong co gi bao loi. Nhung tran bang thong cua CA ROUTER khi do
bang tran cua DUNG 1 tunnel.

**Bang chung do dac** (cua so thoi gian co dinh T=4 s, `SO_BINDTODEVICE`, 2 vong xen ke):

| Cau hinh | Bang thong | So voi tran WAN |
|---|---|---|
| 1 tunnel, 2 luong | **139,2 Mbps** | 16% |
| 33 tunnel, 2 luong/tunnel | **554,2 Mbps** | 62% |
| WAN truc tiep (khong tunnel), 60 luong | 889,7 Mbps | 100% |

=> chia deu may cho cac tunnel dang chay: **3,93x** bang thong.

**Chua - `tools/vpn_spread.py` (moi):**

- Chia deu N may cho M tunnel bang round-robin, **xen ke theo nut** de 2 may lien tiep khong
  cung mot nut Proton (nhieu tunnel co the tro ve cung nut; chia tuan tu se don mot khoi may
  lien tiep vao cung nut do).
- **KHONG dong dinh con so nao.** N dem tu chinh API cua router (`/api/pm/sessions/<id>`),
  M dem tu tien trinh `openvpn`/`wireguard` DANG CHAY that (dung lai `inventory()` cua
  `dataplane_guard.py`). Router 200 may hay 1000 may deu chay dung, khong sua code.
- Mac dinh **chi dung tunnel co `auto=1`** (reboot van con). `--all-running` de dung ca tunnel
  `auto=0`; `--probe` de do that tung tunnel ra Internet truoc khi chia.
- Ghi qua **DUNG API cua app** (`POST /api/pm/sessions/<id>`) - duong ma GUI dung - nen chi
  cham preset + `session_state.json`, **KHONG cham `gencore.json` runtime**: chay luc nao cung
  duoc, khong lam gian doan may dang chay. Viec `apply` van do nguoi van hanh bam.
- Co che do `plan` (in ke hoach, khong ghi gi) va bat buoc `--yes` moi ghi that.
- Doc lai va doi chieu sau khi ghi; lech ke hoach thi tra ve loi.

**Them khoa kiem `[SPREAD]` vao `tools/dataplane_guard.py`** (`spread_drift()`), vi cac khoa cu
khong the thay loai loi nay:

- Doi chieu CA HAI nguon: `map.txt` (dang chay that) va tung session trong `session_state.json`
  (preset - bat truoc khi nguoi van hanh bam apply).
- Bao dong khi: (a) don HET may vao 1 tunnel; (b) mot tunnel ganh qua `SPREAD_TOLERANCE=2.0`
  lan phan chia deu; (c) co tunnel dang chay ma khong phuc vu may nao.
- Nguong tinh theo TY LE tren so dem thuc te, khong theo so may tuyet doi.
- Khi so may < so tunnel thi **im lang** (khong the chia deu, khong phai loi).
- Watchdog **chi canh bao, khong tu chia lai** - dung nguyen tac cua `[AUTODRIFT]`.
- Thu nghiem nguoc 5 tinh huong (don 1 tunnel / chia deu / lech 3x / dung 1 nua so tunnel /
  it may hon so tunnel): bat dung 4, im dung 1.

**Nut co chai con lai cua mode VPN da do duoc, khong phai loi cau hinh: CPU.** May dung
Intel i3-3220 **khong co AES-NI**, `cipher AES-256-GCM` phai ma hoa bang software trong
user-space. Khi 33 tunnel cung tai: 32 process `openvpn` an **313% / 400%** (4 core), CPU toan
may 91%; cung luc do WAN truc tiep chi ton 48% CPU cho 892 Mbps. Vi vay cang nhieu luong/tunnel
thi cang cham: 2 luong 554 Mbps -> 4 luong 472 -> 8 luong 415 -> 12 luong 288. Tran thuc te cua
mode VPN tren phan cung nay la **~550-620 Mbps (62-70% WAN)**; muon cao hon phai doi CPU co
AES-NI hoac chuyen sang WireGuard (ma hoa trong kernel).

**Do an toan cua duong apply (do that, khong suy dien):**

- Chay dung duong ma `apply` se goi - 33 lan `vpn_mgr.sh assign-many` cho 300 may - het **16,14 s**,
  con du 164 s truoc `APPLY_LOCK_TTL=180 s`.
- Nghiem thu sau do: `ip rule` dung table **300/300**, `ipset genrouter_vpn` 300 entry,
  `map.txt` 300 dong, **0/33 table thieu default route**, 4 rule chot cua `gen_vpn_guard.sh`
  van o vi tri 1, `gen_vpn_guard.sh check` = `[OK]`.
- `table`/`prio` cua 33 tunnel **khong trung nhau** (301-337 / 91-127).
- Roll lai bang `unassign-many`: **2,87 s**, `ip rule`/`ipset`/`map.txt` ve dung nguyen trang.

---

## Ver 2.42 (2026-09-05) - FIX GOC: 13 tunnel VPN "song" ma khong ra Internet + watchdog data-plane

**Su co that:** 13/33 tunnel VPN khong ra duoc Internet nhieu NGAY ma khong co bat ky canh bao nao.
Nhin tu ngoai vao thi hoan toan binh thuong: `tun` UP, co IP trong tunnel, ping duoc gateway noi bo
(`10.96.0.1` 2/2), renegotiation cua OpenVPN thanh cong deu moi ~55 phut. Chi co goi tin ra Internet
la chet: `1.1.1.1` 0/2, `rx_packets` chi 44-66 goi so voi hang trieu o tunnel lanh, `rx_dropped/errors = 0`.

**Nguyen nhan goc (da chung minh bang thu nghiem doi chieu, khong phai suy dien):**

36 tai khoan OpenVPN + 1 WireGuard cua router **dung CHUNG 1 username Proton**. Proton gioi han so
session **co data-plane tren MOI NUT** cho moi tai khoan (~5). Session vuot han muc **van giu duoc
control channel**: thiet bi `tun` van UP, van co IP, reneg van OK => `Inactivity timeout` va
`ping-restart` cua OpenVPN **KHONG BAO GIO kich hoat**, nen OpenVPN tu no khong the biet minh da chet.

Bang chung quyet dinh: nut `45.14.71.6` co **9 session** cung tai khoan, dung **5** cai song.
Gui `SIGUSR1` cho `tun4` => `tun4` song va **`tun9` (cai song lau nhat) chet**, tong LUON = 5.
Moi nut co <= 5 session thi 100% OK. WireGuard **cung tinh vao han muc do** (`wg37` endpoint
`141.98.213.194` trung nut voi 4 tunnel OpenVPN => bi cat; bat tay thanh cong nhung chi 36 KiB/13 KiB
toan control, ping `10.2.0.1` OK / `1.1.1.1` 0%).

Da loai tru bang do dac: **khong phai MTU** (moi `tun` = 1500, `wg` = 1420, `mssfix 0` co san),
**khong phai route** (moi dev 1 route rieng, table `300+idx`), **khong phai DNS**, **khong phai trung IP
trong tunnel**.

**Chua:**

- Doi `remote` cua 6 tai khoan sang nut con trong suat, `SIGHUP`/`SIGUSR1` de dang ky lai session.
  Configs khong pin `verify-x509-name`, `ca`/`tls-crypt` giong nhau nen doi nut la an toan.
- Ket qua: **33/33 giao dien ra Internet, 33 exit IP khac nhau**, nut dong nhat con **4 session**
  (giu <= 4 thay vi 5 de co bien an toan, vi moi lan reconnect sinh 1 ban ghi session moi va
  day cai cu nhat ra khoi suat).
- Danh doi duy nhat: `proton-kr-38` ra IP Nhat thay vi Han, vi Proton chi co **3 nut KR** (kr-03/04/05)
  cho 13 suat can dung. Muon vuot 12 suat KR phai mua **tai khoan Proton username khac** - han muc
  tinh theo tai khoan, khong theo thiet bi.

**Fix triet de - watchdog thuong tru `tools/dataplane_guard.py` (moi):**

- Do **THUC TE** tung thiet bi bang `SO_BINDTODEVICE` + HTTP GET ra `api.ipify.org` (RETRY=2).
  **Khong dung `wget --bind-address`**: cach do do cho ket qua SAI (bao mot tunnel da chay 15,8 GB
  la "chet").
- Chet -> `SIGUSR1` (toi da 4 tunnel/lan chay, cooldown 900 s/tai khoan) roi **do lai de xac nhan**.
- Nut > 4 session -> ghi `[RECOMMEND]`; exit IP trung nhau -> ghi `[WARN]`. Watchdog **khong tu doi nut**.
- **`[AUTODRIFT]`**: doi chieu co `auto` trong `meta` voi tap tunnel dang chay THAT, va **du bao so
  session tren tung nut sau reboot**. Ly do: co `auto` lech la **bom hen gio** - dang chay ma `auto=0`
  thi reboot mat tunnel; khong chay ma `auto=1` thi `startall` bat them va co the day mot nut vuot han
  muc, tai lap dung su co nay. Cac chi so cu khong the thay truoc vi chung chi do trang thai hien tai.
- Lay dev/pid/account tu `/proc/<pid>/cmdline`, **khong dung pid file** (pid file tung sai).
- Co file lock chong 2 ban chay chong nhau. Log `/data/vpn/logs/dataplane_guard.log`,
  state `dataplane_guard_state.json`. Che do: mac dinh = do + chua, `check` = chi doc, `status` = in trang thai.
- Cron `*/5` (xem `etc/crontabs/root` - phai **APPEND**, khong ghi de 3 dong vendor).

**Da test tren router that:**

- Thu nghiem chu dong: chan TCP/80 ra `tun23` => watchdog phat hien `X|TimeoutError`, tu `SIGUSR1`,
  ghi `[HEAL]`, do lai OK.
- Tu chua that trong van hanh: 04:11 ngay 05/09, `tun23` chet -> `[HEAL]` -> tro lai 33/33.
- Thu nghiem `[AUTODRIFT]` co doi chieu: co tinh tao lech (tat `auto` 1 tai khoan dang chay + bat
  `auto` 3 tai khoan cung tro ve `45.14.71.6`) => watchdog bao du **ca 3 loai**: mat tunnel sau reboot,
  bat them sau reboot, va **"nut 45.14.71.6 se co 7 session (> 4)"**. Tra lai nguyen trang => bao sach.
- Sau 77 lan chay qua cron: 33/33 lien tuc, 1 lan tu chua thanh cong.

**Bai hoc ky thuat (BusyBox/OpenWrt):** khong co `base64` (day file phai giai ma bang `python3 -c`),
khong co `fold`, khong ho tro `ping -i 0.2`; `AF_PACKET` phai `socket.htons(3)`; chuoi
`100% packet loss` khop ca pattern `0% packet loss` nen parse `ping` de sai; sau khi sua crontab +
reload, moc `*/5` ngay sat do co the bi bo 1 lan (dung `logread` de xac minh, dung ket luan som).

## Ver 2.41-b (2026-09-04) - BAO MAT: bo mat khau cai dat khoi source

**Van de:** `install.sh` gan cung `INSTALL_PASSWORD="..."` dang chu ro, trong khi repo nay la
**PUBLIC**. Mat khau do da nam trong git history tu lau => phai coi nhu **da lo vinh vien**;
doi gia tri moi khong xoa duoc vet trong cac commit cu.

**Fix:**

- Khong con bat ky mat khau dang chu ro nao trong `install.sh`. Chi luu **SHA-256 cua salt+pass**
  (`INSTALL_PASSWORD_SALT` + `INSTALL_PASSWORD_SHA256`), ca hai deu ghi de duoc bang bien moi truong
  nen moi router tu dat mat khau rieng ma khong phai sua file.
- **Chan cung hash cua mat khau cu da lo** (`INSTALL_PASSWORD_LEAKED_SHA256`): du ai co tinh dat lai
  mat khau do thi van bi tu choi, kem thong bao huong dan doi mat khau.
- Them 2 duong chay khong tuong tac: `INSTALL_PASSWORD=...` (bien moi truong) va
  `INSTALL_SKIP_PASSWORD=1` (bo qua co chu y, in canh bao).
- Ham `_hash_pass()` dung `sha256sum` neu co, khong thi fallback sang `python3` - chay duoc tren
  OpenWrt toi gian.

**Da test tren router that** (chi test doan kiem mat khau, khong chay install): 7/7 case dung -
mat khau moi PASS, mat khau cu bi chan FAIL, mat khau sai FAIL, mat khau rong FAIL, bypass PASS,
hash tu dat khop PASS, hash tu dat lech FAIL. Kem: khong con chuoi mat khau cu trong file, khong con
gan `INSTALL_PASSWORD=` chu ro, `sh -n install.sh` pass.

**Luu y con lai:** mat khau cu van doc duoc trong git history cua cac commit truoc. Vi vay no da bi
chan cung trong code thay vi chi don gian doi gia tri.

**Huong dan doi mat khau:** xem `README_INSTALL.md` muc "Mat khau cai dat".

## Ver 2.41 (2026-09-04) - FIX GOC: DNS local phai co `detour: "direct"`

**Su co that:** 322 may khach mat phan giai ten HOAN TOAN. Bat goi tren `br-lan`: **73 query / 0
reply**; `conntrack` client -> `192.14.0.1:53` **42/42 [UNREPLIED]**, moi luong retry 232-255 lan.
GUI 9001, `gencore`, 644 rule TPROXY, tunnel VPN deu binh thuong => nhin ben ngoai tuong nhu khong loi.

**Chuoi nhan qua (da chung minh, khong phai suy doan):**

```
dns.servers[dnsmasq] = {"address":"127.0.0.1:5353","tag":"dnsmasq"}  <-- THIEU "detour"
  -> goi UDP ma CHINH sing-box gui ra 127.0.0.1:5353 van di qua route engine
  -> bi route.rules[2] = {"action":"hijack-dns","protocol":"dns"} bat lai
  -> loi "DNS query loopback in transport[dnsmasq]"
  -> loop-breaker {as.lumiproxy.io -> dnsmasq} khong resolve duoc
  -> outbound proxy_N (server = as.lumiproxy.io) chet
  -> 322 may: 0 reply DNS
```

Rule loop-breaker `{"action":"route","server":"dnsmasq","domain":["as.lumiproxy.io"]}` cua Ver 2.34
**mot minh khong du** - da tai hien: W1 (giong production) TIMEOUT, W3 (`server` la IP) chay duoc.
Thu tu rule cung **khong** phai nguyen nhan: `hijack-dns` nam o index 2, truoc ca 322 rule client.

**Fix:** them **dung 1 truong** `"detour": "direct"` cho server DNS local.

- `DNS_LOCAL_DETOUR = 'direct'`, `is_local_dns_address(addr)` (hieu ca tien to `udp:// tcp:// tls://
  https:// h3:// quic://`, chi nhan `127.0.0.1 / localhost / ::1`), `ensure_dns_local_detour(data)`.
- Ham moi **idempotent** va **fail-safe**: bo qua tag `proxy_*`, va tra ve 0 (khong lam gi) khi
  config khong co outbound `direct` - nen mode VPN thuan khong bi sua sai.
- Noi vao **4 call-site** de khong con duong nao ghi config ma bo sot:
  `migrate_proxy_dns_file`, `rebuild_gencore_rules`, `apply` chinh, `config_heal`.
- Them chi so `dns_local_detour` vao `config_doc_stats()` **va** `CONFIG_GUARD_KEYS` (nay **7 khoa**)
  => khi vendor `:9000` regenerate config bang template rieng lam mat truong nay thi post-vendor guard
  va `config_self_heal` (60 s) **tu phat hien + tu ghi lai**. Da test gia lap: `degraded=['dns_local_detour']`.
  Config dung thi `degraded=[]` (khong bao dong gia); preset VPN `session1.json` cung dem duoc 1.

**Do duoc truoc/sau (cung mot cach bat goi raw AF_PACKET tren `br-lan`, co self-test truoc khi tin so):**

| Chi so | Truoc fix | Sau fix |
|---|---|---|
| DNS reply, may **co** rule | **0 / 48 = 0%** | 20 query / 22 reply, roi 6/6 = **~100%** |
| DNS reply, may **khong** rule | 0 | 0 - deny-by-default, **dung thiet ke** |
| conntrack client | 42/42 **UNREPLIED** | 45 luong roi 32 luong, **0 UNREPLIED** |
| log `loopback in transport` | co | **0** |
| E2E that qua SOCKS Lumi | khong resolve duoc | DoH `rc=0 ans=11` ~650 ms, tai **14,0-19,7 Mbps** |

**Khong gian doan dich vu:** doi app-level thi **chi restart `/etc/init.d/proxy-manager-v1`**, giu
nguyen `pidof gencore` (24400), TPROXY 644, tun 32, GUI 200, md5 4 file config khong doi.

**Ghi chu van hanh:** 176 dong `dns: exchange failed ... context deadline exceeded` con lai trong
`/tmp/gencore_run.log` thuc ra chi la **26 query id** (6,8 dong retry/query, ~1,4% query), tap trung
vao record HTTPS/type-65 cua Apple push - do truc tiep DoH 12 proxy x 3 loai record deu `rc=0`, va
quet 40/322 outbound (3 lan thu/cai) cho **40/40 OK ngay lan 1** => khong phai loi cau hinh router.

**Rollback:** `sh /data/genrouter_backups/v6_dnsdetour_20260904_170638/rollback.sh` (fix DNS) va
`sh /data/genrouter_backups/v7_guard_detour_20260904_201202/rollback.sh` (guard 2.41).

## Ver 2.40 (2026-09-04) - guard chi so `proxy_username_uniq`

**Lo hong duoc bit:** `config_doc_stats()` chi DEM SO LUONG. Neu vendor `/etc/genrouter/server:9000`
regenerate `gencore.json` voi 322 outbound nhung **cung 1 username** thi moi chi so cu van dung
(`proxy_outbounds=322`, `dns_proxy_doh=322`, `dns_loop_breaker=1`, `source_ip_cidr=322`,
`route_rules=326`) => `degraded=[]` => guard va `config_self_heal` **khong biet gi** => fix 322
session rieng bay mat IM LANG. Y het kich ban da xay ra voi loop-breaker truoc Ver 2.34.

- Them chi so `proxy_username_uniq` = so username KHAC NHAU va KHONG RONG cua outbound `proxy_*`.
- Them vao ca `config_doc_stats()` **va** `CONFIG_GUARD_KEYS` (nay 6 khoa) => duoc canh o CA 2 duong:
  post-vendor guard va `config_self_heal` dinh ky 60 s.
- **Khong bao dong gia o mode VPN**: `presets/session1.json` co 322 outbound `{"type":"direct"}`
  khong co `username` => want = 0.
- Dry-run 7/7 PASS truoc khi ghi, gom: VPN uniq=0, PROXY uniq=322, vendor gop ve 1 username thi
  `degraded=['proxy_username_uniq']`, pha 161/322 thi uniq=162 (bat ca pha MOT PHAN), va round-trip
  GUI `build_ip_identity_text` -> `apply_ip_identity_config` giu nguyen 322/322 tag.

## Ver 2.39 (2026-09-04) - 322 session Lumi RIENG cho 322 may

**Nut co chai that su cua mode proxy:** ca 322 outbound dung CHUNG 1 session string
`lumi-...._session-<da-che>` => ca 322 may ra Internet bang **cung 1 exit IP** => tran cung.

- Moi client IP nhan mot session string rieng: thay 4 ky tu cuoi cua phan `session-` bang 4 ky tu
  base36 lay tu `md5("gr|" + ip_client)`. Deterministic (giu sticky IP) va **do dai username khong doi**.
- Ap cho `/etc/genrouter/config/proxy.json` + `gencore.json` (3 ban: runtime, config, `presets/session3.json`).
- Cach patch: sua tren **RAW TEXT bang regex object-level**, KHONG `json.dumps` lai, de giu 100% format
  compact. Bang chung: kich thuoc byte **khong doi** (128.565 va 60.751). Bat buoc, vi vendor `tproxy`
  quet chuoi `"source_ip_cidr"` bang awk - file pretty se lam `CLIENT_IPS` rong => mat het rule TPROXY.

**Do duoc (cung host `speedtest.singapore.linode.com`, cua so co dinh T=3 s, 2 vong xen ke):**

| stream | chung 1 session | 322 session rieng | ty le |
|---|---|---|---|
| 1 | 38,65 Mbps | 103,39 Mbps | 2,68x |
| 4 | 56,33 Mbps | 296,53 Mbps | 5,26x |
| 10 | 57,55 Mbps | 567,38 Mbps | 9,86x |
| 20 | 57,59 Mbps | 921,49 Mbps | **16,00x** |

Chung 1 session **bao hoa phang ~57,5 Mbps** o ca 4/10/20 stream (them stream khong them toc do),
trong khi 322 session rieng scale gan tuyen tinh. Truoc khi sua, do voi tai that cua 322 may:
**9,14 Mbps**; sau khi sua: **842 Mbps** (10 stream).

Da bac bo cac gia thuyet khac bang so do: CPU i3-3220, `mssfix`/phan manh, buffer socket 208 KB,
tran 1 tunnel OpenVPN (chi ung voi mode VPN), va **tang so outbound la vo ich**
(1 proxy 1 stream 4,66 / 1 proxy 8 stream 28,33 / 8 proxy 21,69 / 16 proxy 32,20 Mbps).
Upstream Lumi **khong** gioi han so session: 64 session dong thoi -> 63 exit IP khac nhau, 0 loi.

## Ver 2.35-2.38 (2026-09-02 .. 2026-09-03)

- **FORMAT-HEAL / `save_gencore_json()`**: doi toan bo cho ghi file gencore tu `save_json()` sang
  `save_gencore_json()` ghi COMPACT (khong dau cach sau `:`). Ly do: vendor `tproxy` doc
  `source_ip_cidr` bang awk theo chuoi, file pretty-print lam `CLIENT_IPS` rong.
- **deny-by-default** + vendor tproxy fix: `CLIENT_IPS` chi `/32`, tra lai `RETURN` intra-LAN
  (LAN -> router 886/9001/19123 bi RST khi `tproxy -s` rebuild chain), `rt_tables` dang ky theo SO
  chu khong theo ten (vendor ghi sai `100 proxy` / `200 block` lam `ip route show table block`
  tra ve noi dung table 200 => che mat viec table 201 RONG = kill-switch chet im lang),
  va `unreachable default` cho table 201 dung cu phap hop le.
- `config_self_heal()` + apply lock: nguon su that la preset cua session dang active, so bang
  `CONFIG_GUARD_KEYS`, tu phuc hoi khi vendor ghi de.

## Ver 2.34 (2026-09-04) - guard loop-breaker DNS

Vendor ghi de bao nhieu lan cung khong mat rule `as.lumiproxy.io -> dnsmasq`. Bang chung bat that:
`dns_proxy_doh:0<-322 dns_loop_breaker:0<-1 dns_proxy_legacy:322<-0` luc 05:02:41 khi apply session 3.

## Ver 2.33
Ban nay sua 3 BUG GOC RE gay ra su co ngay 30/08 (mat cau hinh 2, mat mang may `192.14.5.x`, va `map.txt` bi xoa trang 114 may). Ca 3 deu la loi CO SAN tu cac ban truoc, khong phai sinh ra tu Ver 2.32.

### 1. Loi "cau hinh 2 mo khong duoc" - file JSON bi dinh rac (race condition khi ghi file)
- **Hien tuong**: `presets/session2.json` va `session4.json` deu bi **dung 155 byte rac** o duoi phan JSON hop le (`tbound": "proxy_322", "source_ip_cidr": "192.14.4.72"...`) -> `json.loads` bao `Extra data` -> UI khong mo duoc cau hinh.
- **Nguyen nhan**: `_ss_atomic_write()` dung ten file tam **CO DINH** `<file>.tmp_write`. App chay `ThreadingHTTPServer` nen 2 request ghi cung mot file se dung **CHUNG mot tmp**: luong A mo tmp ghi ban dai (172969B), luong B mo lai dung tmp do (mode `'w'` = truncate ve 0) ghi ban ngan hon (172814B), hai lan flush chen nhau -> tmp thanh "noi dung B + phan duoi con lai cua A", roi `os.replace` **cong bo ban rac do**. Dung bang so byte chenh lech quan sat duoc. Loi nay ton tai tu Ver 2.18 - chi la truoc day it khi 2 request ghi trung nhau nen chua no.
- **Fix trong `app.py`**:
  - Ten tmp duy nhat theo `pid + thread_id + so thu tu tang dan` (`_atomic_tmp_name()`) - hai luong khong con dung chung tmp.
  - **Lock rieng theo tung duong dan file** (`_atomic_lock_for()`) - hai lan ghi cung mot file xep hang, khong chen nhau.
  - **Doc lai tmp so tung byte** voi noi dung can ghi TRUOC khi `os.replace`; lech thi huy, khong cong bo -> khong bao gio publish file rac.
  - `_ss_cleanup_stale_tmp()` don `*.tmp_write*` con sot luc khoi dong (BASE_DIR, presets, config, runtime).
  - `_ss_rotate_backups()` / `_ss_seed_backups()` truoc day tu ghi `.tmp` co dinh (cung loi) -> nay dung `_ss_atomic_write()`.
- **`load_json()` tu va file hong**: neu `json.loads` that bai, dung `raw_decode()` lay phan JSON hop le o dau, luu ban hong ra `<file>.broken.<timestamp>` de dieu tra, ghi lai ban sach roi log vao `session_state_guardian.log`. Nguoi dung khong con bi khoa khoi cau hinh vi mot file dinh rac.
- **Do duoc**: 6 luong ghi xen ke 2 payload dai khac nhau + 3 luong doc lien tuc. Ban cu: **1433 lan doc thay `Extra data`**. Ban moi: **0 lan**, khong con tmp sot. Da chay ca tren may Windows va tren chinh router.

### 2. Loi may `192.14.5.x` mat mang - `ip rule` mo coi khong ai don
- **Hien tuong**: sau khi `map.txt` bi xoa trang, con lai **210 rule** `from <ip> lookup 3xx` tro vao tunnel da chet. May bi hut vao tun chet nhung KHONG con trong ipset nen cung khong duoc RETURN khoi pipeline tproxy -> mat mang hoan toan.
- **Nguyen nhan 2a - `gen_vpn_guard.sh` chi biet THEM, khong biet BO**: `ensure_routes()` chi doi chieu `map.txt` roi them cai thieu. Rule con trong `ip rule` ma khong con trong `map.txt` thi khong co ai don -> guard van bao `[OK] duong VPN dung chuan` trong khi mang dang chet.
- **Nguyen nhan 2b - `clean-stale` bi loi regex nen KHONG BAO GIO don duoc gi**: `cmd_clean_stale()` loc IP bang `grep -qE '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'`. Trong ERE, `\\.` co nghia "mot dau backslash roi mot ky tu bat ky", tuc doi IP phai **chua dau backslash** -> khong IP nao khop -> moi dong deu `continue` -> lenh luon in `[OK] clean-stale xong` ma chang don gi. Day chinh la ly do 210 rule mo coi song sot duoc. Da kiem chung truc tiep tren router: `printf '192.14.5.1' | grep -qE '...'` khong khop; them rule test roi chay `clean-stale` -> rule van con.
- **Fix**:
  - `tools/gen_vpn_guard.sh`: them buoc **quet rule mo coi** vao `ensure_routes()`, nam trong **cung mot luot `awk`** da co san nen khong tang so process theo so may. `check` bao `[EXTRA] ip rule mo coi: from <ip> lookup <table>`, `fix` xoa dung tung rule.
  - `ensure_routes()` khong con `return` som khi thieu `map.txt` - map trong/mat chinh la luc can quet rule mo coi nhat.
  - `tools/vpn_mgr.sh`: doi `\\.` thanh `[.]` trong `cmd_clean_stale()`.
- **Do duoc tren router**: them 3 rule mo coi -> guard **cu** bao `[OK] dung chuan` (khong phat hien); guard **moi** bao `[EXTRA]` x3 + `[WARN] 3 diem lech`, chay `fix` don sach con 0. `clean-stale`: truoc 1 rule -> sau 0 rule. **Khi moi thu dung, output `check` cu va moi giong nhau tung byte** (md5 `d12404a81b44ae67a18261162980f048`) -> khong doi hanh vi.

### 3. Loi `map.txt` bi xoa trang 114 may khi apply cau hinh - khong co dau vet, khong the hoan tac
- **Nguyen nhan**: `sync_vpn_state_on_apply()` tu dong bo gan moi IP co trong `map.txt` ma cau hinh dang apply khong khai bao VPN. Cau hinh 4 khai bao **0 may VPN**, nen apply cau hinh 4 da bo gan sach 114 may. Ve logic la dung thiet ke, nhung khong he luu ban sao nao truoc khi xoa.
- **Fix trong `app.py`**:
  - Them `_backup_vpn_map()`: **snapshot `map.txt` vao `persist/map_backups/map.<YYYYMMDD_HHMMSS>.txt` truoc khi bo gan hang loat**, giu 10 ban gan nhat, ghi log vao `session_state_guardian.log`. Duong dan ban backup duoc tra ve trong ket qua apply (`map_backup`).
  - `sync_vpn_state_on_apply()` chuyen tu vong lap `unassign`/`assign` tung IP sang **`unassign-many` / `assign-many` theo nhom account** -> thao tac 100+ may xong trong ~1s thay vi vai phut (dung dung ha tang toc do da lam o Ver 2.32).
- **Do duoc**: `_backup_vpn_map()` tao ban sao 114 dong, md5 **trung khop tuyet doi** voi `map.txt` (`3a9828fd6cb16a6056c11d10394c07c8`).

### Ghi chu
- Khong doi giao dien, khong doi API, khong doi dinh dang `map.txt` / `session*.json`. Router chua update van chay binh thuong.
- Sau khi deploy da xac nhan: 4 preset deu parse OK, `session_state.json` OK, `map.txt` 114 dong md5 khong doi, ipset 114, `ip rule` 3xx = 114, `gen_vpn_guard.sh check` = `[OK] duong VPN dung chuan, khong can sua`.

### Bo sung cho du bo cai (git = ban full)
- Them `apply_xxtouch_bypass.sh` - file dang chay tren router nhung truoc day **chua co trong git** (chen rule `mangle GENROUTER` cho `192.14.0.1/20 -> 192.14.0.1/32 tcp -j RETURN` de may LAN vao duoc GUI router ma khong bi hut qua tproxy). Da khai bao `eol=lf` trong `.gitattributes`.
- Da doi chieu **md5 tung file giua git va router**: 27/27 file nguon (`app.py`, `static/*`, `tools/*`, toan bo `.py` va `.sh` cai dat, cac file `.md`) **trung khop tuyet doi** -> git dung la ban full cua version dang chay.

## Ver 2.32
- TOI UU TOC DO "GAN VPN HANG LOAT" (gan all ~114 may: **~5 phut -> ~2 giay**). Khong doi hanh vi, khong doi giao dien, `assign`/`unassign` cu giu nguyen de router chua update van chay binh thuong.
  - **Nguyen nhan do duoc tren router that** (Ver 2.31.1, `map.txt` 114 dong): `vpn_mgr.sh assign` 1 may ~2.6s, trong do `gen_vpn_guard.sh fix` chiem ~2.5s. Ban than viec gan gan nhu mien phi (`ipset add` + `ip rule add` ~0ms). Boc tach guard: `sync_set` ~0.33s, `ensure_rules` ~0s, `ensure_nft` ~0s, **`ensure_routes` ~1.0s**. `ensure_routes` lap tung dong `map.txt` va spawn ~6 process moi dong (3x`grep` meta + `ip link` + `ip route show` + `ip rule show` + `iptables -C`) = **~700 process moi lan goi guard**. Vi `assign_rules_on()` goi guard sau TUNG IP va UI lai POST tuan tu 1 request/may, tong chi phi thanh binh phuong.
  - `tools/gen_vpn_guard.sh` - viet lai `ensure_routes()`: snapshot **1 lan** (`ip rule show`, `iptables -t nat -S POSTROUTING`, `ls /sys/class/net`, `ip route show table all`, meta cua tat ca account) roi dung **1 luot `awk`** tinh ra danh sach viec can lam; shell chi chay dung so lenh thuc su can. Khi moi thu da dung thi tong chi phi ~5 process, **khong phu thuoc so may**. Do tren router: `guard check` 10 lan **14s -> 3s** (~4.7x). Logic quyet dinh giu Y NGUYEN - da doi chieu output `check` cu/moi giong nhau tung byte (md5 trung).
  - `tools/vpn_mgr.sh` - them `VPN_NO_GUARD=1` cho `guard_run()`, va 2 lenh moi:
    - `assign-many <ten> <IP...>` - gan nhieu may 1 luot: guard chay **dung 1 lan o cuoi**, `map.txt` ghi 1 lan bang `awk`, `ip rule show` doc 1 lan, tu go duong VPN cu neu IP dang thuoc tunnel khac.
    - `unassign-many <IP...>` - bo gan nhieu may 1 luot, cung co che.
    - Them `is_ipv4()` kiem tra that (4 octet, moi octet 0-255) thay cho glob `[0-9]*.[0-9]*...` - truoc day `999.1.1.1`, `256.1.1.1`, `1.2.3.4.5` deu bi coi la IP hop le va lot vao `map.txt`. Danh sach dau vao cung duoc **loai trung lap**.
  - `app.py` - `/api/vpn/action` them 2 action `assign-bulk` / `unassign-bulk` nhan ca danh sach IP trong 1 request (validate + dedupe bang regex dotted-quad, `timeout=max(120, 3*so_IP)`, tra ve `count` + `invalid`). Them `_record_vpn_declaration_bulk()`: doc active session + session state + session file **1 lan**, apply `vpn_account`/`set_outbound_proxy` cho tat ca IP roi save **1 lan** - thay ~700 luot doc/ghi file bang 2.
  - `static/index.html` - `applyBulkVpn()` gui **1 request bulk** thay vi N request tuan tu; neu router chua co action moi thi **tu dong lui ve** vong lap le cu. Them `applyVpnChangeBulk()` va dung cho `applyColumnProxyType()`, `assignAllProxy()`, `clearAllProxy()`, `applyBulkMap()` - cac cho truoc day cung ban N request lien tiep.
  - **Do lai sau fix** (sandbox 114 IP tren router that, khong cham `/data/vpn`): `assign` tung cai x114 = **20-25s** -> `assign-many` 1 lenh = **1s**; `unassign-many` x114 = **1s**. Ket qua cuoi (`map.txt`, `ipset`, `ip rule`) **giong het** cach cu - da doi chieu md5. Da test them: chuyen 114 may tu account nay sang account khac (rule cu xoa sach, rule moi du 114), chay lai y nguyen 3 lan (idempotent, khong sinh rac), IP rac bi loai dung.

## Ver 2.31.1
- Hoan thien Ver 2.31 (cung chu de: may gan VPN mat mang), 4 diem:
  - `install.sh` KHONG con `cat > /etc/rc.local` ghi de ca file. Truoc day moi lan chay lai install.sh la router mat sach cac dong boot custom da co (`/etc/gen_runtime_tune.sh`, `/etc/genrouter/dyn24-runtime/start_dyn24.sh`, `/etc/genrouter_fix_fw.sh`) -> mat tune runtime + mat 24 shard gencore + mat firewall fix o lan reboot sau. Gio la MERGE: backup theo timestamp, chi `sed` bo cac dong frpc/reverse-tunnel, bao dam co `genrouter_fix_fw.sh` va `exit 0` o cuoi. Da test 4 truong hop tren router (co custom+frpc / chay lai lan 2 / khong co rc.local / khong co dong `exit 0`) -> giu du dong custom, idempotent, khong trung lap.
  - `install.sh`: doi thu tu - `gen_fw_fix.sh` + `gen_vpn_guard_install.sh` chay SAU khi rc.local da on dinh, va doc file tu `$APP_DIR` (da copy) thay vi `$SCRIPT_DIR`.
  - `tools/gen_vpn_guard.sh`: them fallback per-IP khi router khong co `ipset` (firmware toi gian) - doc `map.txt` roi ep rule `-s <ip>` ve dau chain, thay vi bo trong hoan toan. Bien `GUARD_FORCE_NO_IPSET=1` de test duong nay tren may co ipset. `check` gio chi tinh `[MISS]/[ORDER]/[EXTRA]` la loi, con `[SKIP]/[DOWN]` (tunnel dang down, thieu ipset) chi la thong tin -> khong con bao dong gia lam cron log ran rac.
  - `tools/gen_vpn_guard_install.sh`: sua `sed -i '/exit 0/i ...'` thanh neo `^exit 0`, neu file khong co dong `exit 0` thi append; them `chmod +x /etc/rc.local`. Truoc day bat ky dong nao chua chu "exit 0" cung bi chen vao truoc.
  - Bo non-ASCII con sot trong 2 file guard (BusyBox sh + locale C an toan hon).
- Da deploy va verify lai tren con .17: `gen_vpn_guard.sh check` exit 0, cron van giu nguyen dong `ov.sh`, hook trong `genrouter_fix_fw.sh` dung 1 lan, client 192.17.4.1 REACHABLE va con 8 ket noi qua tun1.

## Ver 2.31
- FIX GOC RE vu "gan VPN cho may xong may mat mang, VPN van ket noi OK" (su co 29/08 tren con .17, may 192.17.4.1 gan jp-171):
  - Nguyen nhan 1 (chinh): fw4/nftables chan forward `br-lan -> tun*`. Chain `forward` co `policy drop`; `forward_lan` chi `jump accept_to_wan` + `jump accept_to_lan`, ma `accept_to_wan` **RONG 0 rule** vi `tun1..tun4` khong thuoc zone nao. Goi moi tu client ra tun1 khong match gi -> roi xuong `handle_reject`. Bang chung: tun1 chi RX 18 pkt / TX 14 pkt trong khi VPN tunnel van up va router ping 8.8.8.8 qua tun1 OK 53ms.
  - Nguyen nhan 2 (dong thoi): UDP cua may di VPN bi REJECT. `mangle PREROUTING` co `-i br-lan -p udp -j GEN_FW_UDP` -> `MARK 0x4d3` -> `ip rule fwmark 0x4d3 lookup 202` (local default dev lo) -> `INPUT ... -j REJECT icmp-port-unreachable` dem 3449 pkt/897K. Co che chong UDP-leak cho may di proxy nhung **khong loai tru may da gan VPN** -> QUIC/HTTP3 chet. Cong them legacy `FORWARD -i br-lan -p udp -j DROP` (1187 pkt).
  - Vi sao khong sua truc tiep tproxy: `/etc/genrouter/core/tproxy` bi cron `/etc/shm/ov.sh` cp de lai MOI PHUT, va tproxy + gen_fw_fix.sh deu chen rule bang `-I ... 1` moi lan apply -> moi rule per-IP sua tay se bi day xuong duoi va het tac dung.
  - Fix: them `tools/gen_vpn_guard.sh` - guard self-heal, idempotent:
    - ipset `genrouter_vpn` (hash:ip) dong bo 2 chieu tu `/data/vpn/map.txt`. Them/bo may VPN = `ipset add/del`, **khong sinh rule moi** -> khong bao gio lech thu tu.
    - 4 diem thoat luon bi EP VE VI TRI 1 cua chain (neu lech thi xoa het roi `-I ... 1`): `mangle PREROUTING` RETURN, `mangle GENROUTER` RETURN, `mangle GEN_FW_UDP` RETURN, `filter FORWARD` ACCEPT.
    - 2 file include cho fw4 persist qua `fw4 reload`: `chain-pre/forward_lan/99-genrouter-vpn.nft` (accept `oifname "tun*"`) + `chain-pre/mangle_forward/99-genrouter-vpn-mss.nft` (MSS clamp `size set rt mtu`, vi `mtu_fix` chi ap cho device trong zone).
    - Kiem tra/tu them `ip rule from <ip> lookup 3xx`.
    - Log chi ghi khi CO thay doi -> `/data/vpn/logs/guard.log`, tu rotate > 200KB.
  - 3 lop trigger de song qua reload + reboot + tproxy ghi lai: cron 1 phut, hook trong `/etc/genrouter_fix_fw.sh` (marker `gen_vpn_guard_v1`), va `rc.local` da goi `genrouter_fix_fw.sh` san.
  - `gen_fw_fix.sh` them buoc 3: tu cai + goi guard SAU khi chen cac rule `-i br-lan` (vi buoc 2 vua day rule chan len dau chain).
  - `tools/vpn_mgr.sh`: gan/bo VPN cho may chuyen sang `ipset add/del genrouter_vpn` thay vi sinh rule `mangle PREROUTING -s <ip> -j RETURN` per-IP; van co fallback hanh vi cu neu chua cai guard.
  - `app.py`: them `ensure_vpn_guard()` - tu phuc hoi `/etc/gen_vpn_guard.sh` tu `tools/` khi khoi dong va sau moi lan update (giong `ensure_vpn_mgr`), nen moi router tu co guard, khong can deploy tay.
  - `install.sh` / `gen_update.sh`: copy `tools/` va goi `gen_vpn_guard_install.sh` sau `gen_fw_fix.sh`.
  - Da verify tren .17: client 192.17.4.1 ra internet qua tun1 (exit 10.96.0.44), 22 ket noi ESTABLISHED, counter tang lien tuc; test pha hoai (chen lai DROP udp len dau chain) -> guard tu chua ve vi tri 1; test `fw4 reload` -> fw4 tu include 2 file; test mo phong reboot (chay `genrouter_fix_fw.sh`) -> guard tu dung lai day du.
  - Bai hoc ghi lai: fw4 **bo qua include cua chain rong**, nen muon persist rule vao `accept_to_wan` (rong) phai dat include o chain cha dang duoc render (`forward_lan`). Va: counter dong bang != firewall chan - phai check `ip neigh` + `conntrack -L | grep -c src=<ip>` xem client co online that khong truoc khi ket luan.

## Ver 2.30
- FIX GOC RE vu "proxy khong vao duoc web / lag kinh khung" (su co 28/08 tren con .14): DNS query cua MOI client bi proxy tu choi 100%.
  - Nguyen nhan: `apply_rows_to_data` sinh DNS server cho tung proxy la `tcp://8.8.8.8`, tuc DNS-over-TCP **port 53**. Nha cung cap proxy (lumi va nhieu ben khac) **CHAN port 53/853/5353** va tra ve SOCKS5 reply **code=2** (connection not allowed by ruleset). Do do 322/322 DNS server deu fail => client khong resolve duoc ten mien => web khong load, retry lien tuc gay lag.
  - Do kiem chung qua chinh lumi (`as.lumiproxy.io:5888`): `8.8.8.8:53` REJECT rep=2, `1.1.1.1:53` REJECT rep=2; con `:80`, `:443`, `:8080` deu OK. TLS tới `8.8.8.8:443` qua proxy pass full cert verification + ALPN h2 (cert CN = dns.google) nen sing-box DoH chay duoc.
  - Fix: DNS server cua proxy_* doi sang **DoH `https://8.8.8.8/dns-query` (port 443)**. Dung dia chi IP chu khong dung hostname de tranh chicken-and-egg (gencore khong the resolve ten cua resolver truoc khi co resolver). Dat trong hang so `PROXY_DNS_ADDRESS` de sau doi 1 cho.
  - TU CHUA config cu (khong can sua tay tung router):
    - `migrate_proxy_dns_servers()` doi moi DNS server proxy_* dang `tcp://`/`tls://`/`:53` sang DoH; chay trong `run_apply` moi lan Apply.
    - `startup_migrate_proxy_dns()` chay khi app khoi dong: quet `config/gencore.json`, `gencore.json` runtime va ca 5 file session; neu co doi thi ghi log watchdog roi **tu restart gencore** de config moi co hieu luc ngay.
  - Fix bug thu hai cung goc: `socks5_probe_multi` dung target `('8.8.8.8', 53)` de health-check proxy. Vi port 53 bi chan, moi lan check phai cho het timeout tren target do roi moi thu target sau => health-check cham va bao proxy chet oan. Da doi sang `('1.1.1.1', 443)`.
  - Bai hoc ghi lai: "log gencore het loi" KHONG dong nghia "client vao duoc web". Phai co bang chung end-to-end tu client that truoc khi ket luan.

## Ver 2.18
- SESSION STATE GUARDIAN — fix goc re vu mat ca cau hinh proxy khi reboot giua luc ghi (su co 26/08: reboot tay lam hong session_state.json, app nuot loi tra {} roi ghi de trang -> toan bo may nhay sang CHUA CAU HINH):
  - Ghi nguyen tu (atomic write + fsync + os.replace) cho moi file JSON: tren dia chi ton tai ban cu hoan chinh HOAC ban moi hoan chinh, khong bao gio co file do dang nua.
  - Chan save-rong: neu ban moi rong/trang trong khi ban dang tai co du lieu -> tu choi ghi + log canh bao (muon reset that su thi xoa tay cac file session_state.json*).
  - Backup xoay vong 5 ban (session_state.json.bak.1..5): chi dua ban tot (parse duoc + co du lieu) vao chuoi backup.
  - Self-heal khi load: file chinh mat/hong/rong bat thuong -> tu tim backup moi nhat con dung duoc (bao gom ban ngoai rootfs /data/vpn_backup/session_state.json) -> phuc hoi ngay + ghi log. Khong con nuot loi im lang.
  - Moi su kien chan/heal deu ghi logs/session_state_guardian.log de truy vet.

## Ver 2.17
- GENCORE WATCHDOG tu chua (sau su co 26/08: gencore am ~11.000 conn zombie toi upstream :5888 lam LAN di qua core bi den, web khong vao duoc):
  - Thread nen kiem tra moi 60s: gencore chet -> tu start lai (pattern BusyBox subshell, cooldown 180s).
  - Dem conntrack TIME_WAIT dport=5888 (port upstream quay): vuot nguong (mac dinh 5000, total 40000) 2 mau lien tiep -> tu restart gencore, cooldown 10 phut. Het bão zombie không cần ai can thiệp tay nữa.
  - Nguong chinh duoc qua persist/watchdog.json (zombie_tw/ct_total/consecutive/cooldown_sec) — dung de test.
  - Hanh dong + so dem luon ghi logs/gencore_watchdog.log (tu cat khi qua 256KB) — de sau truy vet su co.
- TU PHUC HOI SAU REBOOT (map.txt nam tren tmpfs nen mat theo reboot, may client mat mapping/tunnel):
  - Moi chu ky snapshot trang thai VPN (tunnel dang chay + map ip->account) vao persist/vpn_runtime.json (flash, song sot reboot), chi ghi khi thay doi.
  - Sau khoi dong (uptime < 15 phut) + map.txt mat: tu ghi lai map.txt tu snapshot roi UP lai tung tunnel dang chay truoc mat; do_up trong vpn_mgr.sh tu goi restore_clients nen ip rule + mangle cho tung may duoc tái lap dung nhu cu.
  - Service restart binh thuong (khong reboot) khong bi keo vao: chi kich hoat khi map.txt that mat + uptime ngan.

## Ver 2.16
- Nang cap tu cai deps: opkg update retry 3 lan (mirror vsean chi lac quan, khong chet hang loat); chi khi chet lien tuc moi doi feed userspace sang downloads.openwrt.org va GIU NGUYEN feed kmods (kernel module phai trung vermagic snapshot). Cai tung goi retry 3 lan; goi userspace (openvpn-openssl, wireguard-tools) con co fallback --force-depends khi vong dep kernel khong giai duoc.

## Ver 2.15
- Tu sua feed opkg chet truoc khi cai: mirror snapshot (mirrors.vsean.net/...23.05-SNAPSHOT) thuong 404 -> app tu doi sang downloads.openwrt.org/releases/23.05.5 (co backup distfeeds.conf.bak) roi thu lai "opkg update".
- Cai tung goi rieng (openvpn-openssl truoc, wireguard-tools + kmod-wireguard sau) de co gi nhat cung co openvpn dung duoc; ket qua tong ket ro OK/THAT BAI trong log deps, canh bao neu kmod khong hop kernel.

## Ver 2.14
- Tu cai phan mem VPN thieu qua opkg: router chua co openvpn/wg thi app tu chay "opkg update && opkg install openvpn-openssl wireguard-tools kmod-wireguard" trong nen (khong block GUI), bao tien do bang banner tren /vpn. Lenh VPN lien quan se bao "dang tu cai, cho 1-2 phut roi bam lai" thay vi bao loi thieu.
- /api/vpn/status tra them truong deps (openvpn/wg/installing/log) de giao dien hien trang thai.
- Tu khoi dong service cung tu kiem tra + cai phan mem thieu.

## Ver 2.13
- FIX quan trong (audit tong quat): vpn_mgr.sh gio TU PHUC HOI tren moi router - app tu copy ban gan trong app (tools/vpn_mgr.sh) ve /data/vpn/ khi thieu hoac khac ban, kiem tra truoc moi lenh VPN (add/up/down/assign/import...). Het loi "can't open /data/vpn/vpn_mgr.sh: No such file or directory" tren router chua tung deploy tay.
- Trang /vpn: loi nap nhieu file gio hien ly do that thay vi "LOI: ?".
- Khoi dong service tu dam bao /data/vpn + vpn_mgr.sh san sang; ghi cache exit-ip tu tao thu muc neu thieu.

## Ver 2.12
- Deeper pink-purple ("Fire") theme round 2: table rows, selects, meta/notes strips, bulk bar, modals and all inputs/buttons now carry the pink-violet tint (no more white table body); body gradient and headers deepened one notch. Semantic colors (online/offline, config identity colors, fire-gradient primary buttons) unchanged.

## Ver 2.11
- Fix version pill in the title bar showing only "Ver 2" instead of the full version: the display regex captured just the major number, so Ver 2.10 rendered as "Ver 2". The pill now shows the complete version (e.g. "Ver 2.10") and the hover tooltip keeps the full label including the commit sha.

## Ver 2.10
- Release marker to exercise the new update flow: this is the first build that REBOOTS the router on a successful update (behavior introduced in Ver 2.9 - routers updating FROM older builds could not reboot because the old in-memory code performed the update). From this version onward every successful update notifies and fully reboots the router.

## Ver 2.9
- `vpn_mgr.sh` is now part of the repo (`tools/vpn_mgr.sh`): the updater auto-installs the latest copy to `/data/vpn/vpn_mgr.sh` (chmod 755) on every successful update, so the VPN tunnel engine (add OpenVPN/WireGuard/Express, up/down, assign/unassign, clean-stale) no longer needs to be copied to routers by hand.
- Successful updates now notify clearly AND fully REBOOT the router ~5s after the response (sync + reboot) instead of only restarting the proxy-manager service. Clicking update while already on the latest version just reports "already latest" and only restarts the service - no pointless reboots.

## Ver 2.8
- WireGuard support end-to-end: /vpn now accepts .conf alongside .ovpn with auto-detection (isWgConf) - paste, single upload or multi-file batch; new `add-wg` API + `vpn_add_wg_text()` validation; WG interfaces get correct running status (`ip link show dev`) and base64-padded keys parse safely (sed splits only the first `=`).
- Upload configs from PC: file picker on /vpn feeds the same add flow (one file -> preview, many files -> sequential auto-add).
- WAN IP column on /vpn replaces the Dev column (dev name kept as cell tooltip): server probes the public exit IP of every RUNNING tunnel in parallel batches of 8 threads via a bound socket per tunnel, caches to /data/vpn/exitips.json; GET /api/vpn/exitips + POST action refresh-exitips; frontend polls every 60s, auto-triggers a refresh when data is stale and after up/down/del actions; probing cells show "dang do...".
- New "Fire" pink-purple theme for both pages: main page shifts to a clearly pink-violet light palette with fire-gradient APPLY/primary buttons; /vpn goes dark plum with fire glows and gold WAN IPs. Both pages declare color-scheme (light only / dark) so browsers cannot auto-swap the palette.
- Fleet note for WireGuard routers: opkg install wireguard-tools kmod-wireguard + add the `vpntun` firewall zone (tun*/wg* devices, ACCEPT + masq + mtu_fix), lan->vpntun forwarding and a QUIC UDP/443 reject rule via UCI so forwarded clients get internet (survives fw4 reload).

## Ver 2.7
- Redesigned main toolbar: 4 unified white cards with icon chips, bottom-aligned full-width primary action buttons (GAN 1 ALL / GAN HANG LOAT / GAN VPN).
- Per-config color identity: each session tab, session label chip and panel top border get a distinct fixed color (cfg1 blue, cfg2 green, cfg3 orange, cfg4 violet, cfg5 pink) so the active config is recognizable at a glance even after creating more configs.
- Fixed license line truncation (ACTIVE: FULL | Han: ...) - full text now wraps instead of being cut with ellipsis.
- Fixed machine-count note showing bogus "0.322" (row with machine 0 leaked into range compression; now filtered n > 0).
- Redesigned /vpn page: hero header with live status dot, icon-chip section cards, UP/down status badges, unified buttons, clearer AUTO: BAT/TAT labels, wider action column.
## Ver 2.6

- sync VPN state on every config apply: machines NOT declared as VPN in the applied config are auto-unassigned (map.txt + ip rules); declared machines keep/restore their tunnel (assign only when tunnel is UP); stale ip-rules pointing to dead tunnels are cleaned via new `vpn_mgr.sh clean-stale` (IPv4-guarded, BusyBox-safe)
- /vpn Clients column shows machine numbers from server-side `machine_map` (built from shared identity text) â€” works in any browser tab and without an active session; draft/IP kept as fallback
- assigning/unassigning VPN via panel or API now records `vpn_account` + direct/block outbound into the ACTIVE session config, so re-applying the same config keeps VPN assignments and switching configs syncs cleanly
- fix duplicate-case meta keys (PROXY_5 vs proxy_5): new `sess_item` reuses the existing key regardless of case and `get_session_meta` merges case-insensitive duplicates instead of losing fields
- main GUI opens the ACTIVE session on load instead of always session 1

## Ver 2.4

- remove XXTouch Jobs tab, panel and adm cluster from the UI while keeping all backend functions/routes/constants intact
- move the license pill (ACTIVE/háº¡n) out of the title bar into the table meta row; row count label moves under the tab row
- add Reboot Router button on the license lock screen; exempt `/api/pm/reboot-router` from the license gate so an inactive machine can still reboot its router
- simplify tab switching to the single Proxy Manager tab
- slim the update package: stop shipping legacy gen_backup/versions/1.1 package and per-router update_codes.json state
- updater now removes its update_tmp working dir after a successful run so routers do not accumulate ~10MB per update
- version label regex keeps minor version so Ver 2.4 no longer displays as Ver 2

## Ver 2.3

- re-add license gate block (ACTIVE_URL + get_machine_id + license_active/license_public_payload/license_check_loop/gate_ok) that upstream removed; expose GET /api/license before the root route
- re-add proxy sync-sheet push hooks: run_apply ok branch, POST sessions save, clone 1-to-2, plus PROXY_SHEET_STATE_FILE state cache
- route GENUP-* update codes through the GAS Key Router (action=use_update_key) consumed server-side with LockService; legacy ADMIN2026GEN and per-version codes keep the old path
- import datetime for license expiry display

## V2.2

- restore SETUP ROUTER popup: read current LAN IP and submit LAN IP changes through existing router endpoints
- remove standalone SAVE button above CHECK ALL
- restore gear/session manager popup for hiding/showing/deleting added configurations
- simplify NOTE Tá»”NG display to `MÃ¡y <sá»‘ mÃ¡y> : <note>` without IP/proxy tag noise
- package V2.2 under `gen_backup/versions/2.2/package` for offline/online rollback via `rollback_version.sh 2.2`

## V2.1

- keep GUI 9001 as the active app
- keep Proxy Manager behavior as the main supported scope
- keep XXTOUCH JOBS tab, form, and button layout visible for later redevelopment
- freeze XXTOUCH JOBS actions so buttons do not execute real device operations yet


## v2026.05.01-new9001

- start new clean 9001 workspace from current Proxy Manager baseline
- keep Proxy Manager behavior and shared GÃN MAC/19123 workflow as the active scope
- blank/freeze XXTOUCH JOBS tab and remove bundled XXTouch job scripts for later rebuild


## v2026.05.01-01

- preserve live config files during install/update instead of overwriting router-specific settings on every reinstall
- ensure legacy old GUI service is restarted/enabled alongside the 9001 app when old init scripts already exist, so 9000 can keep running in parallel

## v2026.04.29-121

- fix GÃN IP modal loading when session state is not ready by defaulting safely to session 1 instead of requesting an invalid path
- reduce unnecessary Group3 schedule polling load in the browser by polling every 5 seconds only while active jobs exist
- keep machine identity semantics unchanged for `machine|proxy_tag|ip`: when a leading machine number exists it remains the real machine id

## v2026.04.29-120

- preserve existing Proxy Manager config files during `install.sh` updates instead of overwriting machine/session data
- reduce XXTouch scan latency by shortening probe/deviceinfo timeouts and skipping heavy disk-info fetch during normal scan
- fix severe 9001 GUI lag/freeze symptoms seen from Ver 119 onward while keeping structure and existing features intact

## v2026.04.18-17

- rewrite XXTouch `screen.js` on the fly so remote control posts directly to the device HTTP API and opens websocket against the device IP:46968 instead of browser domain assumptions

## v2026.04.18-16

- proxy XXTouch remote assets (`js/`, `css/`, `mdui/`, `screen.js`, `xxtouch.png`) through router app so remote screen can load over domain instead of breaking on private asset paths

## v2026.04.18-15

- add router-side XXTouch remote-screen proxy endpoint so remote iframe no longer points directly to private `192.15.x.x:46952`

## v2026.04.18-14

- switch FRP client scaffolding from tcp remote-port mode to HTTP subdomain mode
- derive router URL automatically as `<router_id>.aeg.ooguy.com:8080`
- simplify install flow by removing old per-router port registry dependency

## v2026.04.18-13

- integrate `setup_data_disk.sh` into `install.sh` so router install auto-checks and auto-creates `/data` when SSD space is still unallocated, while skipping safely if already prepared

## v2026.04.18-12

- add `setup_data_disk.sh` to create and mount a reusable `/data` partition on x86 routers with unallocated SSD space

## v2026.04.18-11

- switch remote access direction to FRP with auto-assigned unique remote ports
- add FRP registry on server side so each newly installed router gets a non-duplicated port
- add `frpc` config/template/setup/run files for Genrouter-side deployment
- extend `install.sh` to deploy FRP client scaffolding and service hooks

## v2026.04.18-10

- add reverse SSH tunnel scaffold for Genrouter outbound remote access
- add `reverse_tunnel.sh`, `reverse_tunnel_config.json`, and init service template
- extend `install.sh` to deploy and enable reverse tunnel service when configured
- keep site-side requirement minimal by relying on router outbound connectivity

## v2026.04.18-09

- redesign `py_gui_server.py` UI into 3 levels: router list -> session list -> proxy list
- compact router display so central GUI is easier to scan
- selecting a router now shows its sessions, selecting a session shows all proxies inside it

## v2026.04.18-08

- add `py_gui_server.py` as the final central app combining GUI and embedded router push server
- add router online/offline state and last seen display
- keep direct open/copy support for `remote_url`
- move closer to the final one-app workflow: open one Python app and see all routers

## v2026.04.18-07

- set default collector/server URL to `http://aeg.ooguy.com:9010`
- enable router client push by default after install
- default central GUI to read from `aeg.ooguy.com:9010`
- align naming toward `PY GUI Server` as the router center

## v2026.04.18-06

- add `remote_url` support in collector config and router push payload
- upgrade `collector_proxy_gui.py` with `Má»Ÿ 9001` and `Copy URL` actions
- show remote URL in collector GUI so each discovered router can be opened directly from the central tool

## v2026.04.18-05

- add collector model for remote auto-discovery across routers on different networks
- add `collector_server.py` to receive router push data centrally
- add `collector_proxy_gui.py` to read all routers from collector without manual host entry per router
- add router-side collector config and background push loop in `app.py`
- keep rollback path via release tags and update/rollback scripts

## v2026.04.18-04

- add `/api/pm/export-all` for remote export of all sessions and proxies per router
- add `router_proxy_export_gui.py` to scan multiple routers and export aggregated proxy/session data
- support remote collection by router URL instead of relying only on local LAN usage

## v2026.04.18-03

- add `CHANGELOG.md` for release notes tracking
- add committed `VERSION.txt` to define current repo release version
- keep update and rollback workflow standardized

## v2026.04.18-02

- add `RELEASE.md`
- add `update.sh`
- add `rollback.sh`
- standardize release and rollback workflow

## v2026.04.18-01

- update remote machine grid UI
- add machine grid paging for remote popup
- keep left remote view and right machine selector panel

## Ver 2.19 - Loai bo toan bo XXTouch khoi Genrouter (2026-08-27)
- Ly do: XXTouch (iOS device scripting qua port 46952) khong lien quan den gan proxy / network client di ra. AdManager la ten cu cua GUI port 9001 (proxy-manager-v1) - van giu.
- **GIU**: /api/admanager/config, /api/admanager/save-config, load_admanager_config, save_admanager_local, get_router_machine_context (doi ten tu xxtouch_get_router_machine_context)
- **XOA**: 
  - Tat ca xxtouch_* (~30 ham: xxtouch_http_probe, xxtouch_get_selected_machines, xxtouch_post_json, xxtouch_device_info, xxtouch_run_action_on_machine...)
  - Endpoint /api/xxtouch/* (10 routes: remote-screen, remote-assets, remote-proxy, scan-devices, group3-schedule/*, action, remote-link)
  - Endpoint /api/admanager/scan|pull|backup (dung xxtouch_spawn_checked)
  - Ham dmanager_command_spawn, dmanager_download_file, dmanager_download_backups_plist, dmanager_parse_backups_plist_map, dmanager_cleanup_tmp, dmanager_iter_machines, dmanager_validate_machine_selection, dmanager_routers_to_scan, dmanager_detect_app_label, dmanager_get_machine_ip_pairs, dmanager_machine_note_text, dmanager_parse_machine_tokens, dmanager_parse_base, dmanager_parse_date_input, dmanager_parse_daymonth, dmanager_in_mmdd_range, xxtouch_spawn_checked
  - Ham group3_schedule_* (worker, execute, public, job_key, start_worker)
  - Ham load_group3_schedule_store, save_group3_schedule_store, create_group3_schedule_job, ensure_xxtouch_workspace
  - Ham 
ewrite_xxtouch_remote_html, get_xxtouch_remote_online_info
  - Ham uild_event_video_180_script, uild_nurture_tiktok_script, uild_event_dd_20p_tiktok_lite_script, uild_group3_*_script
  - Const: XXTOUCH_*, ADMANAGER_REMOTE_DIR, ADMANAGER_FILE_RE, GROUP3_SCHEDULE_LOCK, GROUP3_SCHEDULE_FILE, GROUP3_SCHEDULE_THREADS, NURTURE_TIKTOK_*, EVENT_DD_20P_*, GROUP3_NURTURE_*, GROUP3_EVENT_*
  - Method _serve_xxtouch
  - Thread group3_schedule_worker start in __main__
- **Folder**: static/xxtouch/ da duoc rename thanh static/xxtouch.disabled_<timestamp> (giu lai de rollback neu can)
- **Kich thuoc**: app.py 220KB -> 126KB (-43%)
- **Backup**: /data/genrouter_backups/app_pre_remove_xxtouch_<timestamp>.py
- **Script xoa**: 
emove_xxtouch_v8.py + ix_remaining.py + ix2.py + ix3.py (chay lan luot)
- **Restart**: ( python3 /opt/proxy-manager-v1/app.py >/tmp/pmv1_v219.log 2>&1 </dev/null & ) (BusyBox subshell pattern, vi khong co init.d)
- **Test pass**: / 200, /api/pm/sessions 200, /api/admanager/config 200, /api/xxtouch/* 404, /api/admanager/scan|pull|backup 404, /api/vpn/status 200
