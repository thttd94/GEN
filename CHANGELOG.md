# CHANGELOG

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
