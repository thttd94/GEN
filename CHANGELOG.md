# Changelog

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
- upgrade `collector_proxy_gui.py` with `Mở 9001` and `Copy URL` actions
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
