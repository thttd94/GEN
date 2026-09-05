#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpn_spread.py - chia DEU so may khach cho cac tunnel VPN dang song.

VAN DE:
  Preset VPN cua router co the gan TAT CA may vao 1 tai khoan VPN duy nhat
  (do do duoc: 322/322 may -> proton-jp-171 -> tun1). Khi do tran bang thong
  cua ca router = tran cua DUNG 1 tunnel (do duoc 147-204 Mbps = 16-23% WAN),
  va o 40-80 luong dong thoi chi mo duoc 20-32 ket noi (con lai TimeoutError).

CACH CHUA:
  Chia deu N may cho M tunnel dang song. KHONG sua code app, chi ghi lai
  truong 'vpn_account' cua tung may qua DUNG API cua app (`/api/pm/sessions/<id>`),
  la duong ma GUI dung. App tu lo phan con lai khi apply.

NGUYEN TAC BAT BUOC - KHONG DONG DINH SO LUONG:
  * N (so may)    = dem tu preset/API cua chinh router do. Router khac co the
                    la 200, 500, 1000 may - script khong quan tam.
  * M (so tunnel) = dem tu tien trinh openvpn/wireguard DANG CHAY that
                    (dung lai inventory() cua dataplane_guard.py).
  Khong co bat ky con so 322/33 nao trong file nay.

AN TOAN:
  * Ghi vao PRESET (`presets/sessionX.json`) + meta, KHONG ghi runtime
    `/etc/genrouter/gencore.json`. Nghia la 'apply' that su van do nguoi van
    hanh bam trong GUI. Chay script nay khong lam gian doan may dang chay.
  * Mac dinh chi dung tai khoan co `auto=1` (reboot van con) va bo qua tai
    khoan khong chay.
  * Che do `plan` in ke hoach va khong ghi gi.

Dung:
  vpn_spread.py plan  <session_id> [--all-running] [--probe]
  vpn_spread.py apply <session_id> [--all-running] [--probe] [--yes]

  --all-running  dung ca tunnel dang chay nhung auto=0 (mac dinh: bo qua)
  --probe        do that tung tunnel co ra internet khong roi moi chia
                 (cham hon nhieu phut, nhung chac chan)
"""
import os
import sys
import json
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dataplane_guard as dg  # noqa: E402  dung lai inventory()/probe() da kiem chung

API = "http://127.0.0.1:9001"
LOGF = "/data/vpn/logs/vpn_spread.log"


def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with open(LOGF, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def api_get(path):
    req = urllib.request.Request(API + path)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def api_post(path, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(API + path, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read().decode("utf-8"))


def meta_val(acc, key):
    """Doc 1 truong trong /data/vpn/accounts/<acc>/meta."""
    try:
        with open(os.path.join(dg.ACCT, acc, "meta")) as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith(key + "="):
                    return ln[len(key) + 1:].strip()
    except Exception:
        pass
    return ""


def account_of_dev(dev, info):
    """Ten THU MUC account. Voi wireguard, inv[dev]['acc'] == dev (vd 'wg37')
    nhung thu muc lai ten khac (vd 'wg-KR-30') vi wg dang ky theo ten device.
    Phai doi chieu qua truong dev= trong meta."""
    acc = info.get("acc") or ""
    if os.path.isdir(os.path.join(dg.ACCT, acc)):
        return acc
    try:
        for name in sorted(os.listdir(dg.ACCT)):
            if meta_val(name, "dev") == dev:
                return name
    except Exception:
        pass
    return acc


def live_tunnels(use_all_running, do_probe):
    """Tra ve list [(dev, acc, node)] - DEM DONG tu tien trinh that."""
    inv = dg.inventory()
    items = []
    for dev in sorted(inv.keys(),
                      key=lambda d: (not d.startswith("tun"),
                                     int("".join(ch for ch in d if ch.isdigit()) or 0))):
        info = inv[dev]
        acc = account_of_dev(dev, info)
        if not use_all_running and meta_val(acc, "auto") != "1":
            log("[BO QUA] %s (%s) auto=0 -> reboot se mat, khong dua vao chia. "
                "Muon dung thi them --all-running hoac bat autostart" % (dev, acc))
            continue
        if do_probe:
            ok, val = dg.probe(dev)
            if not ok:
                log("[BO QUA] %s (%s) khong ra duoc internet: %s" % (dev, acc, val))
                continue
        items.append((dev, acc, info.get("node") or "?"))
    return items


def interleave_by_node(items):
    """Sap thu tu tunnel sao cho 2 may lien tiep KHONG cung 1 nut Proton.

    Ly do: nhieu tunnel co the cung tro ve 1 nut. Neu chia tuan tu thi mot khoi
    may lien tiep se do het vao cung 1 nut. Xen ke theo nut cho phan bo deu hon
    khi chi mot phan may hoat dong.
    """
    groups = {}
    for it in items:
        groups.setdefault(it[2], []).append(it)
    order = sorted(groups.keys())
    out = []
    i = 0
    while len(out) < len(items):
        moved = False
        for node in order:
            g = groups[node]
            if i < len(g):
                out.append(g[i])
                moved = True
        if not moved:
            break
        i += 1
    return out


def build_plan(rows, tunnels):
    """Chia deu round-robin. N va M deu la so DEM DUOC, khong dong dinh."""
    order = interleave_by_node(tunnels)
    plan = []
    for idx, row in enumerate(rows):
        dev, acc, node = order[idx % len(order)]
        plan.append((row, acc, dev, node))
    return plan


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("plan", "apply"):
        print(__doc__)
        return 2
    mode = sys.argv[1]
    sid = str(sys.argv[2]).strip()
    flags = set(sys.argv[3:])
    use_all_running = "--all-running" in flags
    do_probe = "--probe" in flags

    data = api_get("/api/pm/sessions/" + sid)
    all_rows = data.get("rows") or []
    rows = [r for r in all_rows if r.get("configured") and str(r.get("tag") or "").strip()]
    n = len(rows)
    if not n:
        log("[LOI] session %s khong co may nao duoc cau hinh" % sid)
        return 1

    # Chi chia cho may DANG o che do VPN. May dang dung proxy khong dung tay vao.
    vpn_rows = [r for r in rows if str(r.get("proxyType") or "").lower() == "vpn"
                or str(r.get("proxy") or "").startswith("vpn:")]
    if not vpn_rows:
        log("[LOI] session %s (%s) khong co may nao o che do VPN - "
            "day la cau hinh proxy, khong can chia tunnel"
            % (sid, data.get("name")))
        return 1

    tunnels = live_tunnels(use_all_running, do_probe)
    m = len(tunnels)
    if not m:
        log("[LOI] khong tim thay tunnel nao du dieu kien")
        return 1

    log("[DEM] session %s (%s): %d may cau hinh, %d may che do VPN | %d tunnel dung duoc"
        % (sid, data.get("name"), n, len(vpn_rows), m))

    before = {}
    for r in vpn_rows:
        acc = str(r.get("proxy") or "")[4:].strip()
        before[acc] = before.get(acc, 0) + 1
    log("[TRUOC] phan bo: %s" % json.dumps(before, sort_keys=True))

    plan = build_plan(vpn_rows, tunnels)
    after = {}
    per_node = {}
    for _row, acc, dev, node in plan:
        after[acc] = after.get(acc, 0) + 1
        per_node[node] = per_node.get(node, 0) + 1
    lo = min(after.values())
    hi = max(after.values())
    log("[SAU] %d tunnel, moi tunnel %d-%d may" % (len(after), lo, hi))
    log("[SAU] theo nut: %s" % json.dumps(per_node, sort_keys=True))

    if mode == "plan":
        log("[PLAN] khong ghi gi. 10 dong dau:")
        for row, acc, dev, node in plan[:10]:
            log("   %-10s %-14s -> %-16s %s (%s)"
                % (row.get("tag"), row.get("ip"), acc, dev, node))
        return 0

    if "--yes" not in flags:
        log("[DUNG] thieu --yes. Chay lai voi --yes de ghi that.")
        return 3

    payload_rows = []
    for row, acc, _dev, _node in plan:
        new = dict(row)
        new["proxy"] = "vpn:" + acc
        new["proxyType"] = "vpn"
        payload_rows.append(new)
    # giu nguyen may khong o che do VPN
    vpn_tags = set(str(r.get("tag")) for r in vpn_rows)
    for r in rows:
        if str(r.get("tag")) not in vpn_tags:
            payload_rows.append(dict(r))

    log("[GHI] POST /api/pm/sessions/%s voi %d dong (chi ghi PRESET, "
        "KHONG apply runtime)" % (sid, len(payload_rows)))
    res = api_post("/api/pm/sessions/" + sid,
                   {"rows": payload_rows, "name": data.get("name")})
    log("[GHI] tra ve: %s" % json.dumps(res, ensure_ascii=False)[:200])

    # doi chieu lai
    chk = api_get("/api/pm/sessions/" + sid)
    got = {}
    for r in chk.get("rows") or []:
        if not r.get("configured"):
            continue
        if str(r.get("proxyType") or "").lower() != "vpn":
            continue
        acc = str(r.get("proxy") or "")[4:].strip()
        got[acc] = got.get(acc, 0) + 1
    ok = (got == after)
    log("[KIEM] doc lai: %d tunnel, moi tunnel %d-%d may | KHOP KE HOACH: %s"
        % (len(got), min(got.values()) if got else 0,
           max(got.values()) if got else 0, "CO" if ok else "KHONG"))
    if not ok:
        log("[KIEM] ke hoach=%s" % json.dumps(after, sort_keys=True))
        log("[KIEM] thuc te =%s" % json.dumps(got, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
