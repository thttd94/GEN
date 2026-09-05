#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dataplane_guard.py - watchdog DATA-PLANE cho tung tunnel VPN tren router GEN.

VAN DE GOC (da chung minh bang do dac, 2026-09-05):
  36 tai khoan OpenVPN + 1 WireGuard cua router deu dung CHUNG 1 username Proton.
  Proton gioi han so session CO DATA-PLANE tren MOI NUT cho moi tai khoan (~5).
  Session vuot han muc van giu duoc control channel: thiet bi tun van UP, van co IP,
  renegotiation moi ~55 phut van thanh cong => 'Inactivity timeout' cua openvpn
  KHONG BAO GIO kich hoat, nen openvpn tu no khong bao gio biet minh da chet.
  Ket qua: tunnel im lang chet nhieu ngay ma khong ai phat hien.

CACH CHUA CUA WATCHDOG NAY:
  1. Do THUC TE tung thiet bi: SO_BINDTODEVICE + HTTP GET ra internet.
  2. Neu chet -> SIGUSR1 (openvpn ket noi lai, dang ky lai session) - co gioi han
     so lan/lan chay va thoi gian cho giua 2 lan de khong tao bao reconnect.
  3. Neu mot nut dang chua > MAX_PER_NODE session -> ghi canh bao RECOMMEND de nguoi
     van hanh doi 'remote' sang nut khac (watchdog KHONG tu doi nut).
  4. Doi chieu co 'auto' trong meta voi thuc te dang chay (them 2026-09-05):
     - dang chay ma auto=0  -> reboot se MAT tunnel do
     - khong chay ma auto=1 -> reboot se BAT THEM -> co the vuot han muc/nut
     Ca hai deu ghi [AUTODRIFT]. Watchdog KHONG tu sua co auto (viec nay doi
     chu dinh nguoi van hanh: co the account do dang co tinh de danh).
  5. Moi thu ghi vet vao log + state json.

Dung:
  dataplane_guard.py            do + tu chua (mac dinh)
  dataplane_guard.py check      chi do va bao cao, KHONG sua gi
  dataplane_guard.py status     in trang thai lan chay gan nhat
"""
import os
import sys
import json
import time
import socket
import signal
import subprocess

LOGF = "/data/vpn/logs/dataplane_guard.log"
STATEF = "/data/vpn/logs/dataplane_guard_state.json"
LOCKF = "/tmp/dataplane_guard.lock"
LOG_MAX = 300000
ACCT = "/data/vpn/accounts"
LOGDIR = "/data/vpn/logs"

PROBE_HOST = "api.ipify.org"
PROBE_PORT = 80
PROBE_TIMEOUT = 8
RETRY = 2                 # so lan do lai truoc khi ket luan chet
MAX_HEAL_PER_RUN = 4      # toi da bao nhieu tunnel duoc SIGUSR1 moi lan chay
HEAL_COOLDOWN = 900       # giay: khong SIGUSR1 cung 1 account trong khoang nay
MAX_PER_NODE = 4          # nguong an toan da do duoc


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "%s %s\n" % (ts, msg)
    try:
        if os.path.exists(LOGF) and os.path.getsize(LOGF) > LOG_MAX:
            with open(LOGF, "rb") as f:
                data = f.read()[-LOG_MAX // 2:]
            with open(LOGF, "wb") as f:
                f.write(b"...(cat bot)...\n" + data)
        with open(LOGF, "a") as f:
            f.write(line)
    except Exception:
        pass


def sh(cmd, timeout=25):
    try:
        pr = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        out = pr.communicate(timeout=timeout)[0]
        return out.decode("utf-8", "replace").strip()
    except Exception:
        try:
            pr.kill()
        except Exception:
            pass
        return ""


def load_state():
    try:
        with open(STATEF) as f:
            return json.load(f)
    except Exception:
        return {"last_heal": {}, "runs": 0, "healed_total": 0}


def save_state(st):
    try:
        tmp = STATEF + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, STATEF)
    except Exception:
        pass


def inventory():
    """Tra ve dict dev -> {pid, acc, node, kind}. Lay tu /proc/<pid>/cmdline, khong
    dung pid file (pid file tung sai)."""
    inv = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                parts = f.read().split(b"\0")
        except Exception:
            continue
        if not parts or b"openvpn" not in parts[0]:
            continue
        acc = None
        for x in parts:
            s = x.decode("utf-8", "replace")
            if s.startswith(LOGDIR + "/") and s.endswith(".log"):
                acc = os.path.basename(s)[:-4]
                break
        if not acc:
            continue
        dev = sh("grep -o 'TUN/TAP device tun[0-9]* opened' %s/%s.log 2>/dev/null | "
                 "tail -1 | sed 's|TUN/TAP device ||; s| opened||'" % (LOGDIR, acc))
        if not dev:
            continue
        node = sh("grep -m1 '^remote ' %s/%s/config.ovpn 2>/dev/null | awk '{print $2}'"
                  % (ACCT, acc))
        inv[dev] = {"pid": int(pid), "acc": acc, "node": node or "?", "kind": "openvpn"}
    # wireguard
    for dev in os.listdir("/sys/class/net"):
        if not dev.startswith("wg"):
            continue
        ep = sh("wg show %s 2>/dev/null | grep -m1 endpoint | "
                "sed -E 's/.*: ([0-9.]+):.*/\\1/'" % dev)
        inv[dev] = {"pid": 0, "acc": dev, "node": ep or "?", "kind": "wireguard"}
    return inv


def probe(dev):
    """True neu thiet bi thuc su ra duoc internet. Tra ve (ok, exit_ip_hoac_loi)."""
    for _ in range(RETRY):
        s = None
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, 25, dev.encode())
            s.settimeout(PROBE_TIMEOUT)
            s.connect((PROBE_HOST, PROBE_PORT))
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + PROBE_HOST.encode() +
                      b"\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            body = data.decode("utf-8", "replace")
            ip = body.strip().split("\n")[-1].strip()
            if ip.count(".") == 3:
                return True, ip
            return True, "?"
        except Exception as e:
            err = type(e).__name__
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass
        time.sleep(1)
    return False, err


def auto_flag_drift(inv):
    """Doi chieu co 'auto' trong meta voi tap tunnel dang chay THAT.

    Vi sao can: 05/09/2026 do duoc 3 account dang chay nhung auto=0 (reboot mat
    tunnel) va 4 account khong chay nhung auto=1, trong do 3 cai cung tro ve nut
    45.14.71.6 - nut nay dang co 4 session, neu 'startall' bat them 3 nua thanh 7
    thi Proton cat data-plane => tai lap dung loi 13 tun chet. Cac chi so cu cua
    watchdog KHONG the thay truoc viec nay vi chung chi do trang thai HIEN TAI.

    Tra ve (missing_after_reboot, extra_after_reboot, node_forecast).
    """
    # inv duoc khoa theo DEV. Voi openvpn thi inv[dev]['acc'] la ten account, nhung
    # voi wireguard thi acc == dev (vd 'wg37') trong khi thu muc account ten khac
    # (vd 'wg-KR-30'). Vi vay phai doi chieu BANG CA hai: ten account VA ten dev.
    running_accs = set(i["acc"] for i in inv.values())
    running_devs = set(inv.keys())
    missing = []      # dang chay nhung auto=0
    extra = []        # khong chay nhung auto=1
    forecast = {}     # nut -> so session neu reboot (chi tinh auto=1)
    try:
        names = sorted(os.listdir(ACCT))
    except Exception:
        return missing, extra, forecast
    for name in names:
        meta = os.path.join(ACCT, name, "meta")
        auto = ""
        node = "?"
        dev = ""
        try:
            with open(meta) as f:
                for ln in f:
                    ln = ln.strip()
                    if ln.startswith("auto="):
                        auto = ln[5:].strip()
                    elif ln.startswith("endpoint="):
                        node = ln[9:].strip().split(":")[0]
                    elif ln.startswith("dev="):
                        dev = ln[4:].strip()
        except Exception:
            continue
        cfg = os.path.join(ACCT, name, "config.ovpn")
        if os.path.exists(cfg):
            got = sh("grep -m1 '^remote ' %s 2>/dev/null | awk '{print $2}'" % cfg)
            if got:
                node = got
        is_running = (name in running_accs) or (dev and dev in running_devs)
        if is_running and auto != "1":
            missing.append((name, node))
        if (not is_running) and auto == "1":
            extra.append((name, node))
        if auto == "1":
            forecast[node] = forecast.get(node, 0) + 1
    return missing, extra, forecast


def acquire_lock():
    """Khong cho 2 ban chay chong nhau (1 lan quet co the mat vai phut)."""
    try:
        if os.path.exists(LOCKF):
            with open(LOCKF) as f:
                old = f.read().strip()
            if old.isdigit() and os.path.isdir("/proc/%s" % old):
                return False
        with open(LOCKF, "w") as f:
            f.write(str(os.getpid()))
        return True
    except Exception:
        return True


def release_lock():
    try:
        os.unlink(LOCKF)
    except Exception:
        pass


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "fix"
    st = load_state()

    if mode == "status":
        print("runs=%s healed_total=%s" % (st.get("runs"), st.get("healed_total")))
        print(sh("tail -25 %s" % LOGF))
        return 0

    if not acquire_lock():
        return 0

    inv = inventory()
    if not inv:
        log("[ERR] khong tim thay tunnel nao - bo qua")
        return 1

    devs = sorted(inv.keys(), key=lambda d: (not d.startswith("tun"),
                                             int("".join(ch for ch in d if ch.isdigit()) or 0)))
    result = {}
    for d in devs:
        result[d] = probe(d)

    dead = [d for d in devs if not result[d][0]]
    alive = [d for d in devs if result[d][0]]

    # phan bo theo nut
    bynode = {}
    for d in devs:
        bynode.setdefault(inv[d]["node"], []).append(d)
    over = {n: ds for n, ds in bynode.items() if len(ds) > MAX_PER_NODE}

    # exit IP trung nhau
    exips = {}
    for d in alive:
        exips.setdefault(result[d][1], []).append(d)
    dup = {ip: ds for ip, ds in exips.items() if len(ds) > 1 and ip != "?"}

    st["runs"] = st.get("runs", 0) + 1
    changed = bool(dead) or bool(over) or bool(dup)

    if changed or st["runs"] % 12 == 1:
        log("[SCAN] song=%d/%d chet=%s" % (len(alive), len(devs), ",".join(dead) or "-"))
    if over:
        for n, ds in sorted(over.items()):
            log("[RECOMMEND] nut %s dang %d session (>%d): %s -> nen doi 'remote' cua "
                "1-2 account sang nut khac" % (n, len(ds), MAX_PER_NODE, " ".join(ds)))
    if dup:
        for ip, ds in sorted(dup.items()):
            log("[WARN] exit IP trung: %s <- %s" % (ip, " ".join(ds)))

    # ---- doi chieu co 'auto' voi thuc te (chong bom hen gio khi reboot) ----
    miss_auto, extra_auto, forecast = auto_flag_drift(inv)
    over_forecast = {n: k for n, k in forecast.items()
                     if k > MAX_PER_NODE and n not in ("?", "")}
    if miss_auto or extra_auto or over_forecast:
        changed = True
    for name, node in miss_auto:
        log("[AUTODRIFT] %s dang chay nhung auto=0 -> reboot SE MAT tunnel nay. "
            "Chua: vpn_mgr.sh autostart %s on" % (name, name))
    for name, node in extra_auto:
        log("[AUTODRIFT] %s KHONG chay nhung auto=1 (nut %s) -> reboot se bat them"
            % (name, node))
    for node, k in sorted(over_forecast.items()):
        log("[AUTODRIFT] NGUY HIEM: neu reboot/startall thi nut %s se co %d session "
            "(> %d) -> Proton se cat data-plane. Chua: tat auto cua account du "
            "tren nut nay hoac doi 'remote' sang nut trong" % (node, k, MAX_PER_NODE))

    if mode == "check":
        print("song=%d/%d" % (len(alive), len(devs)))
        for d in devs:
            print("%-6s %-16s %-16s %s" % (d, inv[d]["acc"][:16], inv[d]["node"],
                                           ("OK|" + result[d][1]) if result[d][0]
                                           else ("X|" + result[d][1])))
        if over:
            print("nut vuot %d suat: %s" % (MAX_PER_NODE,
                                            {n: len(v) for n, v in over.items()}))
        print("auto=1 tong: %d | dang chay: %d" % (sum(forecast.values()), len(devs)))
        if miss_auto:
            print("dang chay ma auto=0: %s" % " ".join(n for n, _ in miss_auto))
        if extra_auto:
            print("khong chay ma auto=1: %s" % " ".join(n for n, _ in extra_auto))
        if over_forecast:
            print("reboot se vuot suat tai nut: %s" % over_forecast)
        save_state(st)
        return 0

    # ------------------------------------------------------------ tu chua
    now = int(time.time())
    healed = 0
    healed_devs = []
    for d in dead:
        if healed >= MAX_HEAL_PER_RUN:
            log("[SKIP] con %d cai chet, de lan chay sau (gioi han %d/lan)"
                % (len(dead) - healed, MAX_HEAL_PER_RUN))
            break
        info = inv[d]
        acc = info["acc"]
        last = st.get("last_heal", {}).get(acc, 0)
        if now - last < HEAL_COOLDOWN:
            log("[WAIT] %s (%s) chet nhung moi chua %ds truoc - cho het %ds"
                % (d, acc, now - last, HEAL_COOLDOWN))
            continue
        if info["kind"] != "openvpn":
            log("[MANUAL] %s (%s, nut %s) chet - WireGuard khong doi duoc nut, "
                "phai giam so session tren nut do" % (d, acc, info["node"]))
            continue
        try:
            os.kill(info["pid"], signal.SIGUSR1)
        except Exception as e:
            log("[ERR] SIGUSR1 %s pid %s: %s" % (d, info["pid"], e))
            continue
        st.setdefault("last_heal", {})[acc] = now
        st["healed_total"] = st.get("healed_total", 0) + 1
        healed += 1
        healed_devs.append(d)
        log("[HEAL] SIGUSR1 %s (%s pid %s, nut %s) vi khong ra duoc internet: %s"
            % (d, acc, info["pid"], info["node"], result[d][1]))
        time.sleep(20)

    if healed_devs:
        time.sleep(10)
        again = []
        for d in healed_devs:
            ok, val = probe(d)
            again.append("%s=%s" % (d, "OK" if ok else "X"))
        log("[VERIFY] sau khi chua: %s" % " ".join(again))

    save_state(st)
    return 0


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        release_lock()
    sys.exit(rc)
