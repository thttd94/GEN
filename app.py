from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, unquote, parse_qs
import http.client
import mimetypes
import json
import shutil
import subprocess
import time
import urllib.request
import urllib.error
import socket
import struct
import plistlib
import re
import threading
import base64
import hashlib
from datetime import datetime, timedelta
import os
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'
NOTES_FILE = BASE_DIR / 'notes.json'
SESSION_STATE_FILE = BASE_DIR / 'session_state.json'
ACTIVE_SESSION_FILE = BASE_DIR / 'active_session.json'
ROUTER_CONFIG_DIR = Path('/etc/genrouter/config')
ROUTER_RUNTIME_DIR = Path('/etc/genrouter')
ROUTER_GENRUNNER = Path('/etc/genrouter/core/genrunner')
DEV_CONFIG_DIR = Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/genrouter/config')
DEV_RUNTIME_DIR = Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/genrouter')
DEV_GENRUNNER = Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/genrouter/core/genrunner')
STATIC_HOSTS_FILE = Path('/etc/shm/list_ip_static.json') if Path('/etc/shm/list_ip_static.json').exists() else Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/shm/list_ip_static.json')
LEASES_FILE = Path('/tmp/dhcp.leases')
OLD_GUI_BASE = 'http://127.0.0.1:9000'
STATIC_API_BASE = 'http://192.15.0.1:8000'
if ROUTER_CONFIG_DIR.exists():
    CONFIG_DIR = ROUTER_CONFIG_DIR
    RUNTIME_DIR = ROUTER_RUNTIME_DIR
    GENRUNNER = ROUTER_GENRUNNER
else:
    CONFIG_DIR = DEV_CONFIG_DIR
    RUNTIME_DIR = DEV_RUNTIME_DIR
    GENRUNNER = DEV_GENRUNNER
PRESET_DIR = BASE_DIR / 'presets'
ADMANAGER_CONFIG_FILE = BASE_DIR / 'admanager_gui_config.json'
ADMANAGER_LOCAL_FILE = BASE_DIR / 'admanager_gui.local.json'
ADMANAGER_GUI_CONFIG_FILE = Path('/mnt/e/OpenClaw/LocalSend_jobs/GUI/admanager_gui_config.json')
ADMANAGER_GUI_LOCAL_FILE = Path('/mnt/e/OpenClaw/LocalSend_jobs/GUI/admanager_gui.local.json')
COLLECTOR_CONFIG_FILE = BASE_DIR / 'collector_config.json'
VERSION_FILE = BASE_DIR / 'VERSION.txt'
UPDATE_CODES_FILE = BASE_DIR / 'update_codes.json'
BUNDLED_UPDATE_CODES_FILE = Path(__file__).resolve().parent / 'update_codes.json'
DEFAULT_COLLECTOR_URL = 'http://aeg.ooguy.com:9010'
MAX_SESSION_COUNT = 5
SESSION_FILES = {str(i): PRESET_DIR / f'session{i}.json' for i in range(1, MAX_SESSION_COUNT + 1)}
RUNTIME_FILE = RUNTIME_DIR / 'gencore.json'
RUNTIME_SOURCE_FILE = CONFIG_DIR / 'gencore.json'
MAX_PROXY_TAG = 1000
TAGS_PER_SUBNET = 250
BASE_SUBNET_OCTET = 4
# DNS resolver dung cho tung proxy outbound (detour qua chinh proxy do).
# BAT BUOC dung DoH tren port 443: nhieu nha cung cap proxy (lumi, ...) CHAN
# port 53/853/5353 va tra ve SOCKS5 reply code=2 (connection not allowed by
# ruleset) => toan bo DNS query cua client fail => web khong load duoc.
# Dung dia chi IP (khong dung hostname) de tranh chicken-and-egg: gencore
# khong the resolve hostname cua resolver truoc khi co resolver.
PROXY_DNS_ADDRESS = 'https://8.8.8.8/dns-query'
PROXY_DNS_LEGACY_ADDRESSES = ('tcp://8.8.8.8', 'tcp://1.1.1.1', '8.8.8.8:53', '1.1.1.1:53')
REPO_REMOTE_URL = 'https://github.com/thttd94/GEN.git'
REPO_BRANCH = 'main'
DEFAULT_ADMIN_UPDATE_CODE = 'ADMIN2026GEN'
DEFAULT_PER_VERSION_CODE_COUNT = 5
PPPOE_ACCOUNTS_FILE = Path('/data/pppoe/accounts.json')

def pppoe_accounts_load():
    try:
        if not PPPOE_ACCOUNTS_FILE.exists(): return []
        d=json.loads(PPPOE_ACCOUNTS_FILE.read_text(encoding='utf-8'))
        return d if isinstance(d,list) else []
    except Exception: return []

def pppoe_accounts_save(items):
    PPPOE_ACCOUNTS_FILE.parent.mkdir(parents=True,exist_ok=True)
    PPPOE_ACCOUNTS_FILE.write_text(json.dumps(items,ensure_ascii=False,indent=1),encoding='utf-8')

PPPOE_IP_LOG = Path('/data/pppoe/ip_log.json')

# [Ver 2.69] Xoay IP chay nen. Do thuc te 2026-10-21: sau khi ngat, BRAS nha mang
# khong tra PADO ~5-5.5 phut (doi MAC hay khong deu nhu nhau), nen request dong bo
# 135s cu luon tra up=false du IP that su da doi. Gio: rotate tra ngay, GUI poll.
ROTATE_WAIT_MAX_S = 480
_ROTATE_JOBS = {}
_ROTATE_LOCK = threading.Lock()
_IP_LOG_LOCK = threading.Lock()

def _iface_ip(iface):
    try:
        st = json.loads(subprocess.check_output(['ifstatus', iface], text=True, timeout=5))
        ips = st.get('ipv4-address') or []
        return ips[0].get('address', '') if ips else ''
    except Exception:
        return ''

def _rotate_job_set(sid, **kw):
    with _ROTATE_LOCK:
        j = _ROTATE_JOBS.setdefault(sid, {})
        j.update(kw)
        j['updated'] = time.time()

def _rotate_worker(sid, rd, call_rotate):
    iface = 'if_%03d' % sid
    t0 = time.time()
    try:
        # 1) doi MAC macvlan qua server goc (giu nhu cu)
        try:
            res = call_rotate(rd)
            _rotate_job_set(sid, rotate=dict(res or {}) if isinstance(res, dict) else {'raw': str(res)[:160]})
        except Exception as e:
            _rotate_job_set(sid, rotate_err=str(e)[:160])
        # 2) quay lai dung phien nay (khong dung session khac)
        subprocess.run(['ifdown', iface], timeout=20, capture_output=True)
        time.sleep(1)
        subprocess.run(['ifup', iface], timeout=20, capture_output=True)
        _rotate_job_set(sid, state='waiting')
        ip = ''
        while time.time() - t0 < ROTATE_WAIT_MAX_S:
            time.sleep(5)
            ip = _iface_ip(iface)
            if ip:
                break
            _rotate_job_set(sid, elapsed=int(time.time() - t0))
        if not ip:
            _rotate_job_set(sid, state='failed', elapsed=int(time.time() - t0),
                            error='qua %ds chua co IP (BRAS chua tra PADO)' % ROTATE_WAIT_MAX_S)
            return
        # 3) ghi moc thoi gian doi IP
        try:
            with _IP_LOG_LOCK:
                PPPOE_IP_LOG.parent.mkdir(parents=True, exist_ok=True)
                d = {}
                if PPPOE_IP_LOG.exists():
                    d = json.loads(PPPOE_IP_LOG.read_text(encoding='utf-8')) or {}
                d[str(sid)] = {'ip': ip, 'ts': time.time()}
                PPPOE_IP_LOG.write_text(json.dumps(d, ensure_ascii=False), encoding='utf-8')
        except Exception:
            pass
        # 4) [Ver 2.82] Khoi dong lai glider cua phien NGAY khi co IP moi.
        # Do that Gen15 2026-10-24: glider 0.16.4 giu cong pppoe cu (ifindex cu),
        # sau ifdown/ifup forward EOF -> may mat mang toi khi watchdog 3 phut
        # quet toi (71-160s) hoac bam Apply. Kill glider cung cat ket noi cu cua
        # client nen client tu ket noi lai qua IP moi.
        try:
            if time.time() - _GLIDER_RECENT.get(int(sid), 0) > 20:
                gr = pppoe_glider_restart(sid)
                gr['reason'] = 'xoay IP'
                _pppoe_wd_log('GLIDER-ROTATE phien %d: %s' % (sid, gr))
                _rotate_job_set(sid, glider_restart=bool(gr.get('ok')))
        except Exception as ge:
            _rotate_job_set(sid, glider_err=str(ge)[:120])
        with _ROTATE_LOCK:
            old = (_ROTATE_JOBS.get(sid) or {}).get('old_ip', '')
        _rotate_job_set(sid, state='done', wan_ip=ip, changed=bool(old and ip != old),
                        elapsed=int(time.time() - t0))
    except Exception as e:
        _rotate_job_set(sid, state='failed', error=str(e)[:160], elapsed=int(time.time() - t0))

def rotate_start(sid, rd, call_rotate):
    """Bat dau xoay nen. Dang xoay roi thi khong chay chong."""
    with _ROTATE_LOCK:
        j = _ROTATE_JOBS.get(sid)
        if j and j.get('state') in ('starting', 'waiting'):
            return dict(j, ok=True, rotate_id=sid, already=True)
    _rotate_job_set(sid, state='starting', started=time.time(), elapsed=0,
                    old_ip=_iface_ip('if_%03d' % sid), wan_ip='', error='', changed=False)
    threading.Thread(target=_rotate_worker, args=(sid, rd, call_rotate), daemon=True,
                     name='rotate-%d' % sid).start()
    with _ROTATE_LOCK:
        return dict(_ROTATE_JOBS[sid], ok=True, rotate_id=sid, accepted=True)

def rotate_status(ids=None):
    with _ROTATE_LOCK:
        if ids:
            return {str(i): dict(_ROTATE_JOBS[i]) for i in ids if i in _ROTATE_JOBS}
        return {str(k): dict(v) for k, v in _ROTATE_JOBS.items()}

_SYSINFO_PREV = {'total': 0, 'idle': 0, 'ts': 0.0}

def sysinfo_json():
    # Thong so may thoi gian thuc: nhiet do CPU, %CPU, RAM, disk, uptime, load.
    # Doc truc tiep /proc + /sys (khong phu thuoc lenh ngoai, chay duoc BusyBox).
    out = {'ok': True, 'ts': int(time.time())}
    # 1) Nhiet do: lay max cac thermal_zone (mC -> C).
    try:
        temps = []
        for z in sorted(Path('/sys/class/thermal').glob('thermal_zone*')):
            try:
                v = int((z / 'temp').read_text().strip())
                if 0 < v < 1000000:
                    temps.append(v / 1000.0)
            except Exception:
                continue
        out['temp_c'] = round(max(temps), 1) if temps else None
    except Exception:
        out['temp_c'] = None
    # 2) %CPU: delta /proc/stat tu lan goi truoc (lan dau tra None).
    try:
        p = Path('/proc/stat').read_text().split()
        vals = [int(x) for x in p[1:9] if str(x).lstrip('-').isdigit()]
        total = sum(vals)
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        prev = _SYSINFO_PREV
        if prev['ts'] and total > prev['total']:
            dt = total - prev['total']
            di = idle - prev['idle']
            out['cpu_pct'] = round(max(0.0, min(100.0, (1 - di / dt) * 100))) if dt > 0 else 0.0
        else:
            out['cpu_pct'] = None
        _SYSINFO_PREV.update({'total': total, 'idle': idle, 'ts': time.time()})
        try:
            out['cpu_count'] = int(subprocess.check_output(
                "grep -c '^processor' /proc/cpuinfo", shell=True, text=True, timeout=3).strip() or 1)
        except Exception:
            out['cpu_count'] = 1
    except Exception:
        out['cpu_pct'] = None
        out['cpu_count'] = 1
    # 3) RAM.
    try:
        mem = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            k, _, v = line.partition(':')
            try:
                mem[k.strip()] = int(v.strip().split()[0])
            except Exception:
                pass
        total_m = mem.get('MemTotal', 0)
        avail_m = mem.get('MemAvailable', mem.get('MemFree', 0))
        used_m = max(0, total_m - avail_m)
        out['mem'] = {'total_mb': round(total_m / 1024), 'used_mb': round(used_m / 1024),
                      'pct': round(used_m * 100.0 / total_m, 1) if total_m else 0}
    except Exception:
        out['mem'] = {}
    # 4) Disk goc + /data.
    try:
        disks = []
        for mp in ('/', '/data'):
            try:
                st = os.statvfs(mp)
                t = st.f_blocks * st.f_frsize
                f = st.f_bavail * st.f_frsize
                u = t - f
                disks.append({'mount': mp, 'total_gb': round(t / 1073741824, 1),
                               'used_gb': round(u / 1073741824, 1),
                              'pct': round(u * 100.0 / t, 1) if t else 0})
            except Exception:
                continue
        out['disks'] = disks
    except Exception:
        out['disks'] = []
    # 5) Uptime + load.
    try:
        out['uptime_s'] = int(float(Path('/proc/uptime').read_text().split()[0]))
    except Exception:
        out['uptime_s'] = 0
    try:
        out['load'] = [float(x) for x in Path('/proc/loadavg').read_text().split()[:3]]
    except Exception:
        out['load'] = []
    return out
def _http_error_text(e):
    """[Ver 2.83] 'HTTP 400: <ly do cua server goc>' thay vi chi 'HTTP 400'."""
    msg = ''
    try:
        body = e.read().decode('utf-8', 'replace')
        try:
            j = json.loads(body)
            msg = str(j.get('error') or j.get('message') or '') if isinstance(j, dict) else ''
        except Exception:
            msg = body.strip()
    except Exception:
        pass
    msg = msg[:200]
    if 'enable pppoe mode' in msg:
        msg += ' (router chua bat che do PPPoE o GUI goc 9000)'
    return ('HTTP %s: %s' % (e.code, msg)) if msg else ('HTTP %s' % e.code)

def _vendor_result(r):
    """[Ver 2.83] 9000 tra 200 + {success:false,message} khi loi nghiep vu => bao ok=false."""
    out = dict(r or {}) if isinstance(r, dict) else {'ok': True, 'data': r}
    d = out.get('data')
    if isinstance(d, dict) and d.get('success') is False:
        out['ok'] = False
        out['error'] = str(d.get('message') or d.get('error') or 'server goc tu choi')[:200]
    return out

def _is_private_ipv4(ip):
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a in ipaddress.ip_network('100.64.0.0/10')
    except Exception:
        return False

def pppoe_runtime_enrich(raw):
    try:
        data=raw.get('data') if isinstance(raw,dict) else raw
        sessions=data.get('data') if isinstance(data,dict) else data
        if not isinstance(sessions,list): return raw
        dump=json.loads(subprocess.check_output(['ubus','call','network.interface','dump'],text=True,timeout=5))
        rt={str(x.get('interface')):x for x in dump.get('interface',[]) if str(x.get('interface','')).startswith('if_')}
        # Doc log IP cu: ghi lai moc thoi gian moi lan doi IP thanh cong.
        iplog={}
        try:
            if PPPOE_IP_LOG.exists():
                iplog=json.loads(PPPOE_IP_LOG.read_text(encoding='utf-8')) or {}
        except Exception: pass
        dirty=False
        now=time.time()
        for x in sessions:
            try:
                sid=int(x.get('id',x.get('wan_id',0)))
                st=rt.get('if_%03d'%sid)
                if not st: continue
                x['up']=bool(st.get('up')); x['online']=bool(st.get('up'))
                x['status']='online' if st.get('up') else 'offline'
                ips=st.get('ipv4-address') or []
                key=str(sid)
                if ips:
                    cur_ip=ips[0].get('address','')
                    x['ip']=cur_ip
                    old=iplog.get(key) or {}
                    if old.get('ip') != cur_ip:
                        # IP doi (quay so/xoay IP thanh cong) -> ghi moc thoi gian moi.
                        iplog[key]={'ip':cur_ip,'ts':now}
                        dirty=True
                    x['last_changed']=time.strftime('%d/%m %H:%M:%S',time.localtime((iplog.get(key) or {}).get('ts',now)))
                    # [Ver 2.83] Proxy dung tu ngoai Internet: IP WAN cua phien + port glider.
                    x['wan_socks']='%s:%d'%(cur_ip,15000+sid-1)
                    x['wan_http']='%s:%d'%(cur_ip,30000+sid-1)
                    x['wan_private']=_is_private_ipv4(cur_ip)
                    x['ip_ts']=(iplog.get(key) or {}).get('ts',0)
                else:
                    x['last_changed']='—'
            except Exception: pass
        if dirty:
            try:
                PPPOE_IP_LOG.parent.mkdir(parents=True,exist_ok=True)
                PPPOE_IP_LOG.write_text(json.dumps(iplog,ensure_ascii=False),encoding='utf-8')
            except Exception: pass
        return raw
    except Exception: return raw


def random_update_code(length=12):
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join((__import__('secrets').choice(alphabet) for _ in range(length)))

def load_update_codes_store():
    candidates = [UPDATE_CODES_FILE]
    if BUNDLED_UPDATE_CODES_FILE != UPDATE_CODES_FILE:
        candidates.append(BUNDLED_UPDATE_CODES_FILE)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}

def save_update_codes_store(data):
    UPDATE_CODES_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

def normalize_version_key(label: str):
    text = str(label or '').strip()
    m = re.search('(Ver\\s*[\\d.]+)', text, re.IGNORECASE)
    return m.group(1).replace('ver', 'Ver') if m else text

def ensure_update_codes_for_version(version_label: str, count=DEFAULT_PER_VERSION_CODE_COUNT):
    version_key = normalize_version_key(version_label)
    store = load_update_codes_store()
    admin_code = str(store.get('admin_code') or DEFAULT_ADMIN_UPDATE_CODE).strip() or DEFAULT_ADMIN_UPDATE_CODE
    store['admin_code'] = admin_code
    versions = store.setdefault('versions', {}) if isinstance(store, dict) else {}
    entry = versions.setdefault(version_key, {'codes': []})
    codes = entry.setdefault('codes', []) if isinstance(entry, dict) else []
    existing = {str(item.get('code') or '').strip() for item in codes if isinstance(item, dict)}
    while len(codes) < int(count):
        code = random_update_code(12)
        if code in existing or code == admin_code:
            continue
        existing.add(code)
        codes.append({'code': code, 'used': False, 'used_at': '', 'used_version': '', 'used_target': ''})
    versions[version_key] = entry
    store['versions'] = versions
    save_update_codes_store(store)
    return {'version': version_key, 'admin_code': admin_code, 'codes': [item.get('code') for item in codes]}

def consume_update_key_via_gas(key):
    """Xac thuc + tieu thu update key GENUP-... qua Google Sheet (Key Router)."""
    code = str(key or '').strip().upper()
    if not code.startswith('GENUP-'):
        raise PermissionError('Key khong hop le')
    try:
        sep = '&' if '?' in ACTIVE_URL else '?'
        qs = urlencode({'action': 'use_update_key', 'machine_id': get_machine_id(), 'key': code, 't': int(time.time())})
        req = urllib.request.Request(ACTIVE_URL + sep + qs, headers={'User-Agent': 'genrouter-license'})
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode('utf-8', 'replace'))
    except PermissionError:
        raise
    except Exception as exc:
        raise PermissionError('Khong kiem tra duoc key: %s' % exc)
    if isinstance(data, dict) and data.get('ok'):
        return data
    msg = str(data.get('error')) if isinstance(data, dict) and data.get('error') else 'Key khong hop le hoac da dung'
    raise PermissionError(msg)

def consume_update_code(update_code: str, target_version: str):
    code = str(update_code or '').strip()
    if not code:
        raise PermissionError('Mã không hợp lệ')
    if code.upper().startswith('GENUP-'):
        info = consume_update_key_via_gas(code)
        return {'admin': False, 'sheet_key': True, 'version': normalize_version_key(target_version), 'code': code, 'info': info}
    store = load_update_codes_store()
    admin_code = str(store.get('admin_code') or DEFAULT_ADMIN_UPDATE_CODE).strip() or DEFAULT_ADMIN_UPDATE_CODE
    version_key = normalize_version_key(target_version)
    if code == admin_code:
        return {'admin': True, 'version': version_key, 'code': code}
    versions = store.setdefault('versions', {}) if isinstance(store, dict) else {}
    entry = versions.get(version_key) or {}
    codes = entry.get('codes') if isinstance(entry, dict) else []
    for item in codes or []:
        if str(item.get('code') or '').strip() != code:
            continue
        if item.get('used'):
            raise PermissionError('Mã không hợp lệ')
        item['used'] = True
        item['used_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
        item['used_version'] = version_key
        item['used_target'] = str(BASE_DIR)
        versions[version_key] = entry
        store['versions'] = versions
        save_update_codes_store(store)
        return {'admin': False, 'version': version_key, 'code': code}
    raise PermissionError('Mã không hợp lệ')

def run_git_command(args, cwd=None, timeout=60):
    try:
        proc = subprocess.run(['git', *args], cwd=str(cwd or BASE_DIR), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    except FileNotFoundError as e:
        raise RuntimeError('git not available') from e
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or 'git failed').strip())
    return (proc.stdout or '').strip()

def read_current_version_label():
    try:
        text = VERSION_FILE.read_text(encoding='utf-8', errors='replace').strip()
        if text:
            first = text.splitlines()[0].strip()
            if first:
                return first
    except Exception:
        pass
    try:
        msg = run_git_command(['log', '-1', '--pretty=%s'])
        m = re.search('(Ver\\s*[\\d.]+)', msg, re.IGNORECASE)
        if m:
            return m.group(1).replace('ver', 'Ver')
        short = run_git_command(['rev-parse', '--short', 'HEAD'])
        return short
    except Exception:
        return 'Bản đang chạy'
_VERSION_CACHE_FILE = BASE_DIR / '.version_cache.json'
_VERSION_CACHE_TTL = 600

def _fetch_remote_commit_info():
    """Tra (sha, subject) cua commit moi nhat tren GitHub.
    Uu tien REST API; neu 403 rate-limit thi fallback sang feed commits/main.atom (khong tinh quota API)."""
    try:
        req = urllib.request.Request('https://api.github.com/repos/thttd94/GEN/commits/main', headers={'User-Agent': 'proxy-manager-version-check'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode('utf-8', 'replace'))
        sha = str(payload.get('sha') or '').strip()
        subject = str((((payload.get('commit') or {}).get('message') or '').splitlines() or [''])[0]).strip()
        if sha:
            return (sha, subject)
        raise RuntimeError('empty api payload')
    except Exception:
        req = urllib.request.Request('https://github.com/thttd94/GEN/commits/main.atom', headers={'User-Agent': 'proxy-manager-version-check'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode('utf-8', 'replace')
        if '<entry>' not in text:
            raise RuntimeError('khong doc duoc feed commits')
        entry = text.split('<entry>', 1)[1]
        m_sha = re.search('href="[^"]*/commit/([0-9a-fA-F]{40})"', entry)
        if not m_sha:
            raise RuntimeError('khong tim thay sha trong feed')
        sha = m_sha.group(1)
        subject = ''
        m_cont = re.search('<content[^>]*>(.*?)</content>', entry, re.DOTALL)
        raw = m_cont.group(1) if m_cont else ''
        raw = raw.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'").replace('&amp;', '&')
        m_pre = re.search('<pre[^>]*>(.*?)</pre>', raw, re.DOTALL)
        msg = re.sub('<[^>]+>', '', m_pre.group(1) if m_pre else raw).strip()
        if msg:
            subject = msg.splitlines()[0].strip()
        if not subject:
            m_tit = re.search('<title[^>]*>(.*?)</title>', entry, re.DOTALL)
            if m_tit:
                subject = re.sub('\\s+', ' ', re.sub('<[^>]+>', '', m_tit.group(1))).strip()
        return (sha, subject.strip())

def _cached_remote_commit():
    """Cache ket qua check remote de nhieu GUI refresh khong dot API. Tra (sha, subject, from_cache)."""
    now = time.time()
    cache = {}
    try:
        cache = json.loads(_VERSION_CACHE_FILE.read_text('utf-8'))
    except Exception:
        cache = {}
    try:
        ts = float(cache.get('ts') or 0)
    except Exception:
        ts = 0.0
    c_sha = str(cache.get('sha') or '')
    c_subject = str(cache.get('subject') or '')
    if c_sha and now - ts < _VERSION_CACHE_TTL:
        return (c_sha, c_subject, True)
    try:
        sha, subject = _fetch_remote_commit_info()
    except Exception:
        if c_sha:
            return (c_sha, c_subject, True)
        raise
    try:
        _VERSION_CACHE_FILE.write_text(json.dumps({'ts': now, 'sha': sha, 'subject': subject}), 'utf-8')
    except Exception:
        pass
    return (sha, subject, False)

def get_repo_version_info():
    current_label = read_current_version_label()
    try:
        current_commit = run_git_command(['rev-parse', 'HEAD'])
        current_short = run_git_command(['rev-parse', '--short', 'HEAD'])
        current_subject = run_git_command(['log', '-1', '--pretty=%s'])
        remote_url = run_git_command(['remote', 'get-url', 'origin'])
        branch = run_git_command(['branch', '--show-current']) or REPO_BRANCH
    except Exception as e:
        current_commit = ''
        current_short = ''
        current_subject = current_label
        remote_url = REPO_REMOTE_URL
        branch = REPO_BRANCH
        remote_error = str(e)
    else:
        remote_error = ''
    latest_commit = current_commit
    latest_short = current_short
    latest_subject = current_subject or current_label
    latest_label = current_label
    has_update = False
    try:
        remote_commit, remote_subject, _from_cache = _cached_remote_commit()
        if remote_commit:
            latest_commit = remote_commit
            latest_short = remote_commit[:7]
            latest_subject = remote_subject or 'Có bản mới trên Git'
            latest_label = f'{latest_subject} ({latest_short})'.strip()
            if current_commit:
                has_update = remote_commit != current_commit
            elif latest_short and latest_short not in current_label:
                has_update = True
    except Exception as e:
        if not remote_error:
            remote_error = str(e)
        latest_label = current_label
    return {'ok': True, 'current_commit': current_commit, 'current_short': current_short, 'current_subject': current_subject, 'current_label': current_label, 'latest_commit': latest_commit, 'latest_short': latest_short, 'latest_subject': latest_subject, 'latest_label': latest_label, 'has_update': has_update, 'branch': branch, 'remote_url': remote_url, 'remote_error': remote_error, 'update_codes': ensure_update_codes_for_version(latest_subject or latest_label or current_label)}

def _pin_recovery_277(before_label):
    """[Ver 2.78] Ban phuc hoi CHINH = Ver 2.77: luu VINH VIEN 1 lan truoc khi bi ghi de.
    Ten khac gen_app_pre_* nen khong bi vong xoa ban cu dung toi.
    Phuc hoi: tar -xzf <file> -C /opt/proxy-manager-v1 && /etc/init.d/proxy-manager-v1 restart"""
    if not re.match(r'^\s*(Ver\s*)?2\.77\b', str(before_label or ''), re.IGNORECASE):
        return ''
    import tarfile
    base = Path('/data/genrouter_backups') if Path('/data').is_dir() else Path('/root/genrouter_backups')
    pin_dir = base / 'pinned'
    pin = pin_dir / 'gen_app_v2.77_recovery.tgz'
    try:
        if pin.exists() and pin.stat().st_size > 0:
            return str(pin)
        pin_dir.mkdir(parents=True, exist_ok=True)
        tmp = pin.with_name(pin.name + '.tmp')
        with tarfile.open(tmp, 'w:gz') as tf:
            for name in ('app.py', 'VERSION.txt', 'static', 'tools', 'etc', 'rollback_version.sh', 'gen_update.sh', 'install.sh', 'setup_data_disk.sh'):
                p = BASE_DIR / name
                if p.exists():
                    tf.add(str(p), arcname=name)
        os.replace(tmp, pin)
        os.chmod(pin, 0o444)
        return str(pin)
    except Exception:
        return ''

def update_repo_from_remote(password: str):
    before_label = ''
    try:
        before_label = read_current_version_label()
    except Exception:
        before_label = ''
    target_info = get_repo_version_info()
    target_version = normalize_version_key(target_info.get('latest_subject') or target_info.get('latest_label') or target_info.get('current_label') or before_label or 'Ver')
    consume_update_code(password, target_version)
    archive_url = 'https://codeload.github.com/thttd94/GEN/tar.gz/refs/heads/main'
    tmp_root = BASE_DIR.parent / 'update_tmp'
    extract_dir = tmp_root / 'GEN-main'
    archive_path = tmp_root / 'GEN-main.tar.gz'
    latest_label = ''
    latest_short = ''
    try:
        try:
            remote_commit, remote_subject = _fetch_remote_commit_info()
            latest_short = remote_commit[:7] if remote_commit else ''
            m = re.search('(Ver\\s*[\\d.]+)', remote_subject, re.IGNORECASE)
            latest_label = m.group(1).replace('ver', 'Ver') if m else remote_subject or ''
        except Exception:
            latest_label = ''
            latest_short = ''
        if tmp_root.exists():
            shutil.rmtree(tmp_root, ignore_errors=True)
        tmp_root.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(archive_url, headers={'User-Agent': 'proxy-manager-updater'})
        # [Ver 2.83] DNS router tat vai giay moi lan gencore restart (port 53 do gencore
        # giu) => '[Errno -3] Try again'. Thu lai 4 lan, cach 5s.
        for _att in range(4):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    archive_path.write_bytes(resp.read())
                break
            except (urllib.error.URLError, OSError) as _de:
                if isinstance(_de, urllib.error.HTTPError) or _att == 3:
                    raise
                time.sleep(5)
        shutil.unpack_archive(str(archive_path), str(tmp_root), 'gztar')
        if not extract_dir.exists():
            raise RuntimeError('Không giải nén được gói update')
        if latest_label:
            version_text = latest_label if not latest_short else f'{latest_label} ({latest_short})'
            (extract_dir / 'VERSION.txt').write_text(version_text + '\n', encoding='utf-8')
        try:
            _pin_recovery_277(before_label)
        except Exception:
            pass
        # [Ver 2.70] Thu muc co du lieu runtime: chep DE (merge), KHONG xoa truoc.
        # Truoc day rmtree => moi lan update mat xxtouch_jobs/data, log, tmp.
        _merge_dirs = {'xxtouch_jobs', 'logs', 'presets', 'persist'}
        for item in extract_dir.iterdir():
            target = BASE_DIR / item.name
            if item.is_dir() and item.name in _merge_dirs and target.is_dir() and (not target.is_symlink()):
                shutil.copytree(item, target, dirs_exist_ok=True)
                continue
            if target.exists():
                if target.is_dir() and (not target.is_symlink()):
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)
        try:
            _fw_fix_sh = BASE_DIR / 'gen_fw_fix.sh'
            if _fw_fix_sh.exists():
                subprocess.run(['sh', str(_fw_fix_sh)], timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        try:
            _gu_src = BASE_DIR / 'gen_update.sh'
            if _gu_src.exists():
                shutil.copy(str(_gu_src), '/root/gen_update.sh')
                os.chmod('/root/gen_update.sh', 493)
        except Exception:
            pass
        try:
            _vm_src = BASE_DIR / 'tools' / 'vpn_mgr.sh'
            if _vm_src.exists():
                Path('/data/vpn').mkdir(parents=True, exist_ok=True)
                shutil.copy(str(_vm_src), '/data/vpn/vpn_mgr.sh')
                os.chmod('/data/vpn/vpn_mgr.sh', 493)
        except Exception:
            pass
        try:
            _vg_src = BASE_DIR / 'tools' / 'gen_vpn_guard.sh'
            if _vg_src.exists():
                shutil.copy(str(_vg_src), '/etc/gen_vpn_guard.sh')
                os.chmod('/etc/gen_vpn_guard.sh', 493)
                _vg_ins = BASE_DIR / 'tools' / 'gen_vpn_guard_install.sh'
                if _vg_ins.exists():
                    subprocess.run(['sh', str(_vg_ins), str(_vg_src)], timeout=60,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        # [Ver 2.47] etc/: kill-switch + tproxy da sua + cron watchdog.
        # Truoc Ver 2.47 chi install.sh goi etc_install.sh, nen may update qua GUI/key
        # bi THIEU /etc/genrouter_killswitch.sh, /etc/{shm,genrouter/core}/tproxy va
        # cron */5 dataplane_guard.py => ban va tay khong lan ra ca dan may.
        # Truyen tuong minh duong dan etc/ (khong dua vao auto-detect) va GHI LOG de
        # nghiem thu duoc: im lang o buoc nay tung la ly do lo hong khong ai thay.
        try:
            _ei = BASE_DIR / 'tools' / 'etc_install.sh'
            _etc_dir = BASE_DIR / 'etc'
            _ei_log = BASE_DIR / 'logs' / 'etc_install.log'
            _ei_log.parent.mkdir(parents=True, exist_ok=True)
            _stamp = time.strftime('%Y-%m-%d %H:%M:%S')
            if _ei.exists() and _etc_dir.is_dir():
                _r = subprocess.run(['sh', str(_ei), str(_etc_dir)], timeout=120,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                _out = (_r.stdout or b'').decode('utf-8', 'replace')
                with open(_ei_log, 'a', encoding='utf-8') as _fh:
                    _fh.write(f'\n=== {_stamp} etc_install (update_repo_from_remote) rc={_r.returncode} ===\n{_out}')
            else:
                with open(_ei_log, 'a', encoding='utf-8') as _fh:
                    _fh.write(f'\n=== {_stamp} etc_install BO QUA: '
                              f'etc_install.sh={_ei.exists()} etc_dir={_etc_dir.is_dir()} ===\n')
        except Exception as _e:
            try:
                with open(BASE_DIR / 'logs' / 'etc_install.log', 'a', encoding='utf-8') as _fh:
                    _fh.write(f'\n=== {time.strftime("%Y-%m-%d %H:%M:%S")} etc_install LOI: {_e} ===\n')
            except Exception:
                pass
        shutil.rmtree(tmp_root, ignore_errors=True)
        try:
            ensure_lan_syn_bypass()
        except Exception:
            pass
        after_label = read_current_version_label()
        changed = after_label != before_label
        reboot_scheduled = False
        if changed:
            try:
                subprocess.Popen(['sh', '-c', 'sleep 3; sync; reboot >/dev/null 2>&1'], start_new_session=True)
                reboot_scheduled = True
            except Exception:
                pass
        else:
            try:
                subprocess.Popen(['sh', '-c', 'sleep 2; /etc/init.d/proxy-manager-v1 restart >/dev/null 2>&1'], start_new_session=True)
            except Exception:
                pass
        return {'ok': True, 'updated': changed, 'before': before_label, 'after': after_label, 'current_label': after_label, 'current_commit': '', 'current_short': latest_short, 'message': 'Đã cập nhật lên bản mới thành công – ROUTER SẼ TỰ KHỞI ĐỘNG LẠI sau ~5 giây' if reboot_scheduled else 'Vẫn là bản mới nhất – không cần khởi động lại', 'rebooting': reboot_scheduled}
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

def proxy_tag_num(tag):
    try:
        return int(str(tag).split('_', 1)[1])
    except Exception:
        return 10 ** 9

def machine_num(value):
    try:
        return int(str(value).strip())
    except Exception:
        return 10 ** 9

def normalize_machine(value):
    value = str(value or '').strip()
    if not value:
        return ''
    try:
        return str(int(value))
    except Exception:
        return value

def normalize_ip_identity_row(row):
    tag = normalize_tag((row or {}).get('tag', ''))
    ip = str((row or {}).get('ip', '')).strip()
    machine = normalize_machine((row or {}).get('machine', ''))
    if not machine and tag.startswith('proxy_'):
        num = proxy_tag_num(tag)
        if 1 <= num <= MAX_PROXY_TAG:
            machine = str(num)
    return {'machine': machine, 'tag': tag, 'ip': ip}

def format_ip_identity_row(row, include_machine=False):
    norm = normalize_ip_identity_row(row)
    machine = norm.get('machine', '')
    tag = norm.get('tag', '')
    ip = norm.get('ip', '')
    if include_machine and machine:
        return f'{machine}|{tag}|{ip}'
    return f'{tag}|{ip}'

def normalize_tag(tag):
    tag = str(tag or '').strip()
    if not tag:
        return ''
    if tag.lower().startswith('proxy_'):
        return 'proxy_' + tag.split('_', 1)[1]
    return tag

def tag_to_ip(tag):
    num = proxy_tag_num(tag)
    if num < 1 or num > MAX_PROXY_TAG:
        return ''
    subnet_offset = (num - 1) // TAGS_PER_SUBNET
    host_octet = (num - 1) % TAGS_PER_SUBNET + 1
    subnet_octet = BASE_SUBNET_OCTET + subnet_offset
    return f'192.15.{subnet_octet}.{host_octet}'

def ensure_sessions_exist():
    PRESET_DIR.mkdir(parents=True, exist_ok=True)
    base_file = SESSION_FILES['1']
    if not base_file.exists():
        save_gencore_json(base_file, load_json(RUNTIME_SOURCE_FILE))
    create_default_second = not SESSION_STATE_FILE.exists()
    for session_id, path in SESSION_FILES.items():
        if session_id == '1':
            continue
        if create_default_second and (not path.exists()) and (session_id == '2'):
            data = load_json(base_file)
            clear_session_proxies(data)
            save_gencore_json(path, data)
        if not get_saved_ip_identity_text(session_id) and path.exists():
            data = load_json(path)
            rows = build_ip_identity_rows_from_data(data)
            if rows and len(rows) < MAX_PROXY_TAG:
                set_saved_ip_identity_text(session_id, '\n'.join((format_ip_identity_row(row, include_machine=True) for row in rows)))

def create_session(session_id, source_session='1'):
    session_id = str(session_id)
    source_session = str(source_session or '1')
    if session_id not in SESSION_FILES:
        raise ValueError('Session không hợp lệ')
    ensure_sessions_exist()
    source_file = SESSION_FILES.get(source_session, SESSION_FILES['1'])
    if not source_file.exists():
        source_file = SESSION_FILES['1']
    save_gencore_json(SESSION_FILES[session_id], load_json(source_file))
    state = load_session_state()
    source_state = state.get(source_session, {}) if isinstance(state.get(source_session), dict) else {}
    state[session_id] = json.loads(json.dumps(source_state))
    state, meta = get_meta_section(state)
    names = meta.setdefault('session_names', {}) if isinstance(meta, dict) else {}
    if isinstance(names, dict):
        source_name = str(names.get(source_session, get_session_display_name(source_session))).strip() or f'Session {source_session}'
        names[session_id] = f'{source_name} copy'
    ip_text = meta.setdefault('ip_identity_text', {}) if isinstance(meta, dict) else {}
    if isinstance(ip_text, dict):
        source_text = str(ip_text.get(source_session, '')).strip()
        if source_text:
            ip_text[session_id] = source_text
    save_session_state(state)
    return {'session': session_id, 'name': get_session_display_name(session_id), 'source': str(SESSION_FILES[session_id])}

def get_session_hidden_map(state=None):
    state = state if isinstance(state, dict) else load_session_state()
    _state, meta = get_meta_section(state)
    hidden = meta.get('hidden_sessions', {}) if isinstance(meta, dict) else {}
    return hidden if isinstance(hidden, dict) else {}

def is_session_hidden(session_id, state=None):
    hidden = get_session_hidden_map(state)
    return bool(hidden.get(str(session_id), False))

def get_visible_session_ids(state=None):
    state = state if isinstance(state, dict) else load_session_state()
    ensure_sessions_exist()
    items = []
    for session_id, path in SESSION_FILES.items():
        if path.exists() and (not is_session_hidden(session_id, state)):
            items.append(str(session_id))
    items.sort(key=lambda x: int(x))
    return items

def set_session_hidden(session_id, hidden=True):
    session_id = str(session_id)
    if session_id == '1':
        raise ValueError('Không thể ẩn cấu hình 1')
    state = load_session_state()
    visible_ids = get_visible_session_ids(state)
    if hidden and session_id in visible_ids and (len(visible_ids) <= 1):
        raise ValueError('Phải luôn giữ lại ít nhất 1 cấu hình đang hiện')
    state, meta = get_meta_section(state)
    hidden_map = meta.setdefault('hidden_sessions', {}) if isinstance(meta, dict) else {}
    if not isinstance(hidden_map, dict):
        hidden_map = {}
        meta['hidden_sessions'] = hidden_map
    hidden_map[session_id] = bool(hidden)
    save_session_state(state)
    return bool(hidden)

def delete_session(session_id):
    session_id = str(session_id)
    if session_id == '1':
        raise ValueError('Không thể xóa cấu hình mặc định số 1')
    path = SESSION_FILES.get(session_id)
    if not path or not path.exists():
        raise ValueError('Cấu hình không tồn tại')
    try:
        path.unlink()
    except Exception as e:
        raise ValueError(f'Không xóa được file cấu hình: {e}')
    state = load_session_state()
    if isinstance(state, dict):
        state.pop(session_id, None)
        state, meta = get_meta_section(state)
        names = meta.get('session_names', {}) if isinstance(meta, dict) else {}
        if isinstance(names, dict):
            names.pop(session_id, None)
        hidden_map = meta.get('hidden_sessions', {}) if isinstance(meta, dict) else {}
        if isinstance(hidden_map, dict):
            hidden_map.pop(session_id, None)
        ip_text = meta.get('ip_identity_text', {}) if isinstance(meta, dict) else {}
        if isinstance(ip_text, dict):
            ip_text.pop(session_id, None)
        save_session_state(state)
    return True

def get_available_sessions(include_hidden=True):
    ensure_sessions_exist()
    state = load_session_state()
    items = []
    for session_id, path in SESSION_FILES.items():
        if path.exists():
            hidden = is_session_hidden(session_id, state)
            if hidden and (not include_hidden):
                continue
            items.append({'session': session_id, 'name': get_session_display_name(session_id), 'source': str(path), 'exists': True, 'hidden': hidden, 'can_hide': session_id != '1', 'can_delete': session_id != '1', 'is_default': session_id in ('1', '2')})
    items.sort(key=lambda x: int(x['session']))
    return items

def load_json(path: Path):
    """Doc JSON, tu va neu file bi dinh rac o duoi (di san cua loi ghi dua tmp).

    Ver 2.33: truoc day mot so file preset bi dinh duoi rac (phan con lai cua
    mot lan ghi TRUOC dai hon) khien json.loads nem 'Extra data' va toan bo
    cau hinh khong mo duoc. Nay neu phan dau file la JSON hop le thi cat rac,
    luu ban hong lai de dieu tra roi ghi lai ban sach — nguoi dung khong con
    bi khoa khoi cau hinh.
    """
    path = Path(path)
    txt = path.read_text(encoding='utf-8')
    try:
        return json.loads(txt)
    except Exception as first_err:
        try:
            obj, end = json.JSONDecoder().raw_decode(txt)
        except Exception:
            raise first_err
        tail = txt[end:]
        if tail.strip() == '':
            raise first_err
        _ss_log(f'JSON-HEAL {path.name}: cat {len(tail)} byte rac o cuoi (loi goc: {first_err})')
        try:
            broken = path.with_name(f'{path.name}.broken.{time.strftime("%Y%m%d_%H%M%S")}')
            if not broken.exists():
                broken.write_text(txt, encoding='utf-8')
        except Exception as e:
            _ss_log(f'JSON-HEAL {path.name}: khong luu duoc ban hong: {e}')
        try:
            _ss_atomic_write(path, txt[:end].rstrip() + '\n')
            _ss_log(f'JSON-HEAL {path.name}: da ghi lai ban sach ({end} bytes)')
        except Exception as e:
            _ss_log(f'JSON-HEAL {path.name}: khong ghi lai duoc ban sach: {e}')
        return obj
SS_BACKUP_COUNT = 5
SS_EXT_DIR = Path('/data/vpn_backup')
SS_HEAL_LOG = BASE_DIR / 'logs' / 'session_state_guardian.log'
SS_MIN_VALID_BYTES = 1024
_SS_EXT_LAST = {'txt': None}

def _ss_log(msg):
    try:
        SS_HEAL_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(SS_HEAL_LOG, 'a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + str(msg) + '\n')
        try:
            if SS_HEAL_LOG.exists() and SS_HEAL_LOG.stat().st_size > 262144:
                tail = SS_HEAL_LOG.read_text(encoding='utf-8', errors='ignore').splitlines()[-500:]
                tmp = SS_HEAL_LOG.with_suffix('.tmp')
                tmp.write_text('\n'.join(tail) + '\n', encoding='utf-8')
                os.replace(str(tmp), str(SS_HEAL_LOG))
        except Exception:
            pass
    except Exception:
        pass

def _ss_is_meaningful(state):
    """State co du lieu that hay khong (co identity lon hoac it nhat 1 session dict co noi dung)."""
    if not isinstance(state, dict) or not state:
        return False
    meta = state.get('__meta__') if isinstance(state.get('__meta__'), dict) else {}
    sh = str(meta.get('shared_ip_identity_text', '') or '')
    if len(sh.strip()) >= SS_MIN_VALID_BYTES:
        return True
    for k, v in state.items():
        if isinstance(k, str) and k.startswith('__'):
            continue
        if isinstance(v, dict) and len(v) >= 5:
            return True
    return False

def _ss_snapshot_good(path: Path):
    """Tra text neu parse OK va meaningful, nguoc lai None."""
    try:
        txt = path.read_text(encoding='utf-8')
        d = json.loads(txt)
        if _ss_is_meaningful(d):
            return txt
    except Exception:
        pass
    return None

_ATOMIC_PATH_LOCKS = {}
_ATOMIC_PATH_LOCKS_GUARD = threading.Lock()
_ATOMIC_SEQ = {'n': 0}

def _atomic_lock_for(path: Path):
    """Lay lock rieng cho tung duong dan file (serialize ghi cung 1 file)."""
    key = str(path)
    with _ATOMIC_PATH_LOCKS_GUARD:
        lk = _ATOMIC_PATH_LOCKS.get(key)
        if lk is None:
            lk = threading.Lock()
            _ATOMIC_PATH_LOCKS[key] = lk
        return lk

def _atomic_tmp_name(path: Path) -> Path:
    """Ten tmp DUY NHAT cho moi lan ghi: pid + thread + so thu tu."""
    with _ATOMIC_PATH_LOCKS_GUARD:
        _ATOMIC_SEQ['n'] += 1
        seq = _ATOMIC_SEQ['n']
    return path.with_name(f'{path.name}.tmp_write.{os.getpid()}.{threading.get_ident()}.{seq}')

def _ss_cleanup_stale_tmp():
    """Don file .tmp_write* con sot (do lan ghi truoc bi cat giua duong)."""
    seen = 0
    for d in {BASE_DIR, PRESET_DIR, SS_EXT_DIR, CONFIG_DIR, RUNTIME_DIR}:
        try:
            for p in Path(d).glob('*.tmp_write*'):
                try:
                    p.unlink()
                    seen += 1
                except Exception:
                    pass
        except Exception:
            pass
    if seen:
        _ss_log(f'CLEANUP: da xoa {seen} file .tmp_write* con sot')

def _ss_atomic_write(path: Path, text: str):
    """Ghi nguyen tu: tmp DUY NHAT -> flush+fsync -> doc lai kiem tra -> rename.

    Ver 2.33 (fix goc re vu session2/session4.json hong 'Extra data'):
    truoc day ten tmp la CO DINH ('<file>.tmp_write'). App chay tren
    ThreadingHTTPServer nen hai request ghi cung mot file se dung CHUNG mot
    tmp: luong A mo tmp ghi 172969 byte, luong B mo lai chinh tmp do (mode 'w'
    truncate ve 0) ghi 172814 byte, hai lan flush chen nhau => tmp thanh
    'noi dung B + duoi con lai cua A' roi os.replace cong bo ban rac do.
    Dung dung 155 byte rac quan sat duoc chinh la duoi cua lan ghi dai hon.

    Nay: (1) tmp mang pid+thread+seq nen khong bao gio dung chung;
    (2) lock theo tung duong dan de hai lan ghi cung file xep hang;
    (3) doc lai tmp so voi text truoc khi rename — sai la huy, khong cong bo.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _atomic_lock_for(path):
        tmp = _atomic_tmp_name(path)
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            back = tmp.read_text(encoding='utf-8')
            if back != text:
                raise IOError(f'tmp sai lech sau khi ghi ({len(back)} vs {len(text)} bytes) — huy, khong cong bo')
            os.replace(str(tmp), str(path))
        except Exception:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            raise
        try:
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except Exception:
            pass

def _ss_rotate_backups():
    """Day bak.x -> bak.x+1 roi luu ban hien tai vao bak.1 (chi neu ban hien tai tot)."""
    b1 = SESSION_STATE_FILE.parent / (SESSION_STATE_FILE.name + '.bak.1')
    for i in range(SS_BACKUP_COUNT - 1, 0, -1):
        src = SESSION_STATE_FILE.parent / (SESSION_STATE_FILE.name + f'.bak.{i}')
        dst = SESSION_STATE_FILE.parent / (SESSION_STATE_FILE.name + f'.bak.{i + 1}')
        if src.exists():
            try:
                os.replace(str(src), str(dst))
            except Exception:
                pass
    cur_txt = _ss_snapshot_good(SESSION_STATE_FILE)
    if cur_txt is not None:
        try:
            _ss_atomic_write(b1, cur_txt)
        except Exception as e:
            _ss_log(f'rotate: luu bak.1 that bai: {e}')

def _ss_seed_backups():
    """Gieo backup dau tien ngay khoi dong — khong bao gio ton tai 'cua so khong backup'."""
    try:
        txt = _ss_snapshot_good(SESSION_STATE_FILE)
        if txt is None:
            return
        b1 = SESSION_STATE_FILE.parent / (SESSION_STATE_FILE.name + '.bak.1')
        if not b1.exists():
            _ss_atomic_write(b1, txt)
        ext = SS_EXT_DIR / SESSION_STATE_FILE.name
        if _ss_snapshot_good(ext) != txt:
            _ss_atomic_write(ext, txt)
            _SS_EXT_LAST['txt'] = txt
        _ss_log('SEED: backup dau tien da san sang (bak.1 + /data)')
    except Exception as e:
        _ss_log(f'seed backups loi: {e}')

def _ss_try_heal(reason: str):
    """Tim backup moi nhat con dung duoc va phuc hoi lai file chinh. Tra dict hoac None."""
    candidates = []
    for i in range(1, SS_BACKUP_COUNT + 1):
        p = SESSION_STATE_FILE.parent / (SESSION_STATE_FILE.name + f'.bak.{i}')
        try:
            if p.exists():
                candidates.append((p.stat().st_mtime, p))
        except Exception:
            pass
    try:
        ext = SS_EXT_DIR / SESSION_STATE_FILE.name
        if ext.exists():
            candidates.append((ext.stat().st_mtime, ext))
    except Exception:
        pass
    candidates.sort(reverse=True)
    for _, p in candidates:
        txt = _ss_snapshot_good(p)
        if txt is not None:
            try:
                _ss_atomic_write(SESSION_STATE_FILE, txt)
                _ss_log(f'SELF-HEAL ({reason}): da phuc hoi tu {p.name} ({len(txt)} bytes)')
                return json.loads(txt)
            except Exception as e:
                _ss_log(f'SELF-HEAL ({reason}): loi voi {p.name}: {e}')
    _ss_log(f'SELF-HEAL ({reason}): khong con backup nao dung duoc — can can thiep tay')
    return None

CATCH_ALL_DNS_RULE_KEYS = {'outbound', 'server', 'action', 'disable_cache', 'client_subnet'}

def save_json(path: Path, data):
    _ss_atomic_write(Path(path), json.dumps(data, ensure_ascii=False, indent=2) + '\n')

def save_gencore_json(path, data):
    """Ghi file dinh dang gencore o che do COMPACT (khong dau cach sau ':').

    BAT BUOC. Script vendor /etc/genrouter/core/tproxy lay danh sach client
    bang:  awk -F'"source_ip_cidr":"'  (KHONG co dau cach). Neu file ghi
    pretty (indent=2) thi awk khop 0 lan -> CLIENT_IPS rong -> 0 rule TPROXY
    -> toan bo LAN mat mang, MA `tproxy -s` van tra rc=0 (loi im lang).
    Da do thuc te 2026-09-02: file pretty => awk tim thay 0 IP.
    Xem memory/2026-09-02.md muc 26.2, 27.2, 31.
    """
    _ss_atomic_write(Path(path), json.dumps(data, ensure_ascii=False, separators=(',', ':')) + '\n')


DNS_LOOP_BREAKER_SERVER = 'dnsmasq'


# ---------------------------------------------------------------------------
# L1 DENY-BY-DEFAULT (them 2026-09-03)
# Nguyen tac nghiep vu: thiet bi KHONG di qua proxy/VPN thi KHONG duoc ra
# internet -- ke ca DNS. Truoc ban nay, may la (khong co trong 322 mapping)
# van resolve duoc vi dns.final='dnsmasq' -> dnsmasq -> 8.8.8.8 UDP/53 ra WAN
# (da do that: conntrack 192.168.8.3->8.8.8.8:53, va 192.14.1.10 query 3 lan
# du khong co rule nao). Do la ro ten mien + SNI ra ngoai.
#
# VI SAO PHAI NAM CUOI: dns.rules va route.rules la FIRST-MATCH-WINS. Rule
# deny theo source_ip_cidr = ca /20 nen no PHU luon 322 rule proxy_*. Neu no
# dung truoc thi 322 may mat DNS ngay. Ver 2.36 da tung mac dung loi nay voi
# rule {'action':'route','outbound':'block'} (tich tu 8 cai, 7 cai troi len
# index 3..9 => chan sach 322 may). Vi vay: DUY NHAT + CUOI CUNG, va moi lan
# rebuild deu loc cai cu roi append lai.
# ---------------------------------------------------------------------------

def _detect_lan_deny_cidr(fallback='192.14.0.0/20'):
    """Lay dai LAN tu br-lan (192.14.0.1/20 -> 192.14.0.0/20)."""
    try:
        import ipaddress
        out = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'dev', 'br-lan'],
                             capture_output=True, timeout=5).stdout.decode('utf-8', 'replace')
        for token in out.split():
            if token.count('.') == 3 and '/' in token:
                return str(ipaddress.ip_interface(token).network)
    except Exception:
        pass
    return fallback


LAN_DENY_CIDR = _detect_lan_deny_cidr()
DNS_DENY_RULE_KEYS = {'action', 'method', 'source_ip_cidr', 'no_drop'}
ROUTE_DENY_RULE_KEYS = {'action', 'method', 'no_drop'}


def dns_deny_rule():
    return {'action': 'reject', 'source_ip_cidr': LAN_DENY_CIDR}


def is_dns_deny_rule(rule):
    """Rule DNS deny-by-default do chinh app sinh ra (khong co dieu kien khac)."""
    if not isinstance(rule, dict):
        return False
    if str(rule.get('action', '')).strip() != 'reject':
        return False
    return set(rule.keys()) <= DNS_DENY_RULE_KEYS


def ensure_dns_deny_last(data):
    """Bao dam dns.rules co DUNG 1 rule deny va no o VI TRI CUOI. 1 = da doi."""
    dns = (data or {}).setdefault('dns', {})
    rules = dns.get('rules')
    if not isinstance(rules, list):
        rules = []
    kept = [rule for rule in rules if not is_dns_deny_rule(rule)]
    new_rules = kept + [dns_deny_rule()]
    if new_rules == rules:
        return 0
    dns['rules'] = new_rules
    return 1


def is_route_deny_rule(rule):
    """Chot deny cua route: ca dang cu 'outbound block' va dang moi 'reject'."""
    if not isinstance(rule, dict):
        return False
    action = str(rule.get('action', '')).strip()
    if action == 'route' and str(rule.get('outbound', '')).strip() == 'block':
        return set(rule.keys()) <= {'action', 'outbound'}
    if action == 'reject':
        return set(rule.keys()) <= ROUTE_DENY_RULE_KEYS
    return False


def ensure_route_deny_last(data):
    """Chot route deny = {'action':'reject','method':'drop'}, DUY NHAT + CUOI.

    Doi tu {'action':'route','outbound':'block'} sang 'reject' vi outbounds
    KHONG co tag 'block' (sing-box 1.11 bo type block) => rule cu la orphan,
    tung spam 'outbound not found: block' 3.8 lan/giay.
    """
    route = (data or {}).setdefault('route', {})
    rules = route.get('rules')
    if not isinstance(rules, list):
        rules = []
    kept = [rule for rule in rules if not is_route_deny_rule(rule)]
    new_rules = kept + [{'action': 'reject', 'method': 'drop'}]
    if new_rules == rules:
        return 0
    route['rules'] = new_rules
    return 1



def collect_proxy_dns_hosts(data):
    """Ten mien (KHONG phai IP) ma cac outbound proxy_* dung lam server.

    Chi ten mien moi can resolve; neu outbound tro bang IP thi khong co
    vong lap nao ca. Doc tu chinh outbounds nen tu dong dung du nha cung
    cap co doi endpoint (as.lumiproxy.io -> ...).
    """
    hosts = []
    seen = set()
    for item in ((data or {}).get('outbounds') or []):
        if not isinstance(item, dict):
            continue
        if not str(item.get('tag', '')).strip().startswith('proxy_'):
            continue
        host = str(item.get('server', '') or '').strip()
        if not host or host in seen:
            continue
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', host) or ':' in host:
            continue
        seen.add(host)
        hosts.append(host)
    return sorted(hosts)


def is_dns_loop_breaker(rule):
    """Rule pha vong lap do chinh app sinh ra."""
    if not isinstance(rule, dict):
        return False
    if str(rule.get('server', '')).strip() != DNS_LOOP_BREAKER_SERVER:
        return False
    if not rule.get('domain'):
        return False
    return not rule.get('source_ip_cidr')


def ensure_dns_loop_breaker(data):
    """Chen rule pha VONG LAP DNS len dau dns.rules. Tra ve 1 neu co doi.

    TAI SAO BAT BUOC (da do thuc te 2026-09-03, 19984 dong loi):
      outbound proxy_N co server = "as.lumiproxy.io" (TEN MIEN).
      dns server proxy_N = https://8.8.8.8/dns-query voi detour = proxy_N.
      Muon dung detour proxy_N, sing-box phai resolve ten mien do truoc.
      Query resolve MANG THEO source_ip cua client => khop lai dung rule
      source_ip_cidr => server proxy_N => detour proxy_N => VONG LAP.
      sing-box bao: "DNS query loopback in transport[proxy_N]", conntrack
      ra proxy tut ve 0, toan bo LAN mat mang.
    Rule nay tro ten mien cua proxy ve dnsmasq (KHONG co detour) nen cat
    duoc vong lap, va vi chi khop dung ten mien do nen KHONG che 322 rule
    DoH theo source_ip_cidr phia sau.
    Xem memory/2026-09-03.md muc 3 + 4.
    """
    dns = (data or {}).setdefault('dns', {})
    rules = dns.get('rules')
    if not isinstance(rules, list):
        rules = []
    kept = [rule for rule in rules if not is_dns_loop_breaker(rule)]
    hosts = collect_proxy_dns_hosts(data)
    # Khong tao rule tro toi server khong ton tai -- dung sai lam cua
    # 'outbound: block' (tag khong co trong outbounds => sing-box spam
    # 'outbound not found: block' 3.8 lan/giay).
    tags = {str(item.get('tag', '')).strip()
            for item in (dns.get('servers') or []) if isinstance(item, dict)}
    if not hosts or DNS_LOOP_BREAKER_SERVER not in tags:
        if len(kept) != len(rules):
            dns['rules'] = kept
            return 1
        return 0
    wanted = {'action': 'route', 'server': DNS_LOOP_BREAKER_SERVER, 'domain': list(hosts)}
    new_rules = [wanted] + kept
    if new_rules == rules:
        return 0
    dns['rules'] = new_rules
    return 1


DNS_LOCAL_DETOUR = 'direct'


def is_local_dns_address(addr):
    """DNS server tro ve chinh router (dnsmasq local) hay khong."""
    text = str(addr or '').strip().lower()
    for prefix in ('udp://', 'tcp://', 'tls://', 'https://', 'h3://', 'quic://'):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    text = text.split('/')[0]
    host = text.rsplit(':', 1)[0] if text.count(':') == 1 else text
    return host.strip('[]') in ('127.0.0.1', 'localhost', '::1')


def ensure_dns_local_detour(data):
    """Bat buoc DNS server local (dnsmasq 127.0.0.1:5353) co detour='direct'.

    TAI SAO BAT BUOC (do thuc te 2026-09-04: client 0/73 reply DNS):
      Server DNS khong co 'detour' thi ket noi ra cua CHINH sing-box di qua
      route engine. route.rules co {'action':'hijack-dns','protocol':'dns'}
      o index 2, nen no bat luon goi UDP sing-box gui ra 127.0.0.1:5353 va
      day tro lai DNS module => loi "DNS query loopback in transport[dnsmasq]".
      Hau qua day chuyen: loop breaker khong resolve duoc as.lumiproxy.io =>
      detour proxy_N khong dung duoc => 322 may mat phan giai ten hoan toan
      (bat goi tren br-lan: 73 query, 0 reply; client retry 255 lan/luong).
      detour='direct' cho goi di thang, bo qua route engine => het vong lap.
    Da kiem thuc nghiem (d263 Z2 va Z5 tren instance rieng): 3/3 query OK.
    Xem memory/2026-09-04.md muc DNS + out263b.txt.
    Tra ve so entry da doi.
    """
    dns = (data or {}).setdefault('dns', {})
    servers = dns.get('servers')
    if not isinstance(servers, list):
        return 0
    has_direct = any(isinstance(item, dict)
                     and str(item.get('tag', '')).strip() == DNS_LOCAL_DETOUR
                     for item in ((data or {}).get('outbounds') or []))
    if not has_direct:
        return 0
    changed = 0
    for server in servers:
        if not isinstance(server, dict):
            continue
        if str(server.get('tag', '')).strip().startswith('proxy_'):
            continue
        if not is_local_dns_address(server.get('address')):
            continue
        if str(server.get('detour', '')).strip() == DNS_LOCAL_DETOUR:
            continue
        server['detour'] = DNS_LOCAL_DETOUR
        changed += 1
    return changed


def is_catch_all_dns_rule(rule):
    """Rule DNS bat-het kieu {"outbound":"any","server":"google"}.

    Trong sing-box, dns rule co outbound="any" va KHONG co dieu kien nao khac
    la match-all. Vi dns rule la first-match-wins, rule nay dung o vi tri 0 se
    an het 322 rule DoH theo source_ip_cidr phia sau => moi query di ra
    server "google" = 8.8.8.8 port 53 = bi proxy Lumi tra SOCKS rep=2 => lag.
    Da do: 8.8.8.8:53 rep=2, :853 rep=2, :443 rep=0 + DoH 443 chay OK 5/5.
    """
    if not isinstance(rule, dict):
        return False
    if str(rule.get('outbound', '')).strip() != 'any':
        return False
    return set(rule.keys()) <= CATCH_ALL_DNS_RULE_KEYS


def strip_catch_all_dns_rules(data):
    """Bo moi dns rule bat-het. Tra ve so rule da bo."""
    try:
        dns = (data or {}).get('dns') or {}
        rules = dns.get('rules')
    except Exception:
        return 0
    if not isinstance(rules, list):
        return 0
    kept = [r for r in rules if not is_catch_all_dns_rule(r)]
    removed = len(rules) - len(kept)
    if removed:
        dns['rules'] = kept
    return removed

def load_admanager_config():
    cfg = {'routers': {}, 'apps': {'tiktok': {'label': 'TikTok', 'matchPrefixes': ['com.ss.iphone.ugc.Ame', 'com.zhiliaoapp.musically']}, 'tiktok_lite': {'label': 'TikTok Lite', 'matchPrefixes': ['com.ss.iphone.ugc.AmeLite', 'com.zhiliaoapp.musically.lite', 'com.ss.iphone.ugc.tiktoklite']}}, 'backupCommands': {'TikTok': 'echo BACKUP_TIKTOK', 'TikTok Lite': 'echo BACKUP_TIKTOK_LITE'}, 'defaultOutput': '', 'uiState': {'router': '', 'port': '46952', 'machineMode': 'all', 'machineRange': '1-10', 'machineList': '1,2,3', 'dateMode': 'one', 'dateStart': '', 'dateEnd': '', 'appFilter': 'All', 'fullScan': False, 'doBackupBeforePull': False, 'deleteAfterPull': False, 'outputRoot': ''}}
    config_sources = [ADMANAGER_GUI_CONFIG_FILE, ADMANAGER_CONFIG_FILE, ADMANAGER_GUI_LOCAL_FILE, ADMANAGER_LOCAL_FILE]
    for path in config_sources:
        try:
            if path.exists():
                incoming = json.loads(path.read_text(encoding='utf-8'))
                if isinstance(incoming.get('routers'), dict) and incoming.get('routers'):
                    cfg['routers'] = incoming['routers']
                if isinstance(incoming.get('apps'), dict) and incoming.get('apps'):
                    cfg['apps'] = incoming['apps']
                if isinstance(incoming.get('backupCommands'), dict) and incoming.get('backupCommands'):
                    cfg['backupCommands'] = incoming['backupCommands']
                if incoming.get('defaultOutput'):
                    cfg['defaultOutput'] = incoming['defaultOutput']
                if isinstance(incoming.get('uiState'), dict):
                    cfg['uiState'] = {**cfg.get('uiState', {}), **incoming['uiState']}
        except Exception:
            pass
    ui = cfg.get('uiState') if isinstance(cfg.get('uiState'), dict) else {}
    if not ui.get('outputRoot'):
        ui['outputRoot'] = cfg.get('defaultOutput') or ''
    cfg['uiState'] = ui
    return cfg

def save_admanager_local(cfg):
    local = {}
    try:
        if ADMANAGER_LOCAL_FILE.exists():
            local = json.loads(ADMANAGER_LOCAL_FILE.read_text(encoding='utf-8'))
    except Exception:
        local = {}
    for key in ('defaultOutput', 'backupCommands', 'uiState'):
        if key in cfg:
            local[key] = cfg[key]
    save_json(ADMANAGER_LOCAL_FILE, local)

def get_current_router_lan_ip():
    try:
        info = call_old_gui('/api/router/info')
        data = info.get('data') if isinstance(info, dict) else {}
        if isinstance(data, dict):
            nested = data.get('data') if isinstance(data.get('data'), dict) else data
            lan = nested.get('lan') if isinstance(nested.get('lan'), dict) else {}
            networks = lan.get('networks') if isinstance(lan.get('networks'), list) else []
            if networks:
                ip = str((networks[0] or {}).get('ip') or '').strip()
                if ip:
                    return ip
    except Exception:
        pass
    return ''

def get_router_machine_context(cfg: dict, state: dict):
    requested_router = str((state or {}).get('router') or (cfg.get('uiState') or {}).get('router') or '').strip()
    router = (cfg.get('routers') or {}).get(requested_router) if isinstance(cfg.get('routers'), dict) and requested_router else {}
    note = ''
    available = []
    return {'router': requested_router, 'router_obj': router if isinstance(router, dict) else {}, 'note': note, 'available': available}

def load_notes():
    if not NOTES_FILE.exists():
        return {}
    try:
        return load_json(NOTES_FILE)
    except Exception:
        return {}

def save_notes(notes):
    save_json(NOTES_FILE, notes)

def load_session_state():
    if not SESSION_STATE_FILE.exists():
        healed = _ss_try_heal('file chinh khong ton tai')
        if healed is not None:
            return healed
        return {}
    try:
        d = load_json(SESSION_STATE_FILE)
        if _ss_is_meaningful(d):
            return d
        healed = _ss_try_heal('file chinh rong/trang bat thuong')
        if healed is not None:
            return healed
        return d
    except Exception:
        healed = _ss_try_heal('file chinh JSON hong')
        if healed is not None:
            return healed
        return {}

def save_session_state(state):
    new_txt = json.dumps(state, ensure_ascii=False, indent=2) + '\n'
    old_status = 'missing'
    old_len = 0
    try:
        if SESSION_STATE_FILE.exists():
            old_txt = SESSION_STATE_FILE.read_text(encoding='utf-8')
            old_len = len(old_txt)
            try:
                old_parsed = json.loads(old_txt)
                old_status = 'meaningful' if _ss_is_meaningful(old_parsed) else 'empty'
            except Exception:
                old_status = 'corrupt'
    except Exception:
        old_status = 'missing'
    if not _ss_is_meaningful(state) and old_status in ('meaningful', 'corrupt'):
        _ss_log(f'CHAN save-rong: tu choi ghi de (old={old_status} {old_len} bytes, new={len(new_txt)} bytes). Neu muon reset that su, xoa cac file session_state.json* trong {BASE_DIR} roi restart.')
        raise ValueError('session_state guardian: tu choi ghi de state rong len state co du lieu/hong')
    try:
        _ss_rotate_backups()
        _ss_atomic_write(SESSION_STATE_FILE, new_txt)
    except ValueError:
        raise
    except Exception as e:
        _ss_log(f'save atomic that bai ({e}) — fallback ghi truyen thong')
        SESSION_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SESSION_STATE_FILE.write_text(new_txt, encoding='utf-8')
    try:
        ext = SS_EXT_DIR / SESSION_STATE_FILE.name
        if _SS_EXT_LAST.get('txt') != new_txt:
            _ss_atomic_write(ext, new_txt)
            _SS_EXT_LAST['txt'] = new_txt
    except Exception as e:
        _ss_log(f'copy /data that bai (khong anh huong luu chinh): {e}')

def get_session_meta(session_id, tag=None):
    state = load_session_state()
    sess = state.get(str(session_id), {})
    if not isinstance(sess, dict):
        return {} if tag is None else {}
    if tag is None:
        normalized = {}
        for k, v in sess.items():
            nk = normalize_tag(k)
            if nk and isinstance(v, dict):
                if nk in normalized and isinstance(normalized[nk], dict):
                    normalized[nk].update(v)
                else:
                    normalized[nk] = dict(v)
        return normalized
    key = normalize_tag(tag)
    item = sess.get(key, sess.get(str(tag), sess.get(str(tag).upper(), {})))
    if isinstance(item, dict):
        return item
    merged = {}
    for k, v in sess.items():
        if str(k).lower() == key.lower() and isinstance(v, dict):
            merged.update(v)
    return merged

def get_meta_section(state=None):
    state = state if isinstance(state, dict) else load_session_state()
    meta = state.get('__meta__', {}) if isinstance(state, dict) else {}
    if not isinstance(meta, dict):
        meta = {}
        state['__meta__'] = meta
    return (state, meta)

def get_session_display_name(session_id):
    session_id = str(session_id)
    state = load_session_state()
    _state, meta = get_meta_section(state)
    names = meta.get('session_names', {}) if isinstance(meta, dict) else {}
    name = str(names.get(session_id, '')).strip()
    return name or f'CẤU HÌNH {session_id}'

def get_app_title_prefix():
    state = load_session_state()
    _state, meta = get_meta_section(state)
    value = str(meta.get('app_title_prefix', '')).strip()
    return value or 'Genrouter'

def export_all_sessions_payload(include_hidden=True):
    sessions = get_available_sessions(include_hidden=include_hidden)
    session_items = []
    total_rows = 0
    for item in sessions:
        session_id = str(item.get('session', '')).strip()
        path = SESSION_FILES.get(session_id)
        if not session_id or not path or (not path.exists()):
            continue
        rows = extract_rows(load_json(path), session=session_id)
        total_rows += len(rows)
        session_items.append({'session': session_id, 'name': get_session_display_name(session_id), 'hidden': bool(item.get('hidden', False)), 'rows': rows})
    return {'ok': True, 'router_title': get_app_title_prefix(), 'exported_at': int(time.time()), 'session_count': len(session_items), 'row_count': total_rows, 'sessions': session_items}
LICENSE_FILE = BASE_DIR / 'license.json'
ACTIVE_URL = 'https://script.google.com/macros/s/AKfycbx0nfNl1O3cOHpGA2c69nAZgUHib9T7WQch-4ZzdfV8GD-HxT7m5eAg-zro2fmqmV1T/exec'
LICENSE_CHECK_INTERVAL = 45
_license_state = {'data': {}, 'ok': False, 'lock': threading.Lock()}

def _read_hw_value(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace').strip()
    except Exception:
        return ''

def get_machine_id():
    parts = [_read_hw_value('/etc/machine-id'), _read_hw_value('/sys/class/net/eth0/address'), _read_hw_value('/sys/class/dmi/id/product_uuid'), socket.gethostname()]
    raw = 'GEN-V1|' + '|'.join((p.lower() for p in parts if p))
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest().upper()
    groups = [digest[i * 5:(i + 1) * 5] for i in range(6)]
    return 'GEN-' + '-'.join(groups)

def load_license():
    try:
        data = json.loads(LICENSE_FILE.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}

def save_license(data):
    try:
        LICENSE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    except Exception:
        pass

def _parse_expire_datetime(value):
    s = str(value or '').strip()
    if not s:
        return None
    try:
        base = s.split(' GMT')[0].split(' (')[0].strip()
        return datetime.strptime(base, '%a %b %d %Y %H:%M:%S')
    except Exception:
        pass
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d', '%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M', '%d/%m/%Y'):
        try:
            sample = s[:19] if ' ' in s else s[:10]
            dt = datetime.strptime(sample, fmt)
            if fmt in ('%Y-%m-%d', '%d/%m/%Y'):
                dt = dt.replace(hour=23, minute=59, second=59)
            return dt
        except Exception:
            pass
    try:
        return datetime.fromisoformat(s.replace('Z', '+00:00')).replace(tzinfo=None)
    except Exception:
        return None

def _now_vn():
    return datetime.utcnow() + timedelta(hours=7)

def license_active(data=None):
    d = data if isinstance(data, dict) else load_license()
    machine_id = str(d.get('machine_id') or '').strip().upper()
    current = get_machine_id().upper()
    active = bool(d.get('active')) or str(d.get('status') or '').strip().lower() in ('active', 'ok', 'valid')
    if not active:
        return False
    if machine_id and machine_id != current:
        return False
    exp = _parse_expire_datetime(d.get('expire') or d.get('expires_at') or d.get('expiry'))
    if exp is None:
        return False
    return _now_vn() <= exp

def format_active_info(data=None):
    d = data if isinstance(data, dict) else load_license()
    if not license_active(d):
        return 'CHƯA ACTIVE – gửi ID máy cho admin để kích hoạt'
    plan = str(d.get('plan') or 'FULL').upper()
    exp = _parse_expire_datetime(d.get('expire') or d.get('expires_at') or d.get('expiry'))
    total = int((exp - _now_vn()).total_seconds()) if exp else 0
    days, rem = divmod(max(total, 0), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    expire = f'Còn {days} ngày {hours:02d}:{minutes:02d}' if days < 366 else f'Còn {days // 365} năm {days % 365} ngày' if days < 3650 else f'Còn {days // 365} năm'
    customer = str(d.get('customer') or '').strip()
    max_devices = str(d.get('max_devices') or '').strip()
    device_text = '' if not max_devices or max_devices.lower() in ('0', 'unlimited', 'no_limit') else f' | Giới hạn: {max_devices} máy'
    extra = f' | {customer}' if customer else ''
    return f'ACTIVE: {plan} | Hạn: {expire}{device_text}{extra}'

def license_public_payload():
    mid = get_machine_id()
    lic = load_license()
    msg = str(lic.get('message') or lic.get('status') or '')
    return {'ok': True, 'machine_id': mid, 'active': bool(license_active(lic)), 'info': format_active_info(lic), 'message': msg, 'checked_at': int(time.time())}

def license_check_loop():
    while True:
        ok_now = False
        try:
            sep = '&' if '?' in ACTIVE_URL else '?'
            url = ACTIVE_URL + sep + urlencode({'machine_id': get_machine_id(), 't': int(time.time())})
            req = urllib.request.Request(url, headers={'User-Agent': 'genrouter-license'})
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode('utf-8', 'replace'))
            if isinstance(data, dict):
                data['machine_id'] = get_machine_id()
                data['checked_at'] = int(time.time())
                ok_now = license_active(data)
                with _license_state['lock']:
                    _license_state['data'] = data
                    _license_state['ok'] = ok_now
                save_license(data)
        except Exception:
            pass
        if ok_now:
            try:
                push_proxies_to_sheet_once()
            except Exception:
                pass
        time.sleep(LICENSE_CHECK_INTERVAL)

def license_gate_ok():
    with _license_state['lock']:
        if _license_state['ok']:
            return True
        cached = load_license()
        ok = license_active(cached)
        _license_state['data'] = cached
        _license_state['ok'] = ok
        return ok
_proxy_sync_state = {'hash': '', 'fail_count': 0, 'last_fail': 0}

def build_proxy_sync_payload():
    try:
        exported = export_all_sessions_payload(include_hidden=True)
    except Exception:
        return None
    configs = []
    for item in exported.get('sessions', []):
        proxies = []
        for row in item.get('rows', []):
            if not row.get('configured'):
                continue
            proxy = str(row.get('proxy', '')).strip()
            if proxy:
                proxies.append(proxy)
        sid = str(item.get('session', '')).strip()
        name = str(item.get('name') or '').strip() or 'Session ' + sid
        configs.append({'name': name, 'session': sid, 'proxies': proxies})
    if not configs:
        return None
    return {'action': 'sync_proxies', 'machine_id': get_machine_id(), 'router_name': get_app_title_prefix(), 'hostname': socket.gethostname(), 'exported_at': int(time.time()), 'configs': configs}

def push_proxies_to_sheet_once(force=False):
    payload = build_proxy_sync_payload()
    if not payload:
        return False
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    new_hash = hashlib.sha256(blob.encode('utf-8')).hexdigest()
    with _license_state['lock']:
        if not force:
            if new_hash == _proxy_sync_state['hash']:
                return False
            if _proxy_sync_state['fail_count'] >= 5 and time.time() - _proxy_sync_state.get('last_fail', 0) < 900:
                return False
        _proxy_sync_state['hash'] = new_hash
    req = urllib.request.Request(ACTIVE_URL, data=blob.encode('utf-8'), method='POST', headers={'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'genrouter-license'})
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            resp.read()
        with _license_state['lock']:
            _proxy_sync_state['fail_count'] = 0
            _proxy_sync_state['last_fail'] = 0
        return True
    except Exception:
        with _license_state['lock']:
            _proxy_sync_state['fail_count'] += 1
            _proxy_sync_state['last_fail'] = time.time()
            if _proxy_sync_state['fail_count'] < 5:
                _proxy_sync_state['hash'] = ''
        raise
PROXY_SHEET_STATE_FILE = BASE_DIR / 'sheet_sync_state.json'

def spawn_proxy_sheet_push():

    def _worker():
        try:
            push_proxies_to_sheet_once()
        except Exception:
            try:
                with _license_state['lock']:
                    _proxy_sync_state['fail_count'] += 1
            except Exception:
                pass
    try:
        threading.Thread(target=_worker, daemon=True).start()
    except Exception:
        pass

def load_collector_config():
    cfg = {'collector_url': DEFAULT_COLLECTOR_URL, 'router_id': '', 'remote_url': '', 'enabled': True, 'push_interval_sec': 60}
    try:
        if COLLECTOR_CONFIG_FILE.exists():
            data = load_json(COLLECTOR_CONFIG_FILE)
            if isinstance(data, dict):
                cfg.update(data)
    except Exception:
        pass
    return cfg

def save_collector_config(cfg):
    save_json(COLLECTOR_CONFIG_FILE, cfg)
    return cfg

def get_router_id():
    cfg = load_collector_config()
    router_id = str(cfg.get('router_id', '')).strip()
    if router_id:
        return router_id
    raw = f'{get_app_title_prefix()}|{socket.gethostname()}'
    router_id = 'router-' + hashlib.md5(raw.encode('utf-8')).hexdigest()[:12]
    cfg['router_id'] = router_id
    save_collector_config(cfg)
    return router_id

def push_export_to_collector_once():
    cfg = load_collector_config()
    collector_url = str(cfg.get('collector_url', '')).strip().rstrip('/')
    if not collector_url or not cfg.get('enabled'):
        return {'ok': False, 'error': 'collector disabled'}
    payload = export_all_sessions_payload(include_hidden=True)
    payload['router_id'] = get_router_id()
    payload['router_title'] = get_app_title_prefix()
    payload['remote_url'] = str(cfg.get('remote_url', '')).strip()
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(collector_url + '/api/collector/push', data=data, method='POST', headers={'Content-Type': 'application/json; charset=utf-8'})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode('utf-8'))

def collector_push_loop():
    while True:
        try:
            cfg = load_collector_config()
            interval = max(15, int(cfg.get('push_interval_sec', 60) or 60))
            if cfg.get('enabled') and str(cfg.get('collector_url', '')).strip():
                try:
                    push_export_to_collector_once()
                except Exception:
                    pass
            time.sleep(interval)
        except Exception:
            time.sleep(60)

def set_app_title_prefix(value):
    state = load_session_state()
    state, meta = get_meta_section(state)
    value = str(value or '').strip() or 'Genrouter'
    meta['app_title_prefix'] = value
    save_session_state(state)
    return value

def get_saved_ip_identity_text(session_id=None):
    state = load_session_state()
    _state, meta = get_meta_section(state)
    shared_text = str(meta.get('shared_ip_identity_text', '')).strip() if isinstance(meta, dict) else ''
    if shared_text:
        return shared_text
    values = meta.get('ip_identity_text', {}) if isinstance(meta, dict) else {}
    if not isinstance(values, dict):
        return ''
    if session_id is None:
        return ''
    return str(values.get(str(session_id), '')).strip()

def set_saved_ip_identity_text(session_id, text):
    state = load_session_state()
    state, meta = get_meta_section(state)
    normalized = normalize_ip_identity_text(text)
    meta['shared_ip_identity_text'] = normalized
    values = meta.setdefault('ip_identity_text', {}) if isinstance(meta, dict) else {}
    if not isinstance(values, dict):
        values = {}
        meta['ip_identity_text'] = values
    for sid in SESSION_FILES.keys():
        values[str(sid)] = normalized
    save_session_state(state)
    return normalized

def set_session_display_name(session_id, name):
    session_id = str(session_id)
    name = str(name or '').strip() or f'CẤU HÌNH {session_id}'
    state = load_session_state()
    state, meta = get_meta_section(state)
    names = meta.setdefault('session_names', {})
    if not isinstance(names, dict):
        meta['session_names'] = {}
        names = meta['session_names']
    names[session_id] = name
    save_session_state(state)
    return name

def sess_item(sess, tag):
    """Lay/tao item meta cua 1 tag trong session, tai su dung key da co
    (khong phan biet hoa/thuong: PROXY_5 va proxy_5 la cung 1 may)
    de tranh sinh key trung lam mat du lieu khi normalize."""
    want = str(tag or '').strip()
    if want:
        for k in list(sess.keys()):
            if str(k).lower() == want.lower():
                item = sess[k]
                if not isinstance(item, dict):
                    item = {}
                    sess[k] = item
                return item
    item = sess.setdefault(want, {})
    return item if isinstance(item, dict) else {}

def update_session_rows_meta(session_id, rows):
    session_id = str(session_id)
    state = load_session_state()
    sess = state.setdefault(session_id, {})
    for row in rows or []:
        tag = normalize_tag((row or {}).get('tag', ''))
        if not tag:
            continue
        item = sess_item(sess, tag)
        if 'note' in row:
            item['note'] = str(row.get('note', '')).strip()
        if 'vpn_account' in row:
            acc = str(row.get('vpn_account') or '').strip()
            if acc:
                item['vpn_account'] = acc
            else:
                item.pop('vpn_account', None)
        if 'pppoe_account' in row:
            pacc = str(row.get('pppoe_account') or '').strip()
            if pacc:
                item['pppoe_account'] = pacc
            else:
                item.pop('pppoe_account', None)
    save_session_state(state)

def normalize_mac(mac):
    mac = str(mac or '').strip().upper().replace('-', ':')
    return mac

def load_static_hosts_raw():
    if not STATIC_HOSTS_FILE.exists():
        return []
    try:
        data = json.loads(STATIC_HOSTS_FILE.read_text(encoding='utf-8'))
    except Exception:
        return []
    rows = []
    if isinstance(data, dict):
        for key, val in data.items():
            if not isinstance(val, dict):
                continue
            rows.append({'key': str(key), 'ip': str(val.get('ip', '')).strip(), 'mac': normalize_mac(val.get('mac', ''))})
    elif isinstance(data, list):
        for i, val in enumerate(data, 1):
            if not isinstance(val, dict):
                continue
            rows.append({'key': str(val.get('key') or i), 'ip': str(val.get('ip', '')).strip(), 'mac': normalize_mac(val.get('mac', ''))})
    return rows

def save_static_hosts_rows(rows):
    data = {}
    for i, row in enumerate(rows, 1):
        ip = str(row.get('ip', '')).strip()
        mac = normalize_mac(row.get('mac', ''))
        if not ip or not mac:
            continue
        data[str(i)] = {'ip': ip, 'mac': mac}
    save_json(STATIC_HOSTS_FILE, data)

def load_device_map():
    device_map = {}
    for row in load_static_hosts_raw():
        ip = str(row.get('ip', '')).strip()
        if not ip:
            continue
        device_map[ip] = {'mac': normalize_mac(row.get('mac', '')), 'status': 'offline'}
    if LEASES_FILE.exists():
        try:
            now = int(time.time())
            for line in LEASES_FILE.read_text(encoding='utf-8', errors='ignore').splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                expiry, mac, ip, _hostname = parts[:4]
                try:
                    online = int(expiry) > now
                except Exception:
                    online = True
                row = device_map.setdefault(ip, {})
                if not row.get('mac'):
                    row['mac'] = normalize_mac(mac)
                row['status'] = 'online' if online else 'offline'
        except Exception:
            pass
    # [Ver 2.83] Lease DHCP khong phan anh online that: leasetime 30d => may tat van
    # 'online' 30 ngay; may IP tinh/khong xin lai lease => 'offline' (Gen15: 15 lease
    # vs 187 ARP song). Nay ARP (neighbour) la nguon chinh, lease chi bo sung MAC.
    arp = _arp_online_map()
    if arp is not None:
        for ip, row in device_map.items():
            row['status'] = 'online' if ip in arp else 'offline'
        for ip, mac in arp.items():
            if ip not in device_map:
                device_map[ip] = {'mac': normalize_mac(mac), 'status': 'online'}
            elif not device_map[ip].get('mac'):
                device_map[ip]['mac'] = normalize_mac(mac)
    return device_map

ARP_ONLINE_MAX_S = 300

def _arp_online_map():
    """{ip: mac} cac may LAN dang song theo bang neighbour cua br-lan.
    Song = REACHABLE/DELAY/PROBE, hoac STALE ma lan xac nhan cuoi <= 300s.
    Tra None neu khong doc duoc (giu cach cu theo lease)."""
    try:
        out = subprocess.check_output(['ip', '-s', '-4', 'neigh', 'show', 'dev', 'br-lan'],
                                      text=True, timeout=5, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    res = {}
    for ln in out.splitlines():
        p = ln.split()
        if len(p) < 3 or 'lladdr' not in p:
            continue
        ip = p[0]
        mac = p[p.index('lladdr') + 1] if p.index('lladdr') + 1 < len(p) else ''
        st = p[-1].upper()
        if st in ('FAILED', 'INCOMPLETE', 'NONE'):
            continue
        ok = st in ('REACHABLE', 'DELAY', 'PROBE', 'PERMANENT')
        if not ok and st == 'STALE':
            m = re.search(r'used\s+(\d+)/(\d+)/(\d+)', ln)
            ok = bool(m) and int(m.group(2)) <= ARP_ONLINE_MAX_S
        if ok:
            res[ip] = mac
    return res

def build_route_ip_to_tag(data):
    route_by_ip = {}
    for rule in data.get('route', {}).get('rules', []):
        if str(rule.get('action', '')).strip() != 'route':
            continue
        ip = str(rule.get('source_ip_cidr', '')).strip()
        tag = str(rule.get('outbound', '')).strip()
        if not ip or not tag.startswith('proxy_'):
            continue
        route_by_ip[ip] = tag
    return route_by_ip

def build_tag_to_ip(data):
    mapping = {}
    for rule in data.get('route', {}).get('rules', []):
        if str(rule.get('action', '')).strip() != 'route':
            continue
        tag = str(rule.get('outbound', '')).strip()
        ip = str(rule.get('source_ip_cidr', '')).strip()
        if tag.startswith('proxy_') and ip and (tag not in mapping):
            mapping[tag] = ip
    for rule in data.get('dns', {}).get('rules', []):
        if str(rule.get('action', '')).strip() != 'route':
            continue
        tag = str(rule.get('server', '')).strip()
        ip = str(rule.get('source_ip_cidr', '')).strip()
        if tag.startswith('proxy_') and ip and (tag not in mapping):
            mapping[tag] = ip
    return mapping

def build_ip_identity_rows_from_data(data):
    mapping = build_tag_to_ip(data)
    rows = []
    for tag, ip in sorted(mapping.items(), key=lambda kv: proxy_tag_num(kv[0])):
        tag = str(tag).strip()
        ip = str(ip).strip()
        if not tag.startswith('proxy_') or not ip:
            continue
        rows.append({'machine': str(proxy_tag_num(tag)), 'tag': tag, 'ip': ip})
    return rows

def looks_like_default_full_mapping(data):
    rows = build_ip_identity_rows_from_data(data)
    if len(rows) < MAX_PROXY_TAG:
        return False
    first = rows[:3]
    if not first:
        return False
    expected = [('proxy_1', '192.15.4.1'), ('proxy_2', '192.15.4.2'), ('proxy_3', '192.15.4.3')]
    return [(r.get('tag'), r.get('ip')) for r in first] == expected
VPN_MAP_PATH = '/data/vpn/map.txt'

def load_vpn_map():
    mapping = {}
    try:
        with open(VPN_MAP_PATH, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    mapping[parts[0].strip()] = parts[1].strip()
    except OSError:
        pass
    return mapping

def format_proxy(outbound):
    server = str(outbound.get('server', '')).strip()
    port = outbound.get('server_port')
    user = str(outbound.get('username', '')).strip()
    password = str(outbound.get('password', '')).strip()
    if not server or not port:
        return ''
    return f'{server}:{port}:{user}:{password}'

def format_proxy_type(outbound):
    t = str((outbound or {}).get('type', '')).strip().lower()
    if t == 'http':
        return 'http'
    return 'socks5'

def extract_rows(data, session='1'):
    outbounds = {str(item.get('tag')): item for item in data.get('outbounds', []) if str(item.get('tag', '')).startswith('proxy_')}
    static_mac_by_ip = {str(row.get('ip', '')).strip(): normalize_mac(row.get('mac', '')) for row in load_static_hosts_raw() if str(row.get('ip', '')).strip()}
    devices = load_device_map()
    route_by_ip = {str(ip).strip(): normalize_tag(tag) for ip, tag in build_route_ip_to_tag(data).items() if str(ip).strip()}
    vpn_map = load_vpn_map()
    session_meta = get_session_meta(session)
    saved_text = get_saved_ip_identity_text(session)
    configured_rows = parse_ip_identity_text(saved_text) if saved_text else []
    saved_ip_to_tag = {str(item.get('ip', '')).strip(): normalize_tag(item.get('tag', '')) for item in configured_rows if str(item.get('ip', '')).strip()}
    rows = []
    configured_ips = set()
    for item in configured_rows:
        ip = str(item.get('ip', '')).strip()
        tag = normalize_tag(item.get('tag', '')) or route_by_ip.get(ip, '')
        machine = normalize_machine(item.get('machine', '')) or (str(proxy_tag_num(tag)) if tag else '')
        if not ip:
            continue
        configured_ips.add(ip)
        dev = devices.get(ip, {})
        meta = session_meta.get(tag, {}) if isinstance(session_meta, dict) and tag else {}
        outbound = outbounds.get(tag, {}) if tag else {}
        ob_type = str((outbound or {}).get('type', '')).strip().lower() if isinstance(outbound, dict) else ''
        # PPPoE luu outbound dang 'socks' (glider) hoac 'block' (glider chua san sang),
        # nen phai xet pppoe_account TRUOC kieu outbound; neu khong se hien thanh socks5
        # va lan Luu sau xoa mat pppoe_account.
        pppoe_acc = str((meta or {}).get('pppoe_account', '') or '').strip() if tag else ''
        if pppoe_acc:
            proxy_val, ptype = ('pppoe:' + pppoe_acc, 'pppoe')
        elif tag and ob_type == 'direct':
            vpn_acc = str((meta or {}).get('vpn_account', '') or '').strip() or vpn_map.get(ip, '')
            proxy_val, ptype = ('vpn:' + vpn_acc if vpn_acc else 'vpn:', 'vpn')
        else:
            proxy_val, ptype = (format_proxy(outbound), format_proxy_type(outbound))
        rows.append({'machine': machine, 'ip': ip, 'tag': tag, 'proxy': proxy_val, 'proxyType': ptype, 'mac': normalize_mac(static_mac_by_ip.get(ip, '') or dev.get('mac', '')), 'status': str(dev.get('status', 'offline')).strip() or 'offline', 'note': str(meta.get('note', '')).strip(), 'configured': True})
    auto_tags = effective_auto_ip_tags(configured_rows)
    for ip in sorted(set(str(k).strip() for k in devices) | set(auto_tags)):
        if not ip or ip in configured_ips:
            continue
        dev = devices.get(ip, {}) or {}
        tag = auto_tags.get(ip, '')
        machine = ''
        meta = session_meta.get(tag, {}) if isinstance(session_meta, dict) and tag else {}
        outbound = outbounds.get(tag, {}) if tag else {}
        ob_type = str((outbound or {}).get('type', '')).strip().lower() if isinstance(outbound, dict) else ''
        vpn_acc = vpn_map.get(ip, '')
        pppoe_acc = str((meta or {}).get('pppoe_account', '') or '').strip() if tag else ''
        if pppoe_acc:
            proxy_val, ptype = ('pppoe:' + pppoe_acc, 'pppoe')
        elif vpn_acc or (tag and ob_type == 'direct'):
            vpn_acc = str((meta or {}).get('vpn_account', '') or '').strip() or vpn_acc
            proxy_val, ptype = ('vpn:' + vpn_acc if vpn_acc else 'vpn:', 'vpn')
        else:
            proxy_val, ptype = (format_proxy(outbound), format_proxy_type(outbound) if outbound else 'socks5')
        rows.append({'machine': machine, 'ip': ip, 'tag': tag, 'proxy': proxy_val, 'proxyType': ptype, 'mac': normalize_mac(static_mac_by_ip.get(ip, '') or dev.get('mac', '')), 'status': str(dev.get('status', 'offline')).strip() or 'offline', 'note': str(meta.get('note', '')).strip(), 'configured': False})
    return rows

def migrate_proxy_dns_servers(data):
    """Doi cac DNS server cua proxy_* tu port 53/853 sang DoH 443.

    Ly do: proxy provider (lumi, ...) chan port 53 va tra SOCKS5 rep=2 =>
    moi DNS query cua client fail => web khong load. Ham nay tu chua config
    cu, chay moi lan apply va moi lan khoi dong app.
    Tra ve so entry da doi.
    """
    changed = 0
    try:
        servers = ((data or {}).get('dns') or {}).get('servers') or []
    except Exception:
        return 0
    for server in servers:
        if not isinstance(server, dict):
            continue
        if not str(server.get('tag', '')).strip().startswith('proxy_'):
            continue
        addr = str(server.get('address', '')).strip()
        if addr in PROXY_DNS_LEGACY_ADDRESSES or addr.startswith('tcp://') or addr.startswith('tls://'):
            server['address'] = PROXY_DNS_ADDRESS
            changed += 1
    return changed

def migrate_proxy_dns_file(path: Path):
    """Tu chua 1 file config tren disk. Tra ve so entry da doi (0 neu khong can)."""
    try:
        if not path.exists():
            return 0
        data = load_json(path)
    except Exception:
        return 0
    changed = migrate_proxy_dns_servers(data)
    changed += strip_catch_all_dns_rules(data)
    changed += ensure_dns_loop_breaker(data)
    changed += ensure_dns_local_detour(data)
    changed += ensure_dns_deny_last(data)
    changed += ensure_route_deny_last(data)
    # Ver 2.35: tu chua ca DINH DANG. File pretty lam awk cua vendor tproxy
    # khop 0 IP -> xoa sach rule TPROXY. Phat hien pretty thi ghi lai compact
    # ngay, du noi dung khong doi.
    need_compact = False
    try:
        need_compact = b'"source_ip_cidr": "' in Path(path).read_bytes()
    except Exception:
        need_compact = False
    if changed or need_compact:
        try:
            save_gencore_json(path, data)
        except Exception:
            return 0
        if need_compact and not changed:
            try:
                _wd_log(f'FORMAT-HEAL: ghi lai {Path(path).name} dang compact (vendor tproxy awk can)')
            except Exception:
                pass
    return changed

def apply_rows_to_data(data, rows_by_tag, session='1'):
    outbounds = data.setdefault('outbounds', [])
    outbound_idx = {str(item.get('tag')): i for i, item in enumerate(outbounds) if item.get('tag')}
    touched_rows = []
    for tag, row in rows_by_tag.items():
        proxy = str(row.get('proxy', '')).strip()
        proxy_type = str(row.get('proxyType', 'socks5') or 'socks5').strip().lower()
        set_outbound_proxy(outbounds, outbound_idx, tag, proxy, proxy_type)
        ptype_norm = str(proxy_type or 'socks5').strip().lower()
        vpn_acc_row = ''
        pppoe_acc_row = ''
        if ptype_norm == 'vpn' or str(proxy).startswith('vpn:'):
            vpn_acc_row = str(proxy).split(':', 1)[1].strip() if ':' in str(proxy) else ''
        if ptype_norm == 'pppoe' or str(proxy).startswith('pppoe:'):
            pppoe_acc_row = str(proxy).split(':', 1)[1].strip() if ':' in str(proxy) else ''
        touched_rows.append({'tag': tag, 'mac': row.get('mac', ''), 'note': row.get('note', ''), 'vpn_account': vpn_acc_row, 'pppoe_account': pppoe_acc_row})
    update_session_rows_meta(session, touched_rows)
    return data

_PPPOE_LAN_HOST_CACHE = {'ip': '', 'ts': 0.0}

def _pppoe_glider_lan_host():
    """IP LAN cua chinh router nay cho glider PPPoE (truoc day hard-code 192.15.0.1).
    Cache 300s vi set_outbound_proxy goi theo tung dong may."""
    import time as _t
    now = _t.time()
    if _PPPOE_LAN_HOST_CACHE['ip'] and now - _PPPOE_LAN_HOST_CACHE['ts'] < 300:
        return _PPPOE_LAN_HOST_CACHE['ip']
    ip = get_current_router_lan_ip()
    if ip:
        _PPPOE_LAN_HOST_CACHE.update(ip=ip, ts=now)
        return ip
    return _PPPOE_LAN_HOST_CACHE['ip'] or '192.15.0.1'

def set_outbound_proxy(outbounds, outbound_idx, tag, proxy, proxy_type='socks5'):
    idx = outbound_idx.get(tag)
    if idx is None:
        return
    if not proxy:
        outbounds[idx] = {'tag': tag, 'type': 'block'}
        return
    normalized_type = str(proxy_type or 'socks5').strip().lower()
    if normalized_type == 'vpn' or str(proxy).startswith('vpn:'):
        outbounds[idx] = {'tag': tag, 'type': 'direct'}
        return
    if normalized_type == 'pppoe' or str(proxy).startswith('pppoe:'):
        # pppoe:<id> -> SOCKS glider that cua phien khi Apply.
        sid = str(proxy).split(':', 1)[1].strip() if ':' in str(proxy) else ''
        info = pppoe_session_proxies().get(sid, {}) if sid else {}
        raw = str(info.get('socks') or '').strip()
        if raw:
            import urllib.parse as _u
            u = _u.urlparse(raw if '://' in raw else 'socks5://' + raw)
            host = (u.hostname or '').strip()
            if host in ('0.0.0.0', '127.0.0.1', 'localhost', ''): host = _pppoe_glider_lan_host()
            user = _u.unquote(u.username or ''); pw = _u.unquote(u.password or ''); port = int(u.port or 0)
            if host and port and user and pw:
                outbounds[idx] = {'tag': tag, 'type': 'socks', 'server': host, 'server_port': port, 'username': user, 'password': pw, 'version': '5'}
                return
        # [Ver 2.82] Khong lay duoc proxy glider (9000 loi + khong doc duoc glider):
        # truoc day ghi 'block' im lang => Apply 'thanh cong' ma may mat mang.
        # Nay giu outbound cu neu dung la glider cua phien nay, va bao loi len GUI.
        old = outbounds[idx] if isinstance(outbounds[idx], dict) else {}
        exp_port = pppoe_glider_port(sid)
        if old.get('type') == 'socks' and exp_port and int(old.get('server_port') or 0) == exp_port and old.get('username'):
            _PPPOE_APPLY_MISS.append({'tag': tag, 'sid': sid, 'kept': True})
            return
        _PPPOE_APPLY_MISS.append({'tag': tag, 'sid': sid, 'kept': False})
        outbounds[idx] = {'tag': tag, 'type': 'block'}
        return
    server, port, user, password = parse_proxy(proxy)
    if normalized_type == 'http':
        outbounds[idx] = {'tag': tag, 'type': 'http', 'server': server, 'server_port': port, 'username': user, 'password': password}
        return
    outbounds[idx] = {'tag': tag, 'type': 'socks', 'server': server, 'server_port': port, 'username': user, 'password': password, 'version': '5'}

def parse_proxy(proxy):
    parts = proxy.split(':')
    if len(parts) < 4:
        raise ValueError(f'Proxy không hợp lệ: {proxy}')
    server = parts[0].strip()
    port = int(parts[1].strip())
    user = parts[2].strip()
    password = ':'.join(parts[3:]).strip()
    return (server, port, user, password)

def clear_session_proxies(data):
    for item in data.get('outbounds', []):
        tag = str(item.get('tag', '')).strip()
        if tag.startswith('proxy_'):
            item.clear()
            item.update({'tag': tag, 'type': 'block'})

def remap_ip_by_tag(data):
    mapping = {}
    for i in range(1, MAX_PROXY_TAG + 1):
        mapping[f'proxy_{i}'] = tag_to_ip(f'proxy_{i}')
    rebuild_gencore_rules(data, mapping)
    return data

SPLIT_TAG = 'gen_split'
SPLIT_DEFAULT_DOMAINS = [
    '*.googlevideo.com', '*.fbcdn.net', '*.tiktokcdn.com', '*.ibyteimg.com', '*.tiktokcdn-us.com',
    '*.bromite.org', '*.ytimg.com', '*.ggpht.com', '*.gvt1.com', '*.gvt2.com', '*.googleusercontent.com',
    '*.fonts.gstatic.com', '*.gstatic.com', '*.googleapis.com', '*.googlezip.net', '*.cdn-apple.com',
    '*.apple.com', '*.icloud.com', '*.byteeffecttos-g.com', 'dl.google.com', 'downloadwa.b-cdn.net',
    '*.azureedge.net', 'www.gstatic.com',
]
_SPLIT_DOMAIN_RE = re.compile(r'^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)+$')

def parse_split_domains(text):
    """[Ver 2.91] Danh sach ten mien phan luong: '*.x' = x + moi ten mien con, 'a.b' = dung ten do."""
    items = text if isinstance(text, list) else re.split(r'[\s,;]+', str(text or ''))
    out, bad = [], []
    for raw in items:
        d = str(raw or '').strip().lower().rstrip('.')
        if d.startswith('sub:'):
            d = '*.' + d[4:].lstrip('*.')  # [Ver 2.94] sub:abc.com = *.abc.com
        if not d:
            continue
        if not _SPLIT_DOMAIN_RE.match(d):
            bad.append(str(raw).strip())
            continue
        if d not in out:
            out.append(d)
    if bad:
        raise ValueError('Ten mien khong hop le: ' + ', '.join(bad[:10]))
    if len(out) > 500:
        raise ValueError('Toi da 500 ten mien')
    return out

def get_split_config():
    try:
        meta = load_session_state().get('__meta__', {})
        c = meta.get('split', {}) if isinstance(meta, dict) else {}
    except Exception:
        c = {}
    if not isinstance(c, dict):
        c = {}
    doms = c.get('domains')
    if not isinstance(doms, list):
        doms = list(SPLIT_DEFAULT_DOMAINS)
    px = c.get('proxy') if isinstance(c.get('proxy'), dict) else {}
    return {'enabled': bool(c.get('enabled')), 'target': str(c.get('target') or ''), 'domains': [str(d) for d in doms], 'proxy': dict(px)}

def set_split_config(cfg):
    state = load_session_state()
    meta = state.setdefault('__meta__', {})
    if not isinstance(meta, dict):
        meta = {}
        state['__meta__'] = meta
    meta['split'] = {'enabled': bool(cfg.get('enabled')), 'target': str(cfg.get('target') or ''), 'domains': list(cfg.get('domains') or []),
                     'proxy': dict(cfg.get('proxy') or {})}
    save_session_state(state)

def _split_match_fields(domains):
    suffix, exact = [], []
    for d in domains or []:
        d = str(d).strip().lower()
        if not d:
            continue
        if d.startswith('*.'):
            if d[2:] not in suffix:
                suffix.append(d[2:])
        elif d not in exact:
            exact.append(d)
    # 'www.gstatic.com' da nam trong '*.gstatic.com' => bo cho gon
    exact = [d for d in exact if not any(d == x or d.endswith('.' + x) for x in suffix)]
    f = {}
    if exact:
        f['domain'] = exact
    if suffix:
        f['domain_suffix'] = suffix
    return f

SPLIT_TARGET_RE = re.compile(r'^(block|wan|proxy|pppoe:\d{1,3}|vpn:[A-Za-z0-9_.-]{1,40})$')

def parse_split_proxy(text, default_type='socks5'):
    """[Ver 2.93] Proxy duong tach. Nhan:
       socks5://user:pass@host:port | http://user:pass@host:port | host:port:user:pass | host:port
    Pass co '@' => lay toi '@' CUOI (giong 2.85)."""
    raw = str(text or '').strip()
    if not raw:
        raise ValueError('Chua nhap proxy')
    typ = str(default_type or 'socks5').strip().lower()
    m = re.match(r'^([a-z0-9]+)://(.*)$', raw, re.I)
    if m:
        sch = m.group(1).lower()
        rest = m.group(2).rstrip('/')
        if sch in ('socks5', 'socks5h', 'socks'):
            typ = 'socks5'
        elif sch == 'http':
            typ = 'http'
        else:
            raise ValueError('Chi ho tro socks5:// hoac http://')
        user = pw = ''
        if '@' in rest:
            cred, hp = rest.rsplit('@', 1)
            user, _, pw = cred.partition(':')
            user, pw = unquote(user), unquote(pw)
        else:
            hp = rest
        host, _, port = hp.rpartition(':')
    else:
        if typ not in ('socks5', 'http'):
            raise ValueError('Loai proxy phai la socks5 hoac http')
        parts = raw.split(':')
        if len(parts) == 2:
            host, port, user, pw = parts[0], parts[1], '', ''
        elif len(parts) >= 4:
            host, port, user, pw = parts[0], parts[1], parts[2], ':'.join(parts[3:])
        else:
            raise ValueError('Proxy sai dang (host:port hoac host:port:user:pass)')
    host = host.strip().strip('[]')
    if not host or not re.match(r'^[A-Za-z0-9_.:-]+$', host):
        raise ValueError('Host proxy khong hop le')
    try:
        port = int(str(port).strip())
    except Exception:
        raise ValueError('Port proxy khong hop le')
    if not (1 <= port <= 65535):
        raise ValueError('Port proxy khong hop le')
    if bool(user) != bool(pw):
        raise ValueError('Proxy can ca user lan pass (hoac bo trong ca hai)')
    return {'type': typ, 'server': host, 'port': port, 'username': user, 'password': pw}

def split_proxy_display(px):
    if not isinstance(px, dict) or not px.get('server'):
        return ''
    cred = (str(px.get('username')) + ':***@') if px.get('username') else ''
    return '%s://%s%s:%s' % (px.get('type') or 'socks5', cred, px.get('server'), px.get('port'))

def _net_dev_up(dev):
    try:
        return bool(dev) and Path('/sys/class/net/' + dev).exists()
    except Exception:
        return False

def _split_vpn_dev(name):
    for t in vpn_status_json() or []:
        if isinstance(t, dict) and str(t.get('name')) == name:
            return str(t.get('dev') or ''), bool(t.get('running'))
    return '', False

def build_split_outbound(target, old=None, cfg=None):
    """Outbound cua duong tach.
    'block' chan | 'wan' ra mang chinh (bang main) | 'pppoe:N' SOCKS glider phien N |
    'vpn:<ten>' bind vao dev tunnel (tunN/wgN) cua vpn_mgr | 'proxy' socks5/http nhap tay (cfg['proxy'])."""
    t = str(target or '').strip()
    tl = t.lower()
    if tl == 'block':
        return {'tag': SPLIT_TAG, 'type': 'block'}
    if tl == 'wan':
        return {'tag': SPLIT_TAG, 'type': 'direct'}
    if tl == 'proxy':
        px = (cfg or {}).get('proxy') or {}
        if not px.get('server'):
            raise ValueError('Chua nhap proxy cho duong tach')
        ob = {'tag': SPLIT_TAG, 'type': 'socks' if px.get('type') == 'socks5' else 'http',
              'server': str(px['server']), 'server_port': int(px['port'])}
        if ob['type'] == 'socks':
            ob['version'] = '5'
        if px.get('username'):
            ob['username'] = str(px['username'])
            ob['password'] = str(px.get('password') or '')
        return ob
    if tl.startswith('vpn:'):
        name = t.split(':', 1)[1].strip()
        if not re.match(r'^[A-Za-z0-9_.-]{1,40}$', name):
            raise ValueError('Ten VPN khong hop le')
        dev, running = _split_vpn_dev(name)
        if not dev:
            raise ValueError('Khong thay VPN %s' % name)
        if not (running and _net_dev_up(dev)):
            raise ValueError('VPN %s (%s) chua chay' % (name, dev))
        return {'tag': SPLIT_TAG, 'type': 'direct', 'bind_interface': dev}
    t = tl
    if t.startswith('pppoe:'):
        sid = t.split(':', 1)[1].strip()
        if not sid.isdigit() or not (1 <= int(sid) <= 999):
            raise ValueError('So phien PPPoE khong hop le')
        exp = pppoe_glider_port(sid)
        if isinstance(old, dict) and old.get('type') == 'socks' and int(old.get('server_port') or 0) == exp and old.get('username'):
            return dict(old)
        obs = [{'tag': SPLIT_TAG, 'type': 'block'}]
        n0 = len(_PPPOE_APPLY_MISS)
        set_outbound_proxy(obs, {SPLIT_TAG: 0}, SPLIT_TAG, 'pppoe:' + sid, 'pppoe')
        del _PPPOE_APPLY_MISS[n0:]
        if obs[0].get('type') != 'socks':
            raise ValueError('Khong lay duoc proxy glider cua phien PPPoE %s (phien chua len?)' % sid)
        return obs[0]
    raise ValueError('Chua chon duong tach')

def ensure_split_rules(data, cfg=None, strict=False):
    """[Ver 2.91] Phan luong: ten mien media/CDN cua may dang di proxy (socks/http) => di outbound
    gen_split (phien PPPoE rieng / chan) thay vi proxy tinh tien theo dung luong.
    - Rule dat NGAY TRUOC rule proxy_* dau tien (first-match-wins), chi ap cho IP dang co proxy that:
      may VPN (ra khoi gencore tu mangle) va may chua gan (block) khong bi mo duong.
    - Khong lay duoc proxy PPPoE (non-strict): giu outbound cu neu co, khong thi bo rule (may van
      di proxy chinh, khong mat mang).
    Tra ve 1 neu doi config."""
    try:
        cfg = cfg or get_split_config()
        route = data.setdefault('route', {})
        rules = list(route.get('rules') or [])
        obs = list(data.get('outbounds') or [])
        before = json.dumps([rules, obs], sort_keys=True)
        old_ob = next((o for o in obs if isinstance(o, dict) and o.get('tag') == SPLIT_TAG), None)
        rules = [r for r in rules if not (isinstance(r, dict) and r.get('outbound') == SPLIT_TAG)]
        obs = [o for o in obs if not (isinstance(o, dict) and o.get('tag') == SPLIT_TAG)]
        fields = _split_match_fields(cfg.get('domains'))
        if cfg.get('enabled') and fields:
            ob_type = {str(o.get('tag')): str(o.get('type', '')).lower() for o in obs if isinstance(o, dict)}
            ips = []
            for r in rules:
                if not (isinstance(r, dict) and r.get('action') == 'route' and str(r.get('outbound', '')).startswith('proxy_')):
                    continue
                ip = r.get('source_ip_cidr')
                if isinstance(ip, str) and ip.strip() and ob_type.get(str(r['outbound'])) in ('socks', 'http') and ip.strip() not in ips:
                    ips.append(ip.strip())
            ob = None
            if ips:
                try:
                    ob = build_split_outbound(cfg.get('target'), old_ob, cfg)
                except ValueError as e:
                    if strict:
                        raise
                    # pppoe: glider chap chon => giu outbound cu. vpn: tunnel chet => BO tach,
                    # may ve proxy chinh (giu bind vao dev chet = video chet).
                    ob = old_ob if str(cfg.get('target') or '').lower().startswith('pppoe:') else None
                    try:
                        _ss_log('SPLIT: %s => %s' % (e, 'giu outbound cu' if ob else 'tam bo rule, may di proxy chinh'))
                    except Exception:
                        pass
            if ob:
                pos = len(rules)
                for i, r in enumerate(rules):
                    if (isinstance(r, dict) and r.get('action') == 'route' and str(r.get('outbound', '')).startswith('proxy_')) or is_route_deny_rule(r):
                        pos = i
                        break
                rule = {'action': 'route', 'outbound': SPLIT_TAG, 'source_ip_cidr': ips}
                rule.update(fields)
                rules.insert(pos, rule)
                obs.append(ob)
        route['rules'] = rules
        data['outbounds'] = obs
        return 0 if json.dumps([rules, obs], sort_keys=True) == before else 1
    except ValueError:
        if strict:
            raise
        return 0
    except Exception as e:
        if strict:
            raise
        try:
            _ss_log('SPLIT loi: %s' % e)
        except Exception:
            pass
        return 0

def split_applied_count(doc):
    for r in ((doc or {}).get('route') or {}).get('rules') or []:
        if isinstance(r, dict) and r.get('outbound') == SPLIT_TAG:
            v = r.get('source_ip_cidr')
            return len(v) if isinstance(v, list) else 1
    return 0

def split_public_state():
    cfg = get_split_config()
    try:
        applied = split_applied_count(load_json(RUNTIME_SOURCE_FILE))
    except Exception:
        applied = 0
    vpns = []
    try:
        for t in vpn_status_json() or []:
            if isinstance(t, dict) and t.get('name'):
                vpns.append({'name': str(t['name']), 'dev': str(t.get('dev') or ''), 'running': bool(t.get('running')) and _net_dev_up(str(t.get('dev') or ''))})
    except Exception:
        pass
    px = cfg.get('proxy') or {}
    return {'ok': True, 'enabled': cfg['enabled'], 'target': cfg['target'], 'domains': cfg['domains'], 'applied': applied,
            'vpns': vpns, 'proxy': split_proxy_display(px), 'proxy_type': str(px.get('type') or '')}

def split_update(payload, strict=True):
    """Bat/tat/sua phan luong: ghi runtime + moi preset, genrunner check (loi => tra lai file cu),
    roi restart gencore nen. Tra ve trang thai moi."""
    new = dict(get_split_config())
    if 'domains' in payload:
        new['domains'] = parse_split_domains(payload.get('domains'))
    if 'target' in payload:
        t = str(payload.get('target') or '').strip().lower()
        t = str(payload.get('target') or '').strip()
        if t and not SPLIT_TARGET_RE.match(t if not t.lower().startswith('vpn:') else 'vpn:' + t[4:]):
            raise ValueError('Duong tach khong hop le')
        if not t.lower().startswith('vpn:'):
            t = t.lower()
        new['target'] = t
    if str(payload.get('proxy') or '').strip():
        new['proxy'] = parse_split_proxy(payload.get('proxy'), payload.get('proxy_type') or 'socks5')
    if 'enabled' in payload:
        new['enabled'] = bool(payload.get('enabled'))
    if new['enabled']:
        if not new['domains']:
            raise ValueError('Danh sach ten mien trong')
        if strict:
            build_split_outbound(new['target'], None, new)
    if _apply_lock_active():
        raise ValueError('Dang Apply, thu lai sau vai giay')
    files = [RUNTIME_SOURCE_FILE]
    if str(RUNTIME_FILE) != str(RUNTIME_SOURCE_FILE):
        files.append(RUNTIME_FILE)
    files += list(SESSION_FILES.values())
    runtime_names = {str(RUNTIME_SOURCE_FILE), str(RUNTIME_FILE)}
    backups, changed_runtime = {}, False
    _apply_lock_acquire('split')
    try:
        try:
            for f in files:
                p = Path(f)
                if not p.exists() or str(p) in backups:
                    continue
                raw = p.read_text(encoding='utf-8')
                doc = json.loads(raw)
                if ensure_split_rules(doc, cfg=new, strict=strict):
                    backups[str(p)] = raw
                    save_gencore_json(p, doc)
                    if str(p) in runtime_names:
                        changed_runtime = True
            if changed_runtime and GENRUNNER.exists():
                proc = subprocess.run([str(GENRUNNER), 'check', '-c', str(RUNTIME_SOURCE_FILE)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
                if proc.returncode != 0:
                    raise ValueError('genrunner check loi, da tra lai config cu: ' + ((proc.stderr or proc.stdout or '').strip()[:300]))
        except Exception:
            for f, raw in backups.items():
                try:
                    _ss_atomic_write(Path(f), raw)
                except Exception:
                    pass
            raise
        set_split_config(new)
    finally:
        _apply_lock_release()
    if changed_runtime:
        threading.Thread(target=gencore_restart_detached, args=('split',), daemon=True).start()
    try:
        _ss_log('SPLIT: enabled=%s target=%s domains=%d files=%d restart=%s' % (new['enabled'], new['target'] or '-', len(new['domains']), len(backups), changed_runtime))
    except Exception:
        pass
    out = split_public_state()
    out['restarted'] = changed_runtime
    return out

def split_watch_loop():
    """[Ver 2.93] Duong tach = VPN: tunnel chet => bo tach (may ve proxy chinh, khong mat video);
    tunnel song lai => tach lai. Kiem moi 30s, doi config toi da 1 lan / 120s, log SPLIT-WATCH."""
    last_fix = 0.0
    while True:
        time.sleep(30)
        try:
            cfg = get_split_config()
            if not (cfg.get('enabled') and str(cfg.get('target') or '').lower().startswith('vpn:')):
                continue
            if _apply_lock_active() or time.time() - last_fix < 120:
                continue
            doc = load_json(RUNTIME_SOURCE_FILE)
            probe = json.loads(json.dumps(doc))
            if not ensure_split_rules(probe, cfg=cfg):
                continue
            last_fix = time.time()
            r = split_update({}, strict=False)
            _ss_log('SPLIT-WATCH: %s => tach %d may, restart=%s' % (cfg.get('target'), r.get('applied', 0), r.get('restarted')))
        except Exception as e:
            try:
                _ss_log('SPLIT-WATCH loi: %s' % e)
            except Exception:
                pass

# ===================== [Ver 2.94] CAU HINH KET NOI =====================
# __meta__.conn = {
#   direct: [IP]            may ra WAN truc tiep (khong proxy/VPN)
#   iso_allow: [IP|MAC]     ngoai le co lap LAN (noi chuyen voi nhau)
#   iso_master: [IP|MAC]    may master them (192.10.1.10 luon co)
#   udp_block: bool         chan UDP may proxy/VPN (giu DNS 53)
#   webrtc: 'block'|'off'   chan STUN (3478, 5349, 19302-19309)
#   bypass: [ten mien|IP]   khong qua proxy (ra WAN)
#   block:  [ten mien|IP]   chan han
#   fixed: ten mien/IP di duong co dinh = split cu (target/proxy giu trong __meta__.split)
# }
CONN_FIXED_MASTER = '192.10.1.10'
CONN_BYPASS_TAG = 'gen_bypass'
CONN_DIRECT_TAG = 'direct'
ISO_MASTER_FILE = '/data/vpn/isolate.master'
ISO_ALLOW_FILE = '/data/vpn/isolate.allow'
CONN_VPN_SCRIPT = '/data/vpn/gen_conn_vpn.sh'
_CONN_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')
_CONN_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def _conn_valid_ip(s):
    if not _CONN_IP_RE.match(s):
        return False
    a = s.split('/')[0].split('.')
    if any(int(x) > 255 for x in a):
        return False
    return '/' not in s or int(s.split('/')[1]) <= 32

def parse_conn_items(text, allow_domain=True, allow_ip=True, allow_mac=False, limit=1000, label='muc'):
    items = text if isinstance(text, list) else re.split(r'[\s,;]+', str(text or ''))
    out, bad = [], []
    for raw in items:
        d = str(raw or '').strip().lower().rstrip('.')
        if d.startswith('sub:'):
            d = '*.' + d[4:].lstrip('*.')  # [Ver 2.94] sub:abc.com = *.abc.com
        if not d or d.startswith('#'):
            continue
        numeric = bool(re.match(r'^[\d./]+$', d))
        ok = (allow_ip and _conn_valid_ip(d)) or (allow_mac and _CONN_MAC_RE.match(d.replace('-', ':'))) \
            or (allow_domain and not numeric and _SPLIT_DOMAIN_RE.match(d))
        if not ok:
            bad.append(str(raw).strip())
            continue
        d = d.replace('-', ':') if allow_mac and _CONN_MAC_RE.match(d.replace('-', ':')) else d
        if d not in out:
            out.append(d)
    if bad:
        raise ValueError('%s khong hop le: %s' % (label, ', '.join(bad[:10])))
    if len(out) > limit:
        raise ValueError('Toi da %d %s' % (limit, label))
    return out

def _conn_split_fields(items):
    """ten mien -> domain/domain_suffix, IP/CIDR -> ip_cidr (sing-box)."""
    doms = [x for x in items or [] if not _conn_valid_ip(x)]
    ips = [x if '/' in x else x + '/32' for x in items or [] if _conn_valid_ip(x)]
    f = _split_match_fields(doms)
    if ips:
        f['ip_cidr'] = ips
    return f

def get_conn_config():
    try:
        meta = load_session_state().get('__meta__', {})
        c = meta.get('conn') if isinstance(meta, dict) else None
    except Exception:
        c = None
    if not isinstance(c, dict):
        c = {}
    L = lambda k: [str(x) for x in c.get(k) or []] if isinstance(c.get(k), list) else []
    return {'direct': L('direct'), 'iso_allow': L('iso_allow'), 'iso_master': L('iso_master'),
            'udp_block': bool(c.get('udp_block', True)), 'webrtc': 'off' if c.get('webrtc') == 'off' else 'block',
            'bypass': L('bypass'), 'block': L('block'), 'migrated': bool(c.get('migrated'))}

def set_conn_config(cfg):
    state = load_session_state()
    meta = state.setdefault('__meta__', {})
    if not isinstance(meta, dict):
        meta = {}
        state['__meta__'] = meta
    keep = ('direct', 'iso_allow', 'iso_master', 'udp_block', 'webrtc', 'bypass', 'block')
    meta['conn'] = dict({k: cfg.get(k) for k in keep}, migrated=True)
    save_session_state(state)

def conn_migrate_once():
    """2.93 -> 2.94: Phan luong cu thanh danh sach 'duong co dinh' (giu nguyen __meta__.split).
    Chi danh dau migrated; khong doi hanh vi mang."""
    try:
        cfg = get_conn_config()
        if cfg['migrated']:
            return
        set_conn_config(cfg)
        _ss_log('CONN: migrate 2.93 -> 2.94 (split giu nguyen lam danh sach duong co dinh)')
    except Exception as e:
        try:
            _ss_log('CONN migrate loi: %s' % e)
        except Exception:
            pass

def _conn_proxy_ips(rules, obs):
    ob_type = {str(o.get('tag')): str(o.get('type', '')).lower() for o in obs if isinstance(o, dict)}
    ips = []
    for r in rules:
        if isinstance(r, dict) and r.get('action') == 'route' and str(r.get('outbound', '')).startswith('proxy_'):
            ip = r.get('source_ip_cidr')
            if isinstance(ip, str) and ip.strip() and ob_type.get(str(r['outbound'])) not in ('direct', '') and ip.strip() not in ips:
                ips.append(ip.strip())
    return ips

def _is_conn_rule(r):
    return isinstance(r, dict) and (r.get('_gen') == 'conn' or (r.get('outbound') == CONN_BYPASS_TAG))

def ensure_conn_rules(data, cfg=None):
    """[Ver 2.94] Rule gencore cho may proxy/PPPoE (may VPN da RETURN khoi gencore o mangle):
      1. block  : ten mien/IP => reject
      2. bypass : ten mien/IP => outbound gen_bypass (direct, ra WAN)
      3. direct : IP may => outbound direct (toan bo)
    Chen NGAY TRUOC rule proxy_* dau tien / deny (first-match-wins), sau rule split. Tra ve 1 neu doi.
    sing-box khong cho key la => danh dau bang outbound/action, KHONG them field rieng."""
    try:
        cfg = cfg if cfg is not None else get_conn_config()
        route = data.setdefault('route', {})
        rules = list(route.get('rules') or [])
        obs = list(data.get('outbounds') or [])
        before = json.dumps([rules, obs], sort_keys=True)
        def mine(r):
            if not isinstance(r, dict):
                return False
            if r.get('outbound') == CONN_BYPASS_TAG:
                return True
            if r.get('action') == 'reject' and r.get('method') == 'default' and r.get('source_ip_cidr') and (r.get('domain') or r.get('domain_suffix') or r.get('ip_cidr')):
                return True
            if r.get('action') == 'route' and r.get('outbound') == CONN_DIRECT_TAG and set(r.keys()) == {'action', 'outbound', 'source_ip_cidr'}:
                return True
            return False
        rules = [r for r in rules if not mine(r)]
        obs = [o for o in obs if not (isinstance(o, dict) and o.get('tag') == CONN_BYPASS_TAG)]
        ips = _conn_proxy_ips(rules, obs)
        new = []
        fb = _conn_split_fields(cfg.get('block'))
        if ips and fb:
            r = {'action': 'reject', 'method': 'default', 'source_ip_cidr': list(ips)}
            r.update(fb)
            new.append(r)
        fp = _conn_split_fields(cfg.get('bypass'))
        if ips and fp:
            r = {'action': 'route', 'outbound': CONN_BYPASS_TAG, 'source_ip_cidr': list(ips)}
            r.update(fp)
            new.append(r)
            obs.append({'tag': CONN_BYPASS_TAG, 'type': 'direct'})
        dips = [x if '/' in x else x for x in cfg.get('direct') or [] if _conn_valid_ip(x)]
        has_direct = any(isinstance(o, dict) and o.get('tag') == CONN_DIRECT_TAG for o in obs)
        if dips and has_direct:
            # 1 rule / IP, source_ip_cidr dang CHUOI: tproxy + killswitch lay danh sach client bang
            # awk -F'"source_ip_cidr":"' => dang list se khong duoc TPROXY + bi chan DNS.
            for ip in dips:
                new.append({'action': 'route', 'outbound': CONN_DIRECT_TAG, 'source_ip_cidr': ip})
        if new:
            pos = len(rules)
            for i, r in enumerate(rules):
                if (isinstance(r, dict) and r.get('action') == 'route' and (str(r.get('outbound', '')).startswith('proxy_') or r.get('outbound') == SPLIT_TAG)) or is_route_deny_rule(r):
                    pos = i
                    break
            rules[pos:pos] = new
        route['rules'] = rules
        data['outbounds'] = obs
        return 0 if json.dumps([rules, obs], sort_keys=True) == before else 1
    except Exception as e:
        try:
            _ss_log('CONN loi: %s' % e)
        except Exception:
            pass
        return 0

def _conn_write_iso_files(cfg):
    os.makedirs('/data/vpn', exist_ok=True)
    masters = [CONN_FIXED_MASTER] + [x for x in cfg.get('iso_master') or [] if x != CONN_FIXED_MASTER]
    _ss_atomic_write(Path(ISO_MASTER_FILE), '# [Ver 2.94] may master (GUI 9001). 192.10.1.10 luon co.\n' + '\n'.join(masters) + '\n')
    _ss_atomic_write(Path(ISO_ALLOW_FILE), '# [Ver 2.94] ngoai le co lap LAN (GUI 9001)\n' + '\n'.join(cfg.get('iso_allow') or []) + '\n')

def conn_apply_system(cfg=None):
    """Phan ngoai gencore: file isolate + script VPN (dnsmasq nftset, mangle, STUN, UDP). Tra ve list ket qua."""
    cfg = cfg or get_conn_config()
    out = []
    try:
        _conn_write_iso_files(cfg)
        if os.path.exists('/etc/init.d/client-isolate'):
            r = subprocess.run(['/etc/init.d/client-isolate', 'start'], capture_output=True, text=True, timeout=20)
            out.append({'cmd': 'client-isolate', 'ok': r.returncode == 0, 'out': (r.stdout + r.stderr).strip()[-300:]})
    except Exception as e:
        out.append({'cmd': 'client-isolate', 'ok': False, 'out': str(e)})
    try:
        src = BASE_DIR / 'tools' / 'gen_conn_vpn.sh'
        if src.exists():
            shutil.copy(str(src), CONN_VPN_SCRIPT)
            os.chmod(CONN_VPN_SCRIPT, 493)
            lst = lambda k: ' '.join(cfg.get(k) or [])
            env = dict(os.environ, CONN_BYPASS=lst('bypass'), CONN_BLOCK=lst('block'), CONN_DIRECT=lst('direct'),
                       CONN_UDP='1' if cfg.get('udp_block') else '0', CONN_WEBRTC=cfg.get('webrtc') or 'block')
            # luu tham so de cron/boot chay lai giong het
            _ss_atomic_write(Path('/data/vpn/gen_conn.env'), ''.join("%s='%s'\n" % (k, env[k].replace("'", '')) for k in ('CONN_BYPASS', 'CONN_BLOCK', 'CONN_DIRECT', 'CONN_UDP', 'CONN_WEBRTC')))
            r = subprocess.run(['sh', CONN_VPN_SCRIPT, 'apply'], capture_output=True, text=True, timeout=60, env=env)
            out.append({'cmd': 'gen_conn_vpn', 'ok': r.returncode == 0, 'out': (r.stdout + r.stderr).strip()[-500:]})
    except Exception as e:
        out.append({'cmd': 'gen_conn_vpn', 'ok': False, 'out': str(e)})
    return out

def conn_public_state():
    cfg = get_conn_config()
    sp = split_public_state()
    iso = {}
    try:
        iso = vpn_run(['isolate', 'status'])
    except Exception:
        pass
    vpn_ips = sorted(load_vpn_map().keys())
    return {'ok': True, 'conn': cfg, 'fixed_master': CONN_FIXED_MASTER, 'split': sp, 'vpn_ips': vpn_ips,
            'isolate': str(iso.get('output') or '').strip(), 'stun_ports': '3478, 5349, 19302-19309'}

def conn_update(payload):
    """POST /api/pm/conn. payload co the chua: direct, iso_allow, iso_master, udp_block, webrtc, bypass, block,
    isolate ('two-way'|'off'), split {...} (chuyen sang split_update cho danh sach duong co dinh)."""
    new = dict(get_conn_config())
    if 'direct' in payload:
        d = parse_conn_items(payload.get('direct'), allow_domain=False, limit=1000, label='IP may truc tiep')
        d = [x for x in d if '/' not in x]
        clash = sorted(set(d) & set(load_vpn_map().keys()))
        if clash:
            raise ValueError('May dang gan VPN, khong cho ra truc tiep: ' + ', '.join(clash[:10]))
        new['direct'] = d
    if 'iso_allow' in payload:
        new['iso_allow'] = parse_conn_items(payload.get('iso_allow'), allow_domain=False, allow_mac=True, limit=500, label='ngoai le')
    if 'iso_master' in payload:
        new['iso_master'] = [x for x in parse_conn_items(payload.get('iso_master'), allow_domain=False, allow_mac=True, limit=20, label='may master') if x != CONN_FIXED_MASTER]
    if 'udp_block' in payload:
        new['udp_block'] = bool(payload.get('udp_block'))
    if 'webrtc' in payload:
        new['webrtc'] = 'off' if str(payload.get('webrtc')) == 'off' else 'block'
    for k in ('bypass', 'block'):
        if k in payload:
            new[k] = parse_conn_items(payload.get(k), limit=1000, label='ten mien/IP')
    both = sorted(set(new['bypass']) & set(new['block']))
    if both:
        raise ValueError('Trung giua Khong qua proxy va Chan: ' + ', '.join(both[:10]))
    results = []
    if isinstance(payload.get('split'), dict):
        results.append({'cmd': 'split', 'ok': True, 'state': split_update(payload['split'])})
    if str(payload.get('isolate') or '') in ('two-way', 'off'):
        r = vpn_run(['isolate', str(payload['isolate'])])
        results.append({'cmd': 'isolate', 'ok': bool(r.get('ok')), 'out': str(r.get('output') or r.get('error') or '')[-200:]})
    if _apply_lock_active():
        raise ValueError('Dang Apply, thu lai sau vai giay')
    files = [RUNTIME_SOURCE_FILE]
    if str(RUNTIME_FILE) != str(RUNTIME_SOURCE_FILE):
        files.append(RUNTIME_FILE)
    files += list(SESSION_FILES.values())
    runtime_names = {str(RUNTIME_SOURCE_FILE), str(RUNTIME_FILE)}
    backups, changed_runtime = {}, False
    _apply_lock_acquire('conn')
    try:
        try:
            for f in files:
                p = Path(f)
                if not p.exists() or str(p) in backups:
                    continue
                raw = p.read_text(encoding='utf-8')
                doc = json.loads(raw)
                if ensure_conn_rules(doc, cfg=new):
                    backups[str(p)] = raw
                    save_gencore_json(p, doc)
                    if str(p) in runtime_names:
                        changed_runtime = True
            if changed_runtime and GENRUNNER.exists():
                proc = subprocess.run([str(GENRUNNER), 'check', '-c', str(RUNTIME_SOURCE_FILE)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
                if proc.returncode != 0:
                    raise ValueError('genrunner check loi, da tra lai config cu: ' + ((proc.stderr or proc.stdout or '').strip()[:300]))
        except Exception:
            for f, raw in backups.items():
                try:
                    _ss_atomic_write(Path(f), raw)
                except Exception:
                    pass
            raise
        set_conn_config(new)
    finally:
        _apply_lock_release()
    if changed_runtime:
        threading.Thread(target=gencore_restart_detached, args=('conn',), daemon=True).start()
    results += conn_apply_system(new)
    try:
        _ss_log('CONN: direct=%d allow=%d master=%d udp=%s webrtc=%s bypass=%d block=%d restart=%s' % (
            len(new['direct']), len(new['iso_allow']), len(new['iso_master']) + 1, new['udp_block'], new['webrtc'],
            len(new['bypass']), len(new['block']), changed_runtime))
    except Exception:
        pass
    out = conn_public_state()
    out['restarted'] = changed_runtime
    out['results'] = results
    return out

def conn_watch_loop():
    """[Ver 2.94] Sau boot + khi map.txt doi (gan/bo VPN): chay lai gen_conn_vpn.sh de set vpn_clients dung.
    Chi chay khi da tung luu cau hinh (co /data/vpn/gen_conn.env). Kiem moi 20s."""
    last = None
    time.sleep(15)
    while True:
        try:
            if os.path.exists('/data/vpn/gen_conn.env') and os.path.exists(CONN_VPN_SCRIPT):
                try:
                    st = os.stat(VPN_MAP_PATH)
                    sig = (st.st_mtime, st.st_size)
                except OSError:
                    sig = None
                alive = subprocess.run(['nft', 'list', 'table', 'inet', 'gen_conn'], capture_output=True, timeout=5).returncode == 0
                if sig != last or not alive:
                    r = subprocess.run(['sh', CONN_VPN_SCRIPT, 'apply'], capture_output=True, text=True, timeout=60)
                    if r.returncode != 0 or sig != last:
                        _ss_log('CONN-WATCH: %s' % ((r.stdout + r.stderr).strip()[-200:]))
                    last = sig
        except Exception as e:
            try:
                _ss_log('CONN-WATCH loi: %s' % e)
            except Exception:
                pass
        time.sleep(20)

FLOW_API_ADDR = '127.0.0.1:19090'
FLOW_MAX_KEYS = 5000
FLOW = {'lock': threading.Lock(), 'agg': {}, 'last': {}, 'since': 0.0, 'last_req': 0.0, 'thread': None, 'err': '', 'polls': 0}

def get_flow_config():
    try:
        meta = load_session_state().get('__meta__', {})
        c = meta.get('flow', {}) if isinstance(meta, dict) else {}
    except Exception:
        c = {}
    return c if isinstance(c, dict) else {}

def _flow_secret(create=False):
    c = get_flow_config()
    sec = str(c.get('secret') or '')
    if not sec and create:
        sec = base64.urlsafe_b64encode(os.urandom(18)).decode('ascii').rstrip('=')
    return sec

def set_flow_config(enabled, secret):
    state = load_session_state()
    meta = state.setdefault('__meta__', {})
    if not isinstance(meta, dict):
        meta = {}
        state['__meta__'] = meta
    meta['flow'] = {'enabled': bool(enabled), 'secret': str(secret or '')}
    save_session_state(state)

def ensure_flow_api(data, cfg=None):
    """[Ver 2.92] Theo doi luong: bat Clash API cua gencore (sing-box) CHI tren 127.0.0.1, co secret.
    Tat thi go experimental.clash_api. Tra ve 1 neu doi config."""
    try:
        cfg = cfg if cfg is not None else get_flow_config()
        exp = data.get('experimental')
        before = json.dumps(exp, sort_keys=True)
        on = bool(cfg.get('enabled')) and bool(cfg.get('secret'))
        if on:
            exp = dict(exp) if isinstance(exp, dict) else {}
            exp['clash_api'] = {'external_controller': FLOW_API_ADDR, 'secret': str(cfg.get('secret'))}
            data['experimental'] = exp
        elif isinstance(exp, dict) and 'clash_api' in exp:
            exp = dict(exp)
            exp.pop('clash_api', None)
            if exp:
                data['experimental'] = exp
            else:
                data.pop('experimental', None)
        return 0 if json.dumps(data.get('experimental'), sort_keys=True) == before else 1
    except Exception:
        return 0

def _flow_kind(chain):
    c = str(chain or '')
    if c == SPLIT_TAG:
        return 'split'
    if c.startswith('proxy_'):
        return 'proxy'
    if c == 'direct':
        return 'direct'
    return 'other'

def _flow_fetch():
    req = urllib.request.Request('http://%s/connections' % FLOW_API_ADDR, headers={'Authorization': 'Bearer ' + _flow_secret()})
    with urllib.request.urlopen(req, timeout=4) as r:
        return json.loads(r.read().decode('utf-8', 'replace') or '{}')

def flow_ingest(snapshot, agg, last):
    """Cong DELTA byte cua tung ket noi (id) vao agg[(ip, host, chain)]. Ket noi da dong bi bo khoi last.
    Ket noi dong giua 2 lan doc mat phan byte cuoi (< 2s) — sai so nho, ghi ro tren GUI."""
    seen = set()
    for c in (snapshot or {}).get('connections') or []:
        if not isinstance(c, dict):
            continue
        cid = str(c.get('id') or '')
        if not cid:
            continue
        seen.add(cid)
        md = c.get('metadata') or {}
        ip = str(md.get('sourceIP') or '')
        host = str(md.get('host') or '') or str(md.get('destinationIP') or '')
        chains = c.get('chains') or []
        chain = str(chains[0]) if chains else ''
        up, down = int(c.get('upload') or 0), int(c.get('download') or 0)
        pu, pd = last.get(cid, (0, 0))
        du, dd = max(0, up - pu), max(0, down - pd)
        last[cid] = (up, down)
        key = (ip, host, chain)
        a = agg.get(key)
        if a is None:
            if len(agg) >= FLOW_MAX_KEYS:
                key = (ip, '(khac)', chain)
                a = agg.get(key)
            if a is None:
                a = agg[key] = {'up': 0, 'down': 0, 'conns': 0, 'ids': set()}
        a['up'] += du
        a['down'] += dd
        if cid not in a['ids']:
            a['ids'].add(cid)
            a['conns'] += 1
            if len(a['ids']) > 2000:
                a['ids'] = set()
    for cid in list(last):
        if cid not in seen:
            last.pop(cid, None)

def _flow_loop():
    while True:
        with FLOW['lock']:
            idle = time.time() - FLOW['last_req'] > 600
            if idle:
                FLOW['thread'] = None
                FLOW['last'] = {}
                return
        try:
            snap = _flow_fetch()
            with FLOW['lock']:
                flow_ingest(snap, FLOW['agg'], FLOW['last'])
                FLOW['err'] = ''
                FLOW['polls'] += 1
        except Exception as e:
            with FLOW['lock']:
                FLOW['err'] = str(e)[:200]
        time.sleep(2)

def _flow_touch():
    with FLOW['lock']:
        FLOW['last_req'] = time.time()
        if not FLOW['since']:
            FLOW['since'] = time.time()
        if FLOW['thread'] is None:
            t = threading.Thread(target=_flow_loop, daemon=True, name='flow-monitor')
            FLOW['thread'] = t
            t.start()

def flow_reset():
    with FLOW['lock']:
        FLOW['agg'] = {}
        FLOW['since'] = time.time()
        FLOW['polls'] = 0

def flow_summary(agg, ip=''):
    ip = str(ip or '').strip()
    rows, totals = [], {'proxy': 0, 'split': 0, 'direct': 0, 'other': 0}
    for (sip, host, chain), a in agg.items():
        if ip and sip != ip:
            continue
        b = a['up'] + a['down']
        k = _flow_kind(chain)
        totals[k] += b
        rows.append({'ip': sip, 'host': host, 'out': chain, 'kind': k, 'up': a['up'], 'down': a['down'], 'bytes': b, 'conns': a['conns']})
    rows.sort(key=lambda r: -r['bytes'])
    return rows[:300], totals

def flow_public_state(ip=''):
    cfg = get_flow_config()
    enabled = bool(cfg.get('enabled'))
    out = {'ok': True, 'enabled': enabled, 'available': False, 'since': 0, 'rows': [], 'totals': {}, 'ips': [], 'error': ''}
    if not enabled:
        return out
    _flow_touch()
    with FLOW['lock']:
        agg = dict(FLOW['agg'])
        out['since'] = int(FLOW['since'])
        out['error'] = FLOW['err']
        out['available'] = FLOW['polls'] > 0 and not FLOW['err']
    out['rows'], out['totals'] = flow_summary(agg, ip)
    out['ips'] = sorted({k[0] for k in agg if k[0]}, key=lambda x: [int(p) if p.isdigit() else 0 for p in x.split('.')])
    return out

def flow_update(payload):
    action = str(payload.get('action') or '').strip()
    if action == 'reset':
        flow_reset()
        return flow_public_state(payload.get('ip', ''))
    if action not in ('enable', 'disable'):
        raise ValueError('action khong hop le')
    on = action == 'enable'
    cfg = {'enabled': on, 'secret': _flow_secret(create=True)}
    if _apply_lock_active():
        raise ValueError('Dang Apply, thu lai sau vai giay')
    files = [RUNTIME_SOURCE_FILE]
    if str(RUNTIME_FILE) != str(RUNTIME_SOURCE_FILE):
        files.append(RUNTIME_FILE)
    files += list(SESSION_FILES.values())
    runtime_names = {str(RUNTIME_SOURCE_FILE), str(RUNTIME_FILE)}
    backups, changed_runtime = {}, False
    _apply_lock_acquire('flow')
    try:
        try:
            for f in files:
                p = Path(f)
                if not p.exists() or str(p) in backups:
                    continue
                raw = p.read_text(encoding='utf-8')
                doc = json.loads(raw)
                if ensure_flow_api(doc, cfg):
                    backups[str(p)] = raw
                    save_gencore_json(p, doc)
                    if str(p) in runtime_names:
                        changed_runtime = True
            if changed_runtime and GENRUNNER.exists():
                proc = subprocess.run([str(GENRUNNER), 'check', '-c', str(RUNTIME_SOURCE_FILE)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
                if proc.returncode != 0:
                    raise ValueError('genrunner check loi, da tra lai config cu: ' + ((proc.stderr or proc.stdout or '').strip()[:300]))
        except Exception:
            for f, raw in backups.items():
                try:
                    _ss_atomic_write(Path(f), raw)
                except Exception:
                    pass
            raise
        set_flow_config(on, cfg['secret'])
    finally:
        _apply_lock_release()
    if changed_runtime:
        threading.Thread(target=gencore_restart_detached, args=('flow',), daemon=True).start()
    flow_reset()
    try:
        _ss_log('FLOW: enabled=%s files=%d restart=%s' % (on, len(backups), changed_runtime))
    except Exception:
        pass
    out = flow_public_state(payload.get('ip', ''))
    out['restarted'] = changed_runtime
    return out

def rebuild_gencore_rules(data, tag_to_ip_map):
    dns = data.setdefault('dns', {})
    route = data.setdefault('route', {})
    outbounds = data.setdefault('outbounds', [])
    input_map = {str(tag).strip(): str(ip).strip() for tag, ip in (tag_to_ip_map or {}).items() if str(tag).strip().startswith('proxy_') and str(ip).strip()}
    ordered_items = sorted(input_map.items(), key=lambda kv: proxy_tag_num(kv[0]))
    old_dns_rules = list(dns.get('rules', []) or [])
    old_dns_servers = list(dns.get('servers', []) or [])
    old_route_rules = list(route.get('rules', []) or [])
    old_outbounds = list(outbounds or [])
    old_outbound_map = {str(item.get('tag', '')).strip(): item for item in old_outbounds if str(item.get('tag', '')).strip().startswith('proxy_')}
    dns_rules = [rule for rule in old_dns_rules if not (str(rule.get('action', '')).strip() == 'route' and str(rule.get('server', '')).strip().startswith('proxy_')) and not is_catch_all_dns_rule(rule)]
    # Ver 2.35: KHONG tao lai rule bat-het nua. Rule bat-het dung o vi tri 0
    # se an het 322 rule DoH theo source_ip_cidr (dns rule = first-match-wins),
    # dua moi query ve server 'google' 8.8.8.8:53 -- port bi proxy chan (rep=2).
    # Query khong khop rule nao vẫn co dns.final = dnsmasq (127.0.0.1:5353, do 47ms OK).
    dns_servers = [server for server in old_dns_servers if not str(server.get('tag', '')).strip().startswith('proxy_')]
    route_rules = [rule for rule in old_route_rules if not (str(rule.get('action', '')).strip() == 'route' and str(rule.get('outbound', '')).strip().startswith('proxy_'))]
    if not route_rules:
        route_rules = [{'action': 'sniff'}, {'action': 'reject', 'method': 'drop', 'protocol': 'stun'}, {'action': 'hijack-dns', 'protocol': 'dns'}]
    non_proxy_outbounds = [item for item in old_outbounds if not str(item.get('tag', '')).strip().startswith('proxy_')]
    for tag, ip in ordered_items:
        dns_rules.append({'action': 'route', 'server': tag, 'source_ip_cidr': ip})
        dns_servers.append({'address': PROXY_DNS_ADDRESS, 'detour': tag, 'tag': tag})
    route_rules = [rule for rule in route_rules if not (str(rule.get('action', '')).strip() == 'route' and str(rule.get('outbound', '')).strip() in ('direct', 'proxy'))]
    for tag, ip in ordered_items:
        route_rules.append({'action': 'route', 'outbound': tag, 'source_ip_cidr': ip})
    # Ver 2.36: chot deny-by-default PHAI DUY NHAT va nam CUOI cung.
    # Rule nay khong co dieu kien nen sing-box coi la MATCH-ALL; neu no
    # dung TRUOC 322 rule source_ip_cidr thi toan bo may khach mat mang.
    # Truoc 2.36 app append them 1 cai moi lan rebuild ma khong loc cai cu
    # => tich tu 8 cai, 7 cai troi len index [3..9] => chan sach 322 may.
    # KHONG duoc bo han: route.final = None va outbounds[0] = 'direct',
    # bo het thi traffic la ra WAN truc tiep => LO IP THAT cua khach.
    route_rules = [rule for rule in route_rules if not is_route_deny_rule(rule)]
    route_rules.append({'action': 'reject', 'method': 'drop'})
    rebuilt_outbounds = list(non_proxy_outbounds)
    for tag, _ip in ordered_items:
        rebuilt_outbounds.append(old_outbound_map.get(tag, {'tag': tag, 'type': 'block'}))
    # deny-by-default cho DNS: DUY NHAT + CUOI (sau 322 rule source_ip_cidr)
    dns_rules = [rule for rule in dns_rules if not is_dns_deny_rule(rule)]
    dns_rules.append(dns_deny_rule())
    dns['rules'] = dns_rules
    dns['servers'] = dns_servers
    route['rules'] = route_rules
    data['outbounds'] = rebuilt_outbounds
    # Ver 2.36: BAT BUOC goi sau khi da gan outbounds (ham doc outbounds).
    # Thieu dong nay = moi lan Apply se xoa rule pha vong lap => mat mang.
    ensure_dns_loop_breaker(data)
    # Ver 2.39: server DNS local phai co detour='direct', neu khong
    # hijack-dns bat lai goi cua chinh sing-box => loopback => mat DNS.
    ensure_dns_local_detour(data)
    # Ver 2.91: phan luong (neu bat) phai rebuild cung, IP ap dung theo may dang co proxy.
    ensure_split_rules(data)
    ensure_conn_rules(data)
    ensure_flow_api(data)
    return data

def _record_vpn_declaration(ipaddr, account):
    """Gan/bo gan VPN tu panel cung phai ghi lai vao session ACTIVE:
    - gan   -> meta vpn_account + outbound thanh direct (vpn:<ten>)
    - bo gan-> xoa meta vpn_account + outbound thanh block
    Nho vay apply lai chinh cfg khong mat may da gan VPN, va doi cfg
    thi dong bo theo dung y dinh moi."""
    try:
        sid = ''
        try:
            sid = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '') or '').strip()
        except Exception:
            sid = ''
        sid = sid if sid in SESSION_FILES else '1'
        if not SESSION_FILES[sid].exists():
            return
        tag = ''
        saved_text = get_saved_ip_identity_text(sid)
        if saved_text:
            for it in parse_ip_identity_text(saved_text):
                if str(it.get('ip', '')).strip() == str(ipaddr).strip():
                    tag = normalize_tag(it.get('tag', ''))
                    break
        if not tag:
            tag = effective_auto_ip_tags().get(str(ipaddr).strip(), '')
        state = load_session_state()
        sess = state.setdefault(str(sid), {})
        if tag:
            item = sess_item(sess, tag)
            acc = str(account or '').strip()
            if acc:
                item['vpn_account'] = acc
            else:
                item.pop('vpn_account', None)
            save_session_state(state)
            data = load_json(SESSION_FILES[sid])
            obs = data.setdefault('outbounds', [])
            idx = {str(o.get('tag')): i for i, o in enumerate(obs) if o.get('tag')}
            set_outbound_proxy(obs, idx, tag, 'vpn:' + acc if acc else '', 'vpn' if acc else 'socks5')
            save_gencore_json(SESSION_FILES[sid], data)
    except Exception:
        pass

def _record_vpn_declaration_bulk(pairs):
    """Ban BULK cua _record_vpn_declaration: ghi nhieu IP trong 1 luot.
    Ban le goi 1 IP = doc/ghi session state + session file 6 lan; gan 114 may
    thi thanh ~700 lan I/O -> rat cham. Ban nay doc 1 lan, ghi 1 lan.
    pairs: list [(ip, account)] ; account rong = bo gan.
    Hanh vi tren tung IP giu Y NGUYEN nhu ban le."""
    try:
        if not pairs:
            return
        sid = ''
        try:
            sid = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '') or '').strip()
        except Exception:
            sid = ''
        sid = sid if sid in SESSION_FILES else '1'
        if not SESSION_FILES[sid].exists():
            return
        ip2tag = {}
        saved_text = get_saved_ip_identity_text(sid)
        if saved_text:
            for it in parse_ip_identity_text(saved_text):
                _ip = str(it.get('ip', '')).strip()
                if _ip:
                    ip2tag[_ip] = normalize_tag(it.get('tag', ''))
        for _ip, _t in effective_auto_ip_tags().items():
            ip2tag.setdefault(_ip, _t)
        state = load_session_state()
        sess = state.setdefault(str(sid), {})
        data = load_json(SESSION_FILES[sid])
        obs = data.setdefault('outbounds', [])
        idx = {str(o.get('tag')): i for i, o in enumerate(obs) if o.get('tag')}
        touched = 0
        for ipaddr, account in pairs:
            tag = ip2tag.get(str(ipaddr).strip(), '')
            if not tag:
                continue
            item = sess_item(sess, tag)
            acc = str(account or '').strip()
            if acc:
                item['vpn_account'] = acc
            else:
                item.pop('vpn_account', None)
            set_outbound_proxy(obs, idx, tag, 'vpn:' + acc if acc else '', 'vpn' if acc else 'socks5')
            touched += 1
        if touched:
            save_session_state(state)
            save_gencore_json(SESSION_FILES[sid], data)
    except Exception:
        pass

def build_ip_identity_text(data, session='1'):
    rows = build_ip_identity_rows_from_data(data)
    rows.sort(key=lambda x: machine_num(x.get('machine', '')))
    return '\n'.join((format_ip_identity_row(row, include_machine=True) for row in rows))

def normalize_ip_identity_text(text):
    text = str(text or '').replace('\r\n', '\n').replace('\r', '\n')
    text = __import__('re').sub('(?<![\\n|])(?=proxy_\\d+\\|)', '\n', text)
    return text.strip()

def parse_ip_identity_text(text):
    text = normalize_ip_identity_text(text)
    rows = []
    seen_tags = set()
    seen_ips = set()
    seen_machines = set()
    dup_tags = set()
    dup_ips = set()
    dup_machines = set()
    for raw in str(text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) == 2:
            machine = ''
            tag, ip = parts
        elif len(parts) == 3:
            machine, tag, ip = parts
        else:
            raise ValueError(f'Dòng không hợp lệ: {line}')
        tag = normalize_tag(tag)
        machine = normalize_machine(machine)
        if not tag.startswith('proxy_'):
            raise ValueError(f'Tag không hợp lệ: {tag}')
        if not ip:
            raise ValueError(f'IP trống ở dòng: {line}')
        if not machine:
            num = proxy_tag_num(tag)
            if 1 <= num <= MAX_PROXY_TAG:
                machine = str(num)
        if tag in seen_tags:
            dup_tags.add(tag)
        else:
            seen_tags.add(tag)
        if ip in seen_ips:
            dup_ips.add(ip)
        else:
            seen_ips.add(ip)
        if machine:
            if machine in seen_machines:
                dup_machines.add(machine)
            else:
                seen_machines.add(machine)
        rows.append({'machine': machine, 'tag': tag, 'ip': ip})
    errs = []
    if dup_tags:
        errs.append('Proxy bị trùng: ' + ', '.join(sorted(dup_tags, key=proxy_tag_num)))
    if dup_ips:
        errs.append('IP bị trùng: ' + ', '.join(sorted(dup_ips)))
    if dup_machines:
        errs.append('Số máy bị trùng: ' + ', '.join(sorted(dup_machines, key=machine_num)))
    got_tags = {row['tag'] for row in rows}
    extra_tags = sorted([tag for tag in got_tags if proxy_tag_num(tag) > MAX_PROXY_TAG or proxy_tag_num(tag) < 1], key=proxy_tag_num)
    if len(rows) > MAX_PROXY_TAG:
        errs.append(f'Tối đa {MAX_PROXY_TAG} dòng, hiện có {len(rows)} dòng')
    if extra_tags:
        errs.append('Proxy ngoài phạm vi: ' + ', '.join(extra_tags))
    if errs:
        raise ValueError(' | '.join(errs))
    rows.sort(key=lambda x: (machine_num(x.get('machine', '')), proxy_tag_num(x['tag']), x['ip']))
    return rows

_IDENTITY_LOCK = threading.Lock()

AUTO_TAG_LOG = 'AUTO-TAG'

def get_auto_ip_tags():
    """[Ver 2.89] {ip: proxy_N} cua may tab CHUA CAU HINH da duoc gan proxy/VPN/PPPoE.
    Luu RIENG (meta auto_ip_tags), KHONG nam trong danh sach IP chinh => may van o tab CHUA CAU HINH."""
    try:
        meta = load_session_state().get('__meta__', {})
        v = meta.get('auto_ip_tags', {}) if isinstance(meta, dict) else {}
        if not isinstance(v, dict):
            return {}
        return {str(ip).strip(): normalize_tag(t) for ip, t in v.items() if str(ip).strip() and normalize_tag(t)}
    except Exception:
        return {}

def set_auto_ip_tags(mapping):
    state = load_session_state()
    meta = state.setdefault('__meta__', {})
    if not isinstance(meta, dict):
        meta = {}
        state['__meta__'] = meta
    meta['auto_ip_tags'] = {ip: mapping[ip] for ip in sorted(mapping)}
    save_session_state(state)

def effective_auto_ip_tags(identity_items=None):
    """Bo cac entry trung IP hoac trung tag voi danh sach IP chinh (danh sach chinh luon thang)."""
    if identity_items is None:
        try:
            text = get_saved_ip_identity_text()
            identity_items = parse_ip_identity_text(text) if text else []
        except Exception:
            identity_items = []
    ips = {str(it.get('ip', '')).strip() for it in identity_items}
    tags = {normalize_tag(it.get('tag', '')) for it in identity_items}
    return {ip: t for ip, t in get_auto_ip_tags().items() if ip not in ips and t not in tags}

def _clear_tag_accounts(state, tags):
    for sid, sess in state.items():
        if sid == '__meta__' or not isinstance(sess, dict):
            continue
        for k in list(sess.keys()):
            if normalize_tag(k) in tags and isinstance(sess[k], dict):
                sess[k].pop('vpn_account', None)
                sess[k].pop('pppoe_account', None)

def _rebuild_all_sessions_rules():
    text = get_saved_ip_identity_text()
    for sid, sf in SESSION_FILES.items():
        if not sf.exists():
            continue
        d = load_json(sf)
        save_gencore_json(sf, apply_ip_identity_config(d, text, session=sid))

_IDENTITY_LOCK = threading.Lock()

def sync_auto_ip_tags(rows, session_id='1'):
    """[Ver 2.89] May tab CHUA CAU HINH (IP khong co trong danh sach IP chinh):
    - co proxy/VPN/PPPoE: cap tag proxy_N trong (dem tu MAX_PROXY_TAG xuong de it dung so may that),
      luu vao auto_ip_tags, rebuild rule. May VAN o tab CHUA CAU HINH.
    - proxy rong (bam X): tra tag, rebuild rule.
    Sua rows tai cho (tag). Tra ve list thay doi [{ip, tag, action}]."""
    changes = []
    with _IDENTITY_LOCK:
        text = get_saved_ip_identity_text(session_id)
        items = parse_ip_identity_text(text) if text else []
        id_ips = {it['ip'] for it in items}
        id_tags = {it['tag'] for it in items}
        cur = effective_auto_ip_tags(items)
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            ip = str(r.get('ip', '')).strip()
            if not ip or ip in id_ips:
                continue
            proxy = str(r.get('proxy', '')).strip()
            has = bool(proxy) and proxy not in ('vpn:', 'pppoe:')
            if has:
                t = cur.get(ip)
                if not t:
                    if not text:
                        raise ValueError('Chua co danh sach IP/MAC chung - hay cau hinh IP truoc')
                    used = id_tags | set(cur.values())
                    n = MAX_PROXY_TAG
                    while n >= 1 and ('proxy_%d' % n) in used:
                        n -= 1
                    if n < 1:
                        raise ValueError('Het tag proxy trong (toi da %d)' % MAX_PROXY_TAG)
                    t = 'proxy_%d' % n
                    cur[ip] = t
                    changes.append({'ip': ip, 'tag': t, 'action': 'assign'})
                r['tag'] = t
                r['configured'] = False
            elif ip in cur:
                t = cur.pop(ip)
                changes.append({'ip': ip, 'tag': t, 'action': 'release'})
                r['tag'] = ''
        if changes:
            set_auto_ip_tags(cur)
            state = load_session_state()
            _clear_tag_accounts(state, {c['tag'] for c in changes})
            save_session_state(state)
            _rebuild_all_sessions_rules()
            try:
                _ss_log('%s: %s' % (AUTO_TAG_LOG, ', '.join('%s %s=%s' % (c['action'], c['ip'], c['tag']) for c in changes[:20])))
            except Exception:
                pass
    return changes

def migrate_promoted_289():
    """[Ver 2.89] Ban 2.88 da ghi nham may CHUA CAU HINH vao danh sach IP chinh (log PROMOTE-UNCONFIGURED).
    Chuyen cac dong do sang auto_ip_tags (GIU NGUYEN tag => rule/proxy khong doi, khong can apply lai).
    Chay 1 lan (meta promote_migrated_289)."""
    try:
        state = load_session_state()
        meta = state.get('__meta__', {})
        if isinstance(meta, dict) and meta.get('promote_migrated_289'):
            return
        pairs = {}
        try:
            for ln in SS_HEAL_LOG.read_text(encoding='utf-8', errors='ignore').splitlines():
                if 'PROMOTE-UNCONFIGURED' not in ln or 'may:' not in ln:
                    continue
                for part in ln.split('may:', 1)[1].split(','):
                    if '=' in part:
                        ip, t = [x.strip() for x in part.split('=', 1)]
                        if ip and normalize_tag(t):
                            pairs[ip] = normalize_tag(t)
        except Exception:
            pairs = {}
        moved = []
        if pairs:
            with _IDENTITY_LOCK:
                text = get_saved_ip_identity_text()
                items = parse_ip_identity_text(text) if text else []
                keep = []
                auto = get_auto_ip_tags()
                for it in items:
                    t = pairs.get(it['ip'])
                    if t and t == it['tag'] and str(it.get('machine', '')) == str(proxy_tag_num(t)):
                        auto[it['ip']] = t
                        moved.append('%s=%s' % (it['ip'], t))
                    else:
                        keep.append(it)
                if moved:
                    set_saved_ip_identity_text('1', '\n'.join(format_ip_identity_row(it, include_machine=True) for it in keep))
                    set_auto_ip_tags(auto)
                    _rebuild_all_sessions_rules()
        state = load_session_state()
        state.setdefault('__meta__', {})['promote_migrated_289'] = int(time.time())
        save_session_state(state)
        _ss_log('MIGRATE-289: chuyen %d may ve CHUA CAU HINH: %s' % (len(moved), ', '.join(moved)))
    except Exception as e:
        try:
            _ss_log('MIGRATE-289 loi: %s' % e)
        except Exception:
            pass

def apply_ip_identity_config(data, text, session='1'):
    rows = parse_ip_identity_text(text)
    tag_to_ip_map = {row['tag']: row['ip'] for row in rows}
    for _ip, _t in effective_auto_ip_tags(rows).items():
        tag_to_ip_map.setdefault(_t, _ip)
    rebuild_gencore_rules(data, tag_to_ip_map)
    return data

_PPPOE_APPLY_MISS = []

def _pppoe_glider_procs():
    """[Ver 2.82] {sid: {pid, start, socks, http}} doc tu /proc/*/cmdline cua glider.
    Nguon local, khong phu thuoc server goc 9000."""
    out = {}
    try:
        boot = 0.0
        with open('/proc/stat') as fh:
            for ln in fh:
                if ln.startswith('btime'):
                    boot = float(ln.split()[1]); break
        hz = os.sysconf('SC_CLK_TCK') or 100
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open('/proc/%s/cmdline' % pid, 'rb') as fh:
                    args = [a.decode('utf-8', 'replace') for a in fh.read().split(b'\0') if a]
            except Exception:
                continue
            if not args or os.path.basename(args[0]) != 'glider':
                continue
            listens, sid = [], None
            for i, a in enumerate(args):
                if a == '-listen' and i + 1 < len(args):
                    listens.append(args[i + 1])
                m = re.search(r'interface=pppoe-if_(\d+)', a)
                if m:
                    sid = int(m.group(1))
            if sid is None:
                continue
            try:
                with open('/proc/%s/stat' % pid) as fh:
                    st = fh.read().rsplit(')', 1)[-1].split()
                start = boot + int(st[19]) / hz
            except Exception:
                start = 0.0
            socks = next((x for x in listens if x.startswith('socks5://')), '')
            http = next((x for x in listens if x.startswith('http://')), '')
            if socks:
                out[sid] = {'pid': int(pid), 'start': start, 'socks': socks, 'http': http}
    except Exception:
        pass
    return out

def pppoe_session_proxies():
    """Doc proxy glider cua tung phien PPPoE. Tra ve {id: {socks, http}}.
    [Ver 2.82] Truoc day 9000 loi/cham 1 lan => cache {} 60s => moi may PPPoE
    bi ghi 'block' (Apply luc duoc luc khong). Nay: thu 9000 toi da 3 lan,
    thieu phien nao thi lay tu cmdline glider dang chay, chi cache ket qua co du lieu."""
    now = time.time()
    cache = getattr(pppoe_session_proxies, '_cache', None)
    if cache and cache[1] and now - cache[0] < 60:
        return cache[1]
    out = {}
    err = ''
    for attempt in range(3):
        try:
            r = call_old_gui('/api/router/pppoe')
            raw = (r or {}).get('data')
            if isinstance(raw, dict):
                raw = raw.get('data', raw)
            lst = raw if isinstance(raw, list) else (raw.get('sessions') or raw.get('list') or [] if isinstance(raw, dict) else [])
            for s in lst or []:
                if not isinstance(s, dict):
                    continue
                sid = str(s.get('id', s.get('wan_id', ''))).strip()
                if not sid:
                    continue
                socks = str(s.get('socks5') or s.get('socks_proxy') or s.get('proxy') or '').strip()
                if not socks:
                    continue
                out[sid] = {'socks': socks, 'http': str(s.get('http_proxy') or s.get('http') or '').strip()}
            if out:
                break
            err = '9000 tra danh sach rong'
        except Exception as e:
            err = str(e)[:120]
        if attempt < 2:
            time.sleep(1.5)
    n9000 = len(out)
    for sid, g in _pppoe_glider_procs().items():
        k = str(sid)
        if k not in out:
            out[k] = {'socks': g['socks'], 'http': g['http']}
    pppoe_session_proxies._last = {'from_9000': n9000, 'from_glider': len(out) - n9000, 'error': '' if n9000 else err}
    if n9000 == 0 and err:
        try:
            _ss_log('PPPOE-PROXY: 9000 loi (%s) -> lay %d phien tu cmdline glider' % (err, len(out)))
        except Exception:
            pass
    if out:
        pppoe_session_proxies._cache = (now, out)
    return out

def build_old_gui_update_proxy_payload_from_rows(rows):
    """Dung payload cho binary vendor 9000 (/api/update_proxy).

    Ver 2.34: truoc day may di VPN (proxyType='vpn', proxy='vpn:<account>')
    cung bi nem vao parse_proxy(). parse_proxy doi dung 4 phan
    host:port:user:pass nen nem ValueError, roi bi 'except: ALLOW' che di
    khong mot dong log. Ket qua: preset VPN thuan sinh payload 322/322 ALLOW
    va vendor coi day la lenh 'reset proxy config'. Nay nhan dien VPN TRUOC,
    va moi loi parse that su deu duoc ghi log de khong con che loi nghiep vu.
    """
    payload = {}
    for row in rows or []:
        ip = str((row or {}).get('ip', '')).strip()
        proxy = str((row or {}).get('proxy', '')).strip()
        proxy_type = str((row or {}).get('proxyType', 'socks5') or 'socks5').strip().lower()
        if not ip:
            continue
        if not proxy:
            payload[ip] = 'ALLOW'
            continue
        if proxy_type == 'vpn' or proxy.startswith('vpn:'):
            payload[ip] = 'ALLOW'
            continue
        if proxy_type == 'pppoe' or proxy.startswith('pppoe:'):
            # pppoe:<id> -> proxy glider that cua phien, giong VPN resolve tunnel.
            sid = proxy.split(':', 1)[1].strip() if ':' in proxy else ''
            pmap = pppoe_session_proxies()
            info = pmap.get(sid, {}) if sid else {}
            raw_px = info.get('socks') or info.get('http') or ''
            if raw_px:
                try:
                    server, port, username, password = parse_proxy(raw_px)
                    item = {'type': 'http' if info.get('http') and raw_px == info.get('http') else 'socks5', 'server': server, 'port': int(port)}
                    if username or password:
                        item['username'] = username
                        item['password'] = password
                    payload[ip] = item
                    continue
                except Exception:
                    pass
            payload[ip] = 'ALLOW'
            continue
        try:
            server, port, username, password = parse_proxy(proxy)
            item = {'type': 'http' if proxy_type == 'http' else 'socks5', 'server': server, 'port': int(port)}
            if username or password:
                item['username'] = username
                item['password'] = password
            payload[ip] = item
        except Exception as parse_error:
            try:
                _ss_log(f'PAYLOAD-PARSE-FAIL ip={ip} type={proxy_type} proxy={proxy[:48]!r}: {parse_error} -> ALLOW')
            except Exception:
                pass
            payload[ip] = 'ALLOW'
    return payload

def _store_session_vpn_accounts(session_id, tag_accounts):
    if not tag_accounts:
        return
    state = load_session_state()
    sess = state.setdefault(str(session_id), {})
    for item in tag_accounts:
        tag = normalize_tag(item.get('tag', ''))
        acc = str(item.get('vpn_account') or '').strip()
        if not tag or not acc:
            continue
        sess_item(sess, tag)['vpn_account'] = acc
    save_session_state(state)

def _session_vpn_desires(session_id, runtime_data):
    """Cau hinh nay khai bao may nao chay VPN -> ({tag: ten_account}, [adopt])"""
    direct_tags = set()
    for item in (runtime_data or {}).get('outbounds', []) or []:
        try:
            tag = normalize_tag(str((item or {}).get('tag', '')))
            if not tag.startswith('proxy_'):
                continue
            if str((item or {}).get('type', '')).strip().lower() == 'direct':
                direct_tags.add(tag)
        except Exception:
            continue
    if not direct_tags:
        return ({}, [])
    meta = get_session_meta(session_id)
    current_map = load_vpn_map()
    saved_text = get_saved_ip_identity_text(session_id)
    tag_ip = {}
    if saved_text:
        try:
            for it in parse_ip_identity_text(saved_text):
                t = normalize_tag(it.get('tag', ''))
                ip = str(it.get('ip', '')).strip()
                if t and ip:
                    tag_ip[t] = ip
        except Exception:
            tag_ip = {}
    for _ip, _t in effective_auto_ip_tags().items():
        tag_ip.setdefault(_t, _ip)
    desires = {}
    adopt = []
    for tag in sorted(direct_tags):
        info = meta.get(tag) if isinstance(meta, dict) else None
        acc = str((info or {}).get('vpn_account', '') or '').strip() if isinstance(info, dict) else ''
        if not acc:
            old = current_map.get(tag_ip.get(tag, ''), '')
            if old:
                acc = old
                adopt.append({'tag': tag, 'vpn_account': acc})
        if acc:
            desires[tag] = acc
    return (desires, adopt)

def _backup_vpn_map(reason: str):
    """Luu ban sao map.txt truoc khi thay doi hang loat (Ver 2.33).

    Vu 30/08: apply mot cau hinh khai bao 0 may VPN da tu dong bo gan het 114
    may va khong con ban sao nao ngoai file backup tay. Nay moi lan sap bo gan
    hang loat deu luu snapshot vao persist/, giu 10 ban gan nhat.
    """
    try:
        src = Path(VPN_MAP_PATH)
        if not src.exists() or src.stat().st_size == 0:
            return None
        d = WD_PERSIST_DIR / 'map_backups'
        d.mkdir(parents=True, exist_ok=True)
        dst = d / f'map.{time.strftime("%Y%m%d_%H%M%S")}.txt'
        _ss_atomic_write(dst, src.read_text(encoding='utf-8', errors='replace'))
        olds = sorted(d.glob('map.*.txt'))
        for p in olds[:-10]:
            try:
                p.unlink()
            except Exception:
                pass
        _ss_log(f'MAP-BACKUP ({reason}): {dst.name}')
        return dst
    except Exception as e:
        _ss_log(f'MAP-BACKUP that bai ({reason}): {e}')
        return None

def sync_vpn_state_on_apply(session_id, runtime_data, results):
    """Apply cau hinh nao thi trang thai VPN phai theo dung cau hinh do:
    - may cfg KHONG khai bao VPN ma van con map/rule VPN -> tu bo gan
    - may cfg khai bao VPN -> giu/gan dung account (chi gan khi tunnel UP)
    - don rule rac tro den table cua tunnel da chet (vd tun mat bat thuong)

    Ver 2.33: luu snapshot map.txt truoc khi bo gan hang loat, va dung
    `unassign-many`/`assign-many` nen thao tac 100+ may xong trong ~1s thay vi
    vai phut."""
    cmd = 'dong bo VPN theo cau hinh'
    summary = {'declared': 0, 'unassigned': [], 'assigned': [], 'skipped': [], 'clean_stale_ok': None, 'map_backup': None}
    try:
        desires_by_tag, adopt = _session_vpn_desires(session_id, runtime_data)
        if adopt:
            _store_session_vpn_accounts(session_id, adopt)
        desired_ips = {}
        saved_text = get_saved_ip_identity_text(session_id)
        if saved_text:
            tag_ip = {}
            try:
                for it in parse_ip_identity_text(saved_text):
                    t = normalize_tag(it.get('tag', ''))
                    ip = str(it.get('ip', '')).strip()
                    if t and ip:
                        tag_ip[t] = ip
            except Exception:
                tag_ip = {}
            for _ip, _t in effective_auto_ip_tags().items():
                tag_ip.setdefault(_t, _ip)
            for tag, acc in desires_by_tag.items():
                ip = tag_ip.get(tag, '')
                if ip:
                    desired_ips[ip] = acc
        summary['declared'] = len(desired_ips)
        current = load_vpn_map()
        status = {}
        try:
            status = {str(a.get('name', '')): a for a in vpn_status_json()}
        except Exception:
            status = {}
        # [Ver 2.97] Bo gan MOI ip con trong map.txt ma cau hinh khong con khai VPN.
        # Loi cu: chi chay khi co saved_text, va chi khi may do nam trong saved_text.
        # Vi du 192.10.0.16 tu promote (khong co trong saved_text) gan VPN xv-1,
        # sau doi sang proxy Lumi => Apply xong van con ip rule lookup 371 => van ra IP VPN.
        # [Ver 2.98] CHAN AN TOAN: config khai co may VPN nhung khong map duoc IP nao
        # => nghi doc config loi, KHONG xoa (tranh bo gan sach lam mat mang ca router).
        if desires_by_tag and not any(tag_ip.get(t) for t in desires_by_tag):
            stale_ips = []
            try:
                _ss_log('VPN-SYNC bo qua unassign: co %d may khai VPN nhung khong map duoc IP nao' % len(desires_by_tag))
            except Exception:
                pass
        else:
            stale_ips = [ip for ip in sorted(current) if ip not in desired_ips]
        if stale_ips:
            bak = _backup_vpn_map(f'apply session {session_id}: sap bo gan {len(stale_ips)}/{len(current)} may')
            if bak:
                summary['map_backup'] = str(bak)
            r = vpn_run(['unassign-many'] + stale_ips, timeout=max(120, 3 * len(stale_ips)))
            ok = bool(r.get('ok'))
            summary['unassigned'] = [{'ip': ip, 'ok': ok} for ip in stale_ips]
            try:
                _ss_log('VPN-SYNC unassign %d may khong con khai VPN: %s' % (len(stale_ips), ','.join(stale_ips[:20])))
            except Exception:
                pass
        todo = {}
        if saved_text:
            for ip, acc in sorted(desired_ips.items()):
                if current.get(ip, '') == acc:
                    continue
                acc_info = status.get(acc) or {}
                if not acc_info.get('running'):
                    summary['skipped'].append({'ip': ip, 'account': acc, 'reason': 'tunnel khong chay'})
                    continue
                todo.setdefault(acc, []).append(ip)
            for acc, ips in sorted(todo.items()):
                r = vpn_run(['assign-many', acc] + ips, timeout=max(120, 3 * len(ips)))
                ok = bool(r.get('ok'))
                out = (r.get('output') or '')[:120]
                for ip in ips:
                    summary['assigned'].append({'ip': ip, 'account': acc, 'ok': ok, 'output': out})
        rc = vpn_run(['clean-stale'], timeout=120)
        summary['clean_stale_ok'] = bool(rc.get('ok'))
        results.append({'cmd': cmd, 'ok': True, **summary})
    except Exception as e:
        results.append({'cmd': cmd, 'ok': False, 'error': str(e), **summary})

def vpn_map_sweep(session_id=None):
    """[Ver 2.98] Don gan VPN THUA: IP con trong /data/vpn/map.txt ma cau hinh active
    khong con khai VPN. Chay sau Apply va dinh ky 5 phut.

    Vi sao can: 2026-10-27 may 192.10.0.16 doi tu VPN xv-1 sang proxy Lumi JP, Apply xong
    van ra IP My vi map.txt con dong '.16 xv-1' => ip rule lookup 371 + ipset genrouter_vpn
    (rule RETURN o mangle PREROUTING) nen traffic khong bao gio toi gencore/proxy moi.
    """
    res = {'ok': False, 'session': '', 'removed': [], 'reason': ''}
    try:
        sid = str(session_id or '').strip()
        if not sid:
            try:
                sid = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '1')).strip() or '1'
            except Exception:
                return dict(res, reason='khong doc duoc session active')
        res['session'] = sid
        preset = SESSION_FILES.get(str(sid))
        if not preset or not Path(preset).exists():
            return dict(res, reason='khong co preset session %s' % sid)
        data = load_json(preset)
        desires_by_tag, _adopt = _session_vpn_desires(sid, data)
        tag_ip = {}
        saved_text = get_saved_ip_identity_text(sid)
        if saved_text:
            try:
                for it in parse_ip_identity_text(saved_text):
                    t = normalize_tag(it.get('tag', ''))
                    ip = str(it.get('ip', '')).strip()
                    if t and ip:
                        tag_ip[t] = ip
            except Exception:
                tag_ip = {}
        for _ip, _t in effective_auto_ip_tags().items():
            tag_ip.setdefault(_t, _ip)
        # Chan an toan: config khai co may VPN nhung khong map duoc IP nao => nghi doc loi, KHONG xoa.
        if desires_by_tag and not any(tag_ip.get(t) for t in desires_by_tag):
            return dict(res, reason='khong map duoc IP cho may VPN nao (nghi config loi) - khong xoa')
        desired_ips = {tag_ip[t]: acc for t, acc in desires_by_tag.items() if tag_ip.get(t)}
        current = load_vpn_map()
        stale = [ip for ip in sorted(current) if ip not in desired_ips]
        if not stale:
            return dict(res, ok=True, reason='khong co gan thua')
        _backup_vpn_map('sweep session %s: %d/%d may' % (sid, len(stale), len(current)))
        r = vpn_run(['unassign-many'] + stale, timeout=max(120, 3 * len(stale)))
        res['removed'] = stale
        res['ok'] = bool(r.get('ok'))
        try:
            _ss_log('VPN-SWEEP session=%s removed=%d con=%d: %s' % (
                sid, len(stale), len(current) - len(stale), ','.join(stale[:20])))
        except Exception:
            pass
        return res
    except Exception as e:
        return dict(res, reason=str(e))


def vpn_map_sweep_loop():
    time.sleep(120)
    while True:
        try:
            vpn_map_sweep()
        except Exception:
            pass
        time.sleep(300)


def config_doc_stats(doc):
    """Dem cac chi so bat bien cua mot doc gencore (dung de phat hien config bi sut)."""
    stats = {'proxy_outbounds': 0, 'source_ip_cidr': 0, 'route_rules': 0, 'dns_servers': 0,
             'dns_proxy_doh': 0, 'dns_proxy_legacy': 0,
             'dns_loop_breaker': 0, 'proxy_dns_hosts': 0, 'proxy_username_uniq': 0,
             'dns_local_detour': 0}
    try:
        outbounds = (doc or {}).get('outbounds') or []
        route_rules = ((doc or {}).get('route') or {}).get('rules') or []
        dns_servers = ((doc or {}).get('dns') or {}).get('servers') or []
        dns_rules = ((doc or {}).get('dns') or {}).get('rules') or []
    except Exception:
        return stats
    stats['proxy_outbounds'] = sum(1 for x in outbounds if str((x or {}).get('tag', '')).startswith('proxy_'))
    stats['route_rules'] = len(route_rules)
    stats['source_ip_cidr'] = sum(1 for r in route_rules if str((r or {}).get('source_ip_cidr', '')).strip())
    stats['dns_servers'] = len(dns_servers)
    for s in dns_servers:
        if not str((s or {}).get('tag', '')).startswith('proxy_'):
            continue
        if str((s or {}).get('address', '')).strip().startswith('https://'):
            stats['dns_proxy_doh'] += 1
        else:
            stats['dns_proxy_legacy'] += 1
    # Ver 2.39: canh luon RULE PHA VONG LAP DNS (as.lumiproxy.io -> dnsmasq).
    # Truoc day CONFIG_GUARD_KEYS khong co chi so nay nen khi vendor
    # /etc/genrouter/server:9000 regenerate gencore.json, rule bi xoa MA GUARDIAN
    # KHONG BIET -> 322 may quay lai canh vong lap DNS (da xay ra 2026-09-03,
    # 19984 dong 'DNS query loopback in transport[proxy_N]').
    # Dung phep so sanh TUONG DOI got[k] < want[k] nen:
    #   mode VPN  (outbound proxy_* khong co ten mien): want=0 -> khong bao dong gia.
    #   mode proxy (co as.lumiproxy.io)               : want=1 -> vendor xoa la phat hien ngay.
    try:
        stats['proxy_dns_hosts'] = len(collect_proxy_dns_hosts(doc))
        stats['dns_loop_breaker'] = sum(1 for r in dns_rules if is_dns_loop_breaker(r))
    except Exception:
        pass
    # Ver 2.40: canh SO SESSION STRING RIENG cua cac outbound proxy_*.
    # Vi sao can: cac chi so tren chi DEM SO LUONG. Neu vendor 9000 regenerate
    # 322 outbound nhung dat CUNG 1 username (dung tinh trang truoc 2026-09-04)
    # thi proxy_outbounds=322, dns_proxy_doh=322, dns_loop_breaker=1 => degraded=[]
    # => guard KHONG BIET, va 322 may quay lai chen chung 1 exit IP Lumi.
    # Do that: 10 stream 842 Mbps (322 session rieng) tut ve 319 Mbps (chung 1 session),
    # 20 stream 864 -> 48 Mbps. Vi Lumi sticky theo session string nen dung chung
    # = dung chung 1 IP residential = dung chung 1 tran bang thong.
    # Dem username KHAC NHAU va KHONG RONG. Phep so sanh cua guard la got[k] < want[k]:
    #   mode VPN  (session1: outbound proxy_* la {'type': 'direct'}, khong username) -> want=0
    #             => khong bao gio bao dong gia.
    #   mode proxy (session3 da tach 322 session)                                    -> want=322
    #             => vendor ghi ve 1 username la phat hien ngay.
    try:
        stats['proxy_username_uniq'] = len({
            str((x or {}).get('username') or '').strip()
            for x in outbounds
            if str((x or {}).get('tag', '')).startswith('proxy_')
            and str((x or {}).get('username') or '').strip()
        })
    except Exception:
        pass
    # Ver 2.41: canh DETOUR cua DNS server LOCAL (dnsmasq 127.0.0.1:5353).
    # Vi sao BAT BUOC: server DNS khong co detour thi goi ra cua CHINH sing-box
    # di qua route engine, bi rule {'action':'hijack-dns','protocol':'dns'}
    # (index 2) bat lai => "DNS query loopback in transport[dnsmasq]" => loop
    # breaker khong resolve duoc as.lumiproxy.io => detour proxy_N chet =>
    # TOAN BO may khach mat phan giai ten. Da do that 2026-09-04: br-lan
    # 73 query / 0 reply, conntrack 42/42 UNREPLIED, client retry 255 lan/luong.
    # Sau khi them detour='direct': may co rule 20 query / 22 reply, 0 UNREPLIED.
    # Vendor 9000 regenerate config bang template rieng => se lam mat truong nay,
    # nen phai co trong CONFIG_GUARD_KEYS de guard/watchdog tu chua.
    # Phep so sanh la got[k] < want[k] nen mode VPN (want cung 1) khong bao dong gia.
    try:
        stats['dns_local_detour'] = sum(
            1 for s in dns_servers
            if isinstance(s, dict)
            and not str(s.get('tag', '')).startswith('proxy_')
            and is_local_dns_address(s.get('address'))
            and str(s.get('detour', '')).strip() == DNS_LOCAL_DETOUR)
    except Exception:
        pass
    return stats

CONFIG_GUARD_KEYS = ('proxy_outbounds', 'source_ip_cidr', 'route_rules', 'dns_proxy_doh', 'dns_loop_breaker', 'proxy_username_uniq', 'dns_local_detour')

def config_guard_restore(expected_doc, results=None, reason='post-vendor'):
    """So config tren disk voi ban dung trong RAM, sut thi ghi lai ngay + log vet.

    Vi sao can: chu so huu THAT cua /etc/genrouter/config/gencore.json la binary
    vendor /etc/genrouter/server (port 9000) — grep toan router cho thay chi
    minh no doc/ghi config/proxy.json. Khi bi POST /api/update_proxy no
    regenerate gencore.json bang template rieng cua no:
      - DNS cua proxy_* bi doi tu 'https://8.8.8.8/dns-query' (443) ve
        'tcp://8.8.8.8' (port 53);
      - mat bot route rule; truong hop payload toan ALLOW thi ve han template
        mac dinh chi con outbound {direct} va 0 source_ip_cidr.
    Lumi chan port 53 (SOCKS5 tra rep=2 'not allowed by ruleset' — da do that)
    nen ngay khi DNS ve port 53 la client khong resolve duoc => 'khong vao
    duoc web'. Con neu source_ip_cidr ve 0 thi /etc/genrouter/core/tproxy
    (awk theo chuoi "source_ip_cidr") sinh CLIENT_IPS rong => chain GENROUTER
    khong con rule TPROXY nao.
    Tra ve True neu da phai ghi lai.
    """
    want = config_doc_stats(expected_doc)
    try:
        on_disk = load_json(RUNTIME_SOURCE_FILE)
    except Exception as read_error:
        try:
            _ss_log(f'CONFIG-GUARD ({reason}): khong doc duoc {RUNTIME_SOURCE_FILE}: {read_error} — ghi lai ban trong RAM')
        except Exception:
            pass
        try:
            save_gencore_json(RUNTIME_SOURCE_FILE, expected_doc)
        except Exception:
            pass
        return True
    got = config_doc_stats(on_disk)
    degraded = [k for k in CONFIG_GUARD_KEYS if got.get(k, 0) < want.get(k, 0)]
    if got.get('dns_proxy_legacy', 0) > want.get('dns_proxy_legacy', 0):
        degraded.append('dns_proxy_legacy')
    if not degraded:
        return False
    detail = ' '.join(f'{k}:{got.get(k, 0)}<-{want.get(k, 0)}' for k in degraded)
    try:
        save_gencore_json(RUNTIME_SOURCE_FILE, expected_doc)
    except Exception as write_error:
        try:
            _ss_log(f'CONFIG-COLLAPSE-BLOCKED ({reason}) THAT BAI khi ghi lai: {write_error} | {detail}')
        except Exception:
            pass
        if isinstance(results, list):
            results.append({'cmd': 'config guard: chan config bi sut', 'ok': False, 'reason': reason, 'degraded': degraded, 'error': str(write_error)})
        return False
    try:
        _ss_log(f'CONFIG-COLLAPSE-BLOCKED ({reason}): {detail} — da ghi lai {RUNTIME_SOURCE_FILE} tu ban trong RAM')
    except Exception:
        pass
    if isinstance(results, list):
        results.append({'cmd': 'config guard: chan config bi sut', 'ok': True, 'reason': reason, 'degraded': degraded, 'on_disk': got, 'expected': want, 'restored': str(RUNTIME_SOURCE_FILE)})
    return True

APPLY_LOCK_FILE = BASE_DIR / 'persist' / '.apply_lock'
APPLY_LOCK_TTL = 180

def _apply_lock_active():
    """Co dang co mot lan apply chay khong? (co TTL de khong khoa vinh vien)

    Ver 2.34 — co che tai phat #5: moi lan apply, genrunner KILL gencore co chu
    y. Watchdog khong phan biet 'chet do apply' vs 'chet do su co' nen tu dung
    lai gencore ngay giua cua so apply => hai ben cung ghi/doc
    /etc/genrouter/config/gencore.json mot luc (race tren dung file dang sap).
    Da quan sat that trong log: 01/09 18:51:40 va 02/09 08:30:50 (gio router).
    Co nay cho watchdog + self-heal biet duong tranh ra.
    TTL bat buoc: neu app crash giua apply thi cai co phai tu het han, neu
    khong thi watchdog/self-heal bi vo hieu hoa vinh vien.
    """
    try:
        info = json.loads(APPLY_LOCK_FILE.read_text(encoding='utf-8'))
    except Exception:
        return False
    try:
        ts = float(info.get('ts', 0))
    except Exception:
        return False
    return time.time() - ts < APPLY_LOCK_TTL

def _apply_lock_acquire(session=''):
    try:
        APPLY_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        APPLY_LOCK_FILE.write_text(json.dumps({'pid': os.getpid(), 'ts': time.time(), 'session': str(session)}), encoding='utf-8')
        return True
    except Exception:
        return False

def _apply_lock_release():
    try:
        APPLY_LOCK_FILE.unlink()
        return True
    except Exception:
        return False

def _wd_apply_in_progress():
    """Ten rieng cho watchdog doc — cung mot co, de doc log/grep de hieu."""
    return _apply_lock_active()

def run_apply(session: str, rows_override=None):
    """Ver 2.34: bao boc apply bang co khoa, try/finally de khong bao gio ket co."""
    _apply_lock_acquire(session)
    try:
        return _run_apply_inner(session, rows_override=rows_override)
    finally:
        _apply_lock_release()

_APPLY_RESTART = {'pending': False, 'lock': threading.Lock()}

def schedule_gencore_reload_after_apply(session, reason='apply_no_vendor'):
    """[Ver 2.90] Apply ma KHONG POST cho vendor 9000 (cau hinh toan VPN => UPDATE-PROXY-SKIPPED)
    thi khong ai bao gencore nap config moi: may vua gan bi chan toi khi watchdog STALE-CONFIG
    restart (1-4 phut). Nay restart gencore nen, gop cac lan Apply lien tiep trong 3s thanh 1 lan."""
    with _APPLY_RESTART['lock']:
        if _APPLY_RESTART['pending']:
            return False
        _APPLY_RESTART['pending'] = True
    def _job():
        try:
            time.sleep(3)
            with _APPLY_RESTART['lock']:
                _APPLY_RESTART['pending'] = False
            try:
                _ss_log('APPLY-RELOAD session=%s: restart gencore de nap config moi (khong POST vendor)' % session)
            except Exception:
                pass
            gencore_restart_detached(reason)
        except Exception as e:
            with _APPLY_RESTART['lock']:
                _APPLY_RESTART['pending'] = False
            try:
                _ss_log('APPLY-RELOAD loi: %s' % e)
            except Exception:
                pass
    threading.Thread(target=_job, daemon=True, name='apply-reload').start()
    return True

def _run_apply_inner(session: str, rows_override=None):
    preset_source = SESSION_FILES[session]
    results = []
    del _PPPOE_APPLY_MISS[:]
    try:
        pppoe_session_proxies._cache = None  # Apply luon doc moi, khong dung cache cu
    except Exception:
        pass
    preset_data = load_json(preset_source)
    if str(preset_source) != str(RUNTIME_SOURCE_FILE):
        save_gencore_json(RUNTIME_SOURCE_FILE, preset_data)
        results.append({'cmd': 'copy selected preset to gencore runtime source', 'ok': True, 'source': str(preset_source), 'target': str(RUNTIME_SOURCE_FILE)})
    else:
        results.append({'cmd': 'copy selected preset to gencore runtime source', 'ok': True, 'source': str(preset_source), 'target': str(RUNTIME_SOURCE_FILE), 'skipped': True})
    if isinstance(rows_override, list):
        rows_by_tag = {}
        for row in rows_override:
            tag = normalize_tag((row or {}).get('tag', ''))
            if tag:
                rows_by_tag[tag] = row or {}
        runtime_data = apply_rows_to_data(load_json(RUNTIME_SOURCE_FILE), rows_by_tag, session=session)
        save_gencore_json(preset_source, runtime_data)
        save_gencore_json(RUNTIME_SOURCE_FILE, runtime_data)
        results.append({'cmd': 'save posted proxy assignments to preset and gencore runtime source', 'ok': True, 'source': str(preset_source), 'target': str(RUNTIME_SOURCE_FILE), 'count': len(rows_by_tag)})
    else:
        runtime_data = load_json(RUNTIME_SOURCE_FILE)
    if ensure_split_rules(runtime_data) + ensure_conn_rules(runtime_data) + ensure_flow_api(runtime_data):
        save_gencore_json(RUNTIME_SOURCE_FILE, runtime_data)
        if str(preset_source) != str(RUNTIME_SOURCE_FILE):
            save_gencore_json(preset_source, runtime_data)
        results.append({'cmd': 'cap nhat phan luong', 'ok': True, 'applied': split_applied_count(runtime_data)})
    dns_migrated = migrate_proxy_dns_servers(runtime_data)
    # Ver 2.41: apply cung phai bao dam detour cua DNS local, neu khong
    # config vua ghi se lai roi vao vong lap hijack-dns (mat DNS toan bo).
    dns_migrated += ensure_dns_local_detour(runtime_data)
    if dns_migrated:
        save_gencore_json(RUNTIME_SOURCE_FILE, runtime_data)
        results.append({'cmd': 'migrate proxy DNS servers to DoH 443', 'ok': True, 'target': str(RUNTIME_SOURCE_FILE), 'count': dns_migrated})
    if _PPPOE_APPLY_MISS:
        kept = sum(1 for m in _PPPOE_APPLY_MISS if m.get('kept'))
        blocked = [m.get('tag') for m in _PPPOE_APPLY_MISS if not m.get('kept')]
        info = getattr(pppoe_session_proxies, '_last', {}) or {}
        results.append({'cmd': 'PPPoE: lay proxy glider', 'ok': not blocked,
                        'error': ('%d may PPPoE khong lay duoc proxy glider (phien chua len?) => block: %s. 9000: %s' % (
                            len(blocked), ', '.join(blocked[:8]), info.get('error') or 'ok')) if blocked else '',
                        'kept_old': kept})
        try:
            _ss_log('PPPOE-APPLY session=%s miss=%d kept=%d blocked=%s src=%s' % (session, len(_PPPOE_APPLY_MISS), kept, blocked[:8], info))
        except Exception:
            pass
    rows = extract_rows(runtime_data, session=session)
    payload = build_old_gui_update_proxy_payload_from_rows(rows)
    real_proxy_count = sum(1 for v in payload.values() if isinstance(v, dict))
    vendor_skipped = False
    if payload and real_proxy_count == 0:
        vendor_skipped = True
        # Ver 2.34: payload toan ALLOW (preset VPN thuan) chinh la thu kich hoat
        # duong 'reset proxy config' cua binary vendor 9000, lam gencore.json bi
        # regenerate ve template mac dinh. Khong co proxy that thi khong co gi de
        # bao vendor ca — bo qua POST. call_old_gui() vo hieu voi /api/update_proxy
        # cung tra ve 'local-compat success', nen bo qua khong lam lech logic nao.
        try:
            _ss_log(f'UPDATE-PROXY-SKIPPED session={session}: {len(payload)} entry deu ALLOW (khong co proxy that) — khong POST cho vendor 9000')
        except Exception:
            pass
        results.append({'cmd': 'POST old GUI /api/update_proxy', 'ok': True, 'skipped': True, 'source': str(RUNTIME_SOURCE_FILE), 'count': len(payload), 'reason': 'payload toan ALLOW; POST se lam vendor 9000 reset gencore.json'})
    else:
        try:
            resp = call_old_gui('/api/update_proxy', method='POST', data=payload)
            results.append({'cmd': 'POST old GUI /api/update_proxy', 'ok': True, 'source': str(RUNTIME_SOURCE_FILE), 'count': len(payload), 'proxies': real_proxy_count, 'response': resp.get('data') if isinstance(resp, dict) else resp})
        except Exception as e:
            results.append({'cmd': 'POST old GUI /api/update_proxy', 'ok': False, 'source': str(RUNTIME_SOURCE_FILE), 'count': len(payload), 'proxies': real_proxy_count, 'error': str(e)})
        # Vendor vua co the da ghi de RUNTIME_SOURCE_FILE bang template cua no.
        config_guard_restore(runtime_data, results, reason=f'sau POST update_proxy session {session}')
    if str(RUNTIME_FILE) != str(RUNTIME_SOURCE_FILE):
        # Ver 2.34: ghi runtime tu runtime_data trong RAM — nguon su that cua app.
        # Truoc day la save_json(RUNTIME_FILE, load_json(RUNTIME_SOURCE_FILE)) tuc
        # doc lai chinh file vendor vua ghi de, nen ban sap cua vendor duoc nhan
        # ban thang sang runtime.
        save_gencore_json(RUNTIME_FILE, runtime_data)
        results.append({'cmd': 'sync runtime file copy only', 'ok': True, 'source': 'runtime_data (RAM)', 'target': str(RUNTIME_FILE)})
    else:
        results.append({'cmd': 'sync runtime file copy only', 'ok': True, 'source': str(RUNTIME_SOURCE_FILE), 'target': str(RUNTIME_FILE), 'skipped': True})
    sync_vpn_state_on_apply(session, runtime_data, results)
    try:
        if GENRUNNER.exists():
            proc = subprocess.run([str(GENRUNNER), 'check', '-c', str(RUNTIME_SOURCE_FILE)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
            results.append({'cmd': 'genrunner check only', 'ok': proc.returncode == 0, 'returncode': proc.returncode, 'stdout': (proc.stdout or '').strip(), 'stderr': (proc.stderr or '').strip()})
        else:
            results.append({'cmd': 'genrunner check only', 'ok': True, 'skipped': True, 'reason': f'not found: {GENRUNNER}'})
    except Exception as e:
        results.append({'cmd': 'genrunner check only', 'ok': False, 'error': str(e)})
    if vendor_skipped:
        chk = next((r for r in results if r.get('cmd') == 'genrunner check only'), {})
        if chk.get('ok'):
            queued = schedule_gencore_reload_after_apply(session)
            results.append({'cmd': 'reload gencore (khong POST vendor)', 'ok': True, 'queued': queued})
        else:
            results.append({'cmd': 'reload gencore (khong POST vendor)', 'ok': False, 'error': 'genrunner check loi => khong restart, giu config dang chay'})
    if any((r.get('ok') for r in results)):
        try:
            spawn_proxy_sheet_push()
        except Exception:
            pass
    return results

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError('Kết nối bị đóng')
        data += chunk
    return data

def socks5_probe(proxy_host, proxy_port, username, password, target_host='1.1.1.1', target_port=80, timeout=12, send_http=True):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b'\x05\x01\x02')
        resp = recv_exact(sock, 2)
        if resp[0] != 5 or resp[1] != 2:
            raise OSError('SOCKS5 auth method không hợp lệ')
        u = username.encode('utf-8')
        p = password.encode('utf-8')
        if len(u) > 255 or len(p) > 255:
            raise OSError('Username/password quá dài')
        sock.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
        auth = recv_exact(sock, 2)
        if auth[1] != 0:
            raise OSError('Sai user/pass proxy')
        try:
            addr = socket.inet_aton(target_host)
            req = b'\x05\x01\x00\x01' + addr + struct.pack('!H', target_port)
        except OSError:
            host_bytes = target_host.encode('idna')
            req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + struct.pack('!H', target_port)
        sock.sendall(req)
        head = recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError(f'SOCKS5 connect fail code {head[1]}')
        atyp = head[3]
        if atyp == 1:
            recv_exact(sock, 4)
        elif atyp == 3:
            ln = recv_exact(sock, 1)[0]
            recv_exact(sock, ln)
        elif atyp == 4:
            recv_exact(sock, 16)
        recv_exact(sock, 2)
        if not send_http:
            return True
        sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n'.encode('utf-8'))
        data = sock.recv(32)
        return bool(data)
    finally:
        try:
            sock.close()
        except Exception:
            pass

def socks5_probe_multi(proxy_host, proxy_port, username, password, timeout=12):
    # Khong probe port 53: nhieu proxy provider chan port nay va tra rep=2,
    # lam probe bao proxy chet oan. Chi probe cac port thuc su duoc phep.
    targets = [('1.1.1.1', 80, True), ('1.1.1.1', 443, False), ('api.ipify.org', 443, False), ('ifconfig.me', 443, False)]
    last_error = None
    for host, port, send_http in targets:
        try:
            if socks5_probe(proxy_host, proxy_port, username, password, target_host=host, target_port=port, timeout=timeout, send_http=send_http):
                return (True, host, port)
        except Exception as e:
            last_error = e
    if last_error:
        raise last_error
    return (False, None, None)

def get_proxy_public_ip(proxy_host, proxy_port, username, password, timeout=15):
    proxy_url = f'socks5://{username}:{password}@{proxy_host}:{proxy_port}'
    handlers = [urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url}), urllib.request.HTTPSHandler(context=None)]
    opener = urllib.request.build_opener(*handlers)
    urls = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com']
    last_error = None
    for url in urls:
        try:
            with opener.open(url, timeout=timeout) as resp:
                ip = resp.read().decode('utf-8', errors='ignore').strip()
                if ip:
                    return ip
        except Exception as e:
            last_error = e
    if last_error:
        raise last_error
    raise OSError('Không lấy được public IP')

# [Ver 2.95] Quoc gia cua exit IP: chi lay ma 2 chu (US, VN...), UI doi thanh quoc ky.
# Cache 24h/ip trong RAM de CHECK ALL khong dot het quota ip-api (45 req/phut).
_CC_CACHE = {}
_CC_LOCK = threading.Lock()
_CC_TTL = 86400
_CC_MAX = 5000

def _cc_cache_get(ip):
    with _CC_LOCK:
        it = _CC_CACHE.get(ip)
    if not it:
        return ''
    if time.time() - float(it.get('ts') or 0) > _CC_TTL:
        return ''
    return str(it.get('cc') or '')

def _cc_cache_put(ip, cc):
    if not ip or not cc:
        return
    with _CC_LOCK:
        _CC_CACHE[ip] = {'cc': cc, 'ts': time.time()}
        if len(_CC_CACHE) > _CC_MAX:
            drop = sorted(_CC_CACHE, key=lambda k: float((_CC_CACHE.get(k) or {}).get('ts') or 0))[:1000]
            for k in drop:
                _CC_CACHE.pop(k, None)

def country_codes_for_ips(ips, timeout=6):
    """Doi IP -> ma quoc gia. Dung ip-api /batch (100 ip/lan), thieu thi hoi api.country.is.
    Khong bao gio nem loi: khong biet quoc gia thi tra ve rong."""
    out = {}
    todo = []
    for ip in [str(x).strip() for x in (ips or []) if str(x).strip()]:
        cc = _cc_cache_get(ip)
        if cc:
            out[ip] = cc
        elif ip not in todo:
            todo.append(ip)
    if not todo:
        return out
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        try:
            body = json.dumps([{'query': ip, 'fields': 'status,countryCode,query'} for ip in chunk]).encode('utf-8')
            req = urllib.request.Request('http://ip-api.com/batch', data=body, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                rows = json.loads(resp.read().decode('utf-8', 'replace'))
            for it in (rows if isinstance(rows, list) else []):
                ip = str((it or {}).get('query') or '').strip()
                cc = str((it or {}).get('countryCode') or '').strip().upper()
                if ip and len(cc) == 2:
                    out[ip] = cc
                    _cc_cache_put(ip, cc)
        except Exception:
            pass
    miss = [ip for ip in todo if ip not in out]
    for ip in miss[:40]:
        try:
            with urllib.request.urlopen('https://api.country.is/%s' % ip, timeout=timeout) as resp:
                d = json.loads(resp.read().decode('utf-8', 'replace'))
            cc = str((d or {}).get('country') or '').strip().upper()
            if len(cc) == 2:
                out[ip] = cc
                _cc_cache_put(ip, cc)
        except Exception:
            continue
    return out

def country_code_for_ip(ip, timeout=6):
    ip = str(ip or '').strip()
    if not ip:
        return ''
    return country_codes_for_ips([ip], timeout=timeout).get(ip, '')

def find_duplicate_proxy_tags(public_ip, session='1'):
    duplicates = []
    try:
        data = load_json(SESSION_FILES.get(str(session), SESSION_FILES['1']))
        for item in data.get('outbounds', []):
            tag = str(item.get('tag', '')).strip()
            if not tag.startswith('proxy_'):
                continue
            server = str(item.get('server', '')).strip()
            if server == public_ip:
                duplicates.append(tag)
    except Exception:
        pass
    duplicates.sort(key=proxy_tag_num)
    return duplicates

def check_proxy(proxy: str, session='1', with_country=True):
    if not proxy.strip():
        return {'ok': False, 'status': 'empty', 'message': 'DEAD'}
    try:
        server, port, user, password = parse_proxy(proxy)
        ok, _probe_host, _probe_port = socks5_probe_multi(server, port, user, password)
        if not ok:
            return {'ok': False, 'status': 'dead', 'message': 'DEAD'}
        public_ip = ''
        duplicates = []
        try:
            public_ip = get_proxy_public_ip(server, port, user, password)
            if public_ip:
                duplicates = find_duplicate_proxy_tags(public_ip, session=session)
        except Exception:
            pass
        cc = ''
        if with_country and public_ip:
            try:
                cc = country_code_for_ip(public_ip)
            except Exception:
                cc = ''
        return {'ok': True, 'status': 'live', 'message': 'LIVE', 'ip': public_ip, 'public_ip': public_ip,
                'country_code': cc, 'duplicates': duplicates}
    except Exception:
        return {'ok': False, 'status': 'dead', 'message': 'DEAD'}

def check_proxy_batch(items, session='1', max_workers=64):
    jobs = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        tag = str(item.get('tag', '')).strip()
        proxy = str(item.get('proxy', '')).strip()
        if tag and proxy:
            jobs.append((tag, proxy))
    results = {}
    if not jobs:
        return results
    workers = max(1, min(len(jobs), int(max_workers or 64), 128))
    def _one(tag, proxy):
        # [Ver 2.95] Batch phai check duoc ca PPPoE va VPN, khong chi socks5/http.
        p = str(proxy or '').strip()
        if p.startswith('pppoe:'):
            r = check_pppoe_session(p[6:], session=session, with_country=False)
        elif p.startswith('vpn:'):
            r = vpn_exit_ip(p[4:], with_country=False)
            if isinstance(r, dict) and r.get('exit_ip'):
                r['ip'] = r.get('exit_ip')
        else:
            r = check_proxy(p, session, False)
        return r
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_one, tag, proxy): tag for tag, proxy in jobs}
        for fut in as_completed(futs):
            tag = futs[fut]
            try:
                results[tag] = fut.result()
            except Exception as e:
                results[tag] = {'ok': False, 'status': 'dead', 'message': 'DEAD', 'error': str(e)}
    try:
        ips = [str(r.get('ip') or r.get('exit_ip') or '').strip() for r in results.values() if isinstance(r, dict) and r.get('ok')]
        cc = country_codes_for_ips([x for x in ips if x])
        for r in results.values():
            if not isinstance(r, dict) or not r.get('ok'):
                continue
            ip = str(r.get('ip') or r.get('exit_ip') or '').strip()
            if ip and cc.get(ip):
                r['country_code'] = cc[ip]
    except Exception:
        pass
    return results

def check_pppoe_session(sid, session='1', with_country=True):
    """[Ver 2.95] Check 1 phien PPPoE: glider SOCKS nam tren 127.0.0.1:15000+id-1.
    Tra ve cung dinh dang voi check_proxy de UI dung chung 1 ham ve."""
    sid = str(sid or '').strip()
    if not sid.isdigit():
        return {'ok': False, 'status': 'empty', 'message': 'DEAD'}
    try:
        port = pppoe_glider_port(sid)
        _su, _hp, user, pw, sport = pppoe_session_credentials(sid)
        port = int(port or sport or 0)
        if not port:
            return {'ok': False, 'status': 'dead', 'message': 'DEAD', 'error': 'khong ro port phien'}
        return check_proxy('127.0.0.1:%d:%s:%s' % (port, user, pw), session=session, with_country=with_country)
    except Exception as e:
        return {'ok': False, 'status': 'dead', 'message': 'DEAD', 'error': str(e)}

# [Ver 2.68] Quy tac cong WAN/LAN (Anh Thai chot 2026-10-21):
#   - eth0 LUON LA WAN, khong bao gio nam trong br-lan.
#   - eth1..eth5 mac dinh thuoc br-lan; khi duoc chon lam cong quay PPPoE => go khoi br-lan.
#   - Cong da la WAN ma chon tiep => KHONG dung gi (khong reload, khong reset IP phien cu).
#   - Cong khong con phien PPPoE nao => tra ve br-lan ngay.
# Ap dung bang uci (ben vung) + `ip link set master/nomaster` (tuc thi). KHONG goi
# /etc/init.d/network reload vi reload ifdown/ifup moi phien dang chay => mat IP.
# Ban 2.64-2.67 thieu chan eth0 trong pppoe_return_port => xoa phien tren eth0
# day eth0 vao br-lan, macvlan dev_xxx khong claim duoc, toan bo PPPoE chet.
PPPOE_WAN_FIXED = 'eth0'

def router_physical_ports():
    """[Ver 2.81] Cong vat ly cua router: ten, vai tro WAN/LAN, dang co day (up) hay khong.
    Doc thang /sys/class/net (khong goi server 9000) nen nhanh va khong treo.
    LAN = cong dang la slave cua br-lan; con lai = WAN."""
    base = Path('/sys/class/net')
    try:
        names = sorted((p.name for p in base.iterdir()), key=lambda n: (re.sub(r'\d+$', '', n), int((re.findall(r'\d+$', n) or ['0'])[0])))
    except Exception:
        return []
    try:
        uci_lan = set(_lan_ports_get())
    except Exception:
        uci_lan = set()
    out = []
    for n in names:
        p = base / n
        if not (p / 'device').exists() or n == 'lo':
            continue  # chi lay cong vat ly (bo br-lan, macvlan, tun, ppp...)
        try:
            master = os.path.basename(os.readlink(str(p / 'master')))
        except Exception:
            master = ''
        role = 'lan' if (master == 'br-lan' or (not master and n in uci_lan)) else 'wan'
        up = False
        try:
            up = (p / 'carrier').read_text().strip() == '1'
        except Exception:
            try:
                up = (p / 'operstate').read_text().strip() == 'up'
            except Exception:
                up = False
        speed = ''
        if up:
            try:
                sp = int((p / 'speed').read_text().strip())
                if sp > 0:
                    speed = f'{sp // 1000}G' if sp >= 1000 and sp % 1000 == 0 else f'{sp}M'
            except Exception:
                pass
        out.append({'name': n, 'role': role, 'up': up, 'speed': speed})
    return out

def _lan_ports_get():
    cur=subprocess.check_output(['uci','-q','get','network.@device[0].ports'],text=True,timeout=5).strip()
    return [x for x in cur.split() if x]

def _lan_ports_set(ports):
    subprocess.run(['uci','-q','del','network.@device[0].ports'],check=True,timeout=5)
    for x in ports: subprocess.run(['uci','add_list','network.@device[0].ports='+x],check=True,timeout=5)
    subprocess.run(['uci','commit','network'],check=True,timeout=5)

def _port_in_use_by_pppoe(port, exclude_ids=None):
    # Dem phien PPPoE con lai dung cong nay (sau khi tru cac id sap xoa).
    # Loi doc danh sach => coi nhu CON DUNG (an toan: khong tra cong ve LAN).
    exclude_ids=set(exclude_ids or [])
    try:
        old=call_old_gui('/api/router/pppoe'); raw=(old or {}).get('data')
        if isinstance(raw,dict): raw=raw.get('data',raw)
        if not isinstance(raw,list): return True
        for x in raw:
            try: xid=int(x.get('id',-1))
            except Exception: xid=-1
            if xid in exclude_ids: continue
            if str(x.get('device') or '').split('.',1)[0]==port: return True
        return False
    except Exception:
        return True

def ensure_wan_port_not_bridged():
    # Tu chua: eth0 bi nhet vao br-lan (uci hoac kernel) => go ra + log vet.
    st={'ok':True,'changed':False}
    try:
        ports=_lan_ports_get()
        if PPPOE_WAN_FIXED in ports:
            _lan_ports_set([x for x in ports if x!=PPPOE_WAN_FIXED]); st['changed']=True; st['uci']=True
        link=subprocess.run(['ip','-o','link','show',PPPOE_WAN_FIXED],capture_output=True,text=True,timeout=5).stdout
        if 'master br-lan' in link:
            subprocess.run(['ip','link','set',PPPOE_WAN_FIXED,'nomaster'],timeout=5,capture_output=True)
            st['changed']=True; st['kernel']=True
        if st['changed']:
            print('[HEAL] eth0 (WAN) bi nam trong br-lan -> da go ra', st, flush=True)
    except Exception as e:
        st.update({'ok':False,'error':str(e)[:160]})
    return st

def pppoe_prepare_port(device):
    base=(str(device or '').split('.',1)[0] or '').strip()
    if not re.match(r'^eth[0-9]+$',base): return {'ok':False,'error':('port PPPoE khong hop le: '+base)}
    port_state={'ok':True,'port':base,'changed':False,'reloaded':False}
    try:
        if base==PPPOE_WAN_FIXED:
            heal=ensure_wan_port_not_bridged()
            port_state.update({'reason':'eth0 luon la WAN','changed':heal.get('changed',False)})
            return port_state
        cur=_lan_ports_get()
        if base not in cur:
            # Da la WAN tu truoc => khong dung gi, giu IP cac phien cu.
            port_state['reason']='port da la WAN, khong dong'
            return port_state
        _lan_ports_set([x for x in cur if x!=base])
        subprocess.run(['ip','link','set',base,'nomaster'],timeout=5,capture_output=True)
        subprocess.run(['ip','link','set',base,'up'],timeout=5,capture_output=True)
        port_state.update({'changed':True,'lan_ports':[x for x in cur if x!=base]})
    except Exception as e:
        port_state.update({'ok':False,'error':str(e)[:160]})
    return port_state

def pppoe_return_port(base, deleted_ids=None):
    port=(str(base or '').split('.',1)[0] or '').strip()
    port_state={'ok':True,'port':port,'changed':False}
    if not re.match(r'^eth[0-9]+$',port): return port_state
    if port==PPPOE_WAN_FIXED:
        port_state['reason']='eth0 luon la WAN, khong tra ve LAN'
        return port_state
    try:
        if _port_in_use_by_pppoe(port, deleted_ids):
            port_state['reason']='con phien PPPoE dung cong, giu WAN'
            return port_state
        ports=_lan_ports_get()
        if port in ports: return port_state
        ports.append(port)
        _lan_ports_set(ports)
        subprocess.run(['ip','link','set',port,'master','br-lan'],timeout=5,capture_output=True)
        port_state.update({'changed':True,'lan_ports':ports})
    except Exception as e:
        port_state.update({'ok':False,'error':str(e)[:160]})
    return port_state

def call_old_gui(path, method='GET', data=None):
    body = None
    # Server goc 9000 check header trinh duyet voi 1 so API (pppoe list tra 400/ngat neu thieu).
    headers = {'Accept': 'application/json', 'Referer': 'http://127.0.0.1:9000/', 'Origin': 'http://127.0.0.1:9000'}
    if data is not None and method != 'GET':
        body = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    if data is not None and method == 'GET':
        qs = urlencode(data)
        path = path + ('&' if '?' in path else '?') + qs
    url = OLD_GUI_BASE + path
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
            try:
                return {'ok': True, 'data': json.loads(raw) if raw else {}}
            except Exception:
                return {'ok': True, 'data': raw}
    except Exception as remote_error:
        if path == '/api/router/info':
            ip = ''
            prefix = 24
            try:
                ip = subprocess.check_output(['uci', '-q', 'get', 'network.lan.ipaddr'], text=True, timeout=5).strip()
            except Exception:
                pass
            try:
                mask = subprocess.check_output(['uci', '-q', 'get', 'network.lan.netmask'], text=True, timeout=5).strip()
                import ipaddress
                prefix = ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen
            except Exception:
                pass
            ports = []
            try:
                raw_ports = subprocess.check_output(['uci', '-q', 'get', 'network.lan.ports'], text=True, timeout=5).strip()
                ports = [x for x in raw_ports.split() if x]
            except Exception:
                pass
            return {'ok': True, 'data': {'data': {'lan': {'networks': [{'ip': ip, 'prefix_length': prefix, 'device': 'br-lan', 'ports': ports, 'id': 'lan'}]}}, 'success': True}}
        if path == '/api/router/change_lan':
            ip_lan = str((data or {}).get('ip_lan') or '').strip()
            if not ip_lan:
                raise ValueError('ip_lan trống')
            subprocess.run(['uci', 'set', f'network.lan.ipaddr={ip_lan}'], check=True, timeout=10)
            subprocess.run(['uci', 'commit', 'network'], check=True, timeout=10)
            subprocess.Popen(['/etc/init.d/network', 'reload'])
            return {'ok': True, 'data': {'success': True, 'ip_lan': ip_lan, 'mode': 'local-compat'}}
        if path == '/api/update_proxy':
            return {'ok': True, 'data': {'success': True, 'ok': True, 'mode': 'local-compat', 'warning': 'old GUI 9000 unavailable; gencore config already updated'}}
        raise remote_error

def call_static_api(path, method='GET', data=None):
    body = None
    headers = {}
    if data is not None and method != 'GET':
        body = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    if data is not None and method == 'GET':
        qs = urlencode(data)
        path = path + ('&' if '?' in path else '?') + qs
    url = STATIC_API_BASE + path
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode('utf-8', errors='ignore')
        try:
            return {'ok': True, 'data': json.loads(raw) if raw else {}}
        except Exception:
            return {'ok': True, 'data': raw}

def sync_static_to_router(rows, clear_first=False):
    valid_rows = []
    for row in rows or []:
        ip = str(row.get('ip', '')).strip()
        mac = normalize_mac(row.get('mac', ''))
        if not ip or not mac:
            continue
        valid_rows.append({'ip': ip, 'mac': mac})
    if clear_first and valid_rows:
        try:
            call_static_api('/del_all_static', method='GET')
        except Exception:
            pass
    for row in valid_rows:
        ip = str(row.get('ip', '')).strip()
        mac = normalize_mac(row.get('mac', ''))
        try:
            call_static_api('/del_static', method='GET', data={'ip': ip})
        except Exception:
            pass
        try:
            call_static_api('/del_static', method='GET', data={'mac': mac})
        except Exception:
            pass
        call_static_api('/add_static', method='GET', data={'ip': ip, 'mac': mac})
VPN_MGR = '/data/vpn/vpn_mgr.sh'
VPN_HOSTS_FILE = '/data/vpn/express_hosts.txt'

def ensure_vpn_mgr():
    """Tu phat hien + phuc hoi /data/vpn/vpn_mgr.sh tu ban gan trong app (tools/vpn_mgr.sh).
    Moi router tu lai ngay sau update/restart, khong phu thuoc deploy tay. Tra True neu engine san sang.

    [Ver 2.48] So MD5 thay vi so SIZE. Ban truoc chi so st_size: hai ban khac noi dung
    ma trung size thi router GIU BAN CU IM LANG - dung cai bay da lam ban va tay khong
    bao gio lan ra ca dan may (xem Ver 2.47 / etc_install.sh)."""
    try:
        Path('/data/vpn').mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    dst = Path(VPN_MGR)
    src = BASE_DIR / 'tools' / 'vpn_mgr.sh'
    try:
        if src.exists() and (not dst.exists() or _file_md5(str(dst)) != _file_md5(str(src))):
            shutil.copy(str(src), str(dst))
            try:
                os.chmod(str(dst), 493)
            except Exception:
                pass
    except Exception:
        pass
    return dst.exists()
VPN_GUARD = '/etc/gen_vpn_guard.sh'

def ensure_vpn_guard():
    """Tu phat hien + phuc hoi /etc/gen_vpn_guard.sh tu ban gan trong app (tools/gen_vpn_guard.sh).

    Guard nay chua duong di VPN (br-lan -> tun*): tproxy va gen_fw_fix.sh chen rule
    chan theo interface (-i br-lan) len DAU chain moi lan apply, nen may da gan VPN
    bi chan UDP/FORWARD. Guard ep 4 rule thoat theo ipset genrouter_vpn ve vi tri 1
    va nap 2 file include cho fw4 (accept oifname tun* + MSS clamp).

    Idempotent: chi copy khi khac size, chi cai hook/cron khi chua co.
    Tra True neu guard san sang."""
    src = BASE_DIR / 'tools' / 'gen_vpn_guard.sh'
    dst = Path(VPN_GUARD)
    try:
        if src.exists() and (not dst.exists() or dst.stat().st_size != src.stat().st_size):
            shutil.copy(str(src), str(dst))
            try:
                os.chmod(str(dst), 493)
            except Exception:
                pass
    except Exception:
        pass
    if not dst.exists():
        return False
    installer = BASE_DIR / 'tools' / 'gen_vpn_guard_install.sh'
    try:
        if installer.exists():
            subprocess.run(['sh', str(installer), str(src)], timeout=60,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(['sh', VPN_GUARD, 'fix'], timeout=60,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return True
ETC_INSTALL_LOG = BASE_DIR / 'logs' / 'etc_install.log'

def _etc_install_run(reason: str = 'startup'):
    """Chay tools/etc_install.sh (idempotent) va ghi log. Tra (rc, output)."""
    ei = BASE_DIR / 'tools' / 'etc_install.sh'
    etc_dir = BASE_DIR / 'etc'
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        ETC_INSTALL_LOG.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    if not ei.exists() or not etc_dir.is_dir():
        try:
            with open(ETC_INSTALL_LOG, 'a', encoding='utf-8') as fh:
                fh.write(f'\n=== {stamp} etc_install BO QUA ({reason}): '
                         f'etc_install.sh={ei.exists()} etc_dir={etc_dir.is_dir()} ===\n')
        except Exception:
            pass
        return (-1, '')
    try:
        r = subprocess.run(['sh', str(ei), str(etc_dir)], timeout=120,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = (r.stdout or b'').decode('utf-8', 'replace')
        with open(ETC_INSTALL_LOG, 'a', encoding='utf-8') as fh:
            fh.write(f'\n=== {stamp} etc_install ({reason}) rc={r.returncode} ===\n{out}')
        return (r.returncode, out)
    except Exception as e:
        try:
            with open(ETC_INSTALL_LOG, 'a', encoding='utf-8') as fh:
                fh.write(f'\n=== {stamp} etc_install LOI ({reason}): {e} ===\n')
        except Exception:
            pass
        return (-1, '')

def ensure_lan_syn_bypass():
    """[Ver 2.69] Tu ap dung mien syn_flood cho SYN tu br-lan luc KHOI DONG app.py.

    Vi sao o day: router cu update qua GUI chay update_repo_from_remote() cua BAN CU
    (khong biet apply_xxtouch_bypass.sh moi), va /etc/init.d/proxy-manager-v1 tren may
    cu do install.sh cu sinh ra, co the khong goi script nay. Neu chi trong vao init.d
    thi may cu len 2.69 van lag GUI (SYN bi syn_flood 25/s drop). Goi tu app.py => chi
    can app.py moi chay len la co, khong phu thuoc ban cu. Script idempotent.
    Kem: dong bo init.d tu etc/init.d/proxy-manager-v1 neu ban dang cai thieu buoc nay."""
    log = BASE_DIR / 'logs' / 'lan_syn_bypass.log'
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        sh = BASE_DIR / 'apply_xxtouch_bypass.sh'
        out = ''
        if sh.exists():
            try: os.chmod(str(sh), 0o755)
            except Exception: pass
            r = subprocess.run(['sh', str(sh)], timeout=30, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = 'bypass rc=%s %s' % (r.returncode, (r.stdout or b'').decode('utf-8', 'replace')[:300])
        else:
            out = 'bypass BO QUA: thieu %s' % sh
        src = BASE_DIR / 'etc' / 'init.d' / 'proxy-manager-v1'
        dst = Path('/etc/init.d/proxy-manager-v1')
        try:
            if src.exists() and dst.exists():
                cur = dst.read_text(encoding='utf-8', errors='replace')
                if 'apply_xxtouch_bypass.sh' not in cur:
                    shutil.copy2(str(dst), str(dst) + '.bak_v269')
                    shutil.copy2(str(src), str(dst))
                    os.chmod(str(dst), 0o755)
                    out += ' | init.d dong bo (backup .bak_v269)'
        except Exception as e:
            out += ' | init.d loi: %s' % str(e)[:120]
        with open(log, 'a', encoding='utf-8') as fh:
            fh.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), out.strip()))
    except Exception:
        pass

def ensure_etc_installed():
    """[Ver 2.49] Tu trien khai etc/ luc KHOI DONG: kill-switch + ban tproxy da sua +
    cron watchdog. Chay trong thread nen de khong lam cham GUI.

    Vi sao BAT BUOC co: `update_repo_from_remote()` chi bat dau goi etc_install.sh tu
    Ver 2.47. Router dang o ban CU (do duoc: 2.19 va 2.33) khi bam nut update tren GUI
    se chay update_repo_from_remote() cua CHINH BAN CU dang nam trong RAM - ban do KHONG
    biet den etc_install.sh. Ket qua: app.py/static/tools len ban moi va router reboot,
    nhung /etc/genrouter_killswitch.sh, /etc/genrouter/core/tproxy, /etc/shm/tproxy va
    cron */5 dataplane_guard VAN THIEU, va thieu mot cach IM LANG (GUI bao "cap nhat
    thanh cong"). Phai doi den lan update KE TIEP moi duoc bu - dung ho lo hong ma
    Ver 2.47/2.48 vua dong o cac cho khac.

    Dat o khoi khoi dong nen chi can MOT lan update qua GUI la du: app.py moi chay len
    va tu bu phan con thieu, khong phu thuoc ban cu da lam gi. Cung la self-heal: neu
    file /etc/... bi vendor hay tay nguoi ghi de, lan restart sau se dua lai ban dung.

    etc_install.sh idempotent: file trung noi dung thi chi in [=], khong ghi, khong
    backup; crontab chi APPEND dong con thieu, KHONG ghi de; va KHONG tu chay
    kill-switch (viec doi routing/iptables van do cron 1 phut quyet dinh)."""
    def _worker():
        try:
            rc, out = _etc_install_run('startup')
            if rc == 0 and 'file thay doi' in out:
                for ln in out.splitlines():
                    if ln.startswith('[OK] etc_install.sh xong'):
                        _wd_log(f'etc_install (startup): {ln.strip()}')
                        break
        except Exception:
            pass
    try:
        threading.Thread(target=_worker, daemon=True).start()
    except Exception:
        pass
    return True
_VPN_DEPS = {'openvpn': None, 'wg': None, 'installing': False, 'log': '', 'ts': 0}
_VPN_DEPS_LOCK = threading.Lock()
_FEEDS_FILE = Path('/etc/opkg/distfeeds.conf')
_FEED_FIX_RE = re.compile('https://mirrors\\.vsean\\.net/openwrt/releases/[^/\\s]+')
_FEED_FIX_TO = 'https://downloads.openwrt.org/releases/23.05.5'

def _fix_opkg_feeds():
    """Mirror vsean lac quan -> doi cac feed userspace sang downloads.openwrt.org release,
    GIU NGUYEN dong kmods (kernel module phai dung snapshot trung vermagic). Giu file .bak goc."""
    try:
        if not _FEEDS_FILE.exists():
            return False
        text = _FEEDS_FILE.read_text(encoding='utf-8', errors='replace')
        out_lines = []
        changed = False
        for ln in text.splitlines():
            if 'kmods' not in ln and 'mirrors.vsean.net' in ln:
                new_ln = _FEED_FIX_RE.sub(_FEED_FIX_TO, ln)
                if new_ln != ln:
                    changed = True
                ln = new_ln
            out_lines.append(ln)
        if not changed:
            return False
        bak = _FEEDS_FILE.with_name('distfeeds.conf.bak')
        if not bak.exists():
            try:
                bak.write_text(text, encoding='utf-8')
            except Exception:
                pass
        _FEEDS_FILE.write_text('\n'.join(out_lines) + '\n', encoding='utf-8')
        return True
    except Exception:
        return False

def _which(name):
    try:
        p = subprocess.run(['which', name], capture_output=True, text=True, timeout=5)
        return bool(p.returncode == 0 and (p.stdout or '').strip())
    except Exception:
        return False

def _vpn_deps_missing():
    return [b for b in ('openvpn', 'wg') if not _which(b)]

def _install_vpn_deps_worker(missing):
    try:
        pkgs = []
        if 'openvpn' in missing:
            pkgs.append('openvpn-openssl')
        if 'wg' in missing:
            pkgs += ['wireguard-tools', 'kmod-wireguard']
        logs = ['Tu cai dat phan mem con thieu: ' + ' '.join(pkgs)]

        def _opkg(args, timeout=420):
            p = subprocess.run(['opkg'] + args, capture_output=True, text=True, timeout=timeout)
            return (p.returncode, ((p.stdout or '') + (p.stderr or '')).strip())
        try:
            upd_ok = False
            for attempt in (1, 2, 3):
                rc, out = _opkg(['update'])
                logs.append('$ opkg update (lan ' + str(attempt) + ') -> rc=' + str(rc))
                logs.extend(('  ' + ln for ln in out.splitlines()[-3:]))
                if rc == 0:
                    upd_ok = True
                    break
                time.sleep(5)
            if not upd_ok and _fix_opkg_feeds():
                logs.append('Mirror lac quan lien tuc -> tu doi feed userspace sang downloads.openwrt.org (backup distfeeds.conf.bak, giu nguyen feed kmods), thu lai:')
                rc, out = _opkg(['update'])
                logs.append('$ opkg update (sau khi sua feed) -> rc=' + str(rc))
                logs.extend(('  ' + ln for ln in out.splitlines()[-3:]))
        except Exception as e:
            logs.append('$ opkg update -> LOI ' + str(e))
        for pkg in pkgs:
            try:
                rc = 1
                out = ''
                for attempt in (1, 2, 3):
                    rc, out = _opkg(['install', pkg])
                    logs.append('$ opkg install ' + pkg + ' (lan ' + str(attempt) + ') -> rc=' + str(rc))
                    logs.extend(('  ' + ln for ln in out.splitlines()[-2:]))
                    if rc == 0:
                        break
                    time.sleep(4)
                if rc != 0 and pkg in ('openvpn-openssl', 'wireguard-tools'):
                    rc, out = _opkg(['install', '--force-depends', pkg])
                    logs.append('$ opkg install --force-depends ' + pkg + ' -> rc=' + str(rc) + ' (fallback userspace, bo dep kernel)')
                    logs.extend(('  ' + ln for ln in out.splitlines()[-2:]))
            except Exception as e:
                logs.append('$ opkg install ' + pkg + ' -> LOI ' + str(e))
        with _VPN_DEPS_LOCK:
            _VPN_DEPS['installing'] = False
            _VPN_DEPS['log'] = '\n'.join(logs)[-2400:]
            _VPN_DEPS['ts'] = int(time.time())
            _VPN_DEPS['openvpn'] = _which('openvpn')
            _VPN_DEPS['wg'] = _which('wg')
            summary = []
            summary.append('KET QUA: openvpn=' + ('OK' if _VPN_DEPS['openvpn'] else 'THAT BAI') + ', wg=' + ('OK' if _VPN_DEPS['wg'] else 'THAT BAI'))
            if not _VPN_DEPS['wg']:
                summary.append('Luu y: kmod-wireguard co the khong hop kernel firmware nay — openvpn van dung binh thuong, WG can firmware co WireGuard.')
            _VPN_DEPS['log'] = (_VPN_DEPS['log'] + '\n' + '\n'.join(summary))[-2400:]
    except Exception:
        with _VPN_DEPS_LOCK:
            _VPN_DEPS['installing'] = False

def ensure_vpn_deps_async():
    """Tu cai openvpn/wireguard-tools/kmod-wireguard qua opkg khi thieu (chay nen, khong block request)."""
    missing = _vpn_deps_missing()
    if not missing:
        return None
    with _VPN_DEPS_LOCK:
        if _VPN_DEPS['installing']:
            return 'installing'
        _VPN_DEPS['installing'] = True
    threading.Thread(target=_install_vpn_deps_worker, args=(missing,), daemon=True).start()
    return 'installing'

def vpn_deps_status():
    with _VPN_DEPS_LOCK:
        installing = _VPN_DEPS['installing']
        log = _VPN_DEPS['log']
    return {'openvpn': _which('openvpn'), 'wg': _which('wg'), 'installing': installing, 'log': log}

def vpn_run(args, timeout=150):
    try:
        if not ensure_vpn_mgr():
            return {'ok': False, 'error': 'vpn_mgr.sh missing', 'output': 'Thiếu vpn_mgr.sh trên router và không có bản dự phòng tools/vpn_mgr.sh trong thư mục app — hãy bấm Cập nhật lên bản mới nhất rồi thử lại.'}
        a0 = str(args[0]) if args else ''
        missing = _vpn_deps_missing()
        if missing:
            need_ovpn = a0 in ('add-openvpn', 'add-express', 'up', 'startall', 'test')
            need_wg = a0 in ('add-wg',)
            if need_ovpn and 'openvpn' in missing or (need_wg and 'wg' in missing):
                ensure_vpn_deps_async()
                return {'ok': False, 'error': 'deps missing', 'output': 'Thiếu ' + '/'.join(missing) + ' — app đang TỰ CÀI trong nền (opkg, ~1-2 phút). Chờ xíu rồi bấm lại lệnh này nhé.'}
        p = subprocess.run(['/bin/sh', VPN_MGR] + [str(a) for a in args], capture_output=True, text=True, timeout=timeout)
        return {'ok': p.returncode == 0, 'rc': p.returncode, 'output': ((p.stdout or '') + (p.stderr or '')).strip()}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'output': str(e)}

def vpn_machine_map():
    """IP -> so may, lay tu identity text DUNG CHUNG (meta) nen khong phu thuoc
    session active — trang /vpn mo rieng tab van hien so may dung."""
    out = {}
    try:
        text = get_saved_ip_identity_text()
        if text:
            for it in parse_ip_identity_text(text):
                ip = str(it.get('ip', '')).strip()
                num = str(it.get('machine', '')).strip()
                if ip and num:
                    out[ip] = num
    except Exception:
        pass
    return out

def vpn_status_json():
    r = vpn_run(['json'])
    try:
        return json.loads((r.get('output') or '[]').strip() or '[]')
    except Exception:
        return []

def vpn_ping_host(host):
    """[Ver 2.94] Resolve + ping 1 host ExpressVPN (3 goi, toi da ~4s). Khong mo tunnel."""
    out = {'ok': True, 'host': host, 'ip': '', 'ms': None}
    try:
        import socket
        out['ip'] = socket.gethostbyname(host)
    except Exception:
        return {'ok': False, 'host': host, 'error': 'khong resolve duoc (host chet?)'}
    try:
        r = subprocess.run(['ping', '-c', '3', '-W', '1', out['ip']], capture_output=True, text=True, timeout=8)
        m = re.search(r'= [\d.]+/([\d.]+)/', r.stdout or '')
        out['ms'] = round(float(m.group(1))) if m else None
    except Exception:
        pass
    return out

XV_CREDS_FILE = '/data/vpn/express_creds.json'
_XV_CREDS_LOCK = threading.Lock()

def _xv_creds_load():
    try:
        with open(XV_CREDS_FILE, encoding='utf-8') as f:
            d = json.load(f)
        return [c for c in d if isinstance(c, dict) and c.get('user')] if isinstance(d, list) else []
    except Exception:
        return []

def _xv_creds_write(lst):
    Path('/data/vpn').mkdir(parents=True, exist_ok=True)
    tmp = XV_CREDS_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(lst, f, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, XV_CREDS_FILE)

def _xv_cred_id(user):
    import hashlib
    return hashlib.sha1(user.encode('utf-8')).hexdigest()[:10]

def xv_creds_public():
    """[Ver 2.94] Danh sach tai khoan ExpressVPN da luu - KHONG tra pass/key ra trinh duyet."""
    out = []
    for c in _xv_creds_load():
        u = str(c['user'])
        out.append({'id': _xv_cred_id(u), 'user': (u[:4] + '…' + u[-2:]) if len(u) > 8 else u,
                    'has_key': bool(c.get('key')), 'ts': int(c.get('ts') or 0)})
    return out

def xv_creds_save(items):
    """items: list (user, pass, key). Trung user => cap nhat pass/key."""
    n = 0
    with _XV_CREDS_LOCK:
        lst = _xv_creds_load()
        for user, pwd, key in items:
            user = str(user or '').strip()
            pwd = str(pwd or '').strip()
            key = re.sub(r'[^A-Za-z0-9_-]', '', str(key or ''))[:64]
            if not user or not pwd or len(user) > 128 or len(pwd) > 128 or '\n' in user + pwd:
                continue
            cur = next((c for c in lst if c.get('user') == user), None)
            if cur:
                cur.update({'pass': pwd, 'key': key or cur.get('key', ''), 'ts': int(time.time())})
            else:
                lst.append({'user': user, 'pass': pwd, 'key': key, 'ts': int(time.time())})
            n += 1
        if n:
            _xv_creds_write(lst[-200:])
    return n

def xv_creds_del(cid):
    with _XV_CREDS_LOCK:
        lst = _xv_creds_load()
        keep = [c for c in lst if _xv_cred_id(str(c['user'])) != cid]
        if len(keep) != len(lst):
            _xv_creds_write(keep)
        return len(lst) - len(keep)

def xv_cred_get(cid):
    return next((c for c in _xv_creds_load() if _xv_cred_id(str(c['user'])) == cid), None)

VPN_AUTO_FILE = '/data/vpn/auto_assign.json'
VPN_AUTO_LOCK = threading.Lock()
VPN_AUTO_RT = {'ts': 0, 'msg': '', 'last': []}

def _vpn_auto_load():
    try:
        with open(VPN_AUTO_FILE, encoding='utf-8') as f:
            d = json.load(f)
    except Exception:
        d = {}
    if not isinstance(d, dict):
        d = {}
    pool = [str(x) for x in d.get('pool') or [] if re.match(r'^[A-Za-z0-9_.-]{1,64}$', str(x))]
    try:
        rel = max(0, min(1440, int(d.get('release_min', 30))))
    except Exception:
        rel = 30
    auto = d.get('auto') if isinstance(d.get('auto'), dict) else {}
    return {'enabled': bool(d.get('enabled')), 'allow_dup': bool(d.get('allow_dup')), 'pool': pool,
            'range': str(d.get('range') or '')[:400], 'release_min': rel, 'auto': auto}

def _vpn_auto_save(cfg):
    _ss_atomic_write(Path(VPN_AUTO_FILE), json.dumps(cfg, ensure_ascii=False))

def _vpn_auto_ranges(text):
    """'192.10.3.0/24, 192.10.4.10-192.10.4.50, 192.10.5.7' -> [(lo, hi)] so nguyen. Loi -> ValueError."""
    import ipaddress
    out = []
    for tok in re.split(r'[\s,;]+', str(text or '').strip()):
        if not tok:
            continue
        if '/' in tok:
            n = ipaddress.ip_network(tok, strict=False)
            if n.version != 4 or n.prefixlen < 16:
                raise ValueError('dai qua rong: ' + tok)
            out.append((int(n.network_address), int(n.broadcast_address)))
        elif '-' in tok:
            x, y = tok.split('-', 1)
            lo = int(ipaddress.IPv4Address(x))
            hi = int(ipaddress.IPv4Address(y)) if '.' in y else (lo & ~0xFF) | int(y)
            if hi < lo or hi - lo > 65535:
                raise ValueError('khoang sai: ' + tok)
            out.append((lo, hi))
        else:
            v = int(ipaddress.IPv4Address(tok))
            out.append((v, v))
    return out

def _vpn_auto_in(ip, ranges):
    try:
        v = struct.unpack('!I', socket.inet_aton(ip))[0]
    except Exception:
        return False
    return any(lo <= v <= hi for lo, hi in ranges)

def _vpn_auto_excluded():
    ex = {CONN_FIXED_MASTER}
    try:
        c = get_conn_config()
        for k in ('direct', 'iso_master'):
            ex.update(x for x in c.get(k) or [] if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', x))
    except Exception:
        pass
    return ex

def _vpn_auto_manual_proxy_ips():
    """[Ver 2.99] IP dang duoc cau hinh chay PROXY THAT (socks/http, gom ca PPPoE glider)
    trong cau hinh DANG CHAY => VPN-AUTO khong duoc tu gan VPN cho may do.

    Su co 2026-10-27: may 192.10.0.16 doi tu VPN xv-1 sang proxy Lumi JP. Proxy trong
    gencore dung, nhung VPN-AUTO (auto_assign.json, dai '192.10.0.16 192.10.0.121')
    cu ~20s lai gan lai xv-1 => may van ra IP VPN. VPN-SYNC go thi VPN-AUTO gan lai
    (log: unassign 12:19:51 -> assign 12:19:55)."""
    out = set()
    try:
        data = load_json(RUNTIME_SOURCE_FILE)
    except Exception:
        return out
    try:
        route_by_ip = build_route_ip_to_tag(data)
    except Exception:
        route_by_ip = {}
    if not route_by_ip:
        return out
    for ob in data.get('outbounds') or []:
        if not isinstance(ob, dict):
            continue
        tag = str(ob.get('tag') or '')
        if not tag.startswith('proxy_'):
            continue
        if str(ob.get('type') or '').strip().lower() not in ('socks', 'http'):
            continue
        for ip, t in route_by_ip.items():
            if t == tag and ip:
                out.add(str(ip).strip())
    return out


def vpn_auto_tick():
    """[Ver 2.94] Giong MiniSocks 'EnableAuto/AllowDuplicate': may song trong dai IP, chua gan VPN
    => gan vao tunnel UP trong danh sach co it may nhat (khong trung: chi tunnel 0 may).
    Chi dung may DO NO tu gan (auto): may gan tay giu nguyen. Tunnel chet => chuyen may sang tunnel khac.
    May tu gan offline qua release_min phut => tra tunnel (0 = khong tra)."""
    with VPN_AUTO_LOCK:
        cfg = _vpn_auto_load()
        if not cfg['enabled'] or not cfg['pool']:
            return
        try:
            ranges = _vpn_auto_ranges(cfg['range'])
        except ValueError as e:
            VPN_AUTO_RT.update(ts=time.time(), msg='dai IP loi: %s' % e)
            return
        if not ranges:
            VPN_AUTO_RT.update(ts=time.time(), msg='chua nhap dai IP')
            return
        run = {x['name'] for x in vpn_status_json() if x.get('running')}
        pool = [n for n in cfg['pool'] if n in run]
        vmap = load_vpn_map()
        arp = _arp_online_map() or {}
        auto, now, done, changed = cfg['auto'], time.time(), [], False
        excl = _vpn_auto_excluded()
        # [Ver 2.99] May dang cau hinh proxy that thi khong phai may VPN.
        manual = _vpn_auto_manual_proxy_ips()
        for ip in list(auto):
            rec = auto[ip] if isinstance(auto[ip], dict) else {}
            cur = vmap.get(ip)
            if cur != rec.get('name'):          # da bi go / gan tay sang tunnel khac => khong con la auto
                auto.pop(ip); changed = True; continue
            if ip in arp:
                rec['seen'] = now
            off = now - float(rec.get('seen') or now)
            dead = cur not in run
            drop = ((cfg['release_min'] and off > cfg['release_min'] * 60) or ip in excl
                    or ip in manual or not _vpn_auto_in(ip, ranges))
            if dead or drop:
                r = vpn_run(['unassign', ip], timeout=60)
                if r.get('ok'):
                    _record_vpn_declaration(ip, '')
                    vmap.pop(ip, None)
                    done.append('%s bo %s (%s)' % (ip, cur, 'tunnel chet' if dead else 'offline/ngoai dai'))
                auto.pop(ip); changed = True
        cnt = {n: 0 for n in pool}
        for n in vmap.values():
            if n in cnt:
                cnt[n] += 1
        want = sorted((ip for ip in arp if ip not in vmap and ip not in excl and ip not in manual
                       and _vpn_auto_in(ip, ranges)),
                      key=lambda x: socket.inet_aton(x))
        short = 0
        for ip in want[:24]:
            cands = [n for n in pool if cfg['allow_dup'] or cnt[n] == 0]
            if not cands:
                short = len(want) - len(done); break
            n = min(cands, key=lambda x: (cnt[x], pool.index(x)))
            r = vpn_run(['assign', n, ip], timeout=60)
            if r.get('ok'):
                _record_vpn_declaration(ip, n)
                cnt[n] += 1
                auto[ip] = {'name': n, 'ts': int(now), 'seen': now}
                changed = True
                done.append('%s -> %s' % (ip, n))
            else:
                done.append('%s loi: %s' % (ip, str(r.get('error') or r.get('output') or '')[-80:]))
        if changed:
            cfg['auto'] = auto
            _vpn_auto_save(cfg)
        msg = '%d tunnel UP trong danh sach, %d may tu gan' % (len(pool), len(auto))
        if short:
            msg += '; THIEU tunnel trong cho %d may (them tunnel hoac bat "cho dung chung")' % short
        VPN_AUTO_RT.update(ts=now, msg=msg)
        if done:
            VPN_AUTO_RT['last'] = (done + VPN_AUTO_RT['last'])[:30]
            _ss_log('VPN-AUTO: ' + '; '.join(done)[:300])

def _resolve_v4(host, timeout=6):
    """IPv4 cua host, KHONG gom DNS server (khac nslookup)."""
    try:
        socket.setdefaulttimeout(timeout)
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []

DISTINCT = {'lock': threading.Lock(), 'jobs': {}, 'seq': 0}

def _xv_pool_by_loc(locs=None):
    """[(loc, [host...])] trai deu theo thanh pho de moi tunnel ra mot cum server khac nhau."""
    groups = {}
    try:
        with open(VPN_HOSTS_FILE, 'r', encoding='utf-8', errors='replace') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                pp = ln.split('|')
                if len(pp) < 3:
                    continue
                loc = ('%s %s' % (pp[0], pp[1])).strip()
                groups.setdefault(loc, []).append(pp[-1])
    except Exception:
        return []
    keys = [k for k in groups if not locs or any(x in k.lower() for x in locs)]
    # round-robin: moi vong lay 1 host cua tung thanh pho => trai deu, khac cum server
    res, depth = [], 0
    while depth < 40:
        anyh = False
        for k in keys:
            if depth < len(groups[k]):
                res.append((k, groups[k][depth]))
                anyh = True
        if not anyh:
            break
        depth += 1
    return res

def _xv_candidates(locs=None, limit=400):
    """[(loc, host, server_ip)] - uu tien trai deu thanh pho."""
    out, seen = [], set()
    for loc, host in _xv_pool_by_loc(locs):
        for ip in _resolve_v4(host):
            if ip in seen:
                continue
            seen.add(ip)
            out.append((loc, host, ip))
        if len(out) >= limit:
            break
    return out

def vpn_distinct_start(payload):
    """Tao N tunnel, moi tunnel ghim 1 server, do exit IP that, trung thi doi server (toi da 3 lan)."""
    cred = xv_cred_get(str(payload.get('cred_id', ''))) if payload.get('cred_id') else None
    if not cred:
        return {'ok': False, 'error': 'chon tai khoan da luu'}
    count = max(1, min(20, int(payload.get('count') or 1)))
    locs = [str(x).strip().lower() for x in (payload.get('locs') or []) if str(x).strip()][:12]
    with DISTINCT['lock']:
        DISTINCT['seq'] += 1
        jid = 'd%d' % DISTINCT['seq']
        DISTINCT['jobs'][jid] = {'id': jid, 'ts': time.time(), 'done': False, 'rows': [], 'count': count,
                                 'locs': locs, 'proto': 'tcp' if str(payload.get('proto')) == 'tcp' else 'udp',
                                 'cred_id': str(payload.get('cred_id')), 'msg': 'dang chuan bi', 'ok': True,
                                 'auto_up': str(payload.get('up', '1')) in ('1', 'true', 'True')}
        if len(DISTINCT['jobs']) > 20:
            for k in sorted(DISTINCT['jobs'], key=lambda x: DISTINCT['jobs'][x]['ts'])[:10]:
                DISTINCT['jobs'].pop(k, None)
    threading.Thread(target=_vpn_distinct_worker, args=(jid,), daemon=True, name='xv-distinct').start()
    return {'ok': True, 'job': jid}

def vpn_distinct_status(jid=''):
    with DISTINCT['lock']:
        if not jid:
            ks = sorted(DISTINCT['jobs'], key=lambda x: DISTINCT['jobs'][x]['ts'])[-5:]
            return {'ok': True, 'jobs': [{'id': k, 'done': DISTINCT['jobs'][k]['done'], 'msg': DISTINCT['jobs'][k]['msg']} for k in ks]}
        j = DISTINCT['jobs'].get(jid)
        if not j:
            return {'ok': False, 'error': 'khong co job'}
        return {'ok': True, 'job': dict(j, rows=[dict(r) for r in j['rows']])}

def _vpn_distinct_worker(jid):
    j = DISTINCT['jobs'][jid]
    # [Ver 2.94] nap lai cred trong worker: 'cred' cua vpn_distinct_start la bien cuc bo
    cred = xv_cred_get((DISTINCT['jobs'].get(jid) or {}).get('cred_id', '')) or {}
    if not cred.get('user'):
        with DISTINCT['lock']:
            j.update(done=True, ok=False, msg='mat tai khoan da luu')
        return
    def put(**kw):
        with DISTINCT['lock']:
            j.update(kw)
    def row(**kw):
        with DISTINCT['lock']:
            j['rows'].append(kw)
    try:
        used_exit = {}
        for a in vpn_status_json():
            if a.get('running'):
                ip = (_EXITIPS.get(a['name']) or {}).get('ip')
                if ip:
                    used_exit[ip] = a['name']
        put(msg='dang tim server (%d thanh pho)...' % len(j['locs']) if j['locs'] else 'dang tim server...')
        cand = _xv_candidates(j['locs'] or None)
        if not cand:
            return put(done=True, ok=False, msg='khong phan giai duoc server nao')
        srv_used = set()
        for a in vpn_status_json():
            h = str(a.get('host') or '')
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', h):
                srv_used.add(h)
        free = [c for c in cand if c[2] not in srv_used] or cand
        exist = {a['name'] for a in vpn_status_json()}
        made = 0
        ni = 0
        for k in range(j['count']):
            if made >= j['count']:
                break
            okrow = None
            for attempt in range(1, 4):
                if ni >= len(free):
                    break
                loc, host, sip = free[ni]
                ni += 1
                nxt = max([int(x.split('-')[1]) for x in exist if re.match(r'^xv-\d+$', x)] or [0]) + 1
                nm = 'xv-%d' % nxt
                put(msg='tao %s -> %s (lan %d)' % (nm, sip, attempt))
                r = vpn_run(['add-express', nm, sip, str(cred['user']), str(cred.get('pass', '')), j['proto'], str(cred.get('key', ''))], timeout=120)
                if not r.get('ok'):
                    _ss_log('DISTINCT add loi %s: %s' % (nm, str(r.get('error') or r.get('output'))[:150]))
                    continue
                exist.add(nm)
                up_ok = False
                if j['auto_up']:
                    up_ok = bool(vpn_run(['up', nm], timeout=180).get('ok'))
                eip = ''
                if up_ok:
                    d = vpn_exit_ip(nm)
                    eip = str(d.get('exit_ip') or '')
                if not eip:
                    vpn_run(['down', nm], timeout=90)
                    vpn_run(['del', nm], timeout=60)
                    exist.discard(nm)
                    row(name=nm, loc=loc, server=sip, exit='', attempt=attempt, ok=False, error='tunnel khong len hoac khong do duoc IP')
                    continue
                if eip in used_exit:
                    vpn_run(['down', nm], timeout=90)
                    vpn_run(['del', nm], timeout=60)
                    exist.discard(nm)
                    row(name=nm, loc=loc, server=sip, exit=eip, attempt=attempt, ok=False, error='trung IP voi ' + str(used_exit[eip]))
                    continue
                used_exit[eip] = nm
                okrow = dict(name=nm, loc=loc, server=sip, exit=eip, attempt=attempt, ok=True, error='')
                break
            if okrow:
                row(**okrow)
                made += 1
            else:
                row(name='', loc='', server='', exit='', attempt=3, ok=False, error='het server de thu')
        threading.Timer(3, vpn_refresh_exitips_async).start()
        put(done=True, msg='xong: %d/%d tunnel co IP rieng' % (made, j['count']))
    except Exception as e:
        try:
            _ss_log('DISTINCT loi: %s' % e)
        except Exception:
            pass
        put(done=True, ok=False, msg='loi: %s' % e)

def vpn_express_servers(loc='', fetch=False):
    """[Ver 2.94] IP server cu the cua 1 location (kieu MiniSocks endpoint_ip).
    Moi IP = 1 server = 1 IP ra rieng khi tao tunnel. Hostname thanh pho chi co 2-4 IP
    nen nhieu tunnel cung hostname se trung IP."""
    groups = {}
    try:
        with open(VPN_HOSTS_FILE, 'r', encoding='utf-8', errors='replace') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                pp = ln.split('|')
                if len(pp) < 3:
                    continue
                groups.setdefault(('%s %s' % (pp[0], pp[1])).strip().lower(), []).append(pp[-1])
    except Exception:
        pass
    keys = [k for k in groups if loc and loc in k] if loc else sorted(groups)
    used = set()
    for a in vpn_status_json():
        h = str(a.get('host') or '')
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', h):
            used.add(h)
    out, allused = [], []
    for k in keys[:8]:
        ips = []
        for h in groups[k][:4]:
            if not fetch and not loc:
                break
            # [Ver 2.94] dung getaddrinfo, KHONG dung nslookup: output nslookup co dong
            # 'Address: 8.8.8.8' (DNS server) nen IP do bi coi la server ExpressVPN.
            for x in _resolve_v4(h):
                if x not in ips:
                    ips.append(x)
        out.append({'loc': k, 'host': groups[k][0] if groups[k] else '', 'ips': ips[:8],
                    'used': [x for x in ips[:8] if x in used]})
        allused += [x for x in ips[:8] if x in used]
    return {'ok': True, 'groups': out, 'used': allused}

def vpn_auto_public():
    c = _vpn_auto_load()
    return {'ok': True, 'cfg': {k: c[k] for k in ('enabled', 'allow_dup', 'pool', 'range', 'release_min')},
            'auto': {ip: v.get('name') for ip, v in c['auto'].items() if isinstance(v, dict)},
            'msg': VPN_AUTO_RT['msg'], 'ts': int(VPN_AUTO_RT['ts']), 'last': VPN_AUTO_RT['last'][:15]}

def vpn_auto_set(p):
    c = _vpn_auto_load()
    rng = str(p.get('range', c['range']) or '').strip()[:400]
    _vpn_auto_ranges(rng)  # ValueError => bao loi
    pool = [str(x) for x in (p.get('pool') if isinstance(p.get('pool'), list) else c['pool']) if re.match(r'^[A-Za-z0-9_.-]{1,64}$', str(x))][:200]
    try:
        rel = max(0, min(1440, int(p.get('release_min', c['release_min']))))
    except Exception:
        rel = c['release_min']
    c.update(enabled=bool(p.get('enabled')), allow_dup=bool(p.get('allow_dup')), pool=pool, range=rng, release_min=rel)
    with VPN_AUTO_LOCK:
        _vpn_auto_save(c)

def vpn_auto_loop():
    time.sleep(30)
    while True:
        try:
            vpn_auto_tick()
        except Exception as e:
            try:
                _ss_log('VPN-AUTO loi: %s' % e)
            except Exception:
                pass
        time.sleep(20)

def exitip_watch_loop():
    """[Ver 2.94] Tu do exit-IP: tunnel UP ma chua co IP (vua them/vua bat) hoac IP cu > 5 phut => do lai.
    Truoc day chi trang /vpn kich do => tai khoan moi them hien 'dang do...' mai."""
    time.sleep(25)
    while True:
        miss = []
        try:
            run = [x['name'] for x in vpn_status_json() if x.get('running')]
            now = time.time()
            with _EXITIP_LOCK:
                miss = [n for n in run if not (_EXITIPS.get(n) or {}).get('ip')]
                old = [n for n in run if now - float((_EXITIPS.get(n) or {}).get('ts') or 0) > 300]
            if run and (miss or old):
                vpn_refresh_exitips_async()
        except Exception:
            pass
        time.sleep(45 if miss else 90)

def vpn_exit_ip(name, with_country=True):
    acc = next((a for a in vpn_status_json() if a.get('name') == name), None)
    if not acc:
        return {'ok': False, 'error': f'khong co tai khoan {name}'}
    if not acc.get('running'):
        return {'ok': False, 'error': 'tunnel chua UP'}
    dev, tbl = (acc.get('dev'), str(acc.get('table')))
    lip = ''
    try:
        out = subprocess.run(['ip', '-4', 'addr', 'show', dev], capture_output=True, text=True).stdout
        m = re.search('inet (\\d+\\.\\d+\\.\\d+\\.\\d+)', out or '')
        if m:
            lip = m.group(1)
    except Exception:
        pass
    if not lip:
        return {'ok': False, 'error': 'khong lay duoc IP trong tunnel'}
    added = subprocess.run(['ip', 'rule', 'add', 'from', lip, 'table', tbl, 'priority', '5'], capture_output=True).returncode == 0
    ip_out, err = ('', '')
    try:
        s = socket.socket()
        s.settimeout(8)
        s.bind((lip, 0))
        s.connect(('api.ipify.org', 80))
        s.sendall(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n')
        data = b''
        while True:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
        ip_out = data.decode('utf-8', 'replace').split('\r\n\r\n')[-1].strip()
    except Exception as e:
        err = str(e)
    finally:
        if added:
            subprocess.run(['ip', 'rule', 'del', 'from', lip, 'table', tbl, 'priority', '5'], capture_output=True)
    if err:
        return {'ok': False, 'error': err}
    cc = ''
    if with_country and ip_out:
        try:
            cc = country_code_for_ip(ip_out)
        except Exception:
            cc = ''
    return {'ok': True, 'exit_ip': ip_out, 'local_tunnel_ip': lip, 'dev': dev, 'country_code': cc}
EXITIP_CACHE_FILE = '/data/vpn/exitips.json'
_EXITIPS = {}
_EXITIPS_BUSY = {'v': False}
_EXITIP_LOCK = threading.Lock()
try:
    with open(EXITIP_CACHE_FILE, encoding='utf-8') as _f:
        _EXITIPS = json.load(_f) or {}
except Exception:
    _EXITIPS = {}

def _probe_exit_ip_dev(dev, tbl, timeout=8):
    """Bind socket vao IP trong tunnel roi hoi api.ipify.org — tra ve exit IP hoac None."""
    lip = ''
    try:
        out = subprocess.run(['ip', '-4', 'addr', 'show', dev], capture_output=True, text=True).stdout
        m = re.search('inet (\\d+\\.\\d+\\.\\d+\\.\\d+)', out or '')
        if m:
            lip = m.group(1)
    except Exception:
        return None
    if not lip:
        return None
    added = subprocess.run(['ip', 'rule', 'add', 'from', lip, 'table', str(tbl), 'priority', '5'], capture_output=True).returncode == 0
    ip_out = ''
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.bind((lip, 0))
        s.connect(('api.ipify.org', 80))
        s.sendall(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n')
        data = b''
        while True:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
        ip_out = data.decode('utf-8', 'replace').split('\r\n\r\n')[-1].strip()
    except Exception:
        return None
    finally:
        if added:
            subprocess.run(['ip', 'rule', 'del', 'from', lip, 'table', str(tbl), 'priority', '5'], capture_output=True)
    return ip_out or None

def _refresh_exitips_worker():
    try:
        accs = [a for a in vpn_status_json() if a.get('running')]
        results = {}

        def _job(a):
            try:
                results[a['name']] = _probe_exit_ip_dev(a.get('dev'), a.get('table'))
            except Exception:
                pass
        for i in range(0, len(accs), 8):
            batch = accs[i:i + 8]
            ths = [threading.Thread(target=_job, args=(a,), daemon=True) for a in batch]
            for t in ths:
                t.start()
            for t in ths:
                t.join(14)
        now = int(time.time())
        running_names = {a['name'] for a in accs}
        merged = {}
        for name in sorted(set(list(_EXITIPS.keys()) + list(results.keys()))):
            if name in results and results[name]:
                merged[name] = {'ip': results[name], 'ts': now}
            elif name not in running_names:
                continue
            else:
                merged[name] = _EXITIPS.get(name)
        merged = {k: v for k, v in merged.items() if v}
        with _EXITIP_LOCK:
            _EXITIPS.clear()
            _EXITIPS.update(merged)
            try:
                Path('/data/vpn').mkdir(parents=True, exist_ok=True)
                with open(EXITIP_CACHE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(_EXITIPS, f)
            except Exception:
                pass
    finally:
        _EXITIPS_BUSY['v'] = False

def vpn_refresh_exitips_async():
    if _EXITIPS_BUSY['v']:
        return False
    _EXITIPS_BUSY['v'] = True
    threading.Thread(target=_refresh_exitips_worker, daemon=True).start()
    return True
WD_PERSIST_DIR = BASE_DIR / 'persist'
WD_LOG_FILE = BASE_DIR / 'logs' / 'gencore_watchdog.log'
WD_STATE = {'hits': 0, 'last_restart': 0.0, 'last_start': 0.0, 'snap': '', 'last_stale_restart': 0.0, 'last_leak_restart': 0.0}
WD_ZOMBIE_PORT = '5888'
WD_TPROXY_PORT = 9888

def _wd_log(msg):
    try:
        WD_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if WD_LOG_FILE.exists() and WD_LOG_FILE.stat().st_size > 262144:
            txt = WD_LOG_FILE.read_text(errors='replace')
            WD_LOG_FILE.write_text(txt[-131072:], encoding='utf-8', errors='replace')
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(WD_LOG_FILE, 'a', encoding='utf-8') as fh:
            fh.write(f'{ts} {msg}\n')
    except Exception:
        pass

def _wd_thresholds():
    # Ver 2.47 — luu y ve persist/watchdog.json tren router (tao 2026-08-27):
    # file do co san 4 khoa 'fd_max', 'log_stale_sec', 'traffic_min_bytes',
    # 'traffic_stale_sec' MA KHONG CODE NAO DUNG (khoa chet cua ban cu). Vong
    # lap duoi chi nhan khoa co san trong dict nay, nen chung tu dong bi bo qua.
    # KHONG dat lai ten khoa moi thanh 'fd_max': fd_max=4000 con trong file do,
    # ap vao se bao dong gia lien tuc (fd binh thuong khi 322 may tai da la
    # 24.242 — do that 2026-09-05).
    #
    # stale_grace_sec = 1 (KHONG duoc lon hon): trong su co that, gencore start
    # 19:30:58 va file config bi ghi lai 19:31:00 — chenh DUNG 2 GIAY. Grace 5 s
    # se che mat chinh ca can bat (da chung minh o d519 ca B). Van can >0 vi
    # start_epoch tinh tu btime (do phan giai 1 giay) nen co sai so lam tron ~1s.
    thr = {'zombie_tw': 5000, 'ct_total': 40000, 'consecutive': 2, 'cooldown_sec': 600, 'heal_cooldown_sec': 300,
           'fd_pct': 60, 'sock_port_max': 5000, 'stale_grace_sec': 1, 'stale_cooldown_sec': 300}
    try:
        cfg = json.loads((WD_PERSIST_DIR / 'watchdog.json').read_text())
        for k in list(thr.keys()):
            v = cfg.get(k)
            if isinstance(v, int) and v > 0:
                thr[k] = v
    except Exception:
        pass
    return thr

def _wd_conntrack_counts():
    tw = total = 0
    try:
        with open('/proc/net/nf_conntrack', 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                total += 1
                if 'TIME_WAIT' in line and f'dport={WD_ZOMBIE_PORT} ' in line:
                    tw += 1
    except OSError:
        return None
    return (tw, total)

def _wd_uptime_sec():
    try:
        with open('/proc/uptime') as fh:
            return float(fh.read().split()[0])
    except Exception:
        return 1000000000.0

def _proc_start_epoch(pid):
    """Thoi diem tien trinh BAT DAU (epoch giay). None neu khong doc duoc.

    Doc field 22 (starttime, tinh theo tick tu luc boot) trong /proc/<pid>/stat
    roi cong btime cua /proc/stat. Phai tach chuoi bang rsplit(') ') vi
    comm (field 2) co the chua dau cach hoac dau ngoac.
    Da kiem tren router that 2026-09-05 (out517 muc E): SC_CLK_TCK = 100.
    """
    try:
        btime = 0
        with open('/proc/stat', 'r') as fh:
            for line in fh:
                if line.startswith('btime '):
                    btime = int(line.split()[1])
                    break
        if not btime:
            return None
        raw = open(f'/proc/{pid}/stat', 'r').read()
        fields = raw.rsplit(') ', 1)[1].split()
        hz = os.sysconf('SC_CLK_TCK') or 100
        return btime + int(fields[19]) / float(hz)
    except Exception:
        return None

def _proc_fd_count(pid):
    try:
        return len(os.listdir(f'/proc/{pid}/fd'))
    except Exception:
        return -1

def _proc_nofile_soft(pid):
    try:
        with open(f'/proc/{pid}/limits', 'r') as fh:
            for line in fh:
                if 'open files' in line:
                    parts = line.split()
                    return int(parts[-3])
    except Exception:
        pass
    return 0

def _count_sockets_on_port(port):
    """Dem dong /proc/net/tcp co local HOAC remote la <port>.

    Vi sao khong dung `ss`: router khong co `ss` (xem memory 2026-09-05 muc Q4:
    danh sach lenh thieu tren BusyBox). Vi sao khong dung `grep -c`: file nay
    moi socket 1 dong nen grep -c dung, nhung phai loc dung cot va so sanh HEX.
    """
    try:
        hexp = ':%04X' % int(port)
    except Exception:
        return -1
    n = 0
    try:
        with open('/proc/net/tcp', 'r') as fh:
            next(fh, None)
            for line in fh:
                f = line.split()
                if len(f) < 3:
                    continue
                if f[1].endswith(hexp) or f[2].endswith(hexp):
                    n += 1
    except OSError:
        return -1
    return n

def _gencore_pid():
    try:
        r = subprocess.run(['pidof', 'gencore'], capture_output=True, text=True, timeout=8)
        return (r.stdout or '').strip()
    except Exception:
        return ''

def _gencore_pid_first():
    """pidof co the tra nhieu pid; /proc can dung 1 pid."""
    pid = _gencore_pid()
    return pid.split()[0] if pid else ''

# Ver 2.47 — NOFILE cho gencore.
# TAI SAO PHAI DAT O DAY: /etc/genrouter/core/genrunner co 'ulimit -n 100000' o
# dong 2, nen gencore do genrunner start duoc 100000 fd. Nhung app.py start
# gencore bang gencore_start_detached() -> KHONG dat ulimit -> ke thua han muc
# cua procd (do that 2026-09-05: soft/hard = 4095/4096).
# Do that cung ngay: fd cua gencore len 24242 roi 99136 khi 322 may cung tai.
# => gencore do app.py start se het fd o 4096 va chet im lang, trong khi cung
# tinh huong do neu genrunner start thi khong sao. Phai dat ulimit cho BANG
# hoac CAO HON genrunner. Kernel cho phep (fs.nr_open = 1048576, chay bang root).
GENCORE_NOFILE = 262144
GENCORE_NOFILE_FALLBACKS = (100000, 65536, 16384)

def _gencore_ulimit_prefix():
    """Chuoi shell nang NOFILE, co bac thang du phong (ash: ulimit that bai -> in stderr)."""
    parts = [f'ulimit -n {GENCORE_NOFILE} 2>/dev/null']
    parts += [f'ulimit -n {v} 2>/dev/null' for v in GENCORE_NOFILE_FALLBACKS]
    return ' || '.join(parts) + ' || true; '

def gencore_start_detached(reason='manual'):
    if not Path('/usr/bin/gencore').exists():
        return
    try:
        cmd = _gencore_ulimit_prefix() + '( /usr/bin/gencore run -c /etc/genrouter/gencore.json >/tmp/gencore_run.log 2>&1 </dev/null & )'
        subprocess.Popen(['sh', '-c', cmd], start_new_session=True)
        _wd_log(f'START gencore reason={reason} nofile_target={GENCORE_NOFILE}')
    except Exception as e:
        _wd_log(f'START fail reason={reason}: {e}')

def gencore_restart_detached(reason='storm'):
    try:
        subprocess.run(['sh', '-c', 'kill $(pidof gencore) 2>/dev/null; sleep 2; pidof gencore >/dev/null 2>&1 && kill -9 $(pidof gencore) 2>/dev/null; sleep 1; true'], timeout=20)
    except Exception:
        pass
    gencore_start_detached(reason)

def _wd_persist_runtime(accounts):
    try:
        WD_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
        mapping = {}
        try:
            with open('/data/vpn/map.txt', 'r', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2:
                        mapping[parts[0].strip()] = parts[1].strip()
        except OSError:
            pass
        snap = {'ts': int(time.time()), 'running': sorted((str(a.get('name')) for a in accounts if a.get('running'))), 'map': mapping}
        raw = json.dumps(snap, ensure_ascii=False)
        if raw != WD_STATE.get('snap'):
            WD_STATE['snap'] = raw
            (WD_PERSIST_DIR / 'vpn_runtime.json').write_text(raw, encoding='utf-8')
    except Exception as e:
        _wd_log(f'persist error: {e}')

def wd_boot_recover(force=False):
    """Sau reboot: map.txt (tmpfs) bị xoá + tunnel rơi -> trả lại đúng snapshot trước mất."""
    res = {'ok': True, 'actions': []}
    try:
        if not force and _wd_uptime_sec() > 900:
            res['skipped'] = 'uptime > 900s (khong phai vua reboot)'
            return res
        snap_f = WD_PERSIST_DIR / 'vpn_runtime.json'
        snap = json.loads(snap_f.read_text()) if snap_f.exists() else {}
        mapping = snap.get('map') or {}
        running = snap.get('running') or []
        map_path = Path('/data/vpn/map.txt')
        map_missing = not map_path.exists() or map_path.stat().st_size == 0
        if mapping and map_missing:
            lines = [f'{ip} {acc}' for ip, acc in mapping.items()]
            map_path.parent.mkdir(parents=True, exist_ok=True)
            map_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            res['actions'].append(f'restored map.txt ({len(lines)} entries)')
            _wd_log(f'BOOT-RECOVER map.txt restored {len(lines)} entries')
        if running:
            try:
                cur = vpn_status_json()
                still = {str(a.get('name')) for a in cur if a.get('running')}
            except Exception:
                still = set()
            for name in running:
                if name in still:
                    continue
                r = vpn_run(['up', name])
                res['actions'].append(f"up {name}: rc={r.get('rc')}")
                _wd_log(f"BOOT-RECOVER up {name}: rc={r.get('rc')} {(r.get('output') or '')[:100]}")
                time.sleep(3)
    except Exception as e:
        res = {'ok': False, 'error': str(e)}
        _wd_log(f'boot_recover error: {e}')
    return res

HEAL_STATE = {'last_heal': 0.0, 'count': 0}
TPROXY_BIN = GENRUNNER.parent / 'tproxy'
KILLSWITCH_BIN = '/etc/genrouter_killswitch.sh'

def _heal_run_shell(cmd, timeout=90):
    try:
        p = subprocess.run(['sh', '-c', cmd], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
        return {'ok': p.returncode == 0, 'rc': p.returncode, 'output': ((p.stdout or '') + (p.stderr or ''))[:400]}
    except Exception as e:
        return {'ok': False, 'rc': -1, 'output': str(e)}

def _heal_read_stats(path):
    """Tra (stats, ly_do_hong). File mat/rong/JSON hong deu la 'hong'."""
    p = Path(path)
    try:
        if not p.exists():
            return (None, 'mat file')
        if p.stat().st_size == 0:
            return (None, 'file rong 0 byte')
        return (config_doc_stats(load_json(p)), '')
    except Exception as e:
        return (None, f'khong doc duoc: {e}')

def config_self_heal(reason='watchdog'):
    """TU PHAT HIEN + TU CHUA config gencore bi sut, dinh ky, khong can nguoi.

    Vi sao can (cac co che tai phat da chung minh bang bang chung tren router):
      #2 binary vendor 9000 regenerate config/gencore.json sau POST
         /api/update_proxy -> mat DoH 443, mat route rule, xau nhat la ve han
         template chi con outbound {direct} va 0 source_ip_cidr.
      #3 /etc/rc.local co 'exit 0' o dong 18 => moi fix dat sau do la code chet.
      #4 genrunner `rm -f` file runtime khi gencore start fail, va `cp` config
         da sap sang runtime. /etc/shm/tproxy dap lai rt_tables moi lan chay.
    Hau qua chung: source_ip_cidr = 0 => /etc/genrouter/core/tproxy (awk theo
    chuoi 'source_ip_cidr') sinh CLIENT_IPS RONG => chain GENROUTER khong con
    rule TPROXY nao => client Lumi 'khong vao duoc web'.
    Da xac minh truc tiep trong /tmp/genrouter/log.txt: '==> CLIENT_IPS:' rong.

    Nguon su that = preset cua session dang active. So sanh CA HAI file
    (config/gencore.json + gencore.json runtime) voi preset; sut thi ghi lai.

    An toan BAT BUOC: `tproxy -s` FLUSH chain GENROUTER, xoa luon rule
    '--match-set genrouter_vpn src -j RETURN' => 322 may VPN bi TPROXY hijack
    vao gencore (ro IP that). Cron gen_vpn_guard chi chay moi phut nen co cua
    so nguy hiem <= 60 s. Vi vay phai goi /etc/gen_vpn_guard.sh fix NGAY SAU
    tproxy -s, khong phó thác cho cron. Guard idempotent nen goi them vo hai.
    """
    res = {'healed': False, 'reason': '', 'degraded': []}
    if _apply_lock_active():
        res['reason'] = 'dang apply (apply lock bat) — hoan lai de tranh race'
        return res
    try:
        active = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '1')).strip() or '1'
    except Exception:
        active = '1'
    preset = SESSION_FILES.get(active)
    if not preset or not Path(preset).exists():
        res['reason'] = f'khong thay preset session {active}'
        return res
    try:
        expected = load_json(preset)
    except Exception as e:
        res['reason'] = f'preset session {active} khong doc duoc: {e}'
        return res
    want = config_doc_stats(expected)
    if want.get('proxy_outbounds', 0) == 0 and want.get('source_ip_cidr', 0) == 0:
        # Preset cung rong => khong co ban dung nao de dua vao. Ghi de luc nay
        # chi lam hong them. Bao cao ra ngoai, de nguoi quyet dinh.
        res['reason'] = f'preset session {active} cung rong (proxy_outbounds=0, source_ip_cidr=0) — khong ghi de'
        return res
    degraded = []
    for label, path in (('config', RUNTIME_SOURCE_FILE), ('runtime', RUNTIME_FILE)):
        stats, broken = _heal_read_stats(path)
        if stats is None:
            degraded.append(f'{label}:{broken}')
            continue
        miss = [k for k in CONFIG_GUARD_KEYS if stats.get(k, 0) < want.get(k, 0)]
        if stats.get('dns_proxy_legacy', 0) > want.get('dns_proxy_legacy', 0):
            miss.append('dns_proxy_legacy')
        if miss:
            degraded.append(f"{label}:" + ' '.join(f'{k}:{stats.get(k, 0)}<-{want.get(k, 0)}' for k in miss))
    res['degraded'] = degraded
    if not degraded:
        res['reason'] = 'ca hai file con nguyen — khong lam gi'
        return res
    thr = _wd_thresholds()
    cooldown = int(thr.get('heal_cooldown_sec', 300) or 300)
    now = time.time()
    if now - float(HEAL_STATE.get('last_heal', 0.0)) < cooldown:
        res['reason'] = f'cooldown {cooldown}s con hieu luc — hoan lai (van dang sut: {"; ".join(degraded)})'
        _wd_log(f'HEAL-SKIP cooldown ({reason}): {"; ".join(degraded)}')
        return res
    HEAL_STATE['last_heal'] = now
    HEAL_STATE['count'] = HEAL_STATE.get('count', 0) + 1
    doc = expected
    try:
        heal_dns_changed = migrate_proxy_dns_servers(doc)
        heal_dns_changed += ensure_dns_local_detour(doc)
        if heal_dns_changed:
            save_gencore_json(preset, doc)
    except Exception as e:
        _wd_log(f'HEAL warn: migrate DNS loi: {e}')
    steps = []
    for path in (RUNTIME_SOURCE_FILE, RUNTIME_FILE):
        try:
            save_gencore_json(path, doc)
            steps.append(f'ghi {Path(path).name} OK')
        except Exception as e:
            steps.append(f'ghi {Path(path).name} FAIL: {e}')
            _wd_log(f'HEAL FAIL ghi {path}: {e}')
    r_tp = _heal_run_shell(f'{TPROXY_BIN} -s')
    steps.append(f"tproxy -s rc={r_tp.get('rc')}")
    # NGAY SAU tproxy -s: tra lai rule bao ve VPN. Khong doi cron 60 s.
    r_gd = _heal_run_shell(f'{VPN_GUARD} fix')
    steps.append(f"gen_vpn_guard fix rc={r_gd.get('rc')}")
    try:
        if _gencore_pid():
            gencore_restart_detached('config_heal')
            steps.append('gencore restart')
        else:
            gencore_start_detached('config_heal')
            steps.append('gencore start')
    except Exception as e:
        steps.append(f'gencore FAIL: {e}')
    res['healed'] = True
    res['steps'] = steps
    res['reason'] = 'da chua'
    _wd_log(f'HEAL ({reason}) session={active}: SUT [{"; ".join(degraded)}] -> ' + '; '.join(steps))
    try:
        _ss_log(f'CONFIG-SELF-HEAL ({reason}) session={active}: ' + '; '.join(degraded))
    except Exception:
        pass
    return res

GENCORE_LOADED_FILE = WD_PERSIST_DIR / 'gencore_loaded.json'

def _file_md5(path):
    try:
        h = hashlib.md5()
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(262144)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''

def _gencore_loaded_load():
    try:
        d = json.loads(GENCORE_LOADED_FILE.read_text(encoding='utf-8'))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def _gencore_loaded_save(pid, start_epoch, md5):
    try:
        GENCORE_LOADED_FILE.parent.mkdir(parents=True, exist_ok=True)
        GENCORE_LOADED_FILE.write_text(json.dumps({
            'pid': str(pid), 'start_epoch': float(start_epoch or 0), 'md5': str(md5 or ''),
            'ts': int(time.time())}, ensure_ascii=False), encoding='utf-8')
    except Exception:
        pass

def _wd_check_config_stale(pid, thr):
    """Ver 2.47 / chot V2-b: gencore dang chay CO NAP dung config tren dia khong?

    VI SAO PHAI CO (su co 2026-09-05 19:31 -> 21:31, 322 may mat DNS 2 gio):
      19:30:52 vendor /etc/genrouter/server:9000 regenerate config/gencore.json
               bang template rieng (DNS proxy_* ve 'tcp://8.8.8.8' = port 53).
      19:30:58 vendor restart gencore  -> gencore NAP BAN CU vao RAM.
      19:31:00 app.py (config_guard_restore) ghi lai file dung tren dia
               nhung KHONG restart gencore.
      => tu do: DIA DUNG, RAM SAI. Moi khoa cu cua Ver 2.39-2.46
         (CONFIG_GUARD_KEYS, config_self_heal, config_guard_restore) chi doc
         FILE nen deu thay 'khong sut' => degraded=[] => khong ai lam gi.
      Bang chung do that: quet 298,3 MB RAM cua pid 26093 thay 'tcp://8.8.8.8'
      x112 va 'https://8.8.8.8/dns-query' x0, trong khi md5 file tren dia da la
      ban DoH 443 dung. Lumi chan port 53 (SOCKS5 rep=2 'not allowed by
      ruleset', dem duoc 33.646 lan trong log) => client khong resolve duoc ten.

    CACH PHAT HIEN (khong can doc RAM, khong can vendor hop tac):
      So THOI DIEM BAT DAU cua tien trinh gencore voi mtime cua file config.
      mtime > start => file da doi SAU khi tien trinh nap => RAM khong con dung.
      gencore (sing-box 1.11.6) KHONG tu reload config -- da chung minh bang
      chinh su co tren: 2 gio lien RAM giu ban cu.

    CHONG BAO DONG GIA: co truong hop file duoc ghi lai ma NOI DUNG Y NGUYEN
      (migrate_proxy_dns_file ghi lai dang compact cho awk cua vendor doc duoc,
       xem FORMAT-HEAL). Vi vay chi restart khi md5 KHAC md5 ma chinh pid nay
      da duoc xac nhan dong bo truoc do (luu trong persist/gencore_loaded.json).
    Tra ve True neu da restart.
    """
    if not pid:
        return False
    start = _proc_start_epoch(pid)
    if start is None:
        return False
    try:
        mtime = os.stat(RUNTIME_FILE).st_mtime
    except OSError:
        return False
    md5_now = _file_md5(RUNTIME_FILE)
    info = _gencore_loaded_load()
    same_proc = str(info.get('pid') or '') == str(pid) and abs(float(info.get('start_epoch') or 0) - start) <= 2.0
    if same_proc and info.get('md5') == md5_now:
        # Da xac nhan chinh tien trinh nay dong bo voi chinh noi dung nay.
        # Ke ca file bi ghi lai (FORMAT-HEAL ghi lai dang compact ma khong doi
        # noi dung) thi RAM van dung => khong restart.
        return False
    grace = int(thr.get('stale_grace_sec', 1) or 1)
    if mtime <= start + grace:
        # Tien trinh khoi dong SAU lan ghi cuoi => RAM = dia. Ghi nhan lam moc.
        _gencore_loaded_save(pid, start, md5_now)
        return False
    now = time.time()
    cd = int(thr.get('stale_cooldown_sec', 300) or 300)
    if now - float(WD_STATE.get('last_stale_restart', 0.0)) < cd:
        _wd_log(f'STALE-CONFIG phat hien nhung cooldown {cd}s con hieu luc (pid={pid} '
                f'start={time.strftime("%H:%M:%S", time.localtime(start))} '
                f'mtime={time.strftime("%H:%M:%S", time.localtime(mtime))})')
        return False
    WD_STATE['last_stale_restart'] = now
    WD_STATE['restarts'] = WD_STATE.get('restarts', 0) + 1
    _wd_log(f'STALE-CONFIG: gencore pid={pid} start={time.strftime("%H:%M:%S", time.localtime(start))} '
            f'nhung {Path(RUNTIME_FILE).name} mtime={time.strftime("%H:%M:%S", time.localtime(mtime))} '
            f'(muon hon {mtime - start:.0f}s) md5_dia={md5_now[:12]} md5_da_xac_nhan={str(info.get("md5") or "-")[:12]} '
            f'=> RAM giu config CU, restart gencore')
    try:
        _ss_log(f'STALE-CONFIG: restart gencore vi config moi hon tien trinh {mtime - start:.0f}s (md5 dia {md5_now[:12]})')
    except Exception:
        pass
    _gencore_loaded_save('', 0, md5_now)
    gencore_restart_detached('stale_config')
    return True

def _wd_check_fd_leak(pid, thr):
    """Ver 2.47 / chot V5-b: canh FD va socket TPROXY cua gencore.

    VI SAO PHAI CO: trong su co 2026-09-05, fd cua gencore leo 79.520 ->
    99.136 -> 99.660 / 100.000 va sinh 115 loi EMFILE, socket cong 9888 len
    41.899 (100% la self-connect 127.0.0.1 -> 127.0.0.1:9888 o CLOSE_WAIT).
    Watchdog cu chi xet zombie_tw (TIME_WAIT cong 5888) va ct_total
    (conntrack) nen CA HAI chi so do deu duoi nguong => khong ai bao gi.
    Sau khi restart, fd tu 24.242 tut ve 168 => day la RO, khong phai tai that.

    Nguong theo TY LE tren NOFILE thuc te cua tien trinh (doc /proc/<pid>/limits)
    chu khong dong dinh con so, vi NOFILE khac nhau tuy ai start gencore:
    genrunner dat 'ulimit -n 100000', con app.py truoc Ver 2.47 khong dat gi
    nen ke thua 4096 cua procd.
    Tra ve True neu da restart.
    """
    if not pid:
        return False
    fd = _proc_fd_count(pid)
    if fd < 0:
        return False
    nofile = _proc_nofile_soft(pid) or 4096
    sock = _count_sockets_on_port(WD_TPROXY_PORT)
    pct = fd * 100.0 / max(1, nofile)
    lim_pct = int(thr.get('fd_pct', 60) or 60)
    lim_sock = int(thr.get('sock_port_max', 5000) or 5000)
    hit_fd = pct >= lim_pct
    hit_sock = 0 <= lim_sock <= sock
    if not (hit_fd or hit_sock):
        return False
    now = time.time()
    cd = int(thr.get('cooldown_sec', 600) or 600)
    why = []
    if hit_fd:
        why.append(f'fd={fd}/{nofile} ({pct:.0f}% >= {lim_pct}%)')
    if hit_sock:
        why.append(f'sock:{WD_TPROXY_PORT}={sock} >= {lim_sock}')
    if now - float(WD_STATE.get('last_leak_restart', 0.0)) < cd:
        _wd_log(f'FD-LEAK phat hien nhung cooldown {cd}s con hieu luc: ' + ' | '.join(why))
        return False
    WD_STATE['last_leak_restart'] = now
    WD_STATE['restarts'] = WD_STATE.get('restarts', 0) + 1
    _wd_log(f'FD-LEAK: restart gencore pid={pid} — ' + ' | '.join(why))
    try:
        _ss_log('FD-LEAK: restart gencore — ' + ' | '.join(why))
    except Exception:
        pass
    gencore_restart_detached('fd_leak')
    return True

WD_VPN_STATE = {'ts': 0, 'mode': '', 'ok': True, 'problems': [], 'numbers': {}, 'last_fix': 0.0}

def _ipset_count(name):
    """Dem member cua mot ipset. -1 = khong doc duoc / set khong ton tai.

    Khong dung `ipset list <name> | grep -c` vi phan header cung co dong chua
    so; phai cat tu sau dong 'Members:'.
    """
    try:
        r = subprocess.run(['ipset', 'list', name], capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return -1
        seen = False
        n = 0
        for line in (r.stdout or '').splitlines():
            if not seen:
                if line.strip().startswith('Members'):
                    seen = True
                continue
            if line.strip():
                n += 1
        return n
    except Exception:
        return -1

def _ip_rule_vpn_count():
    """So `ip rule` tro vao table 3xx (moi tunnel VPN duoc gan 1 table 301-337)."""
    try:
        r = subprocess.run(['ip', 'rule'], capture_output=True, text=True, timeout=20)
        n = 0
        for line in (r.stdout or '').splitlines():
            m = re.search(r'lookup\s+(\d+)', line)
            if m and 300 <= int(m.group(1)) <= 399:
                n += 1
        return n
    except Exception:
        return -1

def _runtime_mode_counts():
    """(mode, so_may_VPN, so_may_proxy) suy tu RUNTIME gencore.json — nguon su that
    cua data-plane, KHONG phai session_state (cai do chi la y muon tren GUI)."""
    try:
        doc = load_json(RUNTIME_FILE)
    except Exception:
        return ('', -1, -1)
    direct = socks = 0
    for item in (doc or {}).get('outbounds', []) or []:
        if not str((item or {}).get('tag', '')).startswith('proxy_'):
            continue
        t = str((item or {}).get('type', '')).strip().lower()
        if t == 'direct':
            direct += 1
        elif t in ('socks', 'http'):
            socks += 1
    mode = 'vpn' if direct > socks else ('proxy' if socks else '')
    return (mode, direct, socks)

def _wd_check_vpn_integrity(thr):
    """Ver 2.47 / chot V4-d: cau hinh khai VPN thi data-plane PHAI that su la VPN.

    VI SAO PHAI CO (do that 2026-09-05 21:xx):
      session_state['1'] khai 322/322 may -> proton-jp-171, GUI hien "che do VPN",
      nhung RUNTIME gencore.json co 322 outbound proxy_* type=socks (Lumi),
      /data/vpn/map.txt = 0 BYTE, ipset genrouter_vpn = 0, ip rule lookup 3xx = 0.
      Tuc la khong mot may nao thuc su di VPN. Ha tang van tot (37 tunnel UP,
      37 MASQUERADE, table 301-337 du route) nen moi khoa cu deu bao "xanh".
      Khong co chi so nao doi chieu Y MUON voi THUC TE.

    Cach doc dung: mode THAT = type cua outbound proxy_* trong RUNTIME file,
    khong phai session_state. session_state la preset chua apply thi hop le khi
    lech (vi du session 1 la VPN nhung dang active session 3 = proxy).

    TU CHUA O DAY CO GIOI HAN CO Y: tuyet doi KHONG tu gan lai tunnel va
    KHONG tu doi mode (anh Thai: "anh dao qua dao lai la viec cua anh").
    Chi chay lai LOP BAO VE (gen_vpn_guard.sh fix + killswitch) de may khai VPN
    ma chua co duong VPN thi bi CHAN, khong ro IP that. Con viec gan lai thi
    bao do ra GUI de nguoi quyet dinh.
    """
    mode, n_vpn, n_proxy = _runtime_mode_counts()
    if not mode:
        return False
    nmap = len(load_vpn_map())
    v = _ipset_count('genrouter_vpn')
    w = _ipset_count('genrouter_vpn_want')
    rules = _ip_rule_vpn_count()
    nums = {'mode': mode, 'cfg_vpn': n_vpn, 'cfg_proxy': n_proxy, 'map': nmap,
            'ipset_vpn': v, 'ipset_want': w, 'ip_rule_3xx': rules}
    problems = []
    if mode == 'vpn':
        if nmap == 0:
            problems.append(f'cau hinh khai {n_vpn} may VPN nhung map.txt TRONG (0 may duoc gan tunnel)')
        if 0 <= w < n_vpn:
            problems.append(f'ipset genrouter_vpn_want={w} < {n_vpn} may khai VPN (lop chan ro IP that thieu)')
        if nmap > 0 and 0 <= rules < nmap:
            problems.append(f'ip rule table 3xx={rules} < {nmap} may trong map.txt (may thieu rule di ra WAN that)')
        if nmap > 0 and 0 <= v < nmap:
            problems.append(f'ipset genrouter_vpn={v} < {nmap} may trong map.txt')
    else:
        if v > 0 or nmap > 0 or rules > 0:
            problems.append(f'dang mode proxy nhung con ton du VPN: map={nmap} ipset_vpn={v} ip_rule_3xx={rules}')
    WD_VPN_STATE.update({'ts': int(time.time()), 'mode': mode, 'ok': not problems,
                         'problems': list(problems), 'numbers': nums})
    if not problems:
        return False
    now = time.time()
    cd = int(thr.get('stale_cooldown_sec', 300) or 300)
    if now - float(WD_VPN_STATE.get('last_fix', 0.0)) < cd:
        return False
    WD_VPN_STATE['last_fix'] = now
    _wd_log('VPN-INTEGRITY: ' + ' | '.join(problems) + f' | so do: {json.dumps(nums, ensure_ascii=False)}')
    try:
        _ss_log('VPN-INTEGRITY: ' + ' | '.join(problems))
    except Exception:
        pass
    # Chi chay lai lop BAO VE. Khong gan tunnel, khong doi mode.
    steps = []
    try:
        r = _heal_run_shell(f'{VPN_GUARD} fix')
        steps.append(f"gen_vpn_guard fix rc={r.get('rc')}")
    except Exception as e:
        steps.append(f'gen_vpn_guard FAIL: {e}')
    try:
        if Path(KILLSWITCH_BIN).exists():
            r = _heal_run_shell(KILLSWITCH_BIN)
            steps.append(f"killswitch rc={r.get('rc')}")
    except Exception as e:
        steps.append(f'killswitch FAIL: {e}')
    _wd_log('VPN-INTEGRITY buoc bao ve: ' + '; '.join(steps))
    return False

def wd_health_json():
    """Ver 2.47: mot cho duy nhat de GUI/nguoi doc biet HE THONG CO DANG DUNG khong.

    Tra ve chi so THUC DO tai thoi diem goi (khong cache) cho 4 chot moi:
      stale_config — config tren dia moi hon tien trinh gencore (RAM giu ban cu)
      fd           — fd/NOFILE + socket cong TPROXY cua gencore
      vpn          — y muon VPN vs data-plane that (map.txt/ipset/ip rule)
      watchdog     — lan ghi log gan nhat, de biet watchdog co con song
    """
    out = {'ok': True, 'ts': int(time.time()), 'problems': []}
    pid = _gencore_pid_first()
    out['gencore_pid'] = pid
    thr = _wd_thresholds()
    # 1) stale config
    start = _proc_start_epoch(pid) if pid else None
    try:
        mtime = os.stat(RUNTIME_FILE).st_mtime
    except OSError:
        mtime = 0
    stale = bool(pid and start and mtime and mtime > start + int(thr.get('stale_grace_sec', 1) or 1))
    # [Ver 2.48] CHONG BAO DONG GIA: chi so mtime thi health bao stale=True VINH VIEN
    # sau moi lan apply (apply ghi lai gencore.json vai giay SAU khi gencore start),
    # trong khi _wd_check_config_stale() da xac nhan RAM = dia (same_proc + md5 khop)
    # nen KHONG restart. Hai cho dung hai tieu chuan => health.ok=false mai mai va
    # nguoi doc mat long tin vao chi so. Dung DUNG dieu kien cua logic that.
    _li = _gencore_loaded_load()
    _md5_disk = _file_md5(RUNTIME_FILE)
    _same_proc = (str(_li.get('pid') or '') == str(pid)
                  and abs(float(_li.get('start_epoch') or 0) - float(start or 0)) <= 2.0)
    _confirmed = bool(_same_proc and _li.get('md5') == _md5_disk)
    if _confirmed:
        stale = False
    out['config'] = {
        'proc_start': int(start) if start else 0,
        'file_mtime': int(mtime),
        'lag_sec': int(mtime - start) if (start and mtime) else 0,
        'md5_disk': _md5_disk[:12],
        'md5_loaded': str(_li.get('md5') or '')[:12],
        'confirmed': _confirmed,
        'stale': stale}
    if stale:
        out['problems'].append('config tren dia moi hon tien trinh gencore => RAM co the giu ban cu')
    # 2) fd / socket
    fd = _proc_fd_count(pid) if pid else -1
    nofile = _proc_nofile_soft(pid) if pid else 0
    sock = _count_sockets_on_port(WD_TPROXY_PORT)
    pct = round(fd * 100.0 / nofile, 1) if (fd >= 0 and nofile) else 0.0
    out['fd'] = {'used': fd, 'nofile': nofile, 'pct': pct, 'limit_pct': int(thr.get('fd_pct', 60) or 60),
                 'sock_tproxy': sock, 'sock_limit': int(thr.get('sock_port_max', 5000) or 5000),
                 'nofile_target': GENCORE_NOFILE}
    if pct >= int(thr.get('fd_pct', 60) or 60):
        out['problems'].append(f'fd cua gencore {fd}/{nofile} ({pct}%)')
    if 0 <= int(thr.get('sock_port_max', 5000) or 5000) <= sock:
        out['problems'].append(f'socket cong {WD_TPROXY_PORT} = {sock}')
    # 3) vpn integrity (do lai, khong tu chua o day)
    mode, n_vpn, n_proxy = _runtime_mode_counts()
    vpn = {'mode': mode, 'cfg_vpn': n_vpn, 'cfg_proxy': n_proxy,
           'map': len(load_vpn_map()), 'ipset_vpn': _ipset_count('genrouter_vpn'),
           'ipset_want': _ipset_count('genrouter_vpn_want'), 'ip_rule_3xx': _ip_rule_vpn_count()}
    vprob = []
    if mode == 'vpn':
        if vpn['map'] == 0:
            vprob.append(f"khai {n_vpn} may VPN nhung map.txt trong")
        if 0 <= vpn['ipset_want'] < n_vpn:
            vprob.append(f"ipset want {vpn['ipset_want']} < {n_vpn}")
        if vpn['map'] > 0 and 0 <= vpn['ip_rule_3xx'] < vpn['map']:
            vprob.append(f"ip rule 3xx {vpn['ip_rule_3xx']} < map {vpn['map']}")
    elif mode == 'proxy':
        if vpn['map'] > 0 or vpn['ipset_vpn'] > 0 or vpn['ip_rule_3xx'] > 0:
            vprob.append('mode proxy nhung con ton du VPN')
    vpn['problems'] = vprob
    vpn['ok'] = not vprob
    out['vpn'] = vpn
    out['problems'] += vprob
    # 4) watchdog con song?
    try:
        st = WD_LOG_FILE.stat()
        age = int(time.time() - st.st_mtime)
    except OSError:
        age = -1
    out['watchdog'] = {'log_age_sec': age, 'restarts': int(WD_STATE.get('restarts', 0) or 0),
                       'heals': int(HEAL_STATE.get('count', 0) or 0)}
    # 5) [Ver 2.49] etc/: 3 thanh phan NGOAI app dir co dung ban trong repo khong?
    # De nghiem thu rollout tu xa (chi can HTTP, khong can SSH tung may): truoc day
    # muon biet may da co kill-switch + ban tproxy da sua + cron watchdog chua thi phai
    # SSH vao dem tay. Do bang md5 giua etc/ trong app dir va file dang nam o /etc.
    _etc_pairs = [('etc/genrouter_killswitch.sh', '/etc/genrouter_killswitch.sh'),
                  ('etc/genrouter/core/tproxy', '/etc/genrouter/core/tproxy'),
                  ('etc/genrouter/core/tproxy', '/etc/shm/tproxy'),
                  ('etc/gen_vpn_guard.sh', '/etc/gen_vpn_guard.sh')]
    _etc = {'missing': [], 'diff': [], 'cron_killswitch': False, 'cron_dataplane': False}
    for _rel, _dst in _etc_pairs:
        _src = BASE_DIR / _rel
        if not _src.exists():
            continue
        if not os.path.exists(_dst):
            _etc['missing'].append(_dst)
        elif _file_md5(_dst) != _file_md5(str(_src)):
            _etc['diff'].append(_dst)
    try:
        _cron = Path('/etc/crontabs/root').read_text(encoding='utf-8', errors='replace')
    except Exception:
        _cron = ''
    _etc['cron_killswitch'] = 'genrouter_killswitch' in _cron
    _etc['cron_dataplane'] = 'dataplane_guard' in _cron
    _etc['ok'] = not _etc['missing'] and not _etc['diff'] and _etc['cron_killswitch']
    out['etc'] = _etc
    if _etc['missing']:
        out['problems'].append('thieu file he thong: ' + ' '.join(_etc['missing']))
    if _etc['diff']:
        out['problems'].append('file he thong khac ban trong app: ' + ' '.join(_etc['diff']))
    if not _etc['cron_killswitch']:
        out['problems'].append('crontab thieu dong kill-switch')
    out['ok'] = not out['problems']
    return out

def pppoe_glider_port(sid):
    # Port proxy cua phien: 15000 + id - 1 (khớp run_glider.sh). ID lệch thì vẫn
    # lấy theo danh sách vendor là chính, port này chỉ là fallback.
    try:
        return 15000 + int(sid) - 1
    except Exception:
        return 0

def pppoe_sessions_raw(_cache=None):
    # [Ver 2.60] Lay danh sach phien tu server goc 9000, có cache theo goi.
    # Truoc day MỖI phiên lai goi 9000 mot lan -> 35 phien = 35 request,
    # chiem het server goc, GUI 9001 forward qua do bi xep hang -> treo.
    if _cache is not None and _cache.get('ts') and (time.time() - _cache['ts'] < 5):
        return _cache.get('raw', [])
    try:
        r = call_old_gui('/api/router/pppoe')
        raw = (r or {}).get('data')
        if isinstance(raw, dict):
            raw = raw.get('data', raw)
        out = raw if isinstance(raw, list) else []
        if _cache is not None:
            _cache['ts'] = time.time()
            _cache['raw'] = out
        return out
    except Exception:
        return []

def pppoe_session_credentials(sid, sessions=None):
    # Lay user/pass proxy cua 1 phien. sessions: danh sach co san (truyen vao de
    # khong phai goi 9000 lai). Neu khong truoc thi tu lay 1 lan.
    import urllib.parse as _u
    try:
        items = sessions if sessions is not None else pppoe_sessions_raw()
        for item in items or []:
            try:
                if int(item.get('id', -1)) != int(sid):
                    continue
            except Exception:
                continue
            su = hp = ''
            for k in ('socks5', 'socks', 'socks_url'):
                v = str(item.get(k) or '').strip()
                if v:
                    su = v; break
            for k in ('http', 'http_proxy', 'http_url'):
                v = str(item.get(k) or '').strip()
                if v:
                    hp = v; break
            if su:
                u = _u.urlparse(su if '://' in su else 'socks5://' + su)
                return (su, hp, _u.unquote(u.username or ''), _u.unquote(u.password or ''), int(u.port or 0))
            return (su, hp, '', '', 0)
    except Exception:
        pass
    return ('', '', '', '', 0)

def pppoe_glider_forward_alive(sid, port=None, _cache=None):
    # Probe SOCKS 5 rồi bắt tay TLS. Glider treo forward vẫn trả lời greet/auth/
    # CONNECT OK, chỉ rách ở bước đọc data TLS. Chỉ SOCKS CONNECT không đủ để phát hiện.
    try:
        import socket, struct, ssl
        port = port or pppoe_glider_port(sid)
        if not port:
            return True
        su, _hp, user, pw, sport = pppoe_session_credentials(
            sid, (_cache.get('sessions') if isinstance(_cache, dict) else None))
        host = '127.0.0.1'
        s = socket.create_connection((host, port), timeout=6)
        try:
            s.settimeout(9)
            s.sendall(bytes([5, 2, 0, 2]))
            g = s.recv(2)
            if g != b'\x05\x02':
                return True
            ub, pb = (user or '').encode(), (pw or '').encode()
            s.sendall(bytes([1, len(ub)]) + ub + bytes([len(pb)]) + pb)
            a = s.recv(2)
            if a != b'\x01\x00':
                return True
            s.sendall(bytes([5, 1, 0, 1]) + bytes([1, 1, 1, 1]) + struct.pack('>H', 443))
            r = s.recv(10)
            if r[1] != 0:
                return True
            ctx = ssl.create_default_context()
            t = ctx.wrap_socket(s, server_hostname='one.one.one.one')
            try:
                t.settimeout(9)
                t.sendall(b'GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n')
                d = t.recv(32)
                return bool(d)
            finally:
                try: t.close()
                except Exception: pass
        finally:
            try: s.close()
            except Exception: pass
    except Exception as probe_err:
        # [Ver 2.67 QA fix] Phân biệt rõ 4 trạng thái:
        #   1. ConnectionRefusedError -> glider CHƯA KỊP BIND (mới khởi động) => sống, KHÔNG restart
        #   2. timeout                 -> chưa chắc chết => sống, KHÔNG restart
        #   3. SSLEOFError/reset       -> bind xong nhưng forward chết => CHẾT, restart
        #   4. lỗi khác               -> không chắc, không restart
        # Bản v2.66 đoán sai: refused rơi vào nhánh ConnectionError => return False
        # => watchdog coi glider chưa bind là chết, kill rồi khởi động lại liên tục.
        import socket as _s
        if isinstance(probe_err, ConnectionRefusedError):
            return True
        if isinstance(probe_err, ssl.SSLError):
            return False
        if isinstance(probe_err, ConnectionResetError):
            return False
        return True
        return True

_GLIDER_RECENT = {}

def pppoe_glider_restart(sid, sessions=None):
    # Khởi động lại glider của phien: kill PID đang giữ port rồi chạy lại wrapper gốc.
    try:
        port = pppoe_glider_port(sid)
        iface = 'if_%03d' % int(sid)
        iface = 'pppoe-%s' % iface
        # [Ver 2.82] Lay listen URL TRUOC khi kill: 9000 loi thi dung cmdline glider cu.
        gp = _pppoe_glider_procs().get(int(sid)) or {}
        su, hp, user, pw, sport = pppoe_session_credentials(sid, sessions)
        if not su and gp.get('socks'):
            su, hp = gp['socks'], gp.get('http') or ''
        _GLIDER_RECENT[int(sid)] = time.time()
        subprocess.run(
            'for p in $(netstat -tlnp 2>/dev/null | grep ":%d " | grep -oE "[0-9]+/glider" | cut -d/ -f1); do kill -9 $p 2>/dev/null; done; sleep 1' % port,
            shell=True, timeout=10)
        if gp.get('pid'):
            try:
                os.kill(int(gp['pid']), 9)
            except Exception:
                pass
        if su:
            subprocess.Popen(['/etc/genrouter/core/run_glider.sh', su, hp or su, iface],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {'ok': True, 'sid': sid, 'port': port}
        return {'ok': False, 'sid': sid, 'error': 'no credentials'}
    except Exception as e:
        return {'ok': False, 'sid': sid, 'error': str(e)[:160]}

def pppoe_glider_watchdog_check():
    # Quét các phiên đang online; phiên nào glider treo forward thì khởi động lại.
    # Chỉ restart phiên chắc chắn hỏng, không rà soát toàn bộ glider.
    try:
        dump = json.loads(subprocess.check_output(
            ['ubus', 'call', 'network.interface', 'dump'], text=True, timeout=5))
        live = []
        for x in dump.get('interface', []):
            n = str(x.get('interface') or '')
            if not n.startswith('if_') or n.endswith('_6'):
                continue
            if not x.get('up'):
                continue
            ips = x.get('ipv4-address') or []
            if not ips:
                continue
            try:
                live.append(int(n.split('_', 1)[1]))
            except Exception:
                pass
        fixed = []
        # [Ver 2.60] NGUYÊN NHÂN TREO GUI: moi phien lai goi server goc 9000 mot lan
        # (qua pppoe_session_credentials) nen 35 phien = 35 request tuần tự, trong khi
        # GUI cũng phải forward qua 9001 -> 9000 nên bi xếp hàng phía sau -> treo.
        # Nay: goi 9000 DÚNG 1 LẦN cho cả chu kỳ rồi tái sử dụng cho mọi phiên.
        _c = {'sessions': pppoe_sessions_raw()}
        for sid in live:
            try:
                if not pppoe_glider_forward_alive(sid, _cache=_c):
                    r = pppoe_glider_restart(sid, _c.get('sessions'))
                    r['reason'] = 'forward eof/reset'
                    fixed.append(r)
                    _pppoe_wd_log('GLIDER-FIX phien %d: %s' % (sid, r))
            except Exception as e:
                _pppoe_wd_log('GLIDER-FIX loi phien %d: %s' % (sid, str(e)[:80]))
        return fixed
    except Exception as e:
        _pppoe_wd_log('glider watchdog loi: %s' % e)
        return []

def pppoe_glider_stale_check():
    """[Ver 2.82] Glider khoi dong TRUOC khi cong pppoe len lai (xoay IP, BRAS ngat,
    ifup lai) => glider van giu cong/IP cu, forward EOF, may mat mang.
    So thoi diem cong len (ubus uptime) voi thoi diem glider start; cu hon => restart.
    Re: 1 lan ubus dump + doc /proc, khong probe mang."""
    fixed = []
    try:
        dump = json.loads(subprocess.check_output(
            ['ubus', 'call', 'network.interface', 'dump'], text=True, timeout=5))
    except Exception:
        return fixed
    now = time.time()
    procs = _pppoe_glider_procs()
    for x in dump.get('interface', []):
        n = str(x.get('interface') or '')
        if not n.startswith('if_') or n.endswith('_6') or not x.get('up'):
            continue
        if not (x.get('ipv4-address') or []):
            continue
        try:
            sid = int(n.split('_', 1)[1])
        except Exception:
            continue
        g = procs.get(sid)
        if not g or not g.get('start'):
            continue
        if_up = now - float(x.get('uptime') or 0)
        # glider start som hon cong >5s, cong da len >=3s (cho IP on dinh)
        if g['start'] < if_up - 5 and now - if_up >= 3 and now - _GLIDER_RECENT.get(sid, 0) > 20:
            r = pppoe_glider_restart(sid)
            r['reason'] = 'glider cu hon cong (IP doi)'
            _pppoe_wd_log('GLIDER-STALE phien %d: %s' % (sid, r))
            fixed.append(r)
    return fixed

PXWAN_NFT_FILE = Path('/usr/share/nftables.d/chain-pre/input/20-genrouter-pxwan.nft')
PXWAN_NFT_RULE = 'iifname "pppoe-if_*" tcp dport { 15000-15999, 30000-30999 } accept comment "genrouter-pxwan"'
PXWAN_RULE_PREF = 95
PXWAN_TABLE_BASE = 20000

def pppoe_wan_proxy_sync():
    """[Ver 2.83] Proxy glider dung tu NGOAI Internet qua IP WAN cua tung phien:
      <IP WAN phien N>:15000+N-1 (socks5) / 30000+N-1 (http), user/pass cua phien.
    Can 2 thu (da test tay tren Gen15 2026-10-24, if_034 tu ngoai: timeout -> OK):
      1) fw4 input cho phep tcp 15000-15999/30000-30999 tu pppoe-if_* (zone wan khong
         chua pppoe-if_* nen redirect co san cua vendor khong bao gio khop).
      2) Policy route: goi tra loi tu IP WAN phien N phai ra dung pppoe-if_N
         (khong thi theo default route qua phien khac => BRAS drop).
    Idempotent; chi chay lenh khi khac trang thai. 2 lenh doc / chu ky."""
    changed = []
    # 1) firewall: file include (song qua fw4 reload) + chen ngay neu thieu
    try:
        want = PXWAN_NFT_RULE + '\n'
        if not PXWAN_NFT_FILE.exists() or PXWAN_NFT_FILE.read_text() != want:
            PXWAN_NFT_FILE.parent.mkdir(parents=True, exist_ok=True)
            PXWAN_NFT_FILE.write_text(want)
            changed.append('nft-file')
        cur = subprocess.run(['nft', 'list', 'chain', 'inet', 'fw4', 'input'], capture_output=True, text=True, timeout=5).stdout
        if cur and 'genrouter-pxwan' not in cur:
            subprocess.run(['nft', 'insert', 'rule', 'inet', 'fw4', 'input'] + _nft_split(PXWAN_NFT_RULE), capture_output=True, timeout=5)
            changed.append('nft-live')
    except Exception as e:
        changed.append('nft-err:%s' % str(e)[:60])
    # 2) policy route theo IP WAN tung phien
    try:
        dump = json.loads(subprocess.check_output(['ubus', 'call', 'network.interface', 'dump'], text=True, timeout=5))
    except Exception:
        return changed
    want = {}
    for x in dump.get('interface', []):
        n = str(x.get('interface') or '')
        if not n.startswith('if_') or n.endswith('_6') or not x.get('up'):
            continue
        ips = x.get('ipv4-address') or []
        if not ips:
            continue
        try:
            sid = int(n.split('_', 1)[1])
        except Exception:
            continue
        want[sid] = ips[0].get('address', '')
    rules = subprocess.run(['ip', '-4', 'rule', 'show', 'pref', str(PXWAN_RULE_PREF)], capture_output=True, text=True, timeout=5).stdout
    have = set()
    for ln in rules.splitlines():
        m = re.search(r'from (\S+) lookup (\d+)', ln)
        if m:
            have.add((m.group(1), int(m.group(2))))
    routes = subprocess.run(['ip', '-4', 'route', 'show', 'table', 'all'], capture_output=True, text=True, timeout=5).stdout
    have_rt = set()
    for ln in routes.splitlines():
        m = re.match(r'default dev pppoe-if_(\d+) table (\d+)', ln.strip())
        if m and int(m.group(2)) == PXWAN_TABLE_BASE + int(m.group(1)):
            have_rt.add(int(m.group(1)))
    batch = []
    want_rules = {(ip, PXWAN_TABLE_BASE + sid) for sid, ip in want.items() if ip}
    for ip, t in sorted(have - want_rules):
        batch.append('rule del pref %d from %s lookup %d' % (PXWAN_RULE_PREF, ip, t))
    for sid, ip in sorted(want.items()):
        t = PXWAN_TABLE_BASE + sid
        if sid not in have_rt:
            batch.append('route replace default dev pppoe-if_%03d table %d' % (sid, t))
        if ip and (ip, t) not in have:
            batch.append('rule add pref %d from %s lookup %d' % (PXWAN_RULE_PREF, ip, t))
    if batch:
        subprocess.run(['ip', '-force', '-batch', '-'], input='\n'.join(batch) + '\n', capture_output=True, text=True, timeout=20)
        changed.append('ip:%d' % len(batch))
    return changed

_PXCRED_LAST_RESTART = [0.0]

def pppoe_outbound_creds_sync():
    """[Ver 2.87] Doi user/pass proxy phien PPPoE => glider chay pass MOI, nhung outbound
    proxy_* trong gencore.json (may gan phien do) van giu pass CU => auth fail, may mat
    mang (do that Gen15 25/10: may 968 / phien 129, gencore len8 vs glider len11/len9).
    Moi 10s: so outbound socks tro ve glider (port 15000-15999) voi cmdline glider dang
    chay; lech => sua outbound (runtime + preset), restart gencore (toi da 1 lan/60s,
    bo qua khi dang Apply). Tra ve so outbound da sua."""
    if _apply_lock_active():
        return 0
    gl = _pppoe_glider_procs()
    if not gl:
        return 0
    import urllib.parse as _u
    want = {}
    for sid, g in gl.items():
        try:
            u = _u.urlparse(g['socks'])
            user = _u.unquote(u.username or ''); pw = _u.unquote(u.password or ''); port = int(u.port or 0)
        except Exception:
            continue
        # glider vua start (<5s) co the dang doi lai => doi chu ky sau
        if user and pw and port and time.time() - float(g.get('start') or 0) > 5:
            want[port] = (user, pw, sid)
    if not want:
        return 0
    lan = _pppoe_glider_lan_host()
    files = [RUNTIME_SOURCE_FILE]
    if str(RUNTIME_FILE) != str(RUNTIME_SOURCE_FILE):
        files.append(RUNTIME_FILE)
    files += [p for p in SESSION_FILES.values()]
    fixed_runtime, fixed_tags = 0, []
    for f in files:
        try:
            if not Path(f).exists():
                continue
            doc = load_json(f)
        except Exception:
            continue
        n = 0
        for ob in doc.get('outbounds', []) or []:
            if not isinstance(ob, dict) or ob.get('type') != 'socks':
                continue
            if str(ob.get('server') or '') not in (lan, '127.0.0.1', '0.0.0.0'):
                continue
            w = want.get(int(ob.get('server_port') or 0))
            if not w or (ob.get('username'), ob.get('password')) == (w[0], w[1]):
                continue
            ob['username'], ob['password'] = w[0], w[1]
            n += 1
            if f in (RUNTIME_SOURCE_FILE, RUNTIME_FILE):
                fixed_tags.append('%s<-phien%d' % (ob.get('tag'), w[2]))
        if n:
            save_gencore_json(f, doc)
            if f in (RUNTIME_SOURCE_FILE, RUNTIME_FILE):
                fixed_runtime += n
    if fixed_runtime:
        tags = sorted(set(fixed_tags))
        _pppoe_wd_log('PXCRED: %d outbound giu pass proxy cu => da cap nhat theo glider: %s' % (len(tags), ', '.join(tags[:10])))
        try:
            pppoe_session_proxies._cache = None
        except Exception:
            pass
        now = time.time()
        if now - _PXCRED_LAST_RESTART[0] >= 60:
            _PXCRED_LAST_RESTART[0] = now
            # gencore khong tu nap lai config => restart de RAM nhan pass moi
            gencore_restart_detached('pxcred')
            _pppoe_wd_log('PXCRED: restart gencore de nap pass moi')
    return fixed_runtime

def _nft_split(rule):
    import shlex
    return shlex.split(rule)

def pppoe_glider_stale_loop():
    time.sleep(40)
    _last_px = ''
    while True:
        try:
            pppoe_glider_stale_check()
        except Exception as e:
            _pppoe_wd_log('glider stale loi: %s' % str(e)[:80])
        try:
            ch = pppoe_wan_proxy_sync()
            if ch:
                s = ','.join(ch)
                if s != _last_px or any(c.startswith('nft') for c in ch):
                    _pppoe_wd_log('PXWAN sync: %s' % s)
                _last_px = s
        except Exception as e:
            _pppoe_wd_log('PXWAN loi: %s' % str(e)[:80])
        try:
            pppoe_outbound_creds_sync()
        except Exception as e:
            _pppoe_wd_log('PXCRED loi: %s' % str(e)[:80])
        time.sleep(10)

def _pppoe_wd_log(msg):
    try:
        _wd_log('[Ver 2.62] ' + str(msg))
    except Exception:
        pass

def gencore_watchdog_loop():
    # [Ver 2.48] Doc nhan tu VERSION.txt thay vi hardcode: ban 2.47 in "WATCHDOG start
    # (Ver 2.47...)" ngay ca khi may da len 2.48, lam log sai va gay chan doan lech.
    try:
        _wd_ver = normalize_version_key(read_current_version_label()) or 'Ver ?'
    except Exception:
        _wd_ver = 'Ver ?'
    _wd_log('WATCHDOG start (%s: + config self-heal, + apply lock, + STALE-CONFIG, + FD-LEAK)' % _wd_ver)
    time.sleep(25)
    try:
        wd_boot_recover()
    except Exception:
        pass
    _gl_tick = 0
    while True:
        try:
            time.sleep(60)
            try:
                _h = ensure_wan_port_not_bridged()
                if _h.get('changed'):
                    _wd_log('[HEAL] eth0 WAN bi nhet vao br-lan -> da go ra %s' % _h)
            except Exception:
                pass
            thr = _wd_thresholds()
            cnt = _wd_conntrack_counts()
            if cnt is None:
                continue
            tw, total = cnt
            pid = _gencore_pid()
            now = time.time()
            if _wd_apply_in_progress():
                # Dang apply: genrunner kill gencore co chu y roi tu dung lai.
                # Chen vao day la dua tren dung file config dang duoc ghi.
                continue
            try:
                config_self_heal(reason='watchdog')
            except Exception as e:
                _wd_log(f'heal error: {e}')
            # Ver 2.47 — chot V2-c: quet cac ban config ngu dong (gencore2.json...)
            # de vendor khong con mau sai de tai nhiem. Cache theo mtime nen re.
            try:
                heal_dormant_configs(reason='watchdog')
            except Exception as e:
                _wd_log(f'dormant-heal error: {e}')
            if not pid:
                # [QA] Truoc day: `if not Path(...).exists(): continue` cat luon vong
                # while, bo qua glider watchdog. Chi continue khi thuc su thieu binary,
                # con lai van phai chay du cac check gencore.
                if not Path('/usr/bin/gencore').exists(): continue
                if now - WD_STATE.get('last_start', 0) >= 180:
                    WD_STATE['last_start'] = now
                    WD_STATE['restarts'] = WD_STATE.get('restarts', 0) + 1
                    gencore_start_detached('dead')
                continue
            # Ver 2.47 — chot V2-b: config tren dia moi hon tien trinh => RAM giu
            # ban cu. Phai xet TRUOC cac nguong tai vi day la loi im lang nhat:
            # moi chi so khac deu 'xanh' trong khi 322 may mat DNS.
            # [Ver 2.60] Glider watchdog chạy MỖI 3 vòng (~3 phút): phát hiện
            # glider treo forward (SOCKS CONNECT OK nhưng TLS/HTTP EOF) rồi
            # tự khởi động lại đúng phiên. Đặt trước các continue phía dưới để
            # không bao giờ bị bỏ qua.
            _gl_tick += 1
            if _gl_tick >= 3:
                _gl_tick = 0
                try:
                    fixed = pppoe_glider_watchdog_check()
                    if fixed:
                        _pppoe_wd_log('glider fixed: %s' % [(x.get('sid'), x.get('ok')) for x in fixed])
                except Exception as e:
                    _pppoe_wd_log('glider check error: %s' % e)
            pid1 = pid.split()[0] if pid else ''
            try:
                if _wd_check_config_stale(pid1, thr):
                    continue
            except Exception as e:
                _wd_log(f'stale-config error: {e}')
            # Ver 2.47 — chot V5-b: ro fd / socket TPROXY.
            try:
                if _wd_check_fd_leak(pid1, thr):
                    continue
            except Exception as e:
                _wd_log(f'fd-leak error: {e}')
            # Ver 2.47 — chot V4-d: y muon VPN vs data-plane that.
            try:
                _wd_check_vpn_integrity(thr)
            except Exception as e:
                _wd_log(f'vpn-integrity error: {e}')
            if tw >= thr['zombie_tw'] or total >= thr['ct_total']:
                WD_STATE['hits'] = WD_STATE.get('hits', 0) + 1
                _wd_log(f"STORM hit={WD_STATE['hits']} tw={tw} total={total} pid={pid}")
                if WD_STATE['hits'] >= thr['consecutive'] and now - WD_STATE.get('last_restart', 0) >= thr['cooldown_sec']:
                    WD_STATE['last_restart'] = now
                    WD_STATE['hits'] = 0
                    WD_STATE['restarts'] = WD_STATE.get('restarts', 0) + 1
                    _wd_log(f'RESTART gencore do zombie storm tw={tw} total={total}')
                    gencore_restart_detached('zombie_storm')
            elif WD_STATE.get('hits'):
                WD_STATE['hits'] = 0
            try:
                accounts = vpn_status_json()
            except Exception:
                accounts = []
            if accounts:
                _wd_persist_runtime(accounts)
        except Exception as e:
            _wd_log(f'loop error: {e}')

def vpn_add_openvpn_text(name, text, user='', password=''):
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix='vpn_upload_', suffix='.ovpn')
    with os.fdopen(fd, 'w', encoding='utf-8', errors='replace') as f:
        f.write(text.replace('\r\n', '\n'))
    try:
        args = ['add-openvpn', name, tmp]
        if user:
            args += [user, password]
        return vpn_run(args)
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

def vpn_add_wg_text(name, text):
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix='vpn_upload_', suffix='.conf')
    with os.fdopen(fd, 'w', encoding='utf-8', errors='replace') as f:
        f.write(text.replace('\r\n', '\n'))
    try:
        return vpn_run(['add-wg', name, tmp])
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

class Handler(BaseHTTPRequestHandler):

    def _send_no_cache_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self._send_no_cache_headers()
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path, content_type='text/html; charset=utf-8'):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self._send_no_cache_headers()
        self.end_headers()
        self.wfile.write(data)

    def _send_disk_file(self, path: Path):
        if not path.exists() or not path.is_file():
            return self._send_json({'error': 'Not found'}, 404)
        ctype, _ = mimetypes.guess_type(str(path))
        if path.suffix.lower() in ('.js',):
            ctype = 'application/javascript; charset=utf-8'
        elif path.suffix.lower() in ('.css',):
            ctype = 'text/css; charset=utf-8'
        elif path.suffix.lower() in ('.html', '.htm'):
            ctype = 'text/html; charset=utf-8'
        elif path.suffix.lower() in ('.json',):
            ctype = 'application/json; charset=utf-8'
        else:
            ctype = ctype or 'application/octet-stream'
        data = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self._send_no_cache_headers()
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        ensure_sessions_exist()
        path = urlparse(self.path).path
        if path == '/api/license':
            return self._send_json(license_public_payload())
        if not license_gate_ok():
            return self._send_json({'error': 'License inactive or expired', 'license_required': True}, 403)
        if path == '/':
            return self._send_file(STATIC_DIR / 'index.html')
        if path == '/api/pm/split':
            return self._send_json(split_public_state())
        if path == '/api/pm/conn':
            return self._send_json(conn_public_state())
        if path == '/api/pm/flow':
            q = parse_qs(urlparse(self.path).query or '')
            return self._send_json(flow_public_state((q.get('ip') or [''])[0]))
        if path == '/api/pm/sessions':
            include_hidden = 'include_hidden=1' in (urlparse(self.path).query or '')
            # [Ver 2.72] tra kem cau hinh DANG APPLY: GUI mo len (F5/tat-mo) phai nhay dung
            # cau hinh do. Ver 2.70 dua /api/pm/meta ra chay nen nen mat buoc nay => luon ve 1.
            active_session = ''
            try:
                active_session = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '') or '').strip()
            except (OSError, ValueError):
                pass
            return self._send_json({'ok': True, 'sessions': get_available_sessions(include_hidden=include_hidden), 'max_sessions': MAX_SESSION_COUNT, 'active_session': active_session})
        if path.startswith('/api/pm/sessions/'):
            session_id = path.rsplit('/', 1)[-1]
            if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                return self._send_json({'session': session_id, 'name': get_session_display_name(session_id), 'source': str(SESSION_FILES[session_id]), 'rows': extract_rows(load_json(SESSION_FILES[session_id]), session=session_id)})
        if path == '/api/pm/router-network':
            # CHỐNG LAG GUI: WAN down => probe HTTPS timeout 8s x2 + ping 10s = 26s,
            # GUI co the goi endpoint nay 2 lan (bootstrap + badge) => ~52s treo.
            # Badge chi la thong tin phu nen KHONG probe Internet dong bo. Chi đọc
            # route local (0ms) => tra ngay, khong anh huong hien thi.
            try:
                _rc = subprocess.run(['ip', 'route', 'get', '1.1.1.1'], timeout=1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            except Exception:
                _rc = 1
            return self._send_json({'ok': True, 'connected': _rc == 0, 'probe': 'local-route'})
        if path == '/api/pm/router-info':
            return self._send_json(call_old_gui('/api/router/info'))
        if path == '/api/pm/meta':
            # Ver 2.64: khong goi GitHub/git trong luong mo GUI. Truoc day
            # get_repo_version_info() fetch remote => tre ~10s khi WAN cham/loi.
            version_info = {
                'current_label': read_current_version_label(),
                'latest_label': read_current_version_label(),
                'current_commit': '',
                'has_update': False,
            }
            active_session = ''
            try:
                active_session = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '') or '')
            except (OSError, ValueError):
                pass
            return self._send_json({'ok': True, 'app_title_prefix': get_app_title_prefix(), 'version': version_info, 'active_session': active_session})
        if path == '/api/pm/sysinfo':
            return self._send_json(sysinfo_json())
        if path == '/api/pm/version-check':
            # Endpoint rieng cho nut Kiem tra phien ban (chi goi khi nguoi dung bam).
            return self._send_json(get_repo_version_info())
        if path == '/api/pm/health':
            return self._send_json(wd_health_json())
        if path == '/vpn':
            return self._send_file(STATIC_DIR / 'vpn.html')
        if path == '/pppoe':
            return self._send_file(STATIC_DIR / 'pppoe.html')
        if path == '/api/pppoe/list':
            try:
                return self._send_json(pppoe_runtime_enrich(call_old_gui('/api/router/pppoe')))
            except Exception as ex:
                return self._send_json({'ok': False, 'error': 'server goc 9000: ' + str(ex)[:200], 'data': []})
        if path == '/api/pppoe/ports':
            return self._send_json({'ok': True, 'ports': router_physical_ports()})
        if path == '/api/pppoe/status':
            try:
                return self._send_json(call_old_gui('/api/router/status_pppoe'))
            except Exception as ex:
                return self._send_json({'ok': False, 'error': 'server goc 9000: ' + str(ex)[:200]})
        if path == '/api/pppoe/devices':
            try:
                return self._send_json(call_old_gui('/api/router/pppoe/device'))
            except Exception as ex:
                return self._send_json({'ok': False, 'error': 'server goc 9000: ' + str(ex)[:200], 'data': []})
        if path == '/api/vpn/status':
            return self._send_json({'ok': True, 'accounts': vpn_status_json(), 'machine_map': vpn_machine_map(), 'deps': vpn_deps_status()})
        if path == '/api/vpn/auto':
            return self._send_json(vpn_auto_public())
        if path == '/api/vpn/distinct':
            _qd = parse_qs(urlparse(self.path).query or '')
            return self._send_json(vpn_distinct_status((_qd.get('job') or [''])[0]))
        if path == '/api/vpn/servers':
            # [Ver 2.94] parse query tai cho: bien 'q' chi ton tai trong nhanh /api/pm/flow
            _qs = parse_qs(urlparse(self.path).query or '')
            return self._send_json(vpn_express_servers((_qs.get('loc') or [''])[0].strip().lower()))
        if path == '/api/vpn/xv-creds':
            return self._send_json({'ok': True, 'creds': xv_creds_public()})
        if path == '/api/vpn/exitips':
            return self._send_json({'ok': True, 'ips': dict(_EXITIPS), 'busy': _EXITIPS_BUSY['v']})
        if path == '/api/vpn/express-hosts':
            hosts = []
            try:
                with open(VPN_HOSTS_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith('#'):
                            continue
                        p = ln.split('|')
                        if len(p) >= 3:
                            hosts.append({'country': p[0], 'city': p[1], 'host': p[-1]})
                        else:
                            hosts.append({'country': '', 'city': '', 'host': p[-1]})
            except Exception:
                pass
            return self._send_json({'ok': True, 'hosts': hosts})
        if path == '/api/pm/export-all':
            include_hidden = 'include_hidden=1' in (urlparse(self.path).query or '')
            return self._send_json(export_all_sessions_payload(include_hidden=include_hidden))
        if path == '/api/pm/collector-config':
            return self._send_json({'ok': True, 'config': load_collector_config(), 'router_id': get_router_id()})
        if path == '/api/admanager/config':
            cfg = load_admanager_config()
            router_ctx = get_router_machine_context(cfg, cfg.get('uiState') if isinstance(cfg.get('uiState'), dict) else {})
            return self._send_json({'ok': True, 'config': cfg, 'machine_note': router_ctx.get('note', ''), 'machine_indexes': router_ctx.get('available', [])})
        if path.startswith('/api/pm/ip-mac-config/'):
            session_id = path.rsplit('/', 1)[-1]
            if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                data = load_json(SESSION_FILES['1'])
                saved_text = get_saved_ip_identity_text(session_id)
                if not saved_text:
                    rows = build_ip_identity_rows_from_data(data)
                    if rows and len(rows) < MAX_PROXY_TAG:
                        saved_text = set_saved_ip_identity_text(session_id, '\n'.join((format_ip_identity_row(row, include_machine=True) for row in rows)))
                return self._send_json({'ok': True, 'session': session_id, 'shared': True, 'text': saved_text or build_ip_identity_text(data, session='1')})
        self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        ensure_sessions_exist()
        path = urlparse(self.path).path
        if path != '/api/pm/reboot-router' and (not license_gate_ok()):
            return self._send_json({'error': 'License inactive or expired', 'license_required': True}, 403)
        length = int(self.headers.get('Content-Length', '0') or '0')
        body = self.rfile.read(length) if length else b'{}'
        payload = json.loads(body.decode('utf-8') or '{}')
        try:
            if path == '/api/pm/flow':
                try:
                    return self._send_json(flow_update(payload if isinstance(payload, dict) else {}))
                except ValueError as fe:
                    return self._send_json({'ok': False, 'error': str(fe)})
            if path == '/api/pm/split':
                try:
                    return self._send_json(split_update(payload if isinstance(payload, dict) else {}))
                except ValueError as se:
                    return self._send_json({'ok': False, 'error': str(se)})
            if path == '/api/pm/conn':
                try:
                    return self._send_json(conn_update(payload if isinstance(payload, dict) else {}))
                except ValueError as ce:
                    return self._send_json({'ok': False, 'error': str(ce)})
            if path == '/api/pm/sessions/create':
                session_id = str(payload.get('session', '')).strip()
                source_session = str(payload.get('source_session', current if (current := payload.get('current_session')) else '1')).strip() or '1'
                return self._send_json({'ok': True, **create_session(session_id, source_session=source_session)})
            if path == '/api/pm/sessions/hide':
                session_id = str(payload.get('session', '')).strip()
                hidden = bool(payload.get('hidden', True))
                return self._send_json({'ok': True, 'session': session_id, 'hidden': set_session_hidden(session_id, hidden)})
            if path == '/api/pm/sessions/delete':
                session_id = str(payload.get('session', '')).strip()
                delete_session(session_id)
                return self._send_json({'ok': True, 'session': session_id})
            if path.startswith('/api/pm/sessions/'):
                session_id = path.rsplit('/', 1)[-1]
                if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                    rows = payload.get('rows', [])
                    try:
                        promoted = sync_auto_ip_tags(rows, session_id)
                    except ValueError as pe:
                        return self._send_json({'ok': False, 'error': str(pe)})
                    rows_by_tag = {str(row['tag']).strip(): row for row in rows if row.get('tag')}
                    data = load_json(SESSION_FILES[session_id])
                    save_gencore_json(SESSION_FILES[session_id], apply_rows_to_data(data, rows_by_tag, session=session_id))
                    name = payload.get('name')
                    if name is not None:
                        name = set_session_display_name(session_id, name)
                    else:
                        name = get_session_display_name(session_id)
                    try:
                        spawn_proxy_sheet_push()
                    except Exception:
                        pass
                    return self._send_json({'ok': True, 'session': session_id, 'name': name, 'promoted': promoted})
            if path.startswith('/api/pm/apply/'):
                session_id = path.rsplit('/', 1)[-1]
                if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                    rows_override = payload.get('rows') if isinstance(payload, dict) else None
                    promoted = []
                    if isinstance(rows_override, list):
                        try:
                            promoted = sync_auto_ip_tags(rows_override, session_id)
                        except ValueError as pe:
                            return self._send_json({'ok': False, 'error': str(pe)})
                    results = run_apply(session_id, rows_override=rows_override)
                    try:
                        ACTIVE_SESSION_FILE.write_text(json.dumps({'active': str(session_id)}), encoding='utf-8')
                    except OSError:
                        pass
                    return self._send_json({'ok': True, 'applied': session_id, 'results': results, 'promoted': promoted})
            if path == '/api/pm/clone/1-to-2':
                save_gencore_json(SESSION_FILES['2'], load_json(SESSION_FILES['1']))
                state = load_session_state()
                if isinstance(state, dict) and isinstance(state.get('1'), dict):
                    state['2'] = json.loads(json.dumps(state.get('1', {})))
                    _state, meta = get_meta_section(state)
                    names = meta.setdefault('session_names', {}) if isinstance(meta, dict) else {}
                    if isinstance(names, dict) and '1' in names:
                        names['2'] = names['1']
                    ip_text = meta.setdefault('ip_identity_text', {}) if isinstance(meta, dict) else {}
                    if isinstance(ip_text, dict) and '1' in ip_text:
                        ip_text['2'] = ip_text['1']
                    save_session_state(state)
                try:
                    spawn_proxy_sheet_push()
                except Exception:
                    pass
                return self._send_json({'ok': True})
            if path == '/api/pm/meta':
                prefix = set_app_title_prefix(payload.get('app_title_prefix', 'Genrouter'))
                return self._send_json({'ok': True, 'app_title_prefix': prefix, 'version': get_repo_version_info()})
            if path == '/api/pm/version/update':
                result = update_repo_from_remote(payload.get('password', ''))
                return self._send_json(result)
            if path == '/api/admanager/save-config':
                cfg = load_admanager_config()
                incoming = payload.get('config') if isinstance(payload, dict) else {}
                if isinstance(incoming, dict):
                    for key in ('backupCommands', 'defaultOutput', 'uiState'):
                        if key in incoming:
                            cfg[key] = incoming[key]
                save_admanager_local(cfg)
                return self._send_json({'ok': True})
            if path.startswith('/api/pm/map-ip/'):
                session_id = path.rsplit('/', 1)[-1]
                if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                    data = load_json(SESSION_FILES[session_id])
                    save_gencore_json(SESSION_FILES[session_id], remap_ip_by_tag(data))
                    return self._send_json({'ok': True, 'session': session_id})
            if path.startswith('/api/pm/ip-mac-config/'):
                session_id = path.rsplit('/', 1)[-1]
                if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                    text = str(payload.get('text', ''))
                    sync_router = bool(payload.get('sync_router', True))
                    rows = parse_ip_identity_text(text)
                    normalized_text = set_saved_ip_identity_text(session_id, text)
                    apply_results = []
                    for sid, session_file in SESSION_FILES.items():
                        if not session_file.exists():
                            continue
                        data = load_json(session_file)
                        data = apply_ip_identity_config(data, normalized_text, session=sid)
                        save_gencore_json(session_file, data)
                        if payload.get('apply_runtime') and sid == session_id:
                            apply_results = run_apply(sid)
                    if sync_router:
                        sync_static_to_router(rows, clear_first=True)
                    if payload.get('reboot_router'):
                        call_old_gui('/api/system/reboot', method='GET')
                    return self._send_json({'ok': True, 'session': session_id, 'shared': True, 'count': len(rows), 'text': normalized_text, 'apply_results': apply_results})
            if path == '/api/pm/check-proxy':
                return self._send_json(check_proxy(str(payload.get('proxy', '')), session=str(payload.get('session', '1'))))
            if path == '/api/pm/check-proxy-batch':
                return self._send_json({'ok': True, 'results': check_proxy_batch(payload.get('items', []), session=str(payload.get('session', '1')))}) 
            if path == '/api/pm/check-pppoe':
                return self._send_json(check_pppoe_session(payload.get('id', ''), session=str(payload.get('session', '1'))))
            if path == '/api/pm/vpn-sweep':
                return self._send_json(vpn_map_sweep(payload.get('session', '')))
            if path == '/api/pm/reboot-router':
                return self._send_json(call_old_gui('/api/system/reboot', method='GET'))
            if path == '/api/pm/collector-config':
                cfg = load_collector_config()
                cfg.update({'collector_url': str(payload.get('collector_url', cfg.get('collector_url', ''))).strip(), 'router_id': str(payload.get('router_id', cfg.get('router_id', ''))).strip(), 'remote_url': str(payload.get('remote_url', cfg.get('remote_url', ''))).strip(), 'enabled': bool(payload.get('enabled', cfg.get('enabled', False))), 'push_interval_sec': int(payload.get('push_interval_sec', cfg.get('push_interval_sec', 60)) or 60)})
                save_collector_config(cfg)
                return self._send_json({'ok': True, 'config': cfg, 'router_id': get_router_id()})
            if path == '/api/pm/collector-push-now':
                return self._send_json(push_export_to_collector_once())
            if path == '/api/pm/router-change-lan':
                ip_lan = str(payload.get('ip_lan', '')).strip()
                return self._send_json(call_old_gui('/api/router/change_lan', method='POST', data={'ip_lan': ip_lan}))
            if path == '/api/pppoe/action':
                action = str(payload.get('action', '')).strip()
                if action == 'create':
                    data={k:payload.get(k,'') for k in ('device','number','username','password','proxy_username','proxy_password','duration')}
                    try:data['number']=max(1,min(64,int(data.get('number') or 1)))
                    except Exception:data['number']=1
                    try:data['duration']=int(data.get('duration') or 0)
                    except Exception:data['duration']=0
                    data['rotate']=bool(payload.get('rotate'))
                    vlan=str(payload.get('vlan','') or '').strip()
                    if 1<=int(vlan)<=4094 if vlan.isdigit() else False:
                        vdev=(str(data.get('device') or 'eth0')+'.'+vlan)
                        subprocess.run(['ip','link','add','link',str(data.get('device') or 'eth0'),'name',vdev,'type','vlan','id',vlan],timeout=10,capture_output=True)
                        subprocess.run(['ip','link','set',vdev,'up'],timeout=10,capture_output=True)
                        data['device']=vdev
                    # choc den port khong nam trong bridge nua khong bi tranh
                    port_state=pppoe_prepare_port(data.get('device') or 'eth0')
                    # khong tai bridge khi tao nhieu phien
                    out=[]; last=None
                    for _ in range(data['number']):
                        one=dict(data); one['number']=1
                        last=call_old_gui('/api/router/pppoe',method='POST',data=one)
                        out.append(last)
                    result=dict(last or {})
                    result['created_requested']=data['number']
                    result['create_attempts']=len(out)
                    result['port']=port_state
                    result.setdefault('ok',result.get('ok',False))
                    return self._send_json(result)
                if action == 'acc-list': return self._send_json({'ok':True,'accounts':pppoe_accounts_load()})
                if action == 'acc-save':
                    u=str(payload.get('username','')).strip(); pw=str(payload.get('password',''))
                    if not u or not pw: return self._send_json({'ok':False,'error':'thieu user/pass'})
                    a_=pppoe_accounts_load(); row={'u':u,'p':pw,'d':str(payload.get('device','eth0')),'v':str(payload.get('vlan',''))}
                    old=next((z for z in a_ if z.get('u')==u),None)
                    if old: old.update(row)
                    else: a_.append(row)
                    pppoe_accounts_save(a_); return self._send_json({'ok':True,'accounts':a_})
                if action == 'acc-del':
                    u=str(payload.get('username','')).strip(); a_=[z for z in pppoe_accounts_load() if z.get('u')!=u]
                    pppoe_accounts_save(a_); return self._send_json({'ok':True,'accounts':a_})
                if action == 'delete':
                    ids=payload.get('ids') or ([payload.get('id')] if payload.get('id') is not None else [])
                    fixed=[]; ports=set()
                    try:
                        old=call_old_gui('/api/router/pppoe'); raw=(old or {}).get('data')
                        if isinstance(raw,dict): raw=raw.get('data',raw)
                        wanted={int(str(x).strip()) for x in (ids if isinstance(ids,list) else [ids]) if str(x).strip().isdigit()}
                        for x in raw or []:
                            if int(x.get('id',-1)) in wanted: ports.add(str(x.get('device') or '').split('.',1)[0])
                    except Exception: pass
                    for x in (ids if isinstance(ids,list) else [ids]):
                        try: fixed.append(int(str(x).strip()))
                        except Exception: pass
                    res=call_old_gui('/api/router/pppoe',method='DELETE',data={'ids':fixed})
                    res=dict(res or {}); res['delete_requested']=fixed
                    res['ports_returned']=[pppoe_return_port(x, fixed) for x in sorted(ports)]
                    return self._send_json(res)
                if action == 'reset':
                    rd = dict(payload.get('data') or {})
                    try: rd['id'] = int(str(rd.get('id')).strip())
                    except Exception: return self._send_json({'ok': False, 'error': 'id khong hop le'})
                    return self._send_json(_vendor_result(call_old_gui('/api/router/pppoe/reset', method='PUT', data=rd)))
                if action == 'rotate':
                    rd=payload.get('data') or {}
                    if isinstance(rd,str): rd={'id':rd}
                    rd=dict(rd)
                    try: sid=int(str(rd.get('id')).strip())
                    except Exception: return self._send_json({'ok':False,'error':'id khong hop le'})
                    if sid < 1 or sid > 999: return self._send_json({'ok':False,'error':'id khong hop le'})
                    # [Ver 2.69] tra ngay, chay nen; GUI poll action=rotate_status
                    return self._send_json(rotate_start(sid, rd, lambda d: call_old_gui('/api/router/pppoe/rotate',method='PUT',data=d)))
                if action == 'rotate_status':
                    ids=[]
                    for x in (payload.get('ids') or []):
                        try: ids.append(int(str(x).strip()))
                        except Exception: pass
                    return self._send_json({'ok':True,'jobs':rotate_status(ids or None)})
                if action == 'proxy':
                    # [Ver 2.83] 9000 doi id KIEU SO: gui "35" (chuoi) => 400 Invalid body
                    # (do that Gen15). GUI cu lay id tu o input nen luon la chuoi.
                    rd = dict(payload.get('data') or {})
                    try: rd['id'] = int(str(rd.get('id')).strip())
                    except Exception: return self._send_json({'ok': False, 'error': 'id phien khong hop le'})
                    rd['username'] = str(rd.get('username') or '').strip()
                    rd['password'] = str(rd.get('password') or '')
                    if not rd['username'] or not rd['password']:
                        return self._send_json({'ok': False, 'error': 'nhap du USER PROXY va PASS PROXY moi'})
                    res = _vendor_result(call_old_gui('/api/router/pppoe/proxy', method='PUT', data=rd))
                    if res.get('ok'):
                        # glider phai chay lai voi user/pass moi; vendor tu lam, nhung
                        # bo cache de Apply sau lay dung thong tin moi.
                        try: pppoe_session_proxies._cache = None
                        except Exception: pass
                    return self._send_json(res)
                if action == 'enable':
                    return self._send_json(call_old_gui('/api/router/enable_pppoe', method='POST', data=payload.get('data') or {}))
                return self._send_json({'ok': False, 'error': 'action khong hop le (create|delete|reset|rotate|rotate_status|proxy|enable)'})
            if path == '/api/vpn/action':
                action = str(payload.get('action', '')).strip()
                name = str(payload.get('name', '')).strip()
                ipaddr = str(payload.get('ip', '')).strip()
                if action in ('isolate', 'isolate-status'):
                    mode = str(payload.get('mode', 'status')).strip()
                    if action == 'isolate-status' or not mode:
                        mode = 'status'
                    if mode not in ('status', 'hide', 'show', 'two-way', 'one-way', 'off'):
                        return self._send_json({'ok': False, 'error': 'mode khong hop le (hide|show|off)'})
                    r_iso = vpn_run(['isolate', mode])
                    # [Ver 2.83] Chan local chi co tac dung giua cac CONG cua br-lan. Moi may
                    # chung 1 cong (qua switch/AP) => router khong thay goi client<->client.
                    try:
                        r_iso['lan_ports'] = sorted(os.listdir('/sys/class/net/br-lan/brif'))
                    except Exception:
                        r_iso['lan_ports'] = []
                    try:
                        o_iso = subprocess.run(['nft', 'list', 'table', 'bridge', 'client_isolate'], capture_output=True, text=True, timeout=5).stdout
                        m_iso = re.search(r'counter packets (\d+)', o_iso)
                        r_iso['drop_pkts'] = int(m_iso.group(1)) if m_iso else None
                    except Exception:
                        r_iso['drop_pkts'] = None
                    return self._send_json(r_iso)
                # [Ver 2.94] add-express-many/express-servers khong dung ten tai khoan do client gui
                if action not in ('unassign', 'refresh-exitips', 'unassign-bulk', 'set-auth', 'xv-creds-save', 'xv-creds-del', 'auto-save', 'auto-run', 'add-express-many', 'express-servers', 'add-distinct', 'distinct-status') and (not re.match('^[A-Za-z0-9_.-]{1,64}$', name)):
                    return self._send_json({'ok': False, 'error': 'ten tai khoan khong hop le'})
                if action == 'up':
                    return self._send_json(vpn_run(['up', name]))
                if action == 'set-auth':
                    # [Ver 2.48] va tai khoan bi thieu credential (nguyen nhan loi
                    # "openvpn khong chay duoc"): ghi file auth + tra lai dong
                    # auth-user-pass trong config.ovpn. name='--all' = tat ca.
                    au_user = str(payload.get('username', '')).strip()
                    au_pass = str(payload.get('password', ''))
                    if not au_user or not au_pass:
                        return self._send_json({'ok': False, 'error': 'thieu username/password'})
                    tgt = '--all' if str(payload.get('all', '')) in ('1', 'true', 'True') else name
                    return self._send_json(vpn_run(['set-auth', tgt, au_user, au_pass]))
                if action == 'down':
                    return self._send_json(vpn_run(['down', name]))
                if action == 'del':
                    return self._send_json(vpn_run(['del', name]))
                if action in ('autostart_on', 'autostart_off'):
                    return self._send_json(vpn_run(['autostart', name, 'on' if action == 'autostart_on' else 'off']))
                if action == 'assign':
                    if not re.match('^\\d{1,3}(\\.\\d{1,3}){3}$', ipaddr):
                        return self._send_json({'ok': False, 'error': 'IP khong hop le'})
                    r = vpn_run(['assign', name, ipaddr])
                    if r.get('ok'):
                        _record_vpn_declaration(ipaddr, name)
                    return self._send_json(r)
                if action == 'unassign':
                    if not re.match('^\\d{1,3}(\\.\\d{1,3}){3}$', ipaddr):
                        return self._send_json({'ok': False, 'error': 'IP khong hop le'})
                    r = vpn_run(['unassign', ipaddr])
                    if r.get('ok'):
                        _record_vpn_declaration(ipaddr, '')
                    return self._send_json(r)
                if action == 'assign-bulk':
                    # Gan NHIEU may 1 request: tranh N request HTTP + N lan guard.
                    raw = payload.get('ips') or []
                    if not isinstance(raw, list):
                        return self._send_json({'ok': False, 'error': 'ips phai la mang'})
                    ips, bad = ([], [])
                    for x in raw:
                        s = str(x).strip()
                        if re.match('^\\d{1,3}(\\.\\d{1,3}){3}$', s):
                            if s not in ips:
                                ips.append(s)
                        elif s:
                            bad.append(s)
                    if not ips:
                        return self._send_json({'ok': False, 'error': 'khong co IP hop le', 'invalid': bad})
                    r = vpn_run(['assign-many', name] + ips, timeout=max(120, 3 * len(ips)))
                    if r.get('ok'):
                        _record_vpn_declaration_bulk([(s, name) for s in ips])
                    r['count'] = len(ips)
                    if bad:
                        r['invalid'] = bad
                    return self._send_json(r)
                if action == 'unassign-bulk':
                    raw = payload.get('ips') or []
                    if not isinstance(raw, list):
                        return self._send_json({'ok': False, 'error': 'ips phai la mang'})
                    ips = []
                    for x in raw:
                        s = str(x).strip()
                        if re.match('^\\d{1,3}(\\.\\d{1,3}){3}$', s) and s not in ips:
                            ips.append(s)
                    if not ips:
                        return self._send_json({'ok': False, 'error': 'khong co IP hop le'})
                    r = vpn_run(['unassign-many'] + ips, timeout=max(120, 3 * len(ips)))
                    if r.get('ok'):
                        _record_vpn_declaration_bulk([(s, '') for s in ips])
                    r['count'] = len(ips)
                    return self._send_json(r)
                if action == 'add-distinct':
                    return self._send_json(vpn_distinct_start(payload))
                if action == 'distinct-status':
                    return self._send_json(vpn_distinct_status(str(payload.get('job', ''))))
                if action == 'express-servers':
                    loc = str(payload.get('loc', '')).strip().lower()
                    return self._send_json(vpn_express_servers(loc))
                if action == 'add-express-many':
                    # [Ver 2.94] tao N tunnel, moi tunnel ghim 1 server IP khac nhau (giong MiniSocks)
                    loc = str(payload.get('loc', '')).strip()
                    n = max(1, min(32, int(payload.get('count') or 1)))
                    proto = 'tcp' if str(payload.get('proto')) == 'tcp' else 'udp'
                    do_up = str(payload.get('up', '1')) in ('1', 'true', 'True')
                    cred = xv_cred_get(str(payload.get('cred_id', ''))) if payload.get('cred_id') else None
                    if not cred:
                        return self._send_json({'ok': False, 'error': 'chon tai khoan da luu'})
                    srv = vpn_express_servers(loc, fetch=True)
                    ips = [x for g in srv.get('groups') or [] for x in g.get('ips') or []]
                    used = set(srv.get('used') or [])
                    free = [x for x in ips if x not in used] or ips
                    if not free:
                        return self._send_json({'ok': False, 'error': 'khong phan giai duoc server nao cho location nay'})
                    exist = {a['name'] for a in vpn_status_json()}
                    made, i = [], 1
                    for _ in range(n):
                        while ('xv-%d' % i) in exist:
                            i += 1
                        name = 'xv-%d' % i
                        ip = free[i % len(free)] if len(free) < n else free[i % len(free)]
                        r = vpn_run(['add-express', name, ip, str(cred['user']), str(cred.get('pass', '')), proto, str(cred.get('key', ''))], timeout=120)
                        if not r.get('ok'):
                            made.append({'name': name, 'ip': ip, 'ok': False, 'error': str(r.get('error') or r.get('output'))[:120]})
                            i += 1
                            continue
                        exist.add(name)
                        made.append({'name': name, 'ip': ip, 'ok': True})
                        i += 1
                    if do_up:
                        for m in made:
                            if m.get('ok'):
                                m['up'] = bool(vpn_run(['up', m['name']], timeout=150).get('ok'))
                        threading.Timer(15, vpn_refresh_exitips_async).start()
                    return self._send_json({'ok': True, 'made': made, 'creds': xv_creds_public()})
                if action == 'auto-save':
                    try:
                        vpn_auto_set(payload)
                    except ValueError as e:
                        return self._send_json({'ok': False, 'error': 'dai IP loi: %s' % e})
                    threading.Thread(target=vpn_auto_tick, daemon=True).start()
                    return self._send_json(vpn_auto_public())
                if action == 'auto-run':
                    vpn_auto_tick()
                    return self._send_json(vpn_auto_public())
                if action == 'xv-creds-save':
                    items = []
                    for ln in str(payload.get('text', '') or '').splitlines():
                        p = ln.strip().split('|')
                        if len(p) >= 2:
                            items.append((p[0], p[1], p[2] if len(p) > 2 else ''))
                    n = xv_creds_save(items)
                    return self._send_json({'ok': n > 0, 'saved': n, 'creds': xv_creds_public(), 'error': '' if n else 'khong co dong user|pass hop le'})
                if action == 'xv-creds-del':
                    n = xv_creds_del(str(payload.get('id', '')))
                    return self._send_json({'ok': n > 0, 'creds': xv_creds_public()})
                if action == 'add-express':
                    host = str(payload.get('host', '')).strip()
                    user = str(payload.get('username', '')).strip()
                    pwd = str(payload.get('password', ''))
                    cred = xv_cred_get(str(payload.get('cred_id', ''))) if payload.get('cred_id') else None
                    if payload.get('cred_id') and not cred:
                        return self._send_json({'ok': False, 'error': 'tai khoan da luu khong con'})
                    if cred:
                        user, pwd = str(cred['user']), str(cred.get('pass', ''))
                        payload['key'] = cred.get('key', '')
                    if not host or not user:
                        return self._send_json({'ok': False, 'error': 'thieu host/username'})
                    if not re.match(r'^[a-z0-9.-]{3,120}$', host.lower()):
                        return self._send_json({'ok': False, 'error': 'host khong hop le'})
                    proto = 'tcp' if str(payload.get('proto', '')).lower() == 'tcp' else 'udp'
                    xkey = re.sub(r'[^A-Za-z0-9_-]', '', str(payload.get('key', '')))[:64]
                    r = vpn_run(['add-express', name, host.lower(), user, pwd, proto] + ([xkey] if xkey else []))
                    if r.get('ok') and str(payload.get('autostart', '')) in ('1', 'true', 'True'):
                        vpn_run(['autostart', name, 'on'])
                    if r.get('ok') and str(payload.get('up', '')) in ('1', 'true', 'True'):
                        r['up'] = vpn_run(['up', name])
                        threading.Timer(12, vpn_refresh_exitips_async).start()
                    if r.get('ok') and not cred:
                        xv_creds_save([(user, pwd, xkey)])  # luu lai de lan sau chon
                    r['creds'] = xv_creds_public()
                    return self._send_json(r)
                if action == 'ping-host':
                    host = str(payload.get('host', '')).strip().lower()
                    if not re.match(r'^[a-z0-9.-]{3,120}$', host):
                        return self._send_json({'ok': False, 'error': 'host khong hop le'})
                    return self._send_json(vpn_ping_host(host))
                if action == 'add-openvpn':
                    ovpn_text = str(payload.get('ovpn_text', '') or '')
                    user = str(payload.get('username', '')).strip()
                    pwd = str(payload.get('password', ''))
                    if len(ovpn_text) < 50:
                        return self._send_json({'ok': False, 'error': 'thieu noi dung file .ovpn'})
                    return self._send_json(vpn_add_openvpn_text(name, ovpn_text, user, pwd))
                if action == 'add-wg':
                    wg_text = str(payload.get('wg_text', '') or '')
                    if '[Interface]' not in wg_text or 'PrivateKey' not in wg_text:
                        return self._send_json({'ok': False, 'error': 'file khong dung dinh dang WireGuard (thieu [Interface]/PrivateKey)'})
                    return self._send_json(vpn_add_wg_text(name, wg_text))
                if action == 'test-exitip':
                    return self._send_json(vpn_exit_ip(name))
                if action == 'refresh-exitips':
                    started = vpn_refresh_exitips_async()
                    return self._send_json({'ok': True, 'started': started})
                return self._send_json({'ok': False, 'error': f'action khong ho tro: {action}'})
            return self._send_json({'error': 'Not found'}, 404)
        except urllib.error.HTTPError as e:
            # [Ver 2.83] Giu ly do that cua server goc 9000 (truoc day chi con 'HTTP 400',
            # vd mat 'Invalid body' / 'you must enable pppoe mode').
            return self._send_json({'ok': False, 'error': _http_error_text(e)}, 400)
        except Exception as e:
            return self._send_json({'error': str(e)}, 400)
# Ver 2.47 — chot V2-c: cac file config "ngu dong" trong /etc/genrouter/config.
# VI SAO: /etc/genrouter/config/gencore2.json (sinh 2026-08-26) con nguyen
# 311 DNS server 'tcp://8.8.8.8' (port 53 — Lumi CHAN), dnsmasq KHONG co
# 'detour', dns.rules chi co 1 rule catch-all {'outbound':'any','server':'google'},
# route.rules[-1] la {'action':'route','outbound':'direct'} (khong phai
# reject/drop). Tuc la mot ban sao day du cua DUNG cai cau hinh da gay su co
# 2026-09-03 va 2026-09-05, nam san trong thu muc ma binary vendor
# /etc/genrouter/server:9000 lam chu. Hien khong file/script/binary nao tham
# chieu no (do 2026-09-05: grep repo+/etc+strings vendor = 0), nen truoc day
# ket luan "de yen". Su co 19:31 chung minh gia dinh do khong an toan: vendor
# CO san template port 53 o dau do va da dung. De mot ban config sai san trong
# thu muc cua vendor la de moi tai nhiem — tu chua no cho dong nhat, chi phi 0.
DORMANT_CFG_CACHE = {}

def _dormant_config_paths():
    out = []
    try:
        for p in sorted(Path(CONFIG_DIR).glob('gencore*.json')):
            if str(p) in (str(RUNTIME_SOURCE_FILE), str(RUNTIME_FILE)):
                continue
            if p.is_file() and p.stat().st_size > 0:
                out.append(p)
    except Exception:
        pass
    return out

def heal_dormant_configs(reason='startup'):
    """Tu chua cac ban config ngu dong. KHONG restart gencore (chung khong duoc nap).

    Cache theo (mtime, size) de khong parse lai file 135 KB moi vong watchdog;
    file bi ghi lai (vendor tao lai) thi mtime doi => tu kiem lai ngay.
    Tra ve tong so entry da sua.
    """
    total = 0
    for p in _dormant_config_paths():
        try:
            st = p.stat()
            key = f'{st.st_mtime_ns}:{st.st_size}'
        except OSError:
            continue
        if DORMANT_CFG_CACHE.get(str(p)) == key:
            continue
        try:
            n = migrate_proxy_dns_file(p)
        except Exception as e:
            _wd_log(f'DORMANT-HEAL {p.name} loi: {e}')
            continue
        if n:
            total += n
            _wd_log(f'DORMANT-HEAL ({reason}) {p.name}: sua {n} entry (moi tai nhiem: DNS port 53 / thieu detour / thieu deny-last)')
            try:
                _ss_log(f'DORMANT-HEAL ({reason}) {p.name}: sua {n} entry')
            except Exception:
                pass
        try:
            st = p.stat()
            DORMANT_CFG_CACHE[str(p)] = f'{st.st_mtime_ns}:{st.st_size}'
        except OSError:
            pass
    return total

def startup_migrate_proxy_dns():
    """Chay 1 lan khi app start: tu chua config cu con dung DNS port 53.

    Neu co thay doi thi restart gencore de config moi co hieu luc, vi neu
    khong client se tiep tuc khong resolve duoc DNS.
    """
    total = 0
    for path in (RUNTIME_SOURCE_FILE, RUNTIME_FILE):
        try:
            total += migrate_proxy_dns_file(path)
        except Exception:
            pass
    for path in SESSION_FILES.values():
        try:
            total += migrate_proxy_dns_file(path)
        except Exception:
            pass
    # Ver 2.47: file ngu dong dem RIENG — sua chung khong can restart gencore.
    try:
        heal_dormant_configs(reason='startup')
    except Exception:
        pass
    if total:
        try:
            _wd_log(f'STARTUP MIGRATE: doi {total} DNS server proxy_* sang {PROXY_DNS_ADDRESS} (port 53 bi proxy chan)')
        except Exception:
            pass
        try:
            gencore_restart_detached('dns_doh_migrate')
        except Exception:
            pass
    return total

if __name__ == '__main__':
    _ss_cleanup_stale_tmp()
    ensure_sessions_exist()
    migrate_promoted_289()
    startup_migrate_proxy_dns()
    ensure_vpn_mgr()
    ensure_vpn_guard()
    ensure_etc_installed()
    ensure_vpn_deps_async()
    _ss_seed_backups()
    ensure_wan_port_not_bridged()
    ensure_lan_syn_bypass()
    threading.Thread(target=license_check_loop, daemon=True).start()
    threading.Thread(target=collector_push_loop, daemon=True).start()
    threading.Thread(target=gencore_watchdog_loop, daemon=True).start()
    threading.Thread(target=split_watch_loop, daemon=True, name='split-watch').start()
    conn_migrate_once()
    threading.Thread(target=conn_watch_loop, daemon=True, name='conn-watch').start()
    threading.Thread(target=exitip_watch_loop, daemon=True, name='exitip-watch').start()
    threading.Thread(target=vpn_auto_loop, daemon=True, name='vpn-auto').start()
    threading.Thread(target=vpn_map_sweep_loop, daemon=True, name='vpn-sweep').start()
    threading.Thread(target=pppoe_glider_stale_loop, daemon=True, name='glider-stale').start()
    class _GUIServer(ThreadingHTTPServer):
        # [Ver 2.63] Backlog mac dinh cua socketserver la 5. Khi GUI go dong thoi
        # nhieu request (bảng + /api/pppoe/list + /api/vpn/status + badge), SYN
        # bi drop va trinh duyet bao 'Failed to fetch'. Tăng backlog len 128.
        request_queue_size = 128
    _GUIServer(('0.0.0.0', 9001), Handler).serve_forever()