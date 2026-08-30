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
        with urllib.request.urlopen(req, timeout=60) as resp:
            archive_path.write_bytes(resp.read())
        shutil.unpack_archive(str(archive_path), str(tmp_root), 'gztar')
        if not extract_dir.exists():
            raise RuntimeError('Không giải nén được gói update')
        if latest_label:
            version_text = latest_label if not latest_short else f'{latest_label} ({latest_short})'
            (extract_dir / 'VERSION.txt').write_text(version_text + '\n', encoding='utf-8')
        for item in extract_dir.iterdir():
            target = BASE_DIR / item.name
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
        shutil.rmtree(tmp_root, ignore_errors=True)
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
        save_json(base_file, load_json(RUNTIME_SOURCE_FILE))
    create_default_second = not SESSION_STATE_FILE.exists()
    for session_id, path in SESSION_FILES.items():
        if session_id == '1':
            continue
        if create_default_second and (not path.exists()) and (session_id == '2'):
            data = load_json(base_file)
            clear_session_proxies(data)
            save_json(path, data)
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
    save_json(SESSION_FILES[session_id], load_json(source_file))
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

def save_json(path: Path, data):
    _ss_atomic_write(Path(path), json.dumps(data, ensure_ascii=False, indent=2) + '\n')

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
    return device_map

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
        if tag and ob_type == 'direct':
            vpn_acc = str((meta or {}).get('vpn_account', '') or '').strip() or vpn_map.get(ip, '')
            proxy_val, ptype = ('vpn:' + vpn_acc if vpn_acc else 'vpn:', 'vpn')
        else:
            proxy_val, ptype = (format_proxy(outbound), format_proxy_type(outbound))
        rows.append({'machine': machine, 'ip': ip, 'tag': tag, 'proxy': proxy_val, 'proxyType': ptype, 'mac': normalize_mac(static_mac_by_ip.get(ip, '') or dev.get('mac', '')), 'status': str(dev.get('status', 'offline')).strip() or 'offline', 'note': str(meta.get('note', '')).strip(), 'configured': True})
    for ip, dev in sorted(devices.items(), key=lambda kv: kv[0]):
        ip = str(ip).strip()
        if not ip or ip in configured_ips:
            continue
        tag = ''
        machine = ''
        meta = {}
        outbound = {}
        vpn_acc = vpn_map.get(ip, '')
        rows.append({'machine': machine, 'ip': ip, 'tag': tag, 'proxy': 'vpn:' + vpn_acc if vpn_acc else format_proxy(outbound), 'proxyType': 'vpn' if vpn_acc else 'socks5', 'mac': normalize_mac(static_mac_by_ip.get(ip, '') or dev.get('mac', '')), 'status': str(dev.get('status', 'offline')).strip() or 'offline', 'note': str(meta.get('note', '')).strip(), 'configured': False})
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
    if changed:
        try:
            save_json(path, data)
        except Exception:
            return 0
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
        if ptype_norm == 'vpn' or str(proxy).startswith('vpn:'):
            vpn_acc_row = str(proxy).split(':', 1)[1].strip() if ':' in str(proxy) else ''
        touched_rows.append({'tag': tag, 'mac': row.get('mac', ''), 'note': row.get('note', ''), 'vpn_account': vpn_acc_row})
    update_session_rows_meta(session, touched_rows)
    return data

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
    dns_rules = [rule for rule in old_dns_rules if not (str(rule.get('action', '')).strip() == 'route' and str(rule.get('server', '')).strip().startswith('proxy_'))]
    if not dns_rules:
        dns_rules = [{'outbound': 'any', 'server': 'google'}]
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
    route_rules.append({'action': 'route', 'outbound': 'block'})
    rebuilt_outbounds = list(non_proxy_outbounds)
    for tag, _ip in ordered_items:
        rebuilt_outbounds.append(old_outbound_map.get(tag, {'tag': tag, 'type': 'block'}))
    dns['rules'] = dns_rules
    dns['servers'] = dns_servers
    route['rules'] = route_rules
    data['outbounds'] = rebuilt_outbounds
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
            save_json(SESSION_FILES[sid], data)
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
            save_json(SESSION_FILES[sid], data)
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

def apply_ip_identity_config(data, text, session='1'):
    rows = parse_ip_identity_text(text)
    tag_to_ip_map = {row['tag']: row['ip'] for row in rows}
    rebuild_gencore_rules(data, tag_to_ip_map)
    return data

def build_old_gui_update_proxy_payload_from_rows(rows):
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
        try:
            server, port, username, password = parse_proxy(proxy)
            item = {'type': 'http' if proxy_type == 'http' else 'socks5', 'server': server, 'port': int(port)}
            if username or password:
                item['username'] = username
                item['password'] = password
            payload[ip] = item
        except Exception:
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
        if saved_text:
            stale_ips = [ip for ip in sorted(current) if ip not in desired_ips]
            if stale_ips:
                bak = _backup_vpn_map(f'apply session {session_id}: sap bo gan {len(stale_ips)}/{len(current)} may')
                if bak:
                    summary['map_backup'] = str(bak)
                r = vpn_run(['unassign-many'] + stale_ips, timeout=max(120, 3 * len(stale_ips)))
                ok = bool(r.get('ok'))
                summary['unassigned'] = [{'ip': ip, 'ok': ok} for ip in stale_ips]
            todo = {}
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

def run_apply(session: str, rows_override=None):
    preset_source = SESSION_FILES[session]
    results = []
    preset_data = load_json(preset_source)
    if str(preset_source) != str(RUNTIME_SOURCE_FILE):
        save_json(RUNTIME_SOURCE_FILE, preset_data)
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
        save_json(preset_source, runtime_data)
        save_json(RUNTIME_SOURCE_FILE, runtime_data)
        results.append({'cmd': 'save posted proxy assignments to preset and gencore runtime source', 'ok': True, 'source': str(preset_source), 'target': str(RUNTIME_SOURCE_FILE), 'count': len(rows_by_tag)})
    else:
        runtime_data = load_json(RUNTIME_SOURCE_FILE)
    dns_migrated = migrate_proxy_dns_servers(runtime_data)
    if dns_migrated:
        save_json(RUNTIME_SOURCE_FILE, runtime_data)
        results.append({'cmd': 'migrate proxy DNS servers to DoH 443', 'ok': True, 'target': str(RUNTIME_SOURCE_FILE), 'count': dns_migrated})
    rows = extract_rows(runtime_data, session=session)
    payload = build_old_gui_update_proxy_payload_from_rows(rows)
    try:
        resp = call_old_gui('/api/update_proxy', method='POST', data=payload)
        results.append({'cmd': 'POST old GUI /api/update_proxy', 'ok': True, 'source': str(RUNTIME_SOURCE_FILE), 'count': len(payload), 'response': resp.get('data') if isinstance(resp, dict) else resp})
    except Exception as e:
        results.append({'cmd': 'POST old GUI /api/update_proxy', 'ok': False, 'source': str(RUNTIME_SOURCE_FILE), 'count': len(payload), 'error': str(e)})
    if str(RUNTIME_FILE) != str(RUNTIME_SOURCE_FILE):
        save_json(RUNTIME_FILE, load_json(RUNTIME_SOURCE_FILE))
        results.append({'cmd': 'sync runtime file copy only', 'ok': True, 'source': str(RUNTIME_SOURCE_FILE), 'target': str(RUNTIME_FILE)})
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

def check_proxy(proxy: str, session='1'):
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
        return {'ok': True, 'status': 'live', 'message': 'LIVE', 'ip': public_ip, 'public_ip': public_ip, 'duplicates': duplicates}
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
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_proxy, proxy, session): tag for tag, proxy in jobs}
        for fut in as_completed(futs):
            tag = futs[fut]
            try:
                results[tag] = fut.result()
            except Exception as e:
                results[tag] = {'ok': False, 'status': 'dead', 'message': 'DEAD', 'error': str(e)}
    return results

def call_old_gui(path, method='GET', data=None):
    body = None
    headers = {}
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
    Moi router tu lai ngay sau update/restart, khong phu thuoc deploy tay. Tra True neu engine san sang."""
    try:
        Path('/data/vpn').mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    dst = Path(VPN_MGR)
    src = BASE_DIR / 'tools' / 'vpn_mgr.sh'
    try:
        if src.exists() and (not dst.exists() or dst.stat().st_size != src.stat().st_size):
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

def vpn_exit_ip(name):
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
    return {'ok': True, 'exit_ip': ip_out, 'local_tunnel_ip': lip, 'dev': dev}
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
WD_STATE = {'hits': 0, 'last_restart': 0.0, 'last_start': 0.0, 'snap': ''}
WD_ZOMBIE_PORT = '5888'

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
    thr = {'zombie_tw': 5000, 'ct_total': 40000, 'consecutive': 2, 'cooldown_sec': 600}
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

def _gencore_pid():
    try:
        r = subprocess.run(['pidof', 'gencore'], capture_output=True, text=True, timeout=8)
        return (r.stdout or '').strip()
    except Exception:
        return ''

def gencore_start_detached(reason='manual'):
    if not Path('/usr/bin/gencore').exists():
        return
    try:
        subprocess.Popen(['sh', '-c', '( /usr/bin/gencore run -c /etc/genrouter/gencore.json >/tmp/gencore_run.log 2>&1 </dev/null & )'], start_new_session=True)
        _wd_log(f'START gencore reason={reason}')
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

def gencore_watchdog_loop():
    _wd_log('WATCHDOG start (Ver 2.17)')
    time.sleep(25)
    try:
        wd_boot_recover()
    except Exception:
        pass
    while True:
        try:
            time.sleep(60)
            thr = _wd_thresholds()
            cnt = _wd_conntrack_counts()
            if cnt is None:
                continue
            tw, total = cnt
            pid = _gencore_pid()
            now = time.time()
            if not pid:
                if not Path('/usr/bin/gencore').exists():
                    continue
                if now - WD_STATE.get('last_start', 0) >= 180:
                    WD_STATE['last_start'] = now
                    WD_STATE['restarts'] = WD_STATE.get('restarts', 0) + 1
                    gencore_start_detached('dead')
                continue
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
        if path == '/api/pm/sessions':
            include_hidden = 'include_hidden=1' in (urlparse(self.path).query or '')
            return self._send_json({'ok': True, 'sessions': get_available_sessions(include_hidden=include_hidden), 'max_sessions': MAX_SESSION_COUNT})
        if path.startswith('/api/pm/sessions/'):
            session_id = path.rsplit('/', 1)[-1]
            if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                return self._send_json({'session': session_id, 'name': get_session_display_name(session_id), 'source': str(SESSION_FILES[session_id]), 'rows': extract_rows(load_json(SESSION_FILES[session_id]), session=session_id)})
        if path == '/api/pm/router-network':
            probes = [('https://api.ipify.org', 'wan_ip'), ('https://ifconfig.me/ip', 'wan_ip')]
            errors = []
            for url, field in probes:
                try:
                    probe = urllib.request.Request(url, headers={'User-Agent': 'pm-network-check'})
                    with urllib.request.urlopen(probe, timeout=8) as resp:
                        value = resp.read().decode('utf-8', 'replace').strip()
                    if value:
                        return self._send_json({'ok': True, 'connected': True, field: value, 'probe': url})
                except Exception as e:
                    errors.append(f'{url}: {e}')
            try:
                ping = subprocess.run(['ping', '-c', '1', '1.1.1.1'], capture_output=True, text=True, timeout=10)
                if ping.returncode == 0:
                    return self._send_json({'ok': True, 'connected': True, 'probe': 'ping'})
            except Exception as e:
                errors.append(f'ping: {e}')
            return self._send_json({'ok': False, 'connected': False, 'error': ' | '.join(errors)})
        if path == '/api/pm/router-info':
            return self._send_json(call_old_gui('/api/router/info'))
        if path == '/api/pm/meta':
            version_info = get_repo_version_info()
            active_session = ''
            try:
                active_session = str((json.loads(ACTIVE_SESSION_FILE.read_text(encoding='utf-8')) or {}).get('active', '') or '')
            except (OSError, ValueError):
                pass
            return self._send_json({'ok': True, 'app_title_prefix': get_app_title_prefix(), 'version': version_info, 'active_session': active_session})
        if path == '/vpn':
            return self._send_file(STATIC_DIR / 'vpn.html')
        if path == '/api/vpn/status':
            return self._send_json({'ok': True, 'accounts': vpn_status_json(), 'machine_map': vpn_machine_map(), 'deps': vpn_deps_status()})
        if path == '/api/vpn/exitips':
            return self._send_json({'ok': True, 'ips': dict(_EXITIPS), 'busy': _EXITIPS_BUSY['v']})
        if path == '/api/vpn/express-hosts':
            hosts = []
            try:
                with open(VPN_HOSTS_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    hosts = [ln.strip() for ln in f if ln.strip()]
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
                    rows_by_tag = {str(row['tag']).strip(): row for row in rows if row.get('tag')}
                    data = load_json(SESSION_FILES[session_id])
                    save_json(SESSION_FILES[session_id], apply_rows_to_data(data, rows_by_tag, session=session_id))
                    name = payload.get('name')
                    if name is not None:
                        name = set_session_display_name(session_id, name)
                    else:
                        name = get_session_display_name(session_id)
                    try:
                        spawn_proxy_sheet_push()
                    except Exception:
                        pass
                    return self._send_json({'ok': True, 'session': session_id, 'name': name})
            if path.startswith('/api/pm/apply/'):
                session_id = path.rsplit('/', 1)[-1]
                if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                    rows_override = payload.get('rows') if isinstance(payload, dict) else None
                    results = run_apply(session_id, rows_override=rows_override)
                    try:
                        ACTIVE_SESSION_FILE.write_text(json.dumps({'active': str(session_id)}), encoding='utf-8')
                    except OSError:
                        pass
                    return self._send_json({'ok': True, 'applied': session_id, 'results': results})
            if path == '/api/pm/clone/1-to-2':
                save_json(SESSION_FILES['2'], load_json(SESSION_FILES['1']))
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
                    save_json(SESSION_FILES[session_id], remap_ip_by_tag(data))
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
                        save_json(session_file, data)
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
            if path == '/api/vpn/action':
                action = str(payload.get('action', '')).strip()
                name = str(payload.get('name', '')).strip()
                ipaddr = str(payload.get('ip', '')).strip()
                if action not in ('unassign', 'refresh-exitips', 'unassign-bulk') and (not re.match('^[A-Za-z0-9_.-]{1,64}$', name)):
                    return self._send_json({'ok': False, 'error': 'ten tai khoan khong hop le'})
                if action == 'up':
                    return self._send_json(vpn_run(['up', name]))
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
                if action == 'add-express':
                    host = str(payload.get('host', '')).strip()
                    user = str(payload.get('username', '')).strip()
                    pwd = str(payload.get('password', ''))
                    if not host or not user:
                        return self._send_json({'ok': False, 'error': 'thieu host/username'})
                    return self._send_json(vpn_run(['add-express', name, host, user, pwd]))
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
            return self._send_json({'ok': False, 'error': f'HTTP {e.code}'}, 400)
        except Exception as e:
            return self._send_json({'error': str(e)}, 400)
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
    startup_migrate_proxy_dns()
    ensure_vpn_mgr()
    ensure_vpn_guard()
    ensure_vpn_deps_async()
    _ss_seed_backups()
    threading.Thread(target=license_check_loop, daemon=True).start()
    threading.Thread(target=collector_push_loop, daemon=True).start()
    threading.Thread(target=gencore_watchdog_loop, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 9001), Handler).serve_forever()