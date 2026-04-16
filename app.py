from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, unquote
import mimetypes
import json
import shutil
import subprocess
import time
import urllib.request
import urllib.error
import socket
import struct

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'
NOTES_FILE = BASE_DIR / 'notes.json'
SESSION_STATE_FILE = BASE_DIR / 'session_state.json'

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
XXTOUCH_WEB_DIR = STATIC_DIR / 'xxtouch'
XXTOUCH_WORK_DIR = BASE_DIR / 'xxtouch_jobs'
XXTOUCH_DATA_DIR = XXTOUCH_WORK_DIR / 'data'
XXTOUCH_LOG_DIR = XXTOUCH_WORK_DIR / 'log'
XXTOUCH_TMP_DIR = XXTOUCH_WORK_DIR / 'tmp'
MAX_SESSION_COUNT = 5
SESSION_FILES = {
    str(i): PRESET_DIR / f'session{i}.json'
    for i in range(1, MAX_SESSION_COUNT + 1)
}
RUNTIME_FILE = RUNTIME_DIR / 'gencore.json'
RUNTIME_SOURCE_FILE = CONFIG_DIR / 'gencore.json'
MAX_PROXY_TAG = 1000
TAGS_PER_SUBNET = 250
BASE_SUBNET_OCTET = 4


def proxy_tag_num(tag):
    try:
        return int(str(tag).split('_', 1)[1])
    except Exception:
        return 10**9


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
    host_octet = ((num - 1) % TAGS_PER_SUBNET) + 1
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
        if create_default_second and not path.exists() and session_id == '2':
            data = load_json(base_file)
            clear_session_proxies(data)
            save_json(path, data)
        if not get_saved_ip_identity_text(session_id) and path.exists():
            data = load_json(path)
            rows = build_ip_identity_rows_from_data(data)
            if rows and len(rows) < MAX_PROXY_TAG:
                set_saved_ip_identity_text(session_id, '\n'.join(f"{row['tag']}|{row['ip']}" for row in rows))


def ensure_xxtouch_workspace():
    for path in (XXTOUCH_WORK_DIR, XXTOUCH_DATA_DIR, XXTOUCH_LOG_DIR, XXTOUCH_TMP_DIR):
        path.mkdir(parents=True, exist_ok=True)


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
    return {
        'session': session_id,
        'name': get_session_display_name(session_id),
        'source': str(SESSION_FILES[session_id]),
    }


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
        if path.exists() and not is_session_hidden(session_id, state):
            items.append(str(session_id))
    items.sort(key=lambda x: int(x))
    return items


def set_session_hidden(session_id, hidden=True):
    session_id = str(session_id)
    if session_id == '1':
        raise ValueError('Không thể ẩn cấu hình 1')
    state = load_session_state()
    visible_ids = get_visible_session_ids(state)
    if hidden and session_id in visible_ids and len(visible_ids) <= 1:
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
            if hidden and not include_hidden:
                continue
            items.append({
                'session': session_id,
                'name': get_session_display_name(session_id),
                'source': str(path),
                'exists': True,
                'hidden': hidden,
                'can_hide': session_id != '1',
                'can_delete': session_id != '1',
                'is_default': session_id in ('1', '2'),
            })
    items.sort(key=lambda x: int(x['session']))
    return items

def load_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


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
        return {}
    try:
        return load_json(SESSION_STATE_FILE)
    except Exception:
        return {}


def save_session_state(state):
    save_json(SESSION_STATE_FILE, state)


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
                normalized[nk] = v
        return normalized
    key = normalize_tag(tag)
    item = sess.get(key, sess.get(str(tag), sess.get(str(tag).upper(), {})))
    return item if isinstance(item, dict) else {}


def get_meta_section(state=None):
    state = state if isinstance(state, dict) else load_session_state()
    meta = state.get('__meta__', {}) if isinstance(state, dict) else {}
    if not isinstance(meta, dict):
        meta = {}
        state['__meta__'] = meta
    return state, meta


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


def update_session_rows_meta(session_id, rows):
    session_id = str(session_id)
    state = load_session_state()
    sess = state.setdefault(session_id, {})
    for row in rows or []:
        tag = normalize_tag((row or {}).get('tag', ''))
        if not tag:
            continue
        item = sess.setdefault(tag, {})
        if 'note' in row:
            item['note'] = str(row.get('note', '')).strip()
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
            rows.append({
                'key': str(key),
                'ip': str(val.get('ip', '')).strip(),
                'mac': normalize_mac(val.get('mac', '')),
            })
    elif isinstance(data, list):
        for i, val in enumerate(data, 1):
            if not isinstance(val, dict):
                continue
            rows.append({
                'key': str(val.get('key') or i),
                'ip': str(val.get('ip', '')).strip(),
                'mac': normalize_mac(val.get('mac', '')),
            })
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
        device_map[ip] = {
            'mac': normalize_mac(row.get('mac', '')),
            'status': 'offline'
        }

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
        if tag.startswith('proxy_') and ip and tag not in mapping:
            mapping[tag] = ip
    for rule in data.get('dns', {}).get('rules', []):
        if str(rule.get('action', '')).strip() != 'route':
            continue
        tag = str(rule.get('server', '')).strip()
        ip = str(rule.get('source_ip_cidr', '')).strip()
        if tag.startswith('proxy_') and ip and tag not in mapping:
            mapping[tag] = ip
    return mapping


def build_ip_identity_rows_from_data(data):
    mapping = build_tag_to_ip(data)
    rows = [
        {'tag': str(tag).strip(), 'ip': str(ip).strip()}
        for tag, ip in sorted(mapping.items(), key=lambda kv: proxy_tag_num(kv[0]))
        if str(tag).strip().startswith('proxy_') and str(ip).strip()
    ]
    return rows


def looks_like_default_full_mapping(data):
    rows = build_ip_identity_rows_from_data(data)
    if len(rows) < MAX_PROXY_TAG:
        return False
    first = rows[:3]
    if not first:
        return False
    expected = [
        ('proxy_1', '192.15.4.1'),
        ('proxy_2', '192.15.4.2'),
        ('proxy_3', '192.15.4.3'),
    ]
    return [(r.get('tag'), r.get('ip')) for r in first] == expected


def format_proxy(outbound):
    server = str(outbound.get('server', '')).strip()
    port = outbound.get('server_port')
    user = str(outbound.get('username', '')).strip()
    password = str(outbound.get('password', '')).strip()
    if not server or not port:
        return ''
    return f"{server}:{port}:{user}:{password}"


def extract_rows(data, session='1'):
    outbounds = {
        str(item.get('tag')): item
        for item in data.get('outbounds', [])
        if str(item.get('tag', '')).startswith('proxy_')
    }
    static_mac_by_ip = {
        str(row.get('ip', '')).strip(): normalize_mac(row.get('mac', ''))
        for row in load_static_hosts_raw()
        if str(row.get('ip', '')).strip()
    }
    devices = load_device_map()
    route_by_ip = {str(ip).strip(): normalize_tag(tag) for ip, tag in build_route_ip_to_tag(data).items() if str(ip).strip()}
    session_meta = get_session_meta(session)
    saved_text = get_saved_ip_identity_text(session)
    configured_rows = parse_ip_identity_text(saved_text) if saved_text else []
    saved_ip_to_tag = {
        str(item.get('ip', '')).strip(): normalize_tag(item.get('tag', ''))
        for item in configured_rows
        if str(item.get('ip', '')).strip()
    }

    rows = []
    configured_ips = set()

    for item in configured_rows:
        ip = str(item.get('ip', '')).strip()
        tag = normalize_tag(item.get('tag', '')) or route_by_ip.get(ip, '')
        if not ip:
            continue
        configured_ips.add(ip)
        dev = devices.get(ip, {})
        meta = session_meta.get(tag, {}) if isinstance(session_meta, dict) and tag else {}
        outbound = outbounds.get(tag, {}) if tag else {}
        rows.append({
            'ip': ip,
            'tag': tag,
            'proxy': format_proxy(outbound),
            'mac': normalize_mac(static_mac_by_ip.get(ip, '') or dev.get('mac', '')),
            'status': str(dev.get('status', 'offline')).strip() or 'offline',
            'note': str(meta.get('note', '')).strip(),
            'configured': True,
        })

    for ip, dev in sorted(devices.items(), key=lambda kv: kv[0]):
        ip = str(ip).strip()
        if not ip or ip in configured_ips:
            continue
        tag = ''
        meta = {}
        outbound = {}
        rows.append({
            'ip': ip,
            'tag': tag,
            'proxy': format_proxy(outbound),
            'mac': normalize_mac(static_mac_by_ip.get(ip, '') or dev.get('mac', '')),
            'status': str(dev.get('status', 'offline')).strip() or 'offline',
            'note': str(meta.get('note', '')).strip(),
            'configured': False,
        })

    return rows

def apply_rows_to_data(data, rows_by_tag, session='1'):
    outbounds = data.setdefault('outbounds', [])
    outbound_idx = {str(item.get('tag')): i for i, item in enumerate(outbounds) if item.get('tag')}

    touched_rows = []
    for tag, row in rows_by_tag.items():
        proxy = str(row.get('proxy', '')).strip()
        set_outbound_proxy(outbounds, outbound_idx, tag, proxy)
        touched_rows.append({
            'tag': tag,
            'mac': row.get('mac', ''),
            'note': row.get('note', ''),
        })

    update_session_rows_meta(session, touched_rows)
    return data

def set_outbound_proxy(outbounds, outbound_idx, tag, proxy):
    idx = outbound_idx.get(tag)
    if idx is None:
        return
    if not proxy:
        outbounds[idx] = {'tag': tag, 'type': 'direct'}
        return
    server, port, user, password = parse_proxy(proxy)
    outbounds[idx] = {
        'tag': tag,
        'type': 'socks',
        'server': server,
        'server_port': port,
        'username': user,
        'password': password,
        'version': '5'
    }


def parse_proxy(proxy):
    parts = proxy.split(':')
    if len(parts) < 4:
        raise ValueError(f'Proxy không hợp lệ: {proxy}')
    server = parts[0].strip()
    port = int(parts[1].strip())
    user = parts[2].strip()
    password = ':'.join(parts[3:]).strip()
    return server, port, user, password


def clear_session_proxies(data):
    for item in data.get('outbounds', []):
        tag = str(item.get('tag', '')).strip()
        if tag.startswith('proxy_'):
            item.clear()
            item.update({'tag': tag, 'type': 'direct'})


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

    input_map = {
        str(tag).strip(): str(ip).strip()
        for tag, ip in (tag_to_ip_map or {}).items()
        if str(tag).strip().startswith('proxy_') and str(ip).strip()
    }
    ordered_items = sorted(input_map.items(), key=lambda kv: proxy_tag_num(kv[0]))

    old_dns_rules = list(dns.get('rules', []) or [])
    old_dns_servers = list(dns.get('servers', []) or [])
    old_route_rules = list(route.get('rules', []) or [])
    old_outbounds = list(outbounds or [])
    old_outbound_map = {
        str(item.get('tag', '')).strip(): item
        for item in old_outbounds
        if str(item.get('tag', '')).strip().startswith('proxy_')
    }

    dns_rules = [
        rule for rule in old_dns_rules
        if not (str(rule.get('action', '')).strip() == 'route' and str(rule.get('server', '')).strip().startswith('proxy_'))
    ]
    if not dns_rules:
        dns_rules = [{'outbound': 'any', 'server': 'google'}]

    dns_servers = [
        server for server in old_dns_servers
        if not str(server.get('tag', '')).strip().startswith('proxy_')
    ]

    route_rules = [
        rule for rule in old_route_rules
        if not (str(rule.get('action', '')).strip() == 'route' and str(rule.get('outbound', '')).strip().startswith('proxy_'))
    ]
    if not route_rules:
        route_rules = [
            {'action': 'sniff'},
            {'action': 'reject', 'method': 'drop', 'protocol': 'stun'},
            {'action': 'hijack-dns', 'protocol': 'dns'},
            {'action': 'route', 'outbound': 'direct'},
        ]

    non_proxy_outbounds = [
        item for item in old_outbounds
        if not str(item.get('tag', '')).strip().startswith('proxy_')
    ]

    for tag, ip in ordered_items:
        dns_rules.append({'action': 'route', 'server': tag, 'source_ip_cidr': ip})
        dns_servers.append({'address': 'tcp://8.8.8.8', 'detour': tag, 'tag': tag})

    direct_rule = None
    kept_route_rules = []
    for rule in route_rules:
        if str(rule.get('action', '')).strip() == 'route' and str(rule.get('outbound', '')).strip() == 'direct':
            direct_rule = rule
            continue
        kept_route_rules.append(rule)
    route_rules = kept_route_rules

    for tag, ip in ordered_items:
        route_rules.append({'action': 'route', 'outbound': tag, 'source_ip_cidr': ip})

    route_rules.append(direct_rule or {'action': 'route', 'outbound': 'direct'})

    rebuilt_outbounds = list(non_proxy_outbounds)
    for tag, _ip in ordered_items:
        rebuilt_outbounds.append(old_outbound_map.get(tag, {'tag': tag, 'type': 'direct'}))

    dns['rules'] = dns_rules
    dns['servers'] = dns_servers
    route['rules'] = route_rules
    data['outbounds'] = rebuilt_outbounds
    return data


def build_ip_identity_text(data, session='1'):
    mapping = build_tag_to_ip(data)
    items = []
    for tag, ip in mapping.items():
        tag = str(tag).strip()
        ip = str(ip).strip()
        if not tag.startswith('proxy_') or not ip:
            continue
        items.append((proxy_tag_num(tag), f"{tag}|{ip}"))
    items.sort(key=lambda x: x[0])
    return '\n'.join(line for _num, line in items)


def normalize_ip_identity_text(text):
    text = str(text or '').replace('\r\n', '\n').replace('\r', '\n')
    text = __import__('re').sub(r'(?<!\n)(proxy_\d+\|)', r'\n\1', text)
    return text.strip()


def parse_ip_identity_text(text):
    text = normalize_ip_identity_text(text)
    rows = []
    seen_tags = set()
    seen_ips = set()
    dup_tags = set()
    dup_ips = set()

    for raw in str(text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) != 2:
            raise ValueError(f'Dòng không hợp lệ: {line}')
        tag, ip = parts
        if not tag.startswith('proxy_'):
            raise ValueError(f'Tag không hợp lệ: {tag}')
        if not ip:
            raise ValueError(f'IP trống ở dòng: {line}')
        if tag in seen_tags:
            dup_tags.add(tag)
        else:
            seen_tags.add(tag)
        if ip in seen_ips:
            dup_ips.add(ip)
        else:
            seen_ips.add(ip)
        rows.append({'tag': tag, 'ip': ip})

    errs = []
    if dup_tags:
        errs.append('Proxy bị trùng: ' + ', '.join(sorted(dup_tags, key=proxy_tag_num)))
    if dup_ips:
        errs.append('IP bị trùng: ' + ', '.join(sorted(dup_ips)))

    got_tags = {row['tag'] for row in rows}
    extra_tags = sorted([tag for tag in got_tags if proxy_tag_num(tag) > MAX_PROXY_TAG or proxy_tag_num(tag) < 1], key=proxy_tag_num)
    if len(rows) > MAX_PROXY_TAG:
        errs.append(f'Tối đa {MAX_PROXY_TAG} dòng, hiện có {len(rows)} dòng')
    if extra_tags:
        errs.append('Proxy ngoài phạm vi: ' + ', '.join(extra_tags))
    if errs:
        raise ValueError(' | '.join(errs))

    rows.sort(key=lambda x: (proxy_tag_num(x['tag']), x['ip']))
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
        if not ip:
            continue
        if not proxy:
            payload[ip] = 'ALLOW'
            continue
        try:
            server, port, username, password = parse_proxy(proxy)
            item = {'type': 'socks5', 'server': server, 'port': int(port)}
            if username or password:
                item['username'] = username
                item['password'] = password
            payload[ip] = item
        except Exception:
            payload[ip] = 'ALLOW'
    return payload


def run_apply(session: str, rows_override=None):
    preset_source = SESSION_FILES[session]
    results = []

    preset_data = load_json(preset_source)
    if str(preset_source) != str(RUNTIME_SOURCE_FILE):
        save_json(RUNTIME_SOURCE_FILE, preset_data)
        results.append({
            'cmd': 'copy preset to runtime source',
            'ok': True,
            'source': str(preset_source),
            'target': str(RUNTIME_SOURCE_FILE),
        })
    else:
        results.append({
            'cmd': 'copy preset to runtime source',
            'ok': True,
            'source': str(preset_source),
            'target': str(RUNTIME_SOURCE_FILE),
            'skipped': True,
        })

    rows = rows_override if isinstance(rows_override, list) else extract_rows(load_json(RUNTIME_SOURCE_FILE), session=session)
    payload = build_old_gui_update_proxy_payload_from_rows(rows)
    try:
        resp = call_old_gui('/api/update_proxy', method='POST', data=payload)
        results.append({
            'cmd': 'POST /api/update_proxy',
            'ok': True,
            'source': str(RUNTIME_SOURCE_FILE),
            'count': len(payload),
            'response': resp.get('data'),
        })
    except Exception as e:
        results.append({
            'cmd': 'POST /api/update_proxy',
            'ok': False,
            'source': str(RUNTIME_SOURCE_FILE),
            'count': len(payload),
            'error': str(e),
        })
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
    targets = [
        ('1.1.1.1', 80, True),
        ('8.8.8.8', 53, False),
        ('api.ipify.org', 443, False),
        ('ifconfig.me', 443, False),
    ]
    last_error = None
    for host, port, send_http in targets:
        try:
            if socks5_probe(proxy_host, proxy_port, username, password, target_host=host, target_port=port, timeout=timeout, send_http=send_http):
                return True, host, port
        except Exception as e:
            last_error = e
    if last_error:
        raise last_error
    return False, None, None


def get_proxy_public_ip(proxy_host, proxy_port, username, password, timeout=15):
    proxy_url = f'socks5://{username}:{password}@{proxy_host}:{proxy_port}'
    handlers = [
        urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url}),
        urllib.request.HTTPSHandler(context=None),
    ]
    opener = urllib.request.build_opener(*handlers)
    urls = [
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
    ]
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
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode('utf-8', errors='ignore')
        try:
            return {'ok': True, 'data': json.loads(raw) if raw else {}}
        except Exception:
            return {'ok': True, 'data': raw}


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
        call_static_api('/add_static', method='GET', data={
            'ip': ip,
            'mac': mac,
        })


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path, content_type='text/html; charset=utf-8'):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
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
        self.end_headers()
        self.wfile.write(data)

    def _serve_xxtouch(self, request_path: str):
        ensure_xxtouch_workspace()
        if not XXTOUCH_WEB_DIR.exists():
            return self._send_json({'error': 'XXTouch web not found'}, 404)
        raw = request_path[len('/xxtouch'):].lstrip('/') if request_path.startswith('/xxtouch') else ''
        raw = unquote(raw)
        rel = raw or 'index.html'
        safe = (XXTOUCH_WEB_DIR / rel).resolve()
        base = XXTOUCH_WEB_DIR.resolve()
        if base not in safe.parents and safe != base:
            return self._send_json({'error': 'Invalid path'}, 400)
        if safe.is_dir():
            safe = safe / 'index.html'
        return self._send_disk_file(safe)

    def do_GET(self):
        ensure_sessions_exist()
        path = urlparse(self.path).path
        if path == '/':
            return self._send_file(STATIC_DIR / 'index.html')
        if path == '/xxtouch' or path.startswith('/xxtouch/'):
            return self._serve_xxtouch(path)
        if path == '/api/pm/sessions':
            include_hidden = 'include_hidden=1' in (urlparse(self.path).query or '')
            return self._send_json({'ok': True, 'sessions': get_available_sessions(include_hidden=include_hidden), 'max_sessions': MAX_SESSION_COUNT})
        if path.startswith('/api/pm/sessions/'):
            session_id = path.rsplit('/', 1)[-1]
            if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                return self._send_json({'session': session_id, 'name': get_session_display_name(session_id), 'source': str(SESSION_FILES[session_id]), 'rows': extract_rows(load_json(SESSION_FILES[session_id]), session=session_id)})
        if path == '/api/pm/router-network':
            return self._send_json(call_old_gui('/api/system/network'))
        if path == '/api/pm/router-info':
            return self._send_json(call_old_gui('/api/router/info'))
        if path == '/api/pm/meta':
            return self._send_json({'ok': True, 'app_title_prefix': get_app_title_prefix()})
        if path == '/api/pm/xxtouch/workspace':
            ensure_xxtouch_workspace()
            return self._send_json({
                'ok': True,
                'work_dir': str(XXTOUCH_WORK_DIR),
                'data_dir': str(XXTOUCH_DATA_DIR),
                'log_dir': str(XXTOUCH_LOG_DIR),
                'tmp_dir': str(XXTOUCH_TMP_DIR),
            })
        if path.startswith('/api/pm/ip-mac-config/'):
            session_id = path.rsplit('/', 1)[-1]
            if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                data = load_json(SESSION_FILES['1'])
                saved_text = get_saved_ip_identity_text(session_id)
                if not saved_text:
                    rows = build_ip_identity_rows_from_data(data)
                    if rows and len(rows) < MAX_PROXY_TAG:
                        saved_text = set_saved_ip_identity_text(session_id, '\n'.join(f"{row['tag']}|{row['ip']}" for row in rows))
                return self._send_json({'ok': True, 'session': session_id, 'shared': True, 'text': saved_text or build_ip_identity_text(data, session='1')})
        self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        ensure_sessions_exist()
        path = urlparse(self.path).path
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
                    return self._send_json({'ok': True, 'session': session_id, 'name': name})
            if path.startswith('/api/pm/apply/'):
                session_id = path.rsplit('/', 1)[-1]
                if session_id in SESSION_FILES and SESSION_FILES[session_id].exists():
                    rows_override = payload.get('rows') if isinstance(payload, dict) else None
                    results = run_apply(session_id, rows_override=rows_override)
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
                return self._send_json({'ok': True})
            if path == '/api/pm/meta':
                prefix = set_app_title_prefix(payload.get('app_title_prefix', 'Genrouter'))
                return self._send_json({'ok': True, 'app_title_prefix': prefix})
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
                return self._send_json({'ok': True, 'results': check_proxy_batch(payload.get('items', []), session=str(payload.get('session', '1')) )})
            if path == '/api/pm/reboot-router':
                return self._send_json(call_old_gui('/api/system/reboot', method='GET'))
            if path == '/api/pm/router-change-lan':
                ip_lan = str(payload.get('ip_lan', '')).strip()
                return self._send_json(call_old_gui('/api/router/change_lan', method='POST', data={'ip_lan': ip_lan}))
            return self._send_json({'error': 'Not found'}, 404)
        except urllib.error.HTTPError as e:
            return self._send_json({'ok': False, 'error': f'HTTP {e.code}'}, 400)
        except Exception as e:
            return self._send_json({'error': str(e)}, 400)


if __name__ == '__main__':
    ensure_sessions_exist()
    ensure_xxtouch_workspace()
    ThreadingHTTPServer(('0.0.0.0', 9001), Handler).serve_forever()
