from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, urlencode
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

SESSION_FILES = {
    '1': CONFIG_DIR / 'gencore.json',
    '2': CONFIG_DIR / 'gencore2.json',
}
RUNTIME_FILE = RUNTIME_DIR / 'gencore.json'


def proxy_tag_num(tag):
    try:
        return int(str(tag).split('_', 1)[1])
    except Exception:
        return 10**9


def tag_to_ip(tag):
    num = proxy_tag_num(tag)
    if num < 1 or num > 312:
        return ''
    if num <= 250:
        return f'192.15.4.{num}'
    return f'192.15.5.{num - 250}'


def ensure_session2_exists():
    s2 = SESSION_FILES['2']
    if s2.exists():
        return
    data = load_json(SESSION_FILES['1'])
    clear_session_proxies(data)
    save_json(s2, data)


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


def format_proxy(outbound):
    server = str(outbound.get('server', '')).strip()
    port = outbound.get('server_port')
    user = str(outbound.get('username', '')).strip()
    password = str(outbound.get('password', '')).strip()
    if not server or not port:
        return ''
    return f"{server}:{port}:{user}:{password}"


def extract_rows(data):
    outbounds = {
        str(item.get('tag')): item
        for item in data.get('outbounds', [])
        if str(item.get('tag', '')).startswith('proxy_')
    }
    devices = load_device_map()
    notes = load_notes()
    route_by_ip = build_route_ip_to_tag(data)
    rows = []

    for ip, dev in devices.items():
        ip = str(ip).strip()
        tag = route_by_ip.get(ip, '')
        if not tag:
            continue
        outbound = outbounds.get(tag, {})
        rows.append({
            'ip': ip,
            'tag': tag,
            'proxy': format_proxy(outbound),
            'mac': normalize_mac(dev.get('mac', '')),
            'status': str(dev.get('status', 'offline')).strip() or 'offline',
            'note': str(notes.get(ip, '')).strip(),
        })

    rows.sort(key=lambda x: (proxy_tag_num(x['tag']), x['ip']))
    return rows


def apply_rows_to_data(data, rows_by_tag):
    outbounds = data.setdefault('outbounds', [])
    outbound_idx = {str(item.get('tag')): i for i, item in enumerate(outbounds) if item.get('tag')}
    notes = load_notes()

    for tag, row in rows_by_tag.items():
        proxy = str(row.get('proxy', '')).strip()
        set_outbound_proxy(outbounds, outbound_idx, tag, proxy)
        ip = str(row.get('ip', '')).strip()
        if ip:
            notes[ip] = str(row.get('note', '')).strip()

    save_notes(notes)
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
    for i in range(1, 313):
        mapping[f'proxy_{i}'] = tag_to_ip(f'proxy_{i}')
    rebuild_gencore_rules(data, mapping)
    return data


def rebuild_gencore_rules(data, tag_to_ip_map):
    dns = data.setdefault('dns', {})
    route = data.setdefault('route', {})

    dns_rules = [
        {'outbound': 'any', 'server': 'google'}
    ]
    route_rules = [
        {'action': 'sniff'},
        {'action': 'reject', 'method': 'drop', 'protocol': 'stun'},
        {'action': 'hijack-dns', 'protocol': 'dns'},
    ]

    for i in range(1, 313):
        tag = f'proxy_{i}'
        ip = str(tag_to_ip_map.get(tag, '')).strip() or tag_to_ip(tag)
        dns_rules.append({'action': 'route', 'server': tag, 'source_ip_cidr': ip})
        route_rules.append({'action': 'route', 'outbound': tag, 'source_ip_cidr': ip})

    route_rules.append({'action': 'route', 'outbound': 'direct'})
    dns['rules'] = dns_rules
    route['rules'] = route_rules
    return data


def build_ip_mac_config_text(data):
    tag_to_ip = build_tag_to_ip(data)
    static_rows = load_static_hosts_raw()
    mac_by_ip = {str(row.get('ip', '')).strip(): normalize_mac(row.get('mac', '')) for row in static_rows}
    items = []
    for tag, ip in tag_to_ip.items():
        items.append((proxy_tag_num(tag), f'{tag}|{ip}|{mac_by_ip.get(ip, "")}'))
    items.sort(key=lambda x: (x[0], x[1]))
    return '\n'.join(line for _num, line in items)


def parse_ip_mac_config_text(text):
    rows = []
    seen_tags = set()
    seen_ips = set()
    seen_macs = set()
    dup_tags = set()
    dup_ips = set()
    dup_macs = set()
    for raw in str(text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) != 3:
            raise ValueError(f'Dòng không hợp lệ: {line}')
        tag, ip, mac = parts
        if not tag.startswith('proxy_'):
            raise ValueError(f'Tag không hợp lệ: {tag}')
        if not ip:
            raise ValueError(f'IP trống ở dòng: {line}')
        mac = normalize_mac(mac)
        if not mac:
            raise ValueError(f'MAC trống ở dòng: {line}')
        if tag in seen_tags:
            dup_tags.add(tag)
        else:
            seen_tags.add(tag)
        if ip in seen_ips:
            dup_ips.add(ip)
        else:
            seen_ips.add(ip)
        if mac in seen_macs:
            dup_macs.add(mac)
        else:
            seen_macs.add(mac)
        rows.append({'tag': tag, 'ip': ip, 'mac': mac})
    errs = []
    if dup_tags:
        errs.append('Proxy bị trùng: ' + ', '.join(sorted(dup_tags, key=proxy_tag_num)))
    if dup_ips:
        errs.append('IP bị trùng: ' + ', '.join(sorted(dup_ips)))
    if dup_macs:
        errs.append('MAC bị trùng: ' + ', '.join(sorted(dup_macs)))
    if errs:
        raise ValueError(' | '.join(errs))
    rows.sort(key=lambda x: (proxy_tag_num(x['tag']), x['ip']))
    return rows


def apply_ip_mac_config(data, text):
    rows = parse_ip_mac_config_text(text)
    tag_to_ip = {row['tag']: row['ip'] for row in rows}
    rebuild_gencore_rules(data, tag_to_ip)
    save_static_hosts_rows([{'ip': row['ip'], 'mac': row['mac']} for row in rows])
    return data


def run_apply(session: str):
    source = SESSION_FILES[session]
    shutil.copy2(source, RUNTIME_FILE)
    results = []
    if GENRUNNER.exists():
        try:
            r = subprocess.run([str(GENRUNNER), '-c'], check=False, capture_output=True, text=True)
            results.append({'cmd': f'{GENRUNNER} -c', 'code': r.returncode, 'stdout': (r.stdout or '').strip(), 'stderr': (r.stderr or '').strip()})
        except Exception as e:
            results.append({'cmd': f'{GENRUNNER} -c', 'error': str(e)})

    extra_cmds = [
        ['/etc/init.d/genrouter', 'restart'],
        ['/etc/init.d/genrouter_server', 'restart'],
        ['/etc/init.d/odhcpd', 'reload'],
    ]
    for cmd in extra_cmds:
        try:
            if Path(cmd[0]).exists():
                r = subprocess.run(cmd, check=False, capture_output=True, text=True)
                results.append({'cmd': ' '.join(cmd), 'code': r.returncode, 'stdout': (r.stdout or '').strip(), 'stderr': (r.stderr or '').strip()})
        except Exception as e:
            results.append({'cmd': ' '.join(cmd), 'error': str(e)})
    return results


def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError('Kết nối bị đóng')
        data += chunk
    return data


def socks5_probe(proxy_host, proxy_port, username, password, target_host='1.1.1.1', target_port=80, timeout=12):
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

        sock.sendall(b'GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n')
        data = sock.recv(32)
        return bool(data)
    finally:
        try:
            sock.close()
        except Exception:
            pass


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
        return {'ok': False, 'status': 'empty', 'message': 'Proxy trống'}
    try:
        server, port, user, password = parse_proxy(proxy)
        ok = socks5_probe(server, port, user, password)
        if not ok:
            return {'ok': False, 'status': 'dead', 'message': 'Fail'}
        public_ip = get_proxy_public_ip(server, port, user, password)
        duplicates = find_duplicate_proxy_tags(public_ip, session=session)
        if len(duplicates) > 1:
            msg = f"LIVE|{public_ip}|Trùng|{','.join(duplicates)}"
            return {'ok': True, 'status': 'live', 'message': msg, 'ip': public_ip, 'duplicates': duplicates, 'duplicate': True}
        msg = f'LIVE|{public_ip}'
        return {'ok': True, 'status': 'live', 'message': msg, 'ip': public_ip, 'duplicates': duplicates, 'duplicate': False}
    except Exception as e:
        return {'ok': False, 'status': 'dead', 'message': str(e)}


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


def sync_static_to_router(rows):
    for row in rows:
        ip = str(row.get('ip', '')).strip()
        mac = normalize_mac(row.get('mac', ''))
        if not ip or not mac:
            continue
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

    def do_GET(self):
        ensure_session2_exists()
        path = urlparse(self.path).path
        if path == '/':
            return self._send_file(STATIC_DIR / 'index.html')
        if path == '/api/pm/sessions/1':
            return self._send_json({'session': '1', 'source': str(SESSION_FILES['1']), 'rows': extract_rows(load_json(SESSION_FILES['1']))})
        if path == '/api/pm/sessions/2':
            return self._send_json({'session': '2', 'source': str(SESSION_FILES['2']), 'rows': extract_rows(load_json(SESSION_FILES['2']))})
        if path == '/api/pm/router-network':
            return self._send_json(call_old_gui('/api/system/network'))
        if path == '/api/pm/router-info':
            return self._send_json(call_old_gui('/api/router/info'))
        if path in ('/api/pm/ip-mac-config/1', '/api/pm/ip-mac-config/2'):
            session_id = path.rsplit('/', 1)[-1]
            data = load_json(SESSION_FILES[session_id])
            return self._send_json({'ok': True, 'session': session_id, 'text': build_ip_mac_config_text(data)})
        self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        ensure_session2_exists()
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', '0') or '0')
        body = self.rfile.read(length) if length else b'{}'
        payload = json.loads(body.decode('utf-8') or '{}')
        try:
            if path in ('/api/pm/sessions/1', '/api/pm/sessions/2'):
                session_id = path.rsplit('/', 1)[-1]
                rows = payload.get('rows', [])
                rows_by_tag = {str(row['tag']).strip(): row for row in rows if row.get('tag')}
                data = load_json(SESSION_FILES[session_id])
                save_json(SESSION_FILES[session_id], apply_rows_to_data(data, rows_by_tag))
                return self._send_json({'ok': True, 'session': session_id})
            if path in ('/api/pm/apply/1', '/api/pm/apply/2'):
                session_id = path.rsplit('/', 1)[-1]
                results = run_apply(session_id)
                return self._send_json({'ok': True, 'applied': session_id, 'results': results})
            if path == '/api/pm/clone/1-to-2':
                save_json(SESSION_FILES['2'], load_json(SESSION_FILES['1']))
                return self._send_json({'ok': True})
            if path in ('/api/pm/map-ip/1', '/api/pm/map-ip/2'):
                session_id = path.rsplit('/', 1)[-1]
                data = load_json(SESSION_FILES[session_id])
                save_json(SESSION_FILES[session_id], remap_ip_by_tag(data))
                return self._send_json({'ok': True, 'session': session_id})
            if path in ('/api/pm/ip-mac-config/1', '/api/pm/ip-mac-config/2'):
                session_id = path.rsplit('/', 1)[-1]
                text = str(payload.get('text', ''))
                sync_router = bool(payload.get('sync_router', True))
                data = load_json(SESSION_FILES[session_id])
                rows = parse_ip_mac_config_text(text)
                data = apply_ip_mac_config(data, text)
                save_json(SESSION_FILES[session_id], data)
                if sync_router:
                    sync_static_to_router(rows)
                if payload.get('apply_runtime'):
                    apply_results = run_apply(session_id)
                if payload.get('reboot_router'):
                    call_old_gui('/api/system/reboot', method='GET')
                return self._send_json({'ok': True, 'session': session_id, 'count': len(rows), 'apply_results': locals().get('apply_results', [])})
            if path == '/api/pm/check-proxy':
                return self._send_json(check_proxy(str(payload.get('proxy', '')), session=str(payload.get('session', '1'))))
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
    ensure_session2_exists()
    ThreadingHTTPServer(('0.0.0.0', 18123), Handler).serve_forever()
