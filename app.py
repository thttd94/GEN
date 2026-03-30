from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
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


def pick_first_existing(paths):
    for p in paths:
        if p.exists():
            return p
    return paths[0]


CONFIG_DIR = pick_first_existing([
    Path('/etc/genrouter/config'),
    Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/genrouter/config'),
])
RUNTIME_DIR = pick_first_existing([
    Path('/etc/genrouter'),
    Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/genrouter'),
])
GENRUNNER = pick_first_existing([
    Path('/etc/genrouter/core/genrunner'),
    Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/genrouter/core/genrunner'),
])
STATIC_HOSTS_FILE = pick_first_existing([
    Path('/etc/shm/list_ip_static.json'),
    Path('/mnt/e/OpenClaw/Genrouter_jobs/GEN/etc/shm/list_ip_static.json'),
])
LEASES_FILE = Path('/tmp/dhcp.leases')
OLD_GUI_BASE = 'http://127.0.0.1:9000'

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


def load_device_map():
    device_map = {}
    if STATIC_HOSTS_FILE.exists():
        try:
            data = json.loads(STATIC_HOSTS_FILE.read_text(encoding='utf-8'))
            for sec in data.values():
                ip = str(sec.get('ip', '')).strip()
                if not ip:
                    continue
                device_map[ip] = {'mac': str(sec.get('mac', '')).strip(), 'status': 'offline'}
        except Exception:
            pass
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
                row['mac'] = str(mac).strip()
                row['status'] = 'online' if online else 'offline'
        except Exception:
            pass
    return device_map


def extract_rows(data):
    outbounds = {
        str(item.get('tag')): item
        for item in data.get('outbounds', [])
        if str(item.get('tag', '')).startswith('proxy_')
    }
    devices = load_device_map()
    notes = load_notes()
    rows = []
    seen_tags = set()

    for rule in data.get('route', {}).get('rules', []):
        if str(rule.get('action', '')).strip() != 'route':
            continue
        tag = str(rule.get('outbound', '')).strip()
        ip = str(rule.get('source_ip_cidr', '')).strip()
        if not tag.startswith('proxy_') or not ip:
            continue
        if tag in seen_tags:
            continue
        seen_tags.add(tag)
        outbound = outbounds.get(tag, {})
        dev = devices.get(ip, {})
        rows.append({
            'ip': ip,
            'tag': tag,
            'proxy': format_proxy(outbound),
            'mac': str(dev.get('mac', '')).strip(),
            'status': str(dev.get('status', 'offline')).strip() or 'offline',
            'note': str(notes.get(ip, '')).strip(),
        })

    rows.sort(key=lambda x: proxy_tag_num(x['tag']))
    return rows


def format_proxy(outbound):
    server = str(outbound.get('server', '')).strip()
    port = outbound.get('server_port')
    user = str(outbound.get('username', '')).strip()
    password = str(outbound.get('password', '')).strip()
    if not server or not port:
        return ''
    return f"{server}:{port}:{user}:{password}"


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


def run_apply(session: str):
    source = SESSION_FILES[session]
    shutil.copy2(source, RUNTIME_FILE)
    if GENRUNNER.exists():
        subprocess.run([str(GENRUNNER), '-c'], check=False)


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


def check_proxy(proxy: str):
    if not proxy.strip():
        return {'ok': False, 'status': 'empty', 'message': 'Proxy trống'}
    try:
        server, port, user, password = parse_proxy(proxy)
        ok = socks5_probe(server, port, user, password)
        return {'ok': bool(ok), 'status': 'live' if ok else 'dead', 'message': 'Live' if ok else 'Fail'}
    except Exception as e:
        return {'ok': False, 'status': 'dead', 'message': str(e)}


def call_old_gui(path, method='GET', data=None):
    body = None
    headers = {}
    if data is not None:
        body = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    url = OLD_GUI_BASE + path
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode('utf-8', errors='ignore')
        try:
            return {'ok': True, 'data': json.loads(raw) if raw else {}}
        except Exception:
            return {'ok': True, 'data': raw}


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
            return self._send_json({'session': '1', 'rows': extract_rows(load_json(SESSION_FILES['1']))})
        if path == '/api/pm/sessions/2':
            return self._send_json({'session': '2', 'rows': extract_rows(load_json(SESSION_FILES['2']))})
        if path == '/api/pm/router-network':
            return self._send_json(call_old_gui('/api/system/network'))
        if path == '/api/pm/router-info':
            return self._send_json(call_old_gui('/api/router/info'))
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
                run_apply(session_id)
                return self._send_json({'ok': True, 'applied': session_id})
            if path == '/api/pm/clone/1-to-2':
                save_json(SESSION_FILES['2'], load_json(SESSION_FILES['1']))
                return self._send_json({'ok': True})
            if path == '/api/pm/check-proxy':
                return self._send_json(check_proxy(str(payload.get('proxy', ''))))
            if path == '/api/pm/reboot-router':
                return self._send_json(call_old_gui('/api/system/reboot'))
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
