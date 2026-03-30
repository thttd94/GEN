from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import json
import os
import re
import subprocess

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'
STATIC_HOSTS_FILE = Path('/etc/shm/list_ip_static.json') if Path('/etc/shm/list_ip_static.json').exists() else (BASE_DIR / 'list_ip_static.json')
PORT = 19123

MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
LINE_RE = re.compile(r'^\s*([^\s|;,]+)\s*(?:[|;,]|\s+)\s*([0-9A-Fa-f:.-]{17})\s*$')


def run(cmd: str):
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def normalize_mac(mac: str) -> str:
    return str(mac or '').strip().upper().replace('-', ':')


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def load_static_hosts():
    code, out, err = run("ubus call uci get '{\"config\":\"dhcp\"}'")
    if code != 0:
        raise RuntimeError(err or out or 'Không đọc được cấu hình DHCP')
    data = json.loads(out)
    values = data.get('values', {}) if isinstance(data, dict) else {}
    rows = []
    for section, sec in values.items():
        if not isinstance(sec, dict) or sec.get('.type') != 'host':
            continue
        rows.append({
            'section': section,
            'name': str(sec.get('name', '')).strip(),
            'ip': str(sec.get('ip', '')).strip(),
            'mac': normalize_mac(sec.get('mac', '')),
        })
    rows.sort(key=lambda x: (x['ip'], x['mac']))
    return rows


def save_static_cache(rows):
    data = {}
    for i, row in enumerate(rows, 1):
        ip = str(row.get('ip', '')).strip()
        mac = normalize_mac(row.get('mac', ''))
        if not ip or not mac:
            continue
        data[str(i)] = {'ip': ip, 'mac': mac}
    save_json(STATIC_HOSTS_FILE, data)


def parse_mapping_text(text: str):
    rows = []
    seen_ips = {}
    seen_macs = {}
    errors = []
    for idx, raw in enumerate(str(text or '').replace('\r\n', '\n').replace('\r', '\n').split('\n'), 1):
        line = raw.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            errors.append(f'Dòng {idx} sai định dạng: {line}')
            continue
        ip = m.group(1).strip()
        mac = normalize_mac(m.group(2))
        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            errors.append(f'Dòng {idx} IP không hợp lệ: {ip}')
            continue
        if not MAC_RE.match(mac):
            errors.append(f'Dòng {idx} MAC không hợp lệ: {mac}')
            continue
        if ip in seen_ips:
            errors.append(f'IP bị trùng: {ip} (dòng {seen_ips[ip]} và {idx})')
        else:
            seen_ips[ip] = idx
        if mac in seen_macs:
            errors.append(f'MAC bị trùng: {mac} (dòng {seen_macs[mac]} và {idx})')
        else:
            seen_macs[mac] = idx
        rows.append({'ip': ip, 'mac': mac})
    if errors:
        raise ValueError(' | '.join(errors))
    return rows


def replace_all_static_hosts(rows):
    current = load_static_hosts()
    for item in current:
        section = str(item.get('section', '')).strip()
        if section:
            run(f"uci delete dhcp.{section} >/dev/null 2>&1")
    run("uci commit dhcp >/dev/null 2>&1")

    for i, row in enumerate(rows, 1):
        ip = row['ip']
        mac = row['mac']
        name = f'static_{i:04d}_{mac.replace(":", "")}'
        run("uci add dhcp host >/dev/null 2>&1")
        run(f"uci set dhcp.@host[-1].name='{name}' >/dev/null 2>&1")
        run(f"uci set dhcp.@host[-1].ip='{ip}' >/dev/null 2>&1")
        run(f"uci set dhcp.@host[-1].mac='{mac}' >/dev/null 2>&1")
    run("uci commit dhcp >/dev/null 2>&1")
    run("/etc/init.d/odhcpd reload >/dev/null 2>&1")
    save_static_cache(rows)
    return {'count': len(rows)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path: Path, content_type='text/html; charset=utf-8'):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/':
            return self._send_file(STATIC_DIR / 'index.html')
        if path == '/api/mappings':
            rows = load_static_hosts()
            text = '\n'.join(f"{row['ip']} {row['mac']}" for row in rows if row.get('ip') and row.get('mac'))
            return self._send_json({'ok': True, 'rows': rows, 'text': text, 'count': len(rows)})
        return self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', '0') or '0')
        body = self.rfile.read(length) if length else b'{}'
        try:
            payload = json.loads(body.decode('utf-8') or '{}')
        except Exception:
            payload = {}
        try:
            if path == '/api/apply':
                text = str(payload.get('text', ''))
                rows = parse_mapping_text(text)
                result = replace_all_static_hosts(rows)
                return self._send_json({'ok': True, 'count': result['count']})
            if path == '/api/reboot':
                run('/sbin/reboot >/dev/null 2>&1 &')
                return self._send_json({'ok': True})
            return self._send_json({'error': 'Not found'}, 404)
        except Exception as e:
            return self._send_json({'ok': False, 'error': str(e)}, 400)


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
