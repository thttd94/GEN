#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import time
import threading

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'collector_data'
STATE_FILE = DATA_DIR / 'routers.json'
STATIC_DIR = BASE_DIR
UPDATE_CODES_FILE = DATA_DIR / 'update_codes_state.json'
UPDATE_CODES_LOCK = threading.Lock()
DEFAULT_ADMIN_UPDATE_CODE = 'ADMIN2026GEN'


def load_update_code_state():
    if not UPDATE_CODES_FILE.exists():
        return {'admin_code': DEFAULT_ADMIN_UPDATE_CODE, 'versions': {}}
    try:
        data = json.loads(UPDATE_CODES_FILE.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {'admin_code': DEFAULT_ADMIN_UPDATE_CODE, 'versions': {}}
    except Exception:
        return {'admin_code': DEFAULT_ADMIN_UPDATE_CODE, 'versions': {}}


def save_update_code_state(state):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPDATE_CODES_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def refresh_update_codes_from_git():
    import urllib.request
    url = 'https://raw.githubusercontent.com/thttd94/GEN/main/update_codes.json'
    req = urllib.request.Request(f"{url}?ts={int(time.time() * 1000)}", headers={'User-Agent': 'Collector/1.0', 'Cache-Control': 'no-cache'})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read().decode('utf-8', 'replace'))
    if not isinstance(data, dict):
        raise ValueError('invalid update code state')
    save_update_code_state(data)
    return data


def consume_update_code_once(code, router_id, current_version=''):
    with UPDATE_CODES_LOCK:
        state = refresh_update_codes_from_git()
        admin_code = str(state.get('admin_code') or DEFAULT_ADMIN_UPDATE_CODE).strip() or DEFAULT_ADMIN_UPDATE_CODE
        code = str(code or '').strip()
        if not code:
            raise PermissionError('Mã không hợp lệ')
        if code == admin_code:
            return {'ok': True, 'admin': True, 'router_id': router_id, 'current_version': current_version}
        versions = state.setdefault('versions', {}) if isinstance(state, dict) else {}
        for ver_name, entry in (versions or {}).items():
            codes = entry.get('codes') if isinstance(entry, dict) else []
            for item in codes or []:
                if str(item.get('code') or '').strip() != code:
                    continue
                if item.get('used'):
                    raise PermissionError('Mã không hợp lệ')
                item['used'] = True
                item['used_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
                item['used_version'] = str(ver_name)
                item['used_target'] = str(router_id or '')
                item['used_current_version'] = str(current_version or '')
                save_update_code_state(state)
                return {'ok': True, 'admin': False, 'version': str(ver_name), 'router_id': router_id, 'current_version': current_version}
        raise PermissionError('Mã không hợp lệ')


def load_state():
    if not STATE_FILE.exists():
        return {'routers': {}}
    return json.loads(STATE_FILE.read_text(encoding='utf-8'))


def save_state(state):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith('/api/collector/routers'):
            state = load_state()
            routers = state.get('routers', {}) if isinstance(state, dict) else {}
            items = []
            for router_id, item in routers.items():
                payload = item.get('payload', {}) if isinstance(item, dict) else {}
                items.append({
                    'router_id': router_id,
                    'router_title': payload.get('router_title', router_id),
                    'updated_at': item.get('updated_at', 0),
                    'session_count': payload.get('session_count', 0),
                    'row_count': payload.get('row_count', 0),
                    'payload': payload,
                })
            items.sort(key=lambda x: str(x.get('router_title', '')))
            return self._send_json({'ok': True, 'routers': items})
        return self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0') or '0')
        raw = self.rfile.read(length) if length else b'{}'
        payload = json.loads(raw.decode('utf-8') or '{}')
        if self.path == '/api/collector/push':
            router_id = str(payload.get('router_id', '')).strip() or str(payload.get('router_title', '')).strip() or f'router-{int(time.time())}'
            state = load_state()
            routers = state.setdefault('routers', {})
            routers[router_id] = {
                'updated_at': int(time.time()),
                'payload': payload,
            }
            save_state(state)
            return self._send_json({'ok': True, 'router_id': router_id})
        if self.path == '/api/update-code/consume':
            code = str(payload.get('code', '')).strip()
            router_id = str(payload.get('router_id', '')).strip() or self.client_address[0]
            current_version = str(payload.get('current_version', '')).strip()
            try:
                result = consume_update_code_once(code, router_id, current_version=current_version)
            except PermissionError as e:
                return self._send_json({'ok': False, 'error': str(e)}, 400)
            except Exception as e:
                return self._send_json({'ok': False, 'error': f'Consume lỗi: {e}'}, 500)
            return self._send_json(result)
        return self._send_json({'error': 'Not found'}, 404)


if __name__ == '__main__':
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(('0.0.0.0', 9010), Handler).serve_forever()
