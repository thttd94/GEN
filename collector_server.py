#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import time

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'collector_data'
STATE_FILE = DATA_DIR / 'routers.json'
STATIC_DIR = BASE_DIR


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
        if self.path != '/api/collector/push':
            return self._send_json({'error': 'Not found'}, 404)
        length = int(self.headers.get('Content-Length', '0') or '0')
        raw = self.rfile.read(length) if length else b'{}'
        payload = json.loads(raw.decode('utf-8') or '{}')
        router_id = str(payload.get('router_id', '')).strip() or str(payload.get('router_title', '')).strip() or f'router-{int(time.time())}'
        state = load_state()
        routers = state.setdefault('routers', {})
        routers[router_id] = {
            'updated_at': int(time.time()),
            'payload': payload,
        }
        save_state(state)
        return self._send_json({'ok': True, 'router_id': router_id})


if __name__ == '__main__':
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(('0.0.0.0', 9010), Handler).serve_forever()
