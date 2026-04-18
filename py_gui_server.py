#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import threading
import time
import webbrowser

import tkinter as tk
from tkinter import ttk, messagebox

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'collector_data'
STATE_FILE = DATA_DIR / 'routers.json'
CONFIG_FILE = BASE_DIR / 'py_gui_server_config.json'
DEFAULT_BIND_HOST = '0.0.0.0'
DEFAULT_PORT = 9010
DEFAULT_PUBLIC_URL = 'http://aeg.ooguy.com:9010'
ONLINE_WINDOW_SEC = 180


def load_state():
    if not STATE_FILE.exists():
        return {'routers': {}}
    return json.loads(STATE_FILE.read_text(encoding='utf-8'))


def save_state(state):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def load_config():
    cfg = {
        'bind_host': DEFAULT_BIND_HOST,
        'port': DEFAULT_PORT,
        'public_url': DEFAULT_PUBLIC_URL,
    }
    try:
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                cfg.update(data)
    except Exception:
        pass
    return cfg


def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding='utf-8')


def build_router_items():
    state = load_state()
    routers = state.get('routers', {}) if isinstance(state, dict) else {}
    now = int(time.time())
    items = []
    for router_id, item in routers.items():
        payload = item.get('payload', {}) if isinstance(item, dict) else {}
        updated_at = int(item.get('updated_at', 0) or 0)
        status = 'online' if now - updated_at <= ONLINE_WINDOW_SEC else 'offline'
        items.append({
            'router_id': router_id,
            'router_title': str(payload.get('router_title', router_id)).strip() or router_id,
            'updated_at': updated_at,
            'last_seen_ago': max(0, now - updated_at) if updated_at else None,
            'status': status,
            'session_count': int(payload.get('session_count', 0) or 0),
            'row_count': int(payload.get('row_count', 0) or 0),
            'payload': payload,
        })
    items.sort(key=lambda x: str(x.get('router_title', '')))
    return items


class RouterCenterHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith('/api/collector/routers'):
            return self._send_json({'ok': True, 'routers': build_router_items()})
        if self.path.startswith('/api/router-center/meta'):
            cfg = load_config()
            return self._send_json({'ok': True, 'public_url': cfg.get('public_url', DEFAULT_PUBLIC_URL), 'port': cfg.get('port', DEFAULT_PORT)})
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


class PyGuiServerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('PY GUI Server - Router Center')
        self.root.geometry('1660x880')
        self.server_started = False
        self._build_ui()
        self._load_config_into_ui()
        self.start_server()
        self.refresh()
        self.root.after(10000, self._auto_refresh)

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill='x')

        ttk.Label(top, text='Bind Host').grid(row=0, column=0, sticky='w')
        self.bind_host_var = tk.StringVar(value=DEFAULT_BIND_HOST)
        ttk.Entry(top, textvariable=self.bind_host_var, width=18).grid(row=0, column=1, sticky='w', padx=6)

        ttk.Label(top, text='Port').grid(row=0, column=2, sticky='w')
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=0, column=3, sticky='w', padx=6)

        ttk.Label(top, text='Public URL').grid(row=0, column=4, sticky='w')
        self.public_url_var = tk.StringVar(value=DEFAULT_PUBLIC_URL)
        ttk.Entry(top, textvariable=self.public_url_var, width=42).grid(row=0, column=5, sticky='we', padx=6)

        ttk.Button(top, text='Lưu cấu hình', command=self.save_ui_config).grid(row=0, column=6, padx=6)
        ttk.Button(top, text='Làm mới', command=self.refresh).grid(row=0, column=7, padx=6)
        ttk.Button(top, text='Mở 9001', command=self.open_remote_url).grid(row=0, column=8, padx=6)
        ttk.Button(top, text='Copy URL', command=self.copy_remote_url).grid(row=0, column=9, padx=6)
        top.columnconfigure(5, weight=1)

        self.status_var = tk.StringVar(value='Sẵn sàng')
        ttk.Label(top, textvariable=self.status_var).grid(row=1, column=0, columnspan=10, sticky='w', pady=(8, 0))

        cols = ('router_title', 'router_id', 'router_status', 'last_seen', 'remote_url', 'session_name', 'machine', 'proxy', 'status', 'note')
        self.tree = ttk.Treeview(self.root, columns=cols, show='headings')
        self.tree.pack(fill='both', expand=True, padx=10, pady=10)
        headings = {
            'router_title': 'Router Name',
            'router_id': 'Router ID',
            'router_status': 'Router State',
            'last_seen': 'Last Seen',
            'remote_url': 'Remote URL',
            'session_name': 'Cấu hình',
            'machine': 'Máy',
            'proxy': 'Proxy',
            'status': 'Status',
            'note': 'Note',
        }
        widths = {'router_title': 170, 'router_id': 170, 'router_status': 90, 'last_seen': 100, 'remote_url': 250, 'session_name': 160, 'machine': 70, 'proxy': 320, 'status': 90, 'note': 220}
        for col in cols:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor='w')

    def _load_config_into_ui(self):
        cfg = load_config()
        self.bind_host_var.set(str(cfg.get('bind_host', DEFAULT_BIND_HOST)))
        self.port_var.set(str(cfg.get('port', DEFAULT_PORT)))
        self.public_url_var.set(str(cfg.get('public_url', DEFAULT_PUBLIC_URL)))

    def save_ui_config(self):
        cfg = {
            'bind_host': self.bind_host_var.get().strip() or DEFAULT_BIND_HOST,
            'port': int(self.port_var.get().strip() or DEFAULT_PORT),
            'public_url': self.public_url_var.get().strip() or DEFAULT_PUBLIC_URL,
        }
        save_config(cfg)
        self.status_var.set('Đã lưu cấu hình server')

    def start_server(self):
        if self.server_started:
            return
        cfg = load_config()
        bind_host = str(cfg.get('bind_host', DEFAULT_BIND_HOST)).strip() or DEFAULT_BIND_HOST
        port = int(cfg.get('port', DEFAULT_PORT) or DEFAULT_PORT)

        def run():
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            ThreadingHTTPServer((bind_host, port), RouterCenterHandler).serve_forever()

        threading.Thread(target=run, daemon=True).start()
        self.server_started = True
        self.status_var.set(f'Server đang chạy tại {bind_host}:{port}')

    def _auto_refresh(self):
        try:
            self.refresh(silent=True)
        finally:
            self.root.after(10000, self._auto_refresh)

    def refresh(self, silent=False):
        items = build_router_items()
        rows = []
        for router in items:
            payload = router.get('payload', {}) or {}
            router_title = str(router.get('router_title', '')).strip()
            router_id = str(router.get('router_id', '')).strip()
            router_status = str(router.get('status', '')).strip()
            last_seen = f"{int(router.get('last_seen_ago', 0) or 0)}s" if router.get('updated_at') else 'never'
            remote_url = str(payload.get('remote_url', '')).strip()
            for session in payload.get('sessions', []):
                session_name = str(session.get('name', '')).strip()
                for row in session.get('rows', []):
                    rows.append((router_title, router_id, router_status, last_seen, remote_url, session_name, str(row.get('machine', '')).strip(), str(row.get('proxy', '')).strip(), str(row.get('status', '')).strip(), str(row.get('note', '')).strip()))
        self.tree.delete(*self.tree.get_children())
        for item in rows:
            self.tree.insert('', 'end', values=item)
        if not silent:
            self.status_var.set(f'Đã tải {len(rows)} dòng từ {len(items)} router')

    def _selected_remote_url(self):
        sels = self.tree.selection()
        if not sels:
            return ''
        vals = self.tree.item(sels[0], 'values')
        if len(vals) >= 5:
            return str(vals[4]).strip()
        return ''

    def open_remote_url(self):
        url = self._selected_remote_url()
        if not url:
            messagebox.showinfo('Thiếu URL', 'Dòng đang chọn chưa có remote_url')
            return
        webbrowser.open(url)

    def copy_remote_url(self):
        url = self._selected_remote_url()
        if not url:
            messagebox.showinfo('Thiếu URL', 'Dòng đang chọn chưa có remote_url')
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.status_var.set('Đã copy remote URL')


if __name__ == '__main__':
    root = tk.Tk()
    app = PyGuiServerApp(root)
    root.mainloop()
