#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import json
import threading
import time
import webbrowser

import tkinter as tk
from tkinter import ttk, messagebox

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'collector_data'
STATE_FILE = DATA_DIR / 'routers.json'
FRP_REGISTRY_FILE = BASE_DIR / 'frp_registry.json'
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


def load_frp_registry():
    if not FRP_REGISTRY_FILE.exists():
        return {'next_port': 21050, 'assigned': {}}
    return json.loads(FRP_REGISTRY_FILE.read_text(encoding='utf-8'))


def save_frp_registry(data):
    FRP_REGISTRY_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def assign_frp_port(router_id: str):
    reg = load_frp_registry()
    assigned = reg.setdefault('assigned', {})
    rid = str(router_id or '').strip() or 'unknown-router'
    if rid in assigned:
        return int(assigned[rid])
    next_port = int(reg.get('next_port', 21050) or 21050)
    assigned[rid] = next_port
    reg['next_port'] = next_port + 1
    save_frp_registry(reg)
    return next_port


def frp_http_url_for_router(router_id: str):
    rid = str(router_id or '').strip()
    if not rid:
        return ''
    cfg = load_config()
    public_url = str(cfg.get('public_url', DEFAULT_PUBLIC_URL) or DEFAULT_PUBLIC_URL).strip()
    host = ''
    try:
        parsed = urlparse(public_url if '://' in public_url else f'http://{public_url}')
        host = str(parsed.hostname or '').strip()
    except Exception:
        host = ''
    if not host:
        host = 'aeg.ooguy.com'
    return f'http://{rid}.{host}:8080'


def build_router_items():
    state = load_state()
    routers = state.get('routers', {}) if isinstance(state, dict) else {}
    now = int(time.time())
    items = []
    for router_id, item in routers.items():
        payload = item.get('payload', {}) if isinstance(item, dict) else {}
        updated_at = int(item.get('updated_at', 0) or 0)
        status = 'online' if now - updated_at <= ONLINE_WINDOW_SEC else 'offline'
        if status != 'online':
            continue
        sessions = payload.get('sessions', []) if isinstance(payload, dict) else []
        frp_port = assign_frp_port(router_id)
        items.append({
            'router_id': router_id,
            'router_title': str(payload.get('router_title', router_id)).strip() or router_id,
            'updated_at': updated_at,
            'last_seen_ago': max(0, now - updated_at) if updated_at else None,
            'status': status,
            'session_count': int(payload.get('session_count', 0) or 0),
            'row_count': int(payload.get('row_count', 0) or 0),
            'payload': payload,
            'sessions': sessions,
            'frp_port': frp_port,
            'frp_tcp_url': f"tcp://aeg.ooguy.com:{frp_port}",
            'frp_http_url': frp_http_url_for_router(router_id),
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
        self.root.geometry('1660x900')
        self.server_started = False
        self.router_items = []
        self.current_router = None
        self.current_session = None
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

        body = ttk.Panedwindow(self.root, orient='horizontal')
        body.pack(fill='both', expand=True, padx=10, pady=10)

        left = ttk.Frame(body, padding=6)
        mid = ttk.Frame(body, padding=6)
        right = ttk.Frame(body, padding=6)
        body.add(left, weight=1)
        body.add(mid, weight=1)
        body.add(right, weight=3)

        ttk.Label(left, text='Danh sách Router').pack(anchor='w')
        self.router_tree = ttk.Treeview(left, columns=('title', 'state', 'last_seen', 'sessions'), show='headings', height=24)
        self.router_tree.pack(fill='both', expand=True, pady=(6, 0))
        for col, text, width in [
            ('title', 'Router', 150),
            ('state', 'State', 70),
            ('last_seen', 'Last Seen', 80),
            ('sessions', 'Cfg', 50),
        ]:
            self.router_tree.heading(col, text=text)
            self.router_tree.column(col, width=width, anchor='w')
        self.router_tree.bind('<<TreeviewSelect>>', self.on_router_select)

        ttk.Label(mid, text='Cấu hình Router').pack(anchor='w')
        self.session_tree = ttk.Treeview(mid, columns=('name', 'rows'), show='headings', height=24)
        self.session_tree.pack(fill='both', expand=True, pady=(6, 0))
        self.session_tree.heading('name', text='Cấu hình')
        self.session_tree.heading('rows', text='Rows')
        self.session_tree.column('name', width=180, anchor='w')
        self.session_tree.column('rows', width=60, anchor='w')
        self.session_tree.bind('<<TreeviewSelect>>', self.on_session_select)

        ttk.Label(right, text='Toàn bộ Proxy trong cấu hình').pack(anchor='w')
        proxy_actions = ttk.Frame(right)
        proxy_actions.pack(fill='x', pady=(6, 4))
        ttk.Button(proxy_actions, text='Copy Máy + Proxy', command=self.copy_all_machine_proxy).pack(side='left')
        ttk.Button(proxy_actions, text='Copy toàn bộ Proxy', command=self.copy_all_proxy_only).pack(side='left', padx=(6, 0))
        self.proxy_tree = ttk.Treeview(right, columns=('machine', 'proxy', 'status', 'note'), show='headings', height=24)
        self.proxy_tree.pack(fill='both', expand=True, pady=(6, 0))
        for col, text, width in [
            ('machine', 'Máy', 60),
            ('proxy', 'Proxy', 360),
            ('status', 'Status', 80),
            ('note', 'Note', 180),
        ]:
            self.proxy_tree.heading(col, text=text)
            self.proxy_tree.column(col, width=width, anchor='w')

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
        previous_router_id = self.current_router.get('router_id') if self.current_router else None
        previous_session_name = self.current_session.get('name') if self.current_session else None

        self.router_items = build_router_items()
        self.router_tree.delete(*self.router_tree.get_children())
        for router in self.router_items:
            last_seen = f"{int(router.get('last_seen_ago', 0) or 0)}s" if router.get('updated_at') else 'never'
            iid = router['router_id']
            self.router_tree.insert('', 'end', iid=iid, values=(router['router_title'], router['status'], last_seen, len(router.get('sessions', []))))

        self.current_router = None
        if previous_router_id:
            for router in self.router_items:
                if router.get('router_id') == previous_router_id:
                    self.current_router = router
                    break
        if self.current_router is None and self.router_items:
            self.current_router = self.router_items[0]

        if self.current_router:
            try:
                self.router_tree.selection_set(self.current_router['router_id'])
                self.router_tree.focus(self.current_router['router_id'])
            except Exception:
                pass

        self.render_sessions(previous_session_name=previous_session_name)
        if not silent:
            self.status_var.set(f'Đã tải {len(self.router_items)} router')

    def render_sessions(self, previous_session_name=None):
        self.session_tree.delete(*self.session_tree.get_children())
        self.proxy_tree.delete(*self.proxy_tree.get_children())
        self.current_session = None
        if not self.current_router:
            return
        sessions = self.current_router.get('sessions', []) or []
        for idx, session in enumerate(sessions):
            iid = f"session::{idx}"
            rows = session.get('rows', []) or []
            self.session_tree.insert('', 'end', iid=iid, values=(str(session.get('name', '')).strip(), len(rows)))

        if sessions:
            chosen = None
            if previous_session_name:
                for session in sessions:
                    if str(session.get('name', '')).strip() == previous_session_name:
                        chosen = session
                        break
            if chosen is None:
                chosen = sessions[0]
            self.current_session = chosen
            selected_index = sessions.index(chosen)
            iid = f"session::{selected_index}"
            try:
                self.session_tree.selection_set(iid)
                self.session_tree.focus(iid)
            except Exception:
                pass
            self.render_proxies()

    def render_proxies(self):
        self.proxy_tree.delete(*self.proxy_tree.get_children())
        if not self.current_session:
            return
        rows = self.current_session.get('rows', []) or []
        for idx, row in enumerate(rows):
            self.proxy_tree.insert('', 'end', iid=f"proxy::{idx}", values=(
                str(row.get('machine', '')).strip(),
                str(row.get('proxy', '')).strip(),
                str(row.get('status', '')).strip(),
                str(row.get('note', '')).strip(),
            ))

    def on_router_select(self, event=None):
        sels = self.router_tree.selection()
        if not sels:
            return
        rid = sels[0]
        for router in self.router_items:
            if router.get('router_id') == rid:
                self.current_router = router
                break
        self.render_sessions()

    def on_session_select(self, event=None):
        sels = self.session_tree.selection()
        if not sels or not self.current_router:
            return
        iid = sels[0]
        try:
            idx = int(iid.split('::', 1)[1])
        except Exception:
            return
        sessions = self.current_router.get('sessions', []) or []
        if 0 <= idx < len(sessions):
            self.current_session = sessions[idx]
            self.render_proxies()

    def _selected_router(self):
        sels = self.router_tree.selection()
        if sels:
            rid = str(sels[0])
            for router in self.router_items:
                if str(router.get('router_id', '')) == rid:
                    return router
        return self.current_router

    def _selected_remote_url(self):
        router = self._selected_router()
        if not router:
            return ''
        return str(router.get('frp_http_url', '')).strip()

    def _current_proxy_rows(self):
        if not self.current_session:
            return []
        return self.current_session.get('rows', []) or []

    def _copy_text(self, text: str, ok_message: str, empty_message: str):
        text = str(text or '').strip()
        if not text:
            messagebox.showinfo('Thiếu dữ liệu', empty_message)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(ok_message)

    def copy_all_machine_proxy(self):
        rows = self._current_proxy_rows()
        text = '\n'.join(
            f"{str(row.get('machine', '')).strip()} {str(row.get('proxy', '')).strip()}".strip()
            for row in rows
            if str(row.get('proxy', '')).strip()
        )
        self._copy_text(text, 'Đã copy toàn bộ Máy + Proxy', 'Cấu hình hiện tại chưa có proxy để copy')

    def copy_all_proxy_only(self):
        rows = self._current_proxy_rows()
        text = '\n'.join(
            str(row.get('proxy', '')).strip()
            for row in rows
            if str(row.get('proxy', '')).strip()
        )
        self._copy_text(text, 'Đã copy toàn bộ Proxy', 'Cấu hình hiện tại chưa có proxy để copy')

    def open_remote_url(self):
        url = self._selected_remote_url()
        if not url:
            messagebox.showinfo('Thiếu URL', 'Router đang chọn chưa có remote_url')
            return
        webbrowser.open(url)

    def copy_remote_url(self):
        url = self._selected_remote_url()
        if not url:
            messagebox.showinfo('Thiếu URL', 'Router đang chọn chưa có remote_url')
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.status_var.set('Đã copy remote URL')


if __name__ == '__main__':
    root = tk.Tk()
    app = PyGuiServerApp(root)
    root.mainloop()
