#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import threading
import urllib.request
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / 'collector_proxy_gui_config.json'
DEFAULT_COLLECTOR = 'http://127.0.0.1:9010'


class CollectorProxyGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('Collector Proxy GUI')
        self.root.geometry('1440x820')
        self._build_ui()
        self._load_config()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill='x')
        ttk.Label(top, text='Collector URL').pack(side='left')
        self.collector_var = tk.StringVar(value=DEFAULT_COLLECTOR)
        ttk.Entry(top, textvariable=self.collector_var, width=50).pack(side='left', padx=6)
        ttk.Button(top, text='Làm mới', command=self.refresh).pack(side='left')
        self.status_var = tk.StringVar(value='Sẵn sàng')
        ttk.Label(top, textvariable=self.status_var).pack(side='left', padx=10)

        cols = ('router_title', 'router_id', 'session_name', 'machine', 'proxy', 'status', 'note')
        self.tree = ttk.Treeview(self.root, columns=cols, show='headings')
        self.tree.pack(fill='both', expand=True, padx=10, pady=10)
        headings = {
            'router_title': 'Router Name',
            'router_id': 'Router ID',
            'session_name': 'Cấu hình',
            'machine': 'Máy',
            'proxy': 'Proxy',
            'status': 'Status',
            'note': 'Note',
        }
        widths = {'router_title': 180, 'router_id': 180, 'session_name': 160, 'machine': 70, 'proxy': 340, 'status': 90, 'note': 240}
        for col in cols:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor='w')

    def _load_config(self):
        try:
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
                self.collector_var.set(str(data.get('collector_url', DEFAULT_COLLECTOR)))
        except Exception:
            pass

    def _save_config(self):
        CONFIG_FILE.write_text(json.dumps({'collector_url': self.collector_var.get().strip()}, ensure_ascii=False, indent=2), encoding='utf-8')

    def refresh(self):
        self._save_config()
        self.status_var.set('Đang tải dữ liệu collector...')
        threading.Thread(target=self._refresh_worker, daemon=True).start()

    def _refresh_worker(self):
        base = self.collector_var.get().strip().rstrip('/')
        try:
            req = urllib.request.Request(base + '/api/collector/routers', headers={'User-Agent': 'collector-proxy-gui/1.0'})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            rows = []
            for router in data.get('routers', []):
                router_title = str(router.get('router_title', '')).strip()
                router_id = str(router.get('router_id', '')).strip()
                payload = router.get('payload', {}) or {}
                for session in payload.get('sessions', []):
                    session_name = str(session.get('name', '')).strip()
                    for row in session.get('rows', []):
                        rows.append((router_title, router_id, session_name, str(row.get('machine', '')).strip(), str(row.get('proxy', '')).strip(), str(row.get('status', '')).strip(), str(row.get('note', '')).strip()))
            def update():
                self.tree.delete(*self.tree.get_children())
                for item in rows:
                    self.tree.insert('', 'end', values=item)
                self.status_var.set(f'Đã tải {len(rows)} dòng')
            self.root.after(0, update)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror('Lỗi collector', str(e)))
            self.root.after(0, lambda: self.status_var.set('Lỗi tải collector'))


if __name__ == '__main__':
    root = tk.Tk()
    app = CollectorProxyGui(root)
    root.mainloop()
