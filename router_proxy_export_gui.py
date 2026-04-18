#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / 'router_proxy_export_gui_config.json'
DEFAULT_ROUTERS = "http://192.15.0.1:9001\n"


class RouterProxyExportApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('Router Proxy Export GUI')
        self.root.geometry('1420x820')
        self.rows_cache = []
        self.router_payloads = []
        self._build_ui()
        self._load_config()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill='x')

        ttk.Label(top, text='Danh sách router URL (mỗi dòng 1 URL, ví dụ http://host:9001)').pack(anchor='w')
        self.router_text = tk.Text(top, height=5)
        self.router_text.pack(fill='x', pady=(4, 8))

        btns = ttk.Frame(top)
        btns.pack(fill='x')
        ttk.Button(btns, text='Quét tất cả', command=self.scan_all).pack(side='left')
        ttk.Button(btns, text='Xuất JSON', command=self.export_json).pack(side='left', padx=6)
        ttk.Button(btns, text='Xuất CSV', command=self.export_csv).pack(side='left')
        ttk.Button(btns, text='Lưu danh sách router', command=self.save_config).pack(side='left', padx=6)

        self.status_var = tk.StringVar(value='Sẵn sàng')
        ttk.Label(top, textvariable=self.status_var).pack(anchor='w', pady=(8, 0))

        cols = ('router_title', 'router_url', 'session_name', 'machine', 'device_ip', 'proxy', 'status', 'note')
        self.tree = ttk.Treeview(self.root, columns=cols, show='headings')
        self.tree.pack(fill='both', expand=True, padx=10, pady=10)

        headings = {
            'router_title': 'Router Name',
            'router_url': 'Router URL',
            'session_name': 'Cấu hình',
            'machine': 'Máy',
            'device_ip': 'IP máy',
            'proxy': 'Proxy',
            'status': 'Status',
            'note': 'Note',
        }
        widths = {
            'router_title': 180,
            'router_url': 180,
            'session_name': 160,
            'machine': 70,
            'device_ip': 120,
            'proxy': 320,
            'status': 90,
            'note': 220,
        }
        for col in cols:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor='w')

        yscroll = ttk.Scrollbar(self.root, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.place(relx=1.0, rely=0.14, relheight=0.82, anchor='ne')

    def _load_config(self):
        text = DEFAULT_ROUTERS
        try:
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
                text = str(data.get('routers_text', DEFAULT_ROUTERS))
        except Exception:
            pass
        self.router_text.delete('1.0', 'end')
        self.router_text.insert('1.0', text)

    def save_config(self):
        data = {'routers_text': self.router_text.get('1.0', 'end').strip() + '\n'}
        CONFIG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        self.status_var.set('Đã lưu danh sách router')

    def _get_router_urls(self):
        lines = [x.strip().rstrip('/') for x in self.router_text.get('1.0', 'end').splitlines()]
        return [x for x in lines if x]

    def _fetch_json(self, url: str):
        req = urllib.request.Request(url, headers={'User-Agent': 'router-proxy-export-gui/1.0'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def scan_all(self):
        urls = self._get_router_urls()
        if not urls:
            messagebox.showwarning('Thiếu dữ liệu', 'Chưa có router URL để quét')
            return
        self.save_config()
        self.status_var.set(f'Đang quét {len(urls)} router...')
        threading.Thread(target=self._scan_all_worker, args=(urls,), daemon=True).start()

    def _scan_all_worker(self, urls):
        payloads = []
        rows = []
        errors = []
        for idx, base_url in enumerate(urls, start=1):
            try:
                data = self._fetch_json(base_url + '/api/pm/export-all?include_hidden=1')
                payloads.append({'router_url': base_url, 'data': data})
                router_title = str(data.get('router_title', '')).strip() or base_url
                for session in data.get('sessions', []):
                    session_name = str(session.get('name', '')).strip() or f"Cấu hình {session.get('session', '')}"
                    for row in session.get('rows', []):
                        rows.append({
                            'router_title': router_title,
                            'router_url': base_url,
                            'session_name': session_name,
                            'machine': str(row.get('machine', '')).strip(),
                            'device_ip': str(row.get('ip', '')).strip(),
                            'proxy': str(row.get('proxy', '')).strip(),
                            'status': str(row.get('status', '')).strip(),
                            'note': str(row.get('note', '')).strip(),
                        })
            except Exception as e:
                errors.append(f'{base_url}: {e}')
            self.root.after(0, lambda i=idx, total=len(urls): self.status_var.set(f'Đang quét {i}/{total} router...'))

        def update_ui():
            self.router_payloads = payloads
            self.rows_cache = rows
            self.tree.delete(*self.tree.get_children())
            for item in rows:
                self.tree.insert('', 'end', values=(
                    item['router_title'], item['router_url'], item['session_name'], item['machine'],
                    item['device_ip'], item['proxy'], item['status'], item['note']
                ))
            if errors:
                self.status_var.set(f'Xong, {len(rows)} dòng, {len(errors)} router lỗi')
                messagebox.showwarning('Có router lỗi', '\n'.join(errors[:20]))
            else:
                self.status_var.set(f'Xong, {len(rows)} dòng từ {len(payloads)} router')
        self.root.after(0, update_ui)

    def export_json(self):
        if not self.router_payloads:
            messagebox.showinfo('Chưa có dữ liệu', 'Hãy quét router trước')
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json')])
        if not path:
            return
        Path(path).write_text(json.dumps(self.router_payloads, ensure_ascii=False, indent=2), encoding='utf-8')
        self.status_var.set(f'Đã xuất JSON: {path}')

    def export_csv(self):
        if not self.rows_cache:
            messagebox.showinfo('Chưa có dữ liệu', 'Hãy quét router trước')
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if not path:
            return
        import csv
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=['router_title', 'router_url', 'session_name', 'machine', 'device_ip', 'proxy', 'status', 'note'])
            writer.writeheader()
            writer.writerows(self.rows_cache)
        self.status_var.set(f'Đã xuất CSV: {path}')


if __name__ == '__main__':
    root = tk.Tk()
    app = RouterProxyExportApp(root)
    root.mainloop()
