#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import json
import re

BASE_DIR = Path(__file__).resolve().parent
FRPC_CFG = BASE_DIR / 'frpc_config.json'
APP_CFG = BASE_DIR / 'collector_config.json'
OUT_FILE = BASE_DIR / 'frpc.generated.toml'


def load_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def slugify(value: str):
    value = re.sub(r'[^a-zA-Z0-9]+', '-', str(value or '').strip()).strip('-').lower()
    return value or 'genrouter-web'


def main():
    frpc = load_json(FRPC_CFG, {})
    app = load_json(APP_CFG, {})

    router_id = str(app.get('router_id', '')).strip() or 'unknown-router'
    suffix = str(frpc.get('domain_suffix', 'aeg.ooguy.com')).strip() or 'aeg.ooguy.com'
    server_host = str(frpc.get('server_host', 'aeg.ooguy.com')).strip() or 'aeg.ooguy.com'
    custom_domain = f"{router_id}.{suffix}"
    service_name = slugify(frpc.get('service_name', 'genrouter-web'))
    remote_domain = str(frpc.get('remote_http_domain', '')).strip() or f"{router_id}-remote.{suffix}"
    ws_remote_port = int(frpc.get('remote_ws_port', 0) or 0)
    if ws_remote_port <= 0:
        ws_remote_port = 24000 + sum(ord(ch) for ch in router_id) % 10000
        frpc['remote_ws_port'] = ws_remote_port

    changed = False
    if str(frpc.get('custom_domain', '')).strip() != custom_domain:
        frpc['custom_domain'] = custom_domain
        changed = True
    if str(frpc.get('remote_http_domain', '')).strip() != remote_domain:
        frpc['remote_http_domain'] = remote_domain
        changed = True
    if changed:
        save_json(FRPC_CFG, frpc)

    template = (BASE_DIR / 'frpc_template.toml').read_text(encoding='utf-8')
    content = (template
        .replace('{{SERVER_HOST}}', server_host)
        .replace('{{SERVER_PORT}}', str(frpc.get('server_port', 7000)))
        .replace('{{AUTH_TOKEN}}', str(frpc.get('auth_token', '')))
        .replace('{{SERVICE_NAME}}', service_name)
        .replace('{{ROUTER_ID}}', router_id)
        .replace('{{LOCAL_IP}}', str(frpc.get('local_ip', '127.0.0.1')))
        .replace('{{LOCAL_PORT}}', str(frpc.get('local_port', 9001)))
        .replace('{{CUSTOM_DOMAIN}}', custom_domain)
        .replace('{{REMOTE_HTTP_DOMAIN}}', remote_domain)
        .replace('{{REMOTE_HTTP_LOCAL_PORT}}', str(frpc.get('remote_http_local_port', 46952)))
        .replace('{{REMOTE_WS_LOCAL_PORT}}', str(frpc.get('remote_ws_local_port', 46968)))
        .replace('{{REMOTE_WS_PORT}}', str(ws_remote_port))
    )
    OUT_FILE.write_text(content, encoding='utf-8')
    print(json.dumps({
        'custom_domain': custom_domain,
        'remote_http_domain': remote_domain,
        'remote_ws_port': ws_remote_port,
        'remote_http_url': f'http://{remote_domain}',
        'remote_ws_url': f'ws://{server_host}:{ws_remote_port}',
    }, ensure_ascii=False))


if __name__ == '__main__':
    main()
