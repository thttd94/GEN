#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent
FRPC_CFG = BASE_DIR / 'frpc_config.json'
APP_CFG = BASE_DIR / 'collector_config.json'
REGISTRY = BASE_DIR / 'frp_registry.json'
OUT_FILE = BASE_DIR / 'frpc.generated.toml'


def load_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    frpc = load_json(FRPC_CFG, {})
    app = load_json(APP_CFG, {})
    reg = load_json(REGISTRY, {'next_port': 21050, 'assigned': {}})

    router_id = str(app.get('router_id', '')).strip() or 'unknown-router'
    assigned = reg.setdefault('assigned', {})
    port = int(frpc.get('remote_port', 0) or 0)
    if port <= 0:
        if router_id in assigned:
            port = int(assigned[router_id])
        else:
            port = int(reg.get('next_port', 21050) or 21050)
            assigned[router_id] = port
            reg['next_port'] = port + 1
            save_json(REGISTRY, reg)
    frpc['remote_port'] = port
    save_json(FRPC_CFG, frpc)

    template = (BASE_DIR / 'frpc_template.toml').read_text(encoding='utf-8')
    content = (template
        .replace('{{SERVER_HOST}}', str(frpc.get('server_host', 'aeg.ooguy.com')))
        .replace('{{SERVER_PORT}}', str(frpc.get('server_port', 7000)))
        .replace('{{AUTH_TOKEN}}', str(frpc.get('auth_token', '')))
        .replace('{{SERVICE_NAME}}', str(frpc.get('service_name', 'genrouter-web')))
        .replace('{{ROUTER_ID}}', router_id)
        .replace('{{LOCAL_IP}}', str(frpc.get('local_ip', '127.0.0.1')))
        .replace('{{LOCAL_PORT}}', str(frpc.get('local_port', 9001)))
        .replace('{{REMOTE_PORT}}', str(port))
    )
    OUT_FILE.write_text(content, encoding='utf-8')
    print(port)


if __name__ == '__main__':
    main()
