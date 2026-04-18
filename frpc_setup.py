#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import json

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


def main():
    frpc = load_json(FRPC_CFG, {})
    app = load_json(APP_CFG, {})

    router_id = str(app.get('router_id', '')).strip() or 'unknown-router'
    custom_domain = str(frpc.get('custom_domain', '')).strip()
    if not custom_domain:
        suffix = str(frpc.get('domain_suffix', 'aeg.ooguy.com')).strip() or 'aeg.ooguy.com'
        custom_domain = f"{router_id}.{suffix}"
        frpc['custom_domain'] = custom_domain
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
        .replace('{{CUSTOM_DOMAIN}}', custom_domain)
    )
    OUT_FILE.write_text(content, encoding='utf-8')
    print(custom_domain)


if __name__ == '__main__':
    main()
