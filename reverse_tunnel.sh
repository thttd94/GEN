#!/bin/sh
set -eu

APP_DIR="/opt/proxy-manager-v1"
CFG="$APP_DIR/reverse_tunnel_config.json"
[ -f "$CFG" ] || CFG="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/reverse_tunnel_config.json"

json_get() {
  KEY="$1"
  python3 - "$CFG" "$KEY" <<'PY'
import json,sys
path,key=sys.argv[1],sys.argv[2]
with open(path,'r',encoding='utf-8') as f:
    data=json.load(f)
val=data.get(key,'')
if isinstance(val,bool):
    print('true' if val else 'false', end='')
else:
    print(val, end='')
PY
}

ENABLED="$(json_get enabled)"
[ "$ENABLED" = "true" ] || exit 0
SERVER_HOST="$(json_get server_host)"
SERVER_PORT="$(json_get server_port)"
SERVER_USER="$(json_get server_user)"
REMOTE_BIND_PORT="$(json_get remote_bind_port)"
LOCAL_SSH_PORT="$(json_get local_ssh_port)"
SSH_KEY_PATH="$(json_get ssh_key_path)"
ALIVE_INTERVAL="$(json_get server_alive_interval)"
ALIVE_COUNT_MAX="$(json_get server_alive_count_max)"

[ -n "$SERVER_HOST" ] || exit 1
[ -n "$REMOTE_BIND_PORT" ] || exit 1
[ -n "$SERVER_USER" ] || exit 1
[ -n "$SSH_KEY_PATH" ] || exit 1

exec ssh \
  -i "$SSH_KEY_PATH" \
  -N \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/root/.ssh/known_hosts \
  -o ServerAliveInterval="$ALIVE_INTERVAL" \
  -o ServerAliveCountMax="$ALIVE_COUNT_MAX" \
  -o ExitOnForwardFailure=yes \
  -p "$SERVER_PORT" \
  -R "${REMOTE_BIND_PORT}:127.0.0.1:${LOCAL_SSH_PORT}" \
  "${SERVER_USER}@${SERVER_HOST}"
