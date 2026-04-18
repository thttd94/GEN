#!/bin/sh
while true; do
  nslookup aeg.ooguy.com >/dev/null 2>&1 || { sleep 10; continue; }
  cd /opt/proxy-manager-v1 || exit 1
  python3 /opt/proxy-manager-v1/frpc_setup.py >/tmp/genrouter-frpc-domain.log 2>&1 || { sleep 10; continue; }
  ./frpc -c /opt/proxy-manager-v1/frpc.generated.toml >>/tmp/genrouter-frpc.log 2>&1
  sleep 10
done
