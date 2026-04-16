#!/bin/sh
cd /mnt/e/OpenClaw/Genrouter_jobs/proxy-manager-v1
mkdir -p xxtouch_jobs/data xxtouch_jobs/log xxtouch_jobs/tmp
exec python3 app.py
