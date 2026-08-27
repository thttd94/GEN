#!/bin/sh
# apply_2_19.sh - Loai bo toan bo XXTouch khoi Genrouter (Ver 2.19)
# Chay tu /opt/proxy-manager-v1/update/2.19/ (sau khi gen_update.sh copy vao)
set -e

APP=/opt/proxy-manager-v1/app.py
BACKUP_DIR=/data/genrouter_backups
TS=$(date +%Y%m%d_%H%M%S)
LOG=/tmp/apply_2_19_$TS.log

echo "[*] Ver 2.19 - Loai bo XXTouch - $TS" | tee $LOG
echo "[*] Log: $LOG" | tee -a $LOG

# 1. Backup
echo "[1/6] Backup app.py..." | tee -a $LOG
cp $APP $BACKUP_DIR/app_pre_remove_xxtouch_${TS}.py
md5sum $APP $BACKUP_DIR/app_pre_remove_xxtouch_${TS}.py | tee -a $LOG

# 2. Disable static xxtouch (neu co)
echo "[2/6] Disable static/xxtouch/..." | tee -a $LOG
if [ -d /opt/proxy-manager-v1/static/xxtouch ]; then
  mv /opt/proxy-manager-v1/static/xxtouch /opt/proxy-manager-v1/static/xxtouch.disabled_$TS
  echo "  renamed to xxtouch.disabled_$TS" | tee -a $LOG
else
  echo "  (khong co folder xxtouch)" | tee -a $LOG
fi

# 3. Apply Ver 2.19 app.py (neu co file moi)
echo "[3/6] Apply Ver 2.19 app.py..." | tee -a $LOG
if [ -f ./app.py ]; then
  # Verify syntax truoc
  python3 -c "import ast; ast.parse(open('./app.py').read())" 2>&1 | tee -a $LOG
  cp ./app.py $APP
  echo "  applied" | tee -a $LOG
elif [ -f /tmp/remove_xxtouch_v8.py ]; then
  # Fallback: chay transformation scripts
  echo "  (khong co app.py moi, chay transformation scripts)" | tee -a $LOG
  python3 /tmp/remove_xxtouch_v8.py 2>&1 | tee -a $LOG
  python3 /tmp/fix_remaining.py 2>&1 | tee -a $LOG
  python3 /tmp/fix2.py 2>&1 | tee -a $LOG
  python3 /tmp/fix3.py 2>&1 | tee -a $LOG
fi

# 4. Verify syntax cuoi
echo "[4/6] Verify syntax..." | tee -a $LOG
python3 -c "import ast; ast.parse(open('$APP').read()); print('  parse OK')" 2>&1 | tee -a $LOG

# 5. Verify khong con ref xxtouch
echo "[5/6] Verify khong con XXTouch refs..." | tee -a $LOG
REMAINING=$(grep -cE 'XXTOUCH_|xxtouch_jobs|admanager_machine_note_text|admanager_get_machine_ip_pairs|ensure_xxtouch_workspace|group3_schedule|load_group3|create_group3|save_group3' $APP 2>/dev/null || echo 0)
echo "  remaining refs: $REMAINING" | tee -a $LOG
if [ "$REMAINING" != "0" ]; then
  echo "  [!] CANH BAO: van con $REMAINING refs XXTouch. Kiem tra lai." | tee -a $LOG
fi

# 6. Restart
echo "[6/6] Restart proxy-manager-v1..." | tee -a $LOG
PID=$(pgrep -f 'python3 /opt/proxy-manager-v1/app.py' | head -1)
if [ -n "$PID" ]; then
  kill $PID
  sleep 2
fi
( python3 /opt/proxy-manager-v1/app.py >/tmp/pmv1_v219_$TS.log 2>&1 </dev/null & )
sleep 3
NEWPID=$(pgrep -f 'python3 /opt/proxy-manager-v1/app.py' | head -1)
echo "  new pid: $NEWPID" | tee -a $LOG

# 7. Smoke test
echo "[7/7] Smoke test..." | tee -a $LOG
echo "  GET /:" | tee -a $LOG
wget -qO- --timeout=5 http://127.0.0.1:9001/ 2>&1 | head -1 | tee -a $LOG
echo "  GET /api/admanager/config:" | tee -a $LOG
wget -qO- --timeout=5 http://127.0.0.1:9001/api/admanager/config 2>&1 | head -c 100 | tee -a $LOG
echo "" | tee -a $LOG
echo "  GET /api/xxtouch/scan-devices (expect 404):" | tee -a $LOG
wget -qO- --timeout=5 http://127.0.0.1:9001/api/xxtouch/scan-devices 2>&1 | head -1 | tee -a $LOG
echo "  GET /api/admanager/scan (expect 404):" | tee -a $LOG
wget -qO- --timeout=5 http://127.0.0.1:9001/api/admanager/scan 2>&1 | head -1 | tee -a $LOG

echo "" | tee -a $LOG
echo "[OK] Ver 2.19 applied. Log: $LOG" | tee -a $LOG