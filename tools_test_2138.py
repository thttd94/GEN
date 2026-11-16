"""Kiem tra logic moi cua 2.138/2.139 ma KHONG can router.

Chay: python tools_test_2138.py
Nap app.py bang importlib voi stub de khong dung toi /etc, /data.
"""
import os
import sys
import tempfile
import types
import json
import time
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gen_app', REPO / 'app.py')
app = importlib.util.module_from_spec(spec)

# Stub cac ham doc/ghi trang thai: giu state trong RAM.
STATE = {'__meta__': {}}


def _load_state():
    return json.loads(json.dumps(STATE))


def _save_state(st):
    STATE.clear()
    STATE.update(json.loads(json.dumps(st)))


# Nap module TRUOC, roi moi thay ham doc/ghi state (neu thay truoc se bi gia tri that ghi de).
spec.loader.exec_module(app)

app.load_session_state = _load_state
app.save_session_state = _save_state
app._ss_atomic_write = lambda p, t: None
app._ss_log = lambda m: None
app.vpn_status_json = lambda: []
app.load_vpn_map = lambda: {}

FAIL = []


def check(name, cond, extra=''):
    print(('PASS ' if cond else 'FAIL ') + name + (('  <<< ' + extra) if (extra and not cond) else ''))
    if not cond:
        FAIL.append(name)


# ---------------------------------------------------------------- 1) mili giay
now = 1794900000.0
ts = app._flow_start_ts('2026-11-16T15:04:05.123456789+07:00', now)
check('_flow_start_ts giu phan le mili giay', abs(ts % 1 - 0.123456) < 1e-5, str(ts % 1))
ts2 = app._flow_start_ts('2026-11-16T15:04:05Z', now)
check('_flow_start_ts dang Z', abs(ts2 % 1) < 1e-9, str(ts2))
ts3 = app._flow_start_ts('2026-11-16T15:04:05.500+07:00', now)
check('_flow_start_ts dang +07:00 ngan', abs(ts3 % 1 - 0.5) < 1e-6, str(ts3))
ts4 = app._flow_start_ts('rac', now)
check('_flow_start_ts chuoi rac => now', ts4 == float(now), str(ts4))

log = app.flow_log_new()
for cid, st in (('a', '2026-11-16T15:04:05.100000000+07:00'),
                ('b', '2026-11-16T15:04:05.100000000+07:00'),
                ('c', '2026-11-16T15:04:05.900000000+07:00')):
    app._flow_log_open(log, cid, {'start': st}, '192.10.3.5', 'x.com', 'proxy_1', now)
check('moi ket noi = 1 dong rieng (3 ket noi cung giay)', len(log['rows']) == 3, str(len(log['rows'])))
tset = sorted({round(r['ts'] % 1, 3) for r in log['rows']})
check('giu dung moc le trong tung dong', tset == [0.1, 0.9], str(tset))

# ------------------------------------------------------- 2) xoa log theo may
FL = {'lock': app.threading.Lock(), 'agg': {}, 'last': {}, 'since': 0.0, 'last_req': 0.0,
      'thread': None, 'err': '', 'polls': 0, 'log': app.flow_log_new()}
app.FLOW.clear()
app.FLOW.update(FL)
L = app.FLOW['log']
app._flow_log_open(L, 'a1', {'start': '2026-11-16T15:00:00.100+07:00'}, '192.10.3.5', 'x.com', 'proxy_1', now)
app._flow_log_open(L, 'a2', {'start': '2026-11-16T15:00:01.100+07:00'}, '192.10.3.5', 'y.com', 'proxy_1', now)
app._flow_log_open(L, 'b1', {'start': '2026-11-16T15:00:02.100+07:00'}, '192.10.3.6', 'z.com', 'proxy_2', now)
app.FLOW['agg'][('192.10.3.5', 'x.com', 'proxy_1')] = {'up': 1, 'down': 2, 'conns': 1, 'ids': set()}
app.FLOW['agg'][('192.10.3.6', 'z.com', 'proxy_2')] = {'up': 1, 'down': 2, 'conns': 1, 'ids': set()}
n = app.flow_log_clear('192.10.3.5')
check('xoa log theo IP: dung so dong', n == 2, str(n))
check('xoa log theo IP: con dung may khac', len(app.FLOW['log']['rows']) == 1
      and app.FLOW['log']['rows'][0]['ip'] == '192.10.3.6', str(app.FLOW['log']['rows']))
check('xoa log theo IP: agg chi con may khac',
      list(app.FLOW['agg'].keys()) == [('192.10.3.6', 'z.com', 'proxy_2')], str(list(app.FLOW['agg'])))
n = app.flow_log_clear('')
check('xoa log tat ca (ip rong)', n == 1 and app.FLOW['log']['rows'] == [], str(n))

# ---------------------------------------------------------- 3) mau note tong
STATE.clear(); STATE['__meta__'] = {}
cols = app.get_note_colors()
check('mau note mac dinh = ban do, done xanh',
      [c['words'] for c in cols] == [['ban'], ['done']] and cols[0]['color'] == '#ef4444' and cols[1]['color'] == '#22c55e',
      str(cols))
saved = app.set_note_colors([{'id': 'x', 'words': ['ban', 'bi khoa', 'BAN'], 'color': '#FF0000', 'bold': True},
                             {'id': 'x', 'words': 'ok, xong', 'color': 'sai mau', 'bold': False},
                             {'id': 'e', 'words': [], 'color': '#00ff00'}])
check('mau note: tu trung (hoa/thuong) bi gop', saved[0]['words'] == ['ban', 'bi khoa'], str(saved[0]['words']))
check('mau note: mau sai => mac dinh do', saved[1]['color'] == '#ef4444', saved[1]['color'])
check('mau note: tu dang chuoi "ok, xong" tach dung', saved[1]['words'] == ['ok', 'xong'], str(saved[1]['words']))
check('mau note: dong khong co tu bi bo', len(saved) == 2, str(saved))
check('mau note: id trung duoc doi ten', saved[0]['id'] != saved[1]['id'], str([s['id'] for s in saved]))
check('mau note: doc lai tu state', app.get_note_colors() == saved, str(app.get_note_colors()))

# -------------------------------------------- 4) may master khoa cung (bo hard-code)
STATE.clear(); STATE['__meta__'] = {}
c = app.get_conn_config()
check('master: mac dinh rong (khong con 192.10.1.10)', c['fixed_master'] == '', repr(c['fixed_master']))
new = dict(c, fixed_master='192.10.1.10')
app.set_conn_config(new)
check('master: luu duoc IP bat ky', app.get_conn_config()['fixed_master'] == '192.10.1.10')
new2 = dict(app.get_conn_config(), fixed_master='192.15.0.10')
app.set_conn_config(new2)
check('master: doi sang IP khac', app.get_conn_config()['fixed_master'] == '192.15.0.10')
check('master: khong con bien CONN_FIXED_MASTER dung trong _vpn_auto_excluded',
      '192.15.0.10' in app._vpn_auto_excluded(), str(app._vpn_auto_excluded()))

# ------------------------------------------------------- 5) 4 bang dinh tuyen
STATE.clear(); STATE['__meta__'] = {}
STATE['__meta__']['conn'] = {'bypass': ['*.apple.com'], 'block': ['bad.com'],
                            'split': {'enabled': True, 'target': 'vpn:x', 'domains': ['*.googlevideo.com']}}
STATE['__meta__']['split'] = {'enabled': True, 'target': 'vpn:x', 'domains': ['*.googlevideo.com'], 'proxy': {}}
tabs = app.get_route_tables()
check('4 bang: migrate bypass cu -> bang WAN',
      tabs['wan']['items'] == ['*.apple.com'] and tabs['wan']['on'] is True, str(tabs['wan']))
check('4 bang: migrate block cu -> bang Chan',
      tabs['block']['items'] == ['bad.com'] and tabs['block']['on'] is True, str(tabs['block']))
check('4 bang: migrate split cu -> bang Luong phu',
      tabs['split']['items'] == ['*.googlevideo.com'] and tabs['split']['on'] is True, str(tabs['split']))
check('4 bang: bang Proxy moi mac dinh tat', tabs['proxy']['on'] is False and tabs['proxy']['items'] == [], str(tabs['proxy']))

app.set_route_tables({'wan': {'on': True, 'items': ['*.a.com']},
                      'split': {'on': False, 'items': ['*.b.com']},
                      'proxy': {'on': True, 'items': ['api.c.com']},
                      'block': {'on': False, 'items': ['d.com']}})
tabs = app.get_route_tables()
check('4 bang: luu + doc lai dung', tabs['proxy'] == {'on': True, 'items': ['api.c.com']}, str(tabs['proxy']))
check('4 bang: bang tat van giu danh sach', tabs['split'] == {'on': False, 'items': ['*.b.com']}, str(tabs['split']))
check('4 bang: get_split_config theo bang split (tat)',
      app.get_split_config()['enabled'] is False and app.get_split_config()['domains'] == ['*.b.com'],
      str(app.get_split_config()))

# ------------------------------- 6) rule gencore: ap cho moi may + bang proxy theo may
STATE.clear(); STATE['__meta__'] = {}
STATE['__meta__']['split'] = {'enabled': False, 'target': '', 'domains': [], 'proxy': {}}
app.set_conn_config(dict(app.get_conn_config(), fixed_master=''))
app.set_route_tables({'wan': {'on': True, 'items': ['*.wan.com']},
                      'split': {'on': False, 'items': []},
                      'proxy': {'on': True, 'items': ['api.proxy.com']},
                      'block': {'on': True, 'items': ['bad.com']}})
doc = {'route': {'rules': [
            {'action': 'route', 'outbound': 'proxy_1', 'source_ip_cidr': '192.10.3.5'},
            {'action': 'route', 'outbound': 'proxy_2', 'source_ip_cidr': '192.10.3.6'},
            {'action': 'route', 'outbound': 'direct', 'source_ip_cidr': '192.10.3.9'},
            {'action': 'reject', 'method': 'drop'}]},
       'outbounds': [{'tag': 'proxy_1', 'type': 'socks', 'server': '1.1.1.1', 'server_port': 1080},
                     {'tag': 'proxy_2', 'type': 'socks', 'server': '2.2.2.2', 'server_port': 1080},
                     {'tag': 'direct', 'type': 'direct'}],
       'dns': {'rules': [], 'servers': []}}
changed = app.ensure_conn_rules(doc)
rules = doc['route']['rules']
print('\n--- rules sau khi chen (kind, outbound, domain_suffix/domain, source_ip):')
for r in rules:
    print('   ', r.get('action'), '|', r.get('outbound'), '|',
          r.get('domain') or r.get('domain_suffix') or r.get('ip_cidr'), '|', r.get('source_ip_cidr'))
mine = [r for r in rules if (r.get('domain') or r.get('domain_suffix')) or (r.get('outbound') == 'gen_bypass')]
wan_r = [r for r in mine if r.get('outbound') == 'gen_bypass']
blk_r = [r for r in mine if r.get('action') == 'reject']
prx_r = [r for r in mine if str(r.get('outbound') or '').startswith('proxy_')]
# [Ver 2.139b] Anh Thai chot: 4 bang CHI ap cho may co proxy; may VPN di toan bo qua VPN.
check('rule WAN: chi ap cho may co proxy (co source_ip_cidr)',
      len(wan_r) == 1 and bool(wan_r[0].get('source_ip_cidr')), str(wan_r))
check('rule Chan: chi ap cho may co proxy (co source_ip_cidr)',
      len(blk_r) == 1 and bool(blk_r[0].get('source_ip_cidr')), str(blk_r))
check('rule Luong phu: chi ap cho may co proxy (co source_ip_cidr)',
      all(bool(r.get('source_ip_cidr')) for r in rules if r.get('outbound') == 'gen_split'),
      str([r for r in rules if r.get('outbound') == 'gen_split']))
check('rule Proxy: 1 rule cho MOI may co proxy that (2 may)',
      len(prx_r) == 2 and {r['outbound'] for r in prx_r} == {'proxy_1', 'proxy_2'}, str(prx_r))
check('rule Proxy: may di truc tiep khong bi keo vao proxy',
      all(r['source_ip_cidr'] != '192.10.3.9' for r in prx_r), str(prx_r))
deny_idx = max(i for i, r in enumerate(rules) if r.get('action') == 'reject' and not (r.get('domain') or r.get('domain_suffix')))
first_match = min(i for i, r in enumerate(rules) if r in wan_r + blk_r + prx_r)
check('rule: deny-by-default van CUOI CUNG', deny_idx == len(rules) - 1, '%d vs %d' % (deny_idx, len(rules) - 1))
check('rule: rule dinh tuyen nam TRUOC deny', first_match < deny_idx, '%d/%d' % (first_match, deny_idx))

# idempotent
doc2 = json.loads(json.dumps(doc))
ch2 = app.ensure_conn_rules(doc2)
check('rule: chay lai khong doi (idempotent)', ch2 == 0, str(ch2))

# tat het 4 bang => khong con rule cua minh
app.set_route_tables({'wan': {'on': False, 'items': ['*.wan.com']},
                      'split': {'on': False, 'items': []},
                      'proxy': {'on': False, 'items': ['api.proxy.com']},
                      'block': {'on': False, 'items': ['bad.com']}})
doc3 = json.loads(json.dumps(doc))
app.ensure_conn_rules(doc3)
left = [r for r in doc3['route']['rules'] if r.get('outbound') == 'gen_bypass'
        or (r.get('action') == 'reject' and (r.get('domain') or r.get('domain_suffix')))
        or (str(r.get('outbound') or '').startswith('proxy_') and (r.get('domain') or r.get('domain_suffix')))]
check('tat het 4 bang => don sach rule cu', left == [], str(left))

# [Ver 2.138] migrate may master khoa cung tu file isolate.master cu (nang cap khong mat master)
STATE.clear(); STATE['__meta__'] = {'conn': {'bypass': [], 'block': []}}
import tempfile
tf = tempfile.NamedTemporaryFile('w', suffix='.master', delete=False, encoding='utf-8')
tf.write('# [Ver 2.94] may master (GUI 9001). 192.10.1.10 luon co.\n192.10.1.10\n')
tf.close()
app.ISO_MASTER_FILE = tf.name
check('master: nang cap tu file isolate.master cu (khong mat 192.10.1.10)',
      app.get_conn_config()['fixed_master'] == '192.10.1.10', app.get_conn_config()['fixed_master'])
new3 = dict(app.get_conn_config(), fixed_master='')
app.set_conn_config(new3)
check('master: nguoi dung xoa trang => ton trong (khong seed lai)',
      app.get_conn_config()['fixed_master'] == '', repr(app.get_conn_config()['fixed_master']))
os.unlink(tf.name)

# [Ver 2.142] 1 muc KHONG duoc nam 2 bang => BAO LOI, khong tu chuyen.
# Anh Thai chot: "...neu gap truong hop nay phai bao xxx.com dang nam o bang .... Vui long xoa truoc khi gan."
STATE.clear(); STATE['__meta__'] = {}
app.set_split_config(dict(app.get_split_config(), enabled=False, target='', domains=[]))
app.set_route_tables({'wan': {'on': False, 'items': []}, 'split': {'on': False, 'items': []},
                      'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': []}})
app.set_split_config(dict(app.get_split_config(), enabled=False, target='wan', domains=[]))
try:
    app.conn_update({'route': {'wan': {'on': True, 'items': ['*.apple.com', '*.only-wan.com']},
                               'split': {'on': True, 'items': ['*.apple.com', '*.only-split.com']},
                               'proxy': {'on': True, 'items': ['api.x.com']},
                               'block': {'on': True, 'items': ['bad.com']}}})
    check('trung bang: BAO LOI, khong tu chuyen', False, 'khong bao loi')
except ValueError as e:
    msg = str(e)
    check('trung bang: BAO LOI, khong tu chuyen', True)
    check('trung bang: bao dung ten muc + ten bang dang nam',
          '*.apple.com' in msg and 'WAN' in msg and 'xo' in msg.lower(), msg[:200])
rt = app.get_route_tables()
check('trung bang: KHONG ghi gi khi bao loi (WAN giu nguyen)',
      rt['wan']['items'] == [] or '*.apple.com' not in rt['split']['items'], str(rt))

# Muc trung LAP trong CUNG 1 bang => lang le bo (khong bao loi, khong hien 2 dong)
STATE.clear(); STATE['__meta__'] = {}
app.set_split_config(dict(app.get_split_config(), enabled=False, target='wan', domains=[]))
app.set_route_tables({'wan': {'on': False, 'items': []}, 'split': {'on': False, 'items': []},
                      'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': []}})
app.conn_update({'route': {'wan': {'on': True, 'items': ['a.com', 'A.COM', 'a.com', 'b.com']},
                           'split': {'on': False, 'items': []},
                           'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': []}}})
rt = app.get_route_tables()
check('trung trong CUNG 1 bang => chi giu 1 muc', rt['wan']['items'] == ['a.com', 'b.com'], str(rt['wan']['items']))

# Muc trung CO SAN tu cau hinh cu (khong ai sua 2 bang do) => don lang le, khong chan Luu
STATE.clear(); STATE['__meta__'] = {}
app.set_split_config(dict(app.get_split_config(), enabled=False, target='wan', domains=[]))
app.set_route_tables({'wan': {'on': True, 'items': ['*.old.com']},
                      'split': {'on': True, 'items': ['*.old.com']},
                      'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': []}})
r = app.conn_update({'route': {'block': {'on': True, 'items': ['bad.com']}}})
rt = app.get_route_tables()
legacy = [x for x in (r.get('results') or []) if x.get('cmd') == 'dinh-tuyen-trung']
check('trung co san tu cau hinh cu => don duoc, khong chan Luu',
      '*.old.com' in rt['wan']['items'] and '*.old.com' not in rt['split']['items'], str(rt))
check('trung co san tu cau hinh cu => co bao trong ket qua', bool(legacy), str(r.get('results')))

# bat bang Luong phu ma chua chon duong => bao loi ro, khong ghi nua chung
STATE.clear(); STATE['__meta__'] = {}
app.set_split_config({'enabled': False, 'target': '', 'domains': [], 'proxy': {}})
try:
    app.conn_update({'route': {'wan': {'on': False, 'items': []}, 'split': {'on': True, 'items': ['*.a.com']},
                               'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': []}}})
    check('bang Luong phu bat ma chua chon duong => bao loi', False, 'khong bao loi')
except ValueError as ve:
    check('bang Luong phu bat ma chua chon duong => bao loi', 'chua chon duong' in str(ve).lower(), str(ve))

# [Ver 2.138] luu bang Chan/Proxy MOI: rule phai sinh theo bang trong payload,
# khong theo state cu (state chua kip ghi), va xoa het danh sach thi muc cu khong song lai.
STATE.clear(); STATE['__meta__'] = {}
app.set_split_config({'enabled': False, 'target': 'wan', 'domains': [], 'proxy': {}})
app.set_route_tables({'wan': {'on': True, 'items': ['*.old-wan.com']}, 'split': {'on': False, 'items': []},
                      'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': ['old-block.com']}})
rt_new = {'wan': {'on': True, 'items': ['*.new-wan.com']}, 'split': {'on': False, 'items': []},
          'proxy': {'on': True, 'items': ['api.new.com']}, 'block': {'on': True, 'items': ['new-block.com']}}
cfg2 = dict(app.get_conn_config(), route=rt_new)
doc4 = {'route': {'rules': [{'action': 'route', 'outbound': 'proxy_1', 'source_ip_cidr': '192.10.3.5'},
                            {'action': 'reject', 'method': 'drop'}]},
        'outbounds': [{'tag': 'proxy_1', 'type': 'socks', 'server': '1.1.1.1', 'server_port': 1080},
                      {'tag': 'direct', 'type': 'direct'}],
        'dns': {'rules': [], 'servers': []}}
app.ensure_conn_rules(doc4, cfg=cfg2)
blob = json.dumps(doc4)
check('luu bang moi: rule Chan dung danh sach MOI', 'new-block.com' in blob and 'old-block.com' not in blob, blob[-200:])
check('luu bang moi: rule WAN dung danh sach MOI', 'new-wan.com' in blob and 'old-wan.com' not in blob)
check('luu bang moi: bang Proxy co rule cho may proxy', 'api.new.com' in blob)

# xoa het danh sach => muc cu khong song lai
app.set_route_tables({'wan': {'on': True, 'items': []}, 'split': {'on': False, 'items': []},
                      'proxy': {'on': False, 'items': []}, 'block': {'on': True, 'items': []}})
STATE['__meta__']['conn']['bypass'] = ['old-bypass.com']
STATE['__meta__']['conn']['block'] = ['old-block2.com']
tabs2 = app.get_route_tables()
check('xoa het danh sach: bang WAN rong (khong lay lai bypass cu)', tabs2['wan']['items'] == [], str(tabs2['wan']))
check('xoa het danh sach: bang Chan rong (khong lay lai block cu)', tabs2['block']['items'] == [], str(tabs2['block']))

# ===== [Ver 2.139b] Luong cho MAY GAN VPN (doc tu conntrack) =====
CT = """ipv4     2 tcp      6 6881 ESTABLISHED src=192.10.3.11 dst=17.57.145.136 sport=49744 dport=5223 packets=12 bytes=4422 src=17.57.145.136 dst=192.10.3.11 sport=5223 dport=49744 packets=13 bytes=4481 [ASSURED]
ipv4     2 tcp      6 3 TIME_WAIT src=192.10.3.5 dst=23.214.22.195 sport=51234 dport=443 packets=100 bytes=107506 src=23.214.22.195 dst=192.10.3.5 sport=443 dport=51234 packets=120 bytes=135871 [ASSURED]
ipv4     2 udp      17 56 src=192.10.3.14 dst=192.10.0.1 sport=52923 dport=53 packets=1 bytes=69 src=192.10.0.1 dst=192.10.3.14 sport=53 dport=52923 packets=1 bytes=219
ipv4     2 tcp      6 9 ESTABLISHED src=192.10.9.99 dst=1.2.3.4 sport=1111 dport=443 packets=1 bytes=10 src=1.2.3.4 dst=192.10.9.99 sport=443 dport=1111 packets=1 bytes=20"""
ctf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools_ct_sample.txt')
open(ctf, 'w', encoding='utf-8').write(CT)
app.CONNTRACK_PATH = ctf
app.DNSQ_LOG_PATHS = ()
app.load_vpn_map = lambda: {'192.10.3.5': 'proxy_5', '192.10.3.11': 'proxy_11', '192.10.3.14': 'proxy_14'}
app.set_flow_config(True, 'test-secret')   # flow_public_state tra som neu chua bat
app.FLOW['agg'] = {}; app.FLOW['last'] = {}; app.FLOW['log'] = app.flow_log_new()
app.FLOW['polls'] = 0; app.FLOW['err'] = ''
n = app._flow_vpn_ingest()
check('luong VPN: doc duoc ket noi tu conntrack', n >= 2, 'them %d dong' % n)
st = app.flow_public_state(view='log')
check('luong VPN: tong vao nhom vpn (khong vao proxy)', (st['totals'].get('vpn') or 0) > 0 and (st['totals'].get('proxy') or 0) == 0, str(st['totals']))
check('luong VPN: dong co kind=vpn', all(x['kind'] == 'vpn' for x in st['log']), str([x['kind'] for x in st['log']]))
check('luong VPN: bo ket noi DNS noi bo toi router', not any('192.10.0.1' in str(x['host']) for x in st['log']), str([x['host'] for x in st['log']]))
check('luong VPN: khong lay may KHONG gan VPN', not any(x['ip'] == '192.10.9.99' for x in st['log']), str([x['ip'] for x in st['log']]))
check('luong VPN: byte dung chieu (up/down khong lan)', any(x['up'] == 4422 and x['down'] == 4481 for x in st['log']), str([(x['up'], x['down']) for x in st['log']]))
n2 = app._flow_vpn_ingest()
check('luong VPN: doc lai khong sinh dong trung', n2 == 0, 'them %d' % n2)
os.remove(ctf)

# ===== [Ver 2.141] KHONG con co che 'incentive' ep duong =====
STATE.clear(); STATE['__meta__'] = {}
app.set_split_config({'enabled': True, 'target': 'proxy', 'proxy': {'type':'socks5','server':'1.2.3.4','port':1080,'username':'','password':''},
                      'domains': ['p16-ug-incentive-material-us.tiktokcdn-us.com']})
app.set_route_tables({'wan': {'on': False, 'items': []},
                      'split': {'on': True, 'items': ['p16-ug-incentive-material-us.tiktokcdn-us.com']},
                      'proxy': {'on': False, 'items': []}, 'block': {'on': False, 'items': []}})
doc5 = {'route': {'rules': [{'action':'route','outbound':'proxy_3','source_ip_cidr':'192.10.3.3'},
                            {'action':'reject','method':'drop'}]},
        'outbounds': [{'tag':'proxy_3','type':'socks','server':'1.1.1.1','server_port':1080},
                      {'tag':'direct','type':'direct'}],
        'dns': {'rules': [], 'servers': []}}
app.ensure_split_rules(doc5)
blob = json.dumps(doc5)
check('khong con rule incentive ep duong', 'domain_keyword' not in blob or 'incentive' not in blob, blob[:300])
# rule gen_split phai dung TRUOC rule proxy_3
idx_split = next(i for i, r in enumerate(doc5['route']['rules']) if r.get('outbound') == 'gen_split')
idx_proxy = next(i for i, r in enumerate(doc5['route']['rules']) if r.get('outbound') == 'proxy_3')
check('bang Luong phu dung TRUOC proxy_N (first-match-wins)', idx_split < idx_proxy,
      'split@%d proxy@%d' % (idx_split, idx_proxy))
check('host nguoi dung dat vao Luong phu => vao gen_split',
      any('p16-ug-incentive-material-us.tiktokcdn-us.com' in json.dumps(r)
          for r in doc5['route']['rules'] if r.get('outbound') == 'gen_split'), 'khong thay')

print('\n=== %d FAIL / %d check' % (len(FAIL), len(FAIL) + 0))
if FAIL:
    print('FAILED:', FAIL)
    sys.exit(1)
print('ALL PASS')
