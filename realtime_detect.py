import pandas as pd
import numpy as np
import joblib
import os
import time
import subprocess
import sqlite3
import requests
import re
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse, unquote
from scapy.all import AsyncSniffer, IP, TCP, Raw
from scapy_flow import ScapyFlowCollector

MODEL_DIR = os.path.expanduser("~/ips_project/models")
CSV_PATH  = os.path.expanduser("~/ips_project/captures/test.csv")
DB_PATH   = os.path.expanduser("~/ips_project/ips_logs.db")

# ==================== 설정 ====================
AUTO_UNBLOCK_MINUTES = 10
FASTAPI_URL  = "http://localhost:8000/alert"
WATCHLIST_URL = "http://localhost:8000/watchlist"
ENABLE_BLOCK = True
ENABLE_DASHBOARD = True
CONFIDENCE_THRESHOLD = 0.75
BLOCK_THRESHOLD = 1
BLOCK_WINDOW_SECONDS = 300

# 단계별 대응 임계값
LEVEL_LOW      = 0.50  # DB 정밀 기록
LEVEL_MEDIUM   = 0.60  # 대역폭 제한
LEVEL_HIGH     = 0.75  # 허니팟 리다이렉트
LEVEL_CRITICAL = 0.90  # pfctl 즉시 차단 + pcap 수집

EVIDENCE_DIR = os.path.expanduser("~/ips_project/evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Ubuntu SSH 정보 (허니팟 iptables redirect용) - bridge100은 항상 고정
UBUNTU_SSH_HOST      = '192.168.64.10'
UBUNTU_SSH_USER      = 'hisecure'
UBUNTU_REAL_PORT     = 5000
UBUNTU_HONEYPOT_PORT = 9999

# ==================== IP 자동 감지 ====================
def get_my_en0_ip():
    """현재 Mac en0 IP 자동 감지"""
    try:
        r = subprocess.run(['ipconfig', 'getifaddr', 'en0'],
                           capture_output=True, text=True, timeout=3)
        ip = r.stdout.strip()
        return ip if ip else None
    except Exception:
        return None

def get_ubuntu_wifi_ip():
    """Ubuntu 현재 WiFi IP를 bridge100 SSH로 감지"""
    try:
        r = subprocess.run(
            ['ssh', '-i', '/Users/shimyoungjong/.ssh/id_ed25519',
             '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes',
             f'{UBUNTU_SSH_USER}@{UBUNTU_SSH_HOST}',
             "ip -4 addr show | grep 'inet ' | grep -v '192.168.64\\|127.0' | awk '{print $2}' | cut -d/ -f1"],
            capture_output=True, text=True, timeout=5
        )
        ip = r.stdout.strip().split('\n')[0]
        return ip if ip else None
    except Exception:
        return None

# 시작 시 현재 네트워크 IP 자동 감지
_my_ip      = get_my_en0_ip()
_ubuntu_ip  = get_ubuntu_wifi_ip()

print(f"🌐 Mac en0 IP: {_my_ip or '감지 실패'}")
print(f"🖥️  Ubuntu WiFi IP: {_ubuntu_ip or '감지 실패 (bridge100만 사용)'}")

# 화이트리스트 (절대 차단 안 할 IP)
WHITELIST = ['127.0.0.1', '0.0.0.0', '192.168.64.1', '172.20.10.1', '172.20.10.2']
if _my_ip:
    WHITELIST.append(_my_ip)
    print(f"✅ 화이트리스트에 Mac IP 추가: {_my_ip}")

# 오탐 확인된 IP 대역 화이트리스트
WHITELIST_RANGES = [
    ipaddress.ip_network('160.79.104.0/21'),   # Anthropic (Claude AI)
    ipaddress.ip_network('121.53.93.72/32'),   # 드림라인 메일서버
    ipaddress.ip_network('13.64.0.0/11'),      # Microsoft (VSCode/Azure)
    ipaddress.ip_network('20.33.0.0/16'),      # Microsoft Azure
    ipaddress.ip_network('17.0.0.0/8'),        # Apple (백그라운드)
    ipaddress.ip_network('185.125.188.0/22'),  # Canonical (Ubuntu apt)
    ipaddress.ip_network('23.32.0.0/11'),      # Akamai CDN
    ipaddress.ip_network('34.0.0.0/8'),        # Google Cloud
]

def is_whitelisted(ip):
    if ip in WHITELIST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in WHITELIST_RANGES):
            print(f"  ⬜ [WHITELIST_SKIP] {ip} → 오탐 화이트리스트 제외")
            return True
    except ValueError:
        pass
    return False
# ==============================================

# ==================== DB 초기화 ====================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attack_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_type TEXT NOT NULL,
        attacker_ip TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        confidence  REAL NOT NULL,
        is_attack   INTEGER NOT NULL,
        blocked     INTEGER NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        ip              TEXT NOT NULL,
        attack_type     TEXT NOT NULL,
        blocked_at      TEXT NOT NULL,
        auto_unblock_at TEXT NOT NULL,
        unblocked       INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()
    print("✅ DB 초기화 완료!")

# ==================== PF 방화벽 ====================
def reload_pf():
    """테이블 변경 시마다 전체 PF 룰을 다시 로드"""
    # PF 룰 순서: 테이블 → scrub → translation(rdr) → filtering(block/pass)
    pf_rules = (
        'table <blocklist> persist\n'
        'table <throttlelist> persist\n'
        'table <highlist> persist\n'
        'scrub-anchor "com.apple.internet-sharing" all fragment reassemble\n'
        # NAT: Ubuntu VM → 외부 인터넷
        'nat on en0 from 192.168.64.0/24 to any -> (en0)\n'
        # 허니팟 리다이렉트: highlist IP가 Mac:5000 → Ubuntu 허니팟:9999
        'rdr on en0 proto tcp from <highlist> to any port 5000 -> 192.168.64.10 port 9999\n'
        # 포트 포워드: 일반 트래픽 Mac:5000 → Ubuntu Flask:5000
        'rdr on en0 proto tcp to (en0) port 5000 -> 192.168.64.10 port 5000\n'
        # bridge100 허니팟 리다이렉트 (내부 테스트용)
        'rdr on bridge100 proto tcp from <highlist> to any port 5000 -> 192.168.64.10 port 9999\n'
        'anchor "com.apple.internet-sharing" all\n'
        'block drop from <blocklist> to any\n'
        'pass in on en0 proto tcp from <throttlelist> to (en0) port 5000 '
        'keep state (max-src-conn-rate 5/1)\n'
        'pass in on bridge100 proto tcp from <throttlelist> to any port 5000 '
        'keep state (max-src-conn-rate 5/1)\n'
    )
    with open('/tmp/ips_pf.conf', 'w') as f:
        f.write(pf_rules)
    subprocess.run(['/sbin/pfctl', '-f', '/tmp/ips_pf.conf'], capture_output=True)

def init_pf():
    try:
        subprocess.run(['/sbin/pfctl', '-e'], capture_output=True)
        for table in ['blocklist', 'throttlelist', 'highlist']:
            subprocess.run(['/sbin/pfctl', '-t', table, '-T', 'flush'], capture_output=True)
        reload_pf()
        print("✅ PF 방화벽 초기화 완료!")
    except Exception as e:
        print(f"⚠️ PF 초기화 실패: {e}")

# ==================== 감시목록 조회 ====================
def get_watchlist():
    try:
        res = requests.get(WATCHLIST_URL, timeout=1)
        return {item['ip'] for item in res.json()}
    except:
        return set()

# ==================== 단계별 대응 ====================
def respond_low(ip):
    print(f"  📋 [LOW] {ip} → DB 정밀 기록 중")

SSH_KEY = '/Users/shimyoungjong/.ssh/id_ed25519'

def ubuntu_ssh(cmd):
    """Ubuntu에 SSH로 명령 실행"""
    try:
        subprocess.run(
            ['ssh', '-i', SSH_KEY,
             '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
             f'{UBUNTU_SSH_USER}@{UBUNTU_SSH_HOST}', cmd],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=5
        )
    except Exception as e:
        print(f"  ⚠️ Ubuntu SSH 실패: {e}")

def respond_medium(ip):
    print(f"  🔶 [MEDIUM] {ip} → 연결 속도 제한 (초당 5개)")
    try:
        subprocess.run(['/sbin/pfctl', '-t', 'throttlelist', '-T', 'add', ip], capture_output=True)
        reload_pf()
        ubuntu_ssh(
            f"sudo iptables -I INPUT -s {ip} -p tcp --dport 5000 "
            f"-m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 "
            f"--hashlimit-mode srcip --hashlimit-name throttle_{ip.replace('.','_')} "
            f"-j DROP"
        )
        print(f"  🔶 Ubuntu 속도 제한 적용: {ip}")
    except Exception as e:
        print(f"  ⚠️ 속도 제한 실패: {e}")

def ubuntu_iptables_redirect(ip, add=True):
    """Ubuntu에 SSH 접속해서 iptables로 특정 IP를 허니팟으로 redirect"""
    action = '--insert' if add else '--delete'
    rule = (
        f"sudo iptables {action} PREROUTING -t nat "
        f"-s {ip} -p tcp --dport {UBUNTU_REAL_PORT} "
        f"-j REDIRECT --to-port {UBUNTU_HONEYPOT_PORT}"
    )
    try:
        subprocess.run(
            ['ssh', '-i', SSH_KEY,
             '-o', 'StrictHostKeyChecking=no',
             '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes',
             '-o', 'PasswordAuthentication=no',
             f'{UBUNTU_SSH_USER}@{UBUNTU_SSH_HOST}', rule],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=5
        )
        action_str = "추가" if add else "제거"
        print(f"  🍯 Ubuntu iptables redirect {action_str}: {ip}")
    except Exception as e:
        print(f"  ⚠️ Ubuntu iptables 실패: {e}")

def add_to_watchlist(ip, reason="반복 공격 탐지", threat_level="high"):
    try:
        requests.post(f"{FASTAPI_URL.replace('/alert', '/watchlist/add')}", json={
            "ip": ip, "reason": reason, "threat_level": threat_level
        }, timeout=1)
    except Exception:
        pass

def respond_high(ip):
    print(f"  🔴 [HIGH] {ip} → 허니팟으로 리다이렉트 + 감시목록 추가")
    try:
        subprocess.run(['/sbin/pfctl', '-t', 'highlist', '-T', 'add', ip], capture_output=True)
        reload_pf()
        ubuntu_iptables_redirect(ip, add=True)
        add_to_watchlist(ip, reason="HIGH 레벨 공격 — 허니팟 리다이렉트", threat_level="high")
        watchlist_cache.add(ip)  # 즉시 캐시 반영
    except Exception as e:
        print(f"  ⚠️ 리다이렉트 실패: {e}")

def respond_critical(ip, attack_type):
    print(f"  🚫 [CRITICAL] {ip} → 즉시 차단 + pcap 수집")
    try:
        subprocess.run(['/sbin/pfctl', '-t', 'blocklist', '-T', 'add', ip], capture_output=True)
        reload_pf()
        # Ubuntu iptables 완전 차단
        ubuntu_ssh(f"sudo iptables -I INPUT -s {ip} -j DROP")
        ubuntu_ssh(f"sudo iptables -I FORWARD -s {ip} -j DROP")
        print(f"  🚫 Ubuntu iptables 차단 완료: {ip}")
        pcap_path = os.path.join(EVIDENCE_DIR, f"{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        subprocess.Popen(
            ['tcpdump', '-i', 'en0', '-w', pcap_path, f'host {ip}', '-c', '1000'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"  📁 증거 수집 중: {pcap_path}")
        unblock_time = datetime.now() + timedelta(minutes=AUTO_UNBLOCK_MINUTES)
        blocked_ips[ip] = unblock_time
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT OR IGNORE INTO blocked_ips (ip, attack_type, blocked_at, auto_unblock_at)
                     VALUES (?, ?, ?, ?)''',
                  (ip, attack_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                   unblock_time.strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"  ⚠️ 차단 실패: {e}")

def apply_response(ip, conf, attack_type, is_watchlisted):
    if is_whitelisted(ip):
        return

    if conf >= LEVEL_CRITICAL and is_watchlisted:
        respond_critical(ip, attack_type)
    elif conf >= LEVEL_HIGH:
        respond_high(ip)
    elif conf >= LEVEL_MEDIUM:
        respond_medium(ip)
    elif conf >= LEVEL_LOW:
        respond_low(ip)

# ==================== IP 차단 ====================
blocked_ips = {}     # {ip: unblock_time}
attack_counts = {}   # {ip: [timestamp, timestamp, ...]} 이중 확인용

# ==================== PortScan 휴리스틱 ====================
PORT_SCAN_THRESHOLD = 30   # 5초 안에 30개 이상 다른 포트 → PortScan
PORT_SCAN_WINDOW    = 5    # 초
port_scan_tracker   = {}   # {ip: {'ports': set, 'first_seen': float}}

def check_port_scan(src_ip, dst_port):
    now = time.time()
    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {'ports': set(), 'first_seen': now}
    t = port_scan_tracker[src_ip]
    if now - t['first_seen'] > PORT_SCAN_WINDOW:
        port_scan_tracker[src_ip] = {'ports': set(), 'first_seen': now}
        t = port_scan_tracker[src_ip]
    t['ports'].add(dst_port)
    if len(t['ports']) >= PORT_SCAN_THRESHOLD:
        port_scan_tracker[src_ip] = {'ports': set(), 'first_seen': now}
        return True
    return False

def check_attack_count(ip):
    now = time.time()
    if ip not in attack_counts:
        attack_counts[ip] = []
    attack_counts[ip] = [t for t in attack_counts[ip] if now - t < BLOCK_WINDOW_SECONDS]
    attack_counts[ip].append(now)
    return len(attack_counts[ip])

def block_ip(ip, attack_type):
    if not ENABLE_BLOCK:
        return False
    if is_whitelisted(ip):
        return False
    if ip in blocked_ips:
        return False

    try:
        subprocess.run(
            ['/sbin/pfctl', '-t', 'blocklist', '-T', 'add', ip],
            capture_output=True
        )

        unblock_time = datetime.now() + timedelta(minutes=AUTO_UNBLOCK_MINUTES)
        blocked_ips[ip] = unblock_time

        # DB 저장
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO blocked_ips (ip, attack_type, blocked_at, auto_unblock_at)
                     VALUES (?, ?, ?, ?)''',
                  (ip, attack_type,
                   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                   unblock_time.strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()

        print(f"  🚫 {ip} 차단 완료! ({AUTO_UNBLOCK_MINUTES}분 후 자동 해제)")
        return True
    except Exception as e:
        print(f"  ⚠️ 차단 실패: {e}")
        return False

# ==================== IP 자동 해제 ====================
def check_unblock():
    now = datetime.now()
    changed = False
    for ip in list(blocked_ips.keys()):
        if now >= blocked_ips[ip]:
            try:
                for table in ['blocklist', 'throttlelist', 'highlist']:
                    subprocess.run(['/sbin/pfctl', '-t', table, '-T', 'delete', ip], capture_output=True)
                ubuntu_iptables_redirect(ip, add=False)
                ubuntu_ssh(f"sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null; true")
                ubuntu_ssh(f"sudo iptables -D FORWARD -s {ip} -j DROP 2>/dev/null; true")
                ubuntu_ssh(f"sudo iptables -D PREROUTING -t nat -s {ip} -p tcp --dport 5000 -j REDIRECT --to-port 9999 2>/dev/null; true")
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('UPDATE blocked_ips SET unblocked=1 WHERE ip=? AND unblocked=0', (ip,))
                conn.commit()
                conn.close()
                del blocked_ips[ip]
                changed = True
                print(f"  🔓 {ip} 차단 해제!")
            except Exception as e:
                print(f"  ⚠️ 해제 실패: {e}")
    if changed:
        reload_pf()

# ==================== 로그 저장 ====================
def save_log(attack_type, attacker_ip, confidence, is_attack, blocked):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO attack_logs
                     (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (attack_type, attacker_ip,
                   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                   confidence, 1 if is_attack else 0, 1 if blocked else 0))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"  ⚠️ 로그 저장 실패: {e}")

# ==================== 대시보드 전송 ====================
def send_to_dashboard(attack_type, attacker_ip, confidence, is_attack, blocked):
    if not ENABLE_DASHBOARD:
        return
    try:
        requests.post(FASTAPI_URL, json={
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "confidence": confidence,
            "is_attack": is_attack,
            "blocked": blocked
        }, timeout=1)
    except Exception:
        pass

# ==================== 모델 로드 ====================
model               = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))
feature_names       = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))
classes             = joblib.load(os.path.join(MODEL_DIR, 'classes.pkl'))
http_model          = joblib.load(os.path.join(MODEL_DIR, 'rf_model_http.pkl'))
http_feature_names  = joblib.load(os.path.join(MODEL_DIR, 'http_feature_names.pkl'))
print("✅ 모델 로드 완료!")
print(f"✅ 탐지 클래스: {list(classes)}")
print(f"✅ HTTP 탐지 클래스: SQLi / XSS")

init_db()
init_pf()

# ==================== HTTP 스니퍼 ====================
def extract_http_features(payload):
    p = payload.lower()
    return [[
        len(payload),
        payload.count("'"),
        payload.count('"'),
        payload.count('--'),
        payload.count(';'),
        payload.count('='),
        payload.count(' ') + payload.count('+') + payload.count('%20'),
        payload.count('%'),
        int('select' in p),
        int('union' in p),
        int('insert' in p),
        int('drop' in p),
        int('delete' in p),
        int('update' in p),
        int(' or ' in p),
        int(' and ' in p),
        int('where' in p),
        int('from' in p),
        int('sleep' in p),
        int('benchmark' in p),
        int('<script' in p),
        int('<img' in p),
        int('<svg' in p),
        int('<iframe' in p),
        int('onerror' in p),
        int('onload' in p),
        int('onclick' in p),
        int('alert' in p),
        int('document' in p),
        int('javascript' in p),
        payload.count('<') + payload.count('>'),
        sum(payload.count(c) for c in "!@#$%^&*()[]{}|\\<>"),
    ]]

def scapy_packet_callback(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    src_ip   = pkt[IP].src
    dst_port = pkt[TCP].dport

    if is_whitelisted(src_ip):
        return

    # PortScan 휴리스틱: 모든 포트 대상으로 체크 (HTTP payload 불필요)
    if check_port_scan(src_ip, dst_port):
        conf = 0.95
        print(f"  🔍 [PortScan] 탐지! | IP: {src_ip} | {PORT_SCAN_THRESHOLD}개+ 포트 스캔")
        count = check_attack_count(src_ip)
        is_watchlisted = src_ip in watchlist_cache
        if count >= BLOCK_THRESHOLD:
            apply_response(src_ip, conf, 'PortScan', is_watchlisted)
            attack_counts[src_ip] = []
        save_log('PortScan', src_ip, conf, True, False)
        send_to_dashboard('PortScan', src_ip, conf, True, False)
        return

    # HTTP SQLi/XSS 탐지: 포트 5000만
    if dst_port != 5000:
        return
    if Raw not in pkt:
        return

    try:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
    except Exception:
        return

    get_match = re.search(r'GET ([^\s]+) HTTP', payload)
    if not get_match:
        return

    url   = get_match.group(1)
    query = unquote(urlparse(url).query)
    if not query:
        return

    try:
        X    = extract_http_features(query)
        pred = http_model.predict(X)[0]
        conf = float(http_model.predict_proba(X)[0].max())
        if pred != 'BENIGN' and conf >= 0.5:
            print(f"  🌐 [HTTP/{pred}] 탐지! (신뢰도: {conf:.1%}) | IP: {src_ip} | {query[:60]}")
            count = check_attack_count(src_ip)
            is_watchlisted = src_ip in watchlist_cache
            if count >= BLOCK_THRESHOLD:
                apply_response(src_ip, conf, pred, is_watchlisted)
                attack_counts[src_ip] = []
            save_log(pred, src_ip, conf, True, False)
            send_to_dashboard(pred, src_ip, conf, True, False)
    except Exception:
        pass

_http_sniffer = AsyncSniffer(
    iface='en0',
    filter='tcp and dst port 5000',
    prn=scapy_packet_callback,
    store=False,
)

# ==================== Scapy → RF 모델 콜백 ====================
PROTECTED_IPS = {'192.168.64.10', '192.168.64.11'} | ({_ubuntu_ip} if _ubuntu_ip else set())

def on_flow_complete(features):
    """ScapyFlowCollector 콜백: 완료된 플로우 → RF 모델 탐지"""
    try:
        src_ip = features.get('src_ip', 'unknown')
        dst_ip = features.get('dst_ip', 'unknown')

        if is_whitelisted(src_ip):
            return

        # 피처 dict → DataFrame + 파생 피처 (train_mydata.py와 동일)
        df = pd.DataFrame([features])
        df['win_ratio']         = df['init_fwd_win_byts'] / (df['init_bwd_win_byts'] + 1)
        df['payload_ratio']     = df['totlen_fwd_pkts']   / (df['totlen_bwd_pkts']   + 1)
        df['fwd_bwd_pkt_ratio'] = df['tot_fwd_pkts']      / (df['tot_bwd_pkts']      + 1)
        df['pkt_len_range']     = df['pkt_len_max']        - df['pkt_len_min']
        df['iat_cv']            = df['flow_iat_std']  / (df['flow_iat_mean']  + 1)
        df['fwd_iat_cv']        = df['fwd_iat_std']   / (df['fwd_iat_mean']   + 1)
        df['pkt_per_flow']      = (df['tot_fwd_pkts'] + df['tot_bwd_pkts']) / (df['flow_duration'] + 1)
        total_pkts              = df['tot_fwd_pkts'] + df['tot_bwd_pkts'] + 1
        df['syn_ratio']         = df['syn_flag_cnt'] / total_pkts
        df['fin_ratio']         = df['fin_flag_cnt'] / total_pkts
        df['rst_ratio']         = df['rst_flag_cnt'] / total_pkts
        df['active_idle_ratio'] = df['active_mean']  / (df['idle_mean']  + 1)
        df['bytes_per_pkt']     = df['flow_byts_s']  / (df['flow_pkts_s'] + 1)
        df['header_ratio']      = (df['fwd_header_len'] + df['bwd_header_len']) / (df['totlen_fwd_pkts'] + df['totlen_bwd_pkts'] + 1)
        df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

        # feature_names 순서로 입력 벡터 생성
        X = pd.DataFrame([[df[f].iloc[0] if f in df.columns else 0 for f in feature_names]],
                         columns=feature_names)

        pred = model.predict(X)[0]
        conf = float(model.predict_proba(X)[0].max())
        is_attack = pred != 'BENIGN'

        # 공격자 IP 결정 (보호 대상이 src이면 dst가 공격자)
        if src_ip in PROTECTED_IPS and dst_ip not in ('unknown', ''):
            attacker_ip = dst_ip
        else:
            attacker_ip = src_ip

        if is_whitelisted(attacker_ip) or attacker_ip in PROTECTED_IPS:
            return

        threshold = (0.80 if pred == 'PortScan'
                     else 0.80 if pred == 'BruteForce'
                     else 0.80 if pred == 'DDoS'
                     else 0.85 if pred == 'XSS'
                     else 0.85 if pred == 'SQLi'
                     else CONFIDENCE_THRESHOLD)
        if is_attack and conf < threshold:
            return

        if is_attack:
            count  = check_attack_count(attacker_ip)
            is_wl  = attacker_ip in watchlist_cache
            wl_tag = " [⚠️감시목록]" if is_wl else ""
            print(f"  🚨 [플로우/{pred}] 탐지! (신뢰도: {conf:.1%}) | IP: {attacker_ip} [{count}/{BLOCK_THRESHOLD}회]{wl_tag}")
            if count >= BLOCK_THRESHOLD:
                apply_response(attacker_ip, conf, pred, is_wl)
                attack_counts[attacker_ip] = []
            blocked = conf >= LEVEL_CRITICAL
            save_log(pred, attacker_ip, conf, True, blocked)
            send_to_dashboard(pred, attacker_ip, conf, True, blocked)
        else:
            save_log('BENIGN', attacker_ip, conf, False, False)

    except Exception:
        pass

# ==================== 감시목록 캐시 초기화 ====================
watchlist_cache      = set()
last_unblock_check   = datetime.now()
last_watchlist_fetch = datetime.now()

# ==================== HTTP 스니퍼 시작 ====================
_http_sniffer.start()
print("✅ Scapy HTTP 스니퍼 시작! (en0 포트 5000 → SQLi/XSS + PortScan 탐지)")

# ==================== Scapy 플로우 수집기 시작 ====================
flow_collector = ScapyFlowCollector(iface='en0', callback=on_flow_complete)
flow_collector.start()
print("✅ Scapy 플로우 수집기 시작! (en0 전체 트래픽 → RF 모델 탐지)")

print(f"\n{'='*50}")
print(f"🔍 실시간 IPS 시작! (Scapy 플로우 탐지)")
print(f"⏱️  자동 차단 해제: {AUTO_UNBLOCK_MINUTES}분")
print(f"{'='*50}\n")

# ==================== 메인 루프 (자동 해제 + 감시목록) ====================
try:
    while True:
        if (datetime.now() - last_unblock_check).seconds >= 60:
            check_unblock()
            last_unblock_check = datetime.now()
        if (datetime.now() - last_watchlist_fetch).seconds >= 30:
            watchlist_cache = get_watchlist()
            last_watchlist_fetch = datetime.now()
        time.sleep(1)
except KeyboardInterrupt:
    flow_collector.stop()
    print(f"\n{'='*50}")
    print(f"🛑 IPS 종료!")
    print(f"차단된 IP 수: {len(blocked_ips)}개")
    print(f"{'='*50}")