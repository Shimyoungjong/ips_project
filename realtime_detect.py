import pandas as pd
import numpy as np
import joblib
import os
import time
import subprocess
import sqlite3
import requests
import ipaddress
import socket
import threading
import atexit
import signal
from datetime import datetime, timedelta
from scapy_flow import ScapyFlowCollector

# ==================== 경로/환경 설정 ====================
# 환경변수로 재정의 가능. 미지정 시 기존 기본값과 동일하게 동작.
#   IPS_HOME        : 프로젝트 루트 (기본 ~/ips_project)
#   IPS_SSH_KEY     : Ubuntu 접속용 SSH 키 (기본 ~/.ssh/id_ed25519)
#   IPS_UBUNTU_HOST : Ubuntu 호스트 (기본 192.168.64.10)
#   IPS_UBUNTU_USER : Ubuntu 사용자 (기본 hisecure)
IPS_HOME  = os.environ.get("IPS_HOME") or os.path.expanduser("~/ips_project")

MODEL_DIR = os.path.join(IPS_HOME, "models")
CSV_PATH  = os.path.join(IPS_HOME, "captures", "test.csv")
DB_PATH   = os.path.join(IPS_HOME, "ips_logs.db")

# ==================== 설정 ====================
FASTAPI_URL  = "http://localhost:8000/alert"
WATCHLIST_URL = "http://localhost:8000/watchlist"
ENABLE_DASHBOARD = True
BLOCK_WINDOW_SECONDS = 300
RULES_PATH = os.path.join(IPS_HOME, "rules.json")

import json

def load_rules():
    global AUTO_UNBLOCK_MINUTES, ENABLE_BLOCK, BLOCK_THRESHOLD
    global LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL
    global HIGH_TO_CRITICAL_DELAY, DETECTION_THRESHOLD
    try:
        with open(RULES_PATH) as f:
            r = json.load(f)
        AUTO_UNBLOCK_MINUTES  = r.get('auto_unblock_minutes', 10)
        ENABLE_BLOCK          = r.get('enable_block', True)
        BLOCK_THRESHOLD       = r.get('block_threshold', 3)
        LEVEL_LOW             = r.get('level_low', 0.40)
        LEVEL_MEDIUM          = r.get('level_medium', 0.55)
        LEVEL_HIGH            = r.get('level_high', 0.65)
        LEVEL_CRITICAL        = r.get('level_critical', 0.80)
        HIGH_TO_CRITICAL_DELAY= r.get('high_to_critical_delay', 60)
        DETECTION_THRESHOLD   = r.get('detection_threshold', {})
        for ip in r.get('extra_whitelist', []):
            if ip not in WHITELIST:
                WHITELIST.append(ip)
        print(f"✅ rules.json 로드 완료 (BLOCK_THRESHOLD={BLOCK_THRESHOLD}, HIGH={LEVEL_HIGH}, CRITICAL={LEVEL_CRITICAL})")
    except Exception as e:
        print(f"⚠️ rules.json 로드 실패: {e}")

# 초기 기본값
AUTO_UNBLOCK_MINUTES = 10
ENABLE_BLOCK = True
BLOCK_THRESHOLD = 3
LEVEL_LOW      = 0.40
LEVEL_MEDIUM   = 0.55
LEVEL_HIGH     = 0.65
LEVEL_CRITICAL = 0.80
HIGH_TO_CRITICAL_DELAY = 60
DETECTION_THRESHOLD = {}

EVIDENCE_DIR = os.path.join(IPS_HOME, "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Ubuntu SSH 정보 (허니팟 iptables redirect용) - bridge100은 항상 고정
UBUNTU_SSH_HOST      = os.environ.get("IPS_UBUNTU_HOST", '192.168.64.10')
UBUNTU_SSH_USER      = os.environ.get("IPS_UBUNTU_USER", 'hisecure')
UBUNTU_REAL_PORT     = 5000
UBUNTU_HONEYPOT_PORT = 9999
SSH_KEY = os.environ.get("IPS_SSH_KEY") or os.path.expanduser("~/.ssh/id_ed25519")

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
            ['ssh', '-i', SSH_KEY,
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

def get_default_gateway():
    """현재 라우팅 테이블의 default gateway 자동 감지 (네트워크 바뀌어도 항상 예외처리)"""
    try:
        r = subprocess.run(['route', '-n', 'get', 'default'],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if 'gateway:' in line:
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return None

def get_self_ips():
    """이 호스트(Mac) 자신의 모든 IP — self-block 방지용 동적 화이트리스트"""
    ips = {'127.0.0.1', '0.0.0.0'}
    try:
        hostname = socket.gethostname()
        ips |= set(socket.gethostbyname_ex(hostname)[2])
    except Exception:
        pass
    return ips

# 화이트리스트 (절대 차단 안 할 IP)
# self-IP / 게이트웨이는 네트워크가 바뀌어도(가정 와이파이 ↔ 핫스팟) 항상 동적으로 감지해서 추가
# → 과거 IPS가 맥북 자기 자신을 PortScan으로 오탐·차단해 인터넷이 끊긴 장애 재발 방지
WHITELIST = list({'127.0.0.1', '0.0.0.0', '192.168.64.1'}
                  | get_self_ips()
                  | ({_my_ip} if _my_ip else set())
                  | ({get_default_gateway()} if get_default_gateway() else set()))
print(f"⬜ 화이트리스트(self/gateway 포함): {WHITELIST}")

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
        f'rdr on en0 proto tcp from <highlist> to any port 5000 -> {UBUNTU_SSH_HOST} port 9999\n'
        # 포트 포워드: 일반 트래픽 Mac:5000 → Ubuntu Flask:5000
        f'rdr on en0 proto tcp to (en0) port 5000 -> {UBUNTU_SSH_HOST} port 5000\n'
        # bridge100 허니팟 리다이렉트 (내부 테스트용)
        f'rdr on bridge100 proto tcp from <highlist> to any port 5000 -> {UBUNTU_SSH_HOST} port 9999\n'
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

# SSH_KEY는 파일 상단에서 IPS_SSH_KEY 환경변수 기준으로 정의됨

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

    now = time.time()
    if conf >= LEVEL_CRITICAL:
        # 감시목록 or HIGH 이력 있으면 즉시 CRITICAL, 아니면 HIGH로 격상 후 CRITICAL 준비
        if is_watchlisted or (ip in high_response_time and (now - high_response_time[ip]) >= HIGH_TO_CRITICAL_DELAY):
            respond_critical(ip, attack_type)
        else:
            respond_high(ip)
            high_response_time[ip] = now - HIGH_TO_CRITICAL_DELAY  # 다음번엔 바로 CRITICAL 발동
    elif conf >= LEVEL_HIGH:
        respond_high(ip)
        high_response_time[ip] = now
    elif conf >= LEVEL_MEDIUM:
        respond_medium(ip)
    elif conf >= LEVEL_LOW:
        respond_low(ip)

# ==================== IP 차단 ====================
blocked_ips = {}     # {ip: unblock_time}
attack_counts = {}   # {ip: [timestamp, timestamp, ...]} 이중 확인용
high_response_time = {}  # {ip: timestamp} HIGH 발동 시각 기록
HIGH_TO_CRITICAL_DELAY = 60  # HIGH → CRITICAL 최소 대기 시간 (초)
dst_port_tracker = {}   # {ip: set(dst_ports)} 목적지 포트 추적
DST_PORT_WINDOW = 30    # 초


def check_attack_count(ip):
    now = time.time()
    if ip not in attack_counts:
        attack_counts[ip] = []
    attack_counts[ip] = [t for t in attack_counts[ip] if now - t < BLOCK_WINDOW_SECONDS]
    attack_counts[ip].append(now)
    return len(attack_counts[ip])


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
print("✅ 모델 로드 완료!")
print(f"✅ 탐지 클래스: {list(classes)}")

init_db()
init_pf()


# ==================== Scapy → RF 모델 콜백 ====================
PROTECTED_IPS = {'192.168.64.10', '192.168.64.11', UBUNTU_SSH_HOST} | ({_ubuntu_ip} if _ubuntu_ip else set())

# 보호 대상(타겟) 명시 — 웹서버(5000)/허니팟(9999)으로 향하거나 그 응답인 플로우만 탐지 대상으로 삼음.
# 이걸 두면 Mac 자체 트래픽이든 Ubuntu 관리 트래픽이든 "보호 자산"과 무관한 플로우는
# 캡처 소스(en0 / ubuntu_agent)가 뭐든 상관없이 애초에 모델 판정 자체를 안 함.
PROTECT_TARGET_PORTS = {UBUNTU_REAL_PORT, UBUNTU_HONEYPOT_PORT}

def on_flow_complete(features):
    """ScapyFlowCollector 콜백: 완료된 플로우 → RF 모델 탐지"""
    try:
        src_ip = features.get('src_ip', 'unknown')
        dst_ip = features.get('dst_ip', 'unknown')

        if is_whitelisted(src_ip):
            return

        # 보호 대상(웹서버/허니팟) 포트와 무관한 플로우는 애초에 판정하지 않음
        _sp = int(features.get('src_port', 0) or 0)
        _dp = int(features.get('dst_port', 0) or 0)
        if PROTECT_TARGET_PORTS and _sp not in PROTECT_TARGET_PORTS and _dp not in PROTECT_TARGET_PORTS:
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

        # 공격자 IP 결정 (보호 대상이 src이면 dst가 공격자)
        if src_ip in PROTECTED_IPS and dst_ip not in ('unknown', ''):
            attacker_ip = dst_ip
        else:
            attacker_ip = src_ip

        # DDoS → PortScan 후처리: 목적지 포트 종류 3개 이상이면 PortScan으로 변경
        dst_port = int(features.get('dst_port', 0))
        now_t = time.time()
        if attacker_ip not in dst_port_tracker:
            dst_port_tracker[attacker_ip] = {'ports': set(), 'first_seen': now_t}
        if now_t - dst_port_tracker[attacker_ip]['first_seen'] > DST_PORT_WINDOW:
            dst_port_tracker[attacker_ip] = {'ports': set(), 'first_seen': now_t}
        dst_port_tracker[attacker_ip]['ports'].add(dst_port)
        if pred == 'DDoS' and len(dst_port_tracker[attacker_ip]['ports']) >= 3:
            pred = 'PortScan'

        is_attack = pred != 'BENIGN'

        if is_whitelisted(attacker_ip) or attacker_ip in PROTECTED_IPS:
            return

        # 이미 차단된 IP → 조용히 DROP (로그/대시보드 미기록)
        if attacker_ip in blocked_ips:
            print(f"  🚫 [DROP] {attacker_ip} 이미 차단된 IP — 플로우 무시")
            return

        threshold = DETECTION_THRESHOLD.get(pred, LEVEL_HIGH)
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
            blocked = attacker_ip in blocked_ips
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

# ==================== Ubuntu 에이전트 수신 서버 ====================
AGENT_PORT = 9001

def _handle_agent_client(conn, addr):
    print(f"✅ Ubuntu 에이전트 연결됨: {addr[0]}:{addr[1]}")
    buf = ''
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data.decode('utf-8', errors='ignore')
            while '\n' in buf:
                line, buf = buf.split('\n', 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    features = json.loads(line)
                    on_flow_complete(features)
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        conn.close()
        print(f"⚠️ Ubuntu 에이전트 연결 끊김: {addr[0]}")

def _agent_server_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', AGENT_PORT))
    srv.listen(5)
    print(f"✅ Ubuntu 에이전트 수신 서버 시작! (포트 {AGENT_PORT})")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=_handle_agent_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception:
            pass

threading.Thread(target=_agent_server_thread, daemon=True).start()

# ==================== Scapy 플로우 수집기 시작 ====================
flow_collector = ScapyFlowCollector(iface='en0', callback=on_flow_complete)
flow_collector.start()
print("✅ Scapy 플로우 수집기 시작! (en0 전체 트래픽 → RF 모델 탐지)")

print(f"\n{'='*50}")
print(f"🔍 실시간 IPS 시작! (Scapy 플로우 탐지)")
print(f"⏱️  자동 차단 해제: {AUTO_UNBLOCK_MINUTES}분")
print(f"{'='*50}\n")

# ==================== 메인 루프 (자동 해제 + 감시목록 + 룰 갱신) ====================
_rules_mtime = 0
load_rules()  # 시작 시 룰 로드

def cleanup_pf():
    """종료 시 pf 차단 테이블 정리 — '유령 룰' 잔존으로 인터넷이 영구 차단되는 것 방지"""
    try:
        for table in ['blocklist', 'throttlelist', 'highlist']:
            subprocess.run(['/sbin/pfctl', '-t', table, '-T', 'flush'], capture_output=True)
        print("🧹 pf 차단 테이블 정리 완료 (blocklist/throttlelist/highlist flush)")
    except Exception as e:
        print(f"⚠️ pf 정리 실패: {e}")

atexit.register(cleanup_pf)
signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit()))

try:
    while True:
        if (datetime.now() - last_unblock_check).seconds >= 60:
            check_unblock()
            last_unblock_check = datetime.now()
        if (datetime.now() - last_watchlist_fetch).seconds >= 30:
            watchlist_cache = get_watchlist()
            last_watchlist_fetch = datetime.now()
        # rules.json 변경 감지 → 자동 반영
        try:
            mtime = os.path.getmtime(RULES_PATH)
            if mtime != _rules_mtime:
                _rules_mtime = mtime
                load_rules()
        except Exception:
            pass
        time.sleep(1)
except (KeyboardInterrupt, SystemExit):
    flow_collector.stop()
    print(f"\n{'='*50}")
    print(f"🛑 IPS 종료!")
    print(f"차단된 IP 수: {len(blocked_ips)}개")
    print(f"{'='*50}")