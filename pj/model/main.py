import os
import sys
import signal
import atexit
import sqlite3
import subprocess
import pandas as pd
import joblib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Any, Dict
import time
import asyncio

app = FastAPI()

# 모든 외부 접근 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 환경변수로 재정의 가능. 미지정 시 기존 기본값과 동일하게 동작.
#   IPS_HOME        : 프로젝트 루트 (기본 ~/ips_project)
#   IPS_SSH_KEY     : Ubuntu 접속용 SSH 키 (기본 ~/.ssh/id_ed25519)
#   IPS_UBUNTU_HOST : Ubuntu 호스트 (기본 192.168.64.10)
#   IPS_UBUNTU_USER : Ubuntu 사용자 (기본 hisecure)
#   IPS_PYTHON      : realtime_detect 실행용 Python (기본 miniforge ips_env)
IPS_HOME   = os.environ.get("IPS_HOME") or os.path.expanduser("~/ips_project")
SSH_KEY    = os.environ.get("IPS_SSH_KEY") or os.path.expanduser("~/.ssh/id_ed25519")
UBUNTU_HOST = os.environ.get("IPS_UBUNTU_HOST", "192.168.64.10")
UBUNTU_USER = os.environ.get("IPS_UBUNTU_USER", "hisecure")

DB_PATH    = os.path.join(IPS_HOME, "ips_logs.db")
MODEL_DIR  = os.path.join(IPS_HOME, "models")

# 모델 로드
model               = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))
feature_names       = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))
http_model          = joblib.load(os.path.join(MODEL_DIR, 'rf_model_http.pkl'))
http_feature_names  = joblib.load(os.path.join(MODEL_DIR, 'http_feature_names.pkl'))

# 화이트리스트 (Mac 관리 호스트 자신은 절대 차단/리다이렉트되지 않도록 보호)
WHITELIST = ['192.168.64.1', '127.0.0.1', '0.0.0.0']
AUTO_UNBLOCK_MINUTES = 10
HTTP_BLOCK_THRESHOLD = 3       # 이 횟수 이상이면 PF 차단
HTTP_BLOCK_WINDOW    = 30      # 초 단위 윈도우

blocked_ips = {}          # {ip: unblock_time}
http_attack_counts = {}   # {ip: [timestamp, ...]}  HTTP 공격 카운터

def check_http_count(ip: str) -> int:
    """HTTP 공격 횟수를 윈도우 내로 집계 후 반환"""
    now = time.time()
    if ip not in http_attack_counts:
        http_attack_counts[ip] = []
    http_attack_counts[ip] = [t for t in http_attack_counts[ip] if now - t < HTTP_BLOCK_WINDOW]
    http_attack_counts[ip].append(now)
    return len(http_attack_counts[ip])

def block_ip(ip: str, attack_type: str = "unknown") -> bool:
    """PF blocklist에 IP 추가 + blocked_ips DB 기록"""
    if ip in WHITELIST or ip in blocked_ips:
        return False
    try:
        subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'add', ip], capture_output=True)
        unblock_time = datetime.now() + timedelta(minutes=AUTO_UNBLOCK_MINUTES)
        blocked_ips[ip] = unblock_time
        # blocked_ips 테이블 기록
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO blocked_ips (ip, attack_type, blocked_at, auto_unblock_at) VALUES (?,?,?,?)",
            (ip, attack_type,
             datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
             unblock_time.strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        print(f"  🚫 [HTTP] {ip} PF 차단 완료! ({attack_type}, {AUTO_UNBLOCK_MINUTES}분 후 자동 해제)")
        return True
    except Exception as e:
        print(f"  ⚠️ [HTTP] 차단 실패: {e}")
        return False

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS attack_logs
        (id INTEGER PRIMARY KEY AUTOINCREMENT, attack_type TEXT, attacker_ip TEXT,
         timestamp TEXT, confidence REAL, is_attack INTEGER, blocked INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        ip              TEXT NOT NULL,
        attack_type     TEXT NOT NULL,
        blocked_at      TEXT NOT NULL,
        auto_unblock_at TEXT NOT NULL,
        unblocked       INTEGER DEFAULT 0,
        permanent       INTEGER DEFAULT 0,
        reviewed        INTEGER DEFAULT 0
    )''')
    # 기존 DB에 컬럼이 없으면 추가 (마이그레이션)
    for col, ddl in [('permanent', 'INTEGER DEFAULT 0'), ('reviewed', 'INTEGER DEFAULT 0')]:
        try:
            cursor.execute(f'ALTER TABLE blocked_ips ADD COLUMN {col} {ddl}')
        except sqlite3.OperationalError:
            pass  # 이미 존재함
    cursor.execute('''CREATE TABLE IF NOT EXISTS watchlist (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL UNIQUE,
        reason       TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        added_at     TEXT NOT NULL,
        active       INTEGER DEFAULT 1
    )''')
    conn.commit()
    conn.close()

init_db()

# --- 실시간 탐지용 변수 ---
# 초당 요청이 5번 이상이면 DDoS로 간주 (테스트를 위해 낮게 설정)
THRESHOLD = 5 
request_counts = {} # IP별 요청 횟수 저장

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    async def broadcast(self, data: dict):
        for connection in self.active_connections:
            try: await connection.send_json(data)
            except: pass

manager = ConnectionManager()

# [중요] 모든 요청을 감시하는 미들웨어 추가 (여기서 hping3를 잡아냅니다)
@app.middleware("http")
async def detect_ddos_middleware(request: Request, call_next):
    client_ip = request.client.host
    current_time = time.time()

    # 로컬호스트 및 우분투 서버는 DDoS 감지 제외
    if client_ip in ('127.0.0.1', '::1', '192.168.64.10', '192.168.64.11', UBUNTU_HOST):
        return await call_next(request)

    # IP별 요청 카운트 계산
    if client_ip not in request_counts:
        request_counts[client_ip] = []

    # 1초 이내의 요청만 유지
    request_counts[client_ip] = [t for t in request_counts[client_ip] if current_time - t < 1.0]
    request_counts[client_ip].append(current_time)

    # 임계치 초과 시 DB에 공격 로그 자동 저장
    if len(request_counts[client_ip]) > THRESHOLD:
        print(f"🚨 [ALERT] DDoS Detected from {client_ip}!")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO attack_logs (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked) VALUES (?,?,?,?,?,?)",
                       ("DDoS Attack", client_ip, now, 0.98, 1, 1))
        conn.commit()
        conn.close()
        
        # 대시보드에 실시간 전송
        await manager.broadcast({
            "attack_type": "DDoS Attack",
            "attacker_ip": client_ip,
            "timestamp": now,
            "confidence": 0.98,
            "is_attack": True,
            "blocked": True
        })

    response = await call_next(request)
    return response

# --- 나머지 API 엔진 ---

class AlertData(BaseModel):
    attack_type: str
    attacker_ip: str
    timestamp: str
    confidence: float
    is_attack: bool
    blocked: bool

@app.post("/alert")
async def receive_alert(data: AlertData):
    # ── 이미 차단된 IP → 조용히 무시 (로그/대시보드 미기록) ──
    if data.attacker_ip in blocked_ips:
        print(f"  🚫 [ALERT] {data.attacker_ip} 이미 차단된 IP — 무시")
        return {"status": "blocked_skip"}

    # ── HTTP 공격 횟수 카운트 → 임계치(3회/30초) 초과 시 PF 차단 ──
    count = check_http_count(data.attacker_ip)
    actually_blocked = False
    if count >= HTTP_BLOCK_THRESHOLD:
        actually_blocked = block_ip(data.attacker_ip, data.attack_type)

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attack_logs (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked) VALUES (?,?,?,?,?,?)",
        (data.attack_type, data.attacker_ip, now_str, data.confidence, int(data.is_attack), int(actually_blocked))
    )
    conn.commit()
    conn.close()
    await manager.broadcast({
        "attack_type": data.attack_type,
        "attacker_ip": data.attacker_ip,
        "timestamp": now_str,
        "confidence": data.confidence,
        "is_attack": data.is_attack,
        "blocked": actually_blocked
    })
    return {"status": "ok"}

class HttpPayload(BaseModel):
    payload: str
    attacker_ip: str = "unknown"

def extract_http_features(payload: str) -> dict:
    p = payload.lower()
    return {
        "length":        len(payload),
        "single_quote":  payload.count("'"),
        "double_quote":  payload.count('"'),
        "dash_dash":     payload.count('--'),
        "semicolon":     payload.count(';'),
        "equal_sign":    payload.count('='),
        "space_count":   payload.count(' '),
        "pct_encoded":   payload.count('%'),
        "kw_select":     int('select' in p),
        "kw_union":      int('union' in p),
        "kw_insert":     int('insert' in p),
        "kw_drop":       int('drop' in p),
        "kw_delete":     int('delete' in p),
        "kw_update":     int('update' in p),
        "kw_or":         int(' or ' in p),
        "kw_and":        int(' and ' in p),
        "kw_where":      int('where' in p),
        "kw_from":       int('from' in p),
        "kw_sleep":      int('sleep' in p),
        "kw_benchmark":  int('benchmark' in p),
        "tag_script":    int('<script' in p),
        "tag_img":       int('<img' in p),
        "tag_svg":       int('<svg' in p),
        "tag_iframe":    int('<iframe' in p),
        "attr_onerror":  int('onerror' in p),
        "attr_onload":   int('onload' in p),
        "attr_onclick":  int('onclick' in p),
        "js_alert":      int('alert' in p),
        "js_document":   int('document' in p),
        "js_javascript": int('javascript' in p),
        "angle_bracket": payload.count('<') + payload.count('>'),
        "special_total": sum(1 for c in payload if c in "\"'<>;=(){}[]"),
    }

class ServerLogData(BaseModel):
    server_type: str   # "real" or "honeypot"
    ip: str
    method: str
    path: str
    payload: str = ""
    timestamp: str = ""

server_logs: List[dict] = []   # 최근 500개 메모리 저장

@app.post("/server_log")
async def receive_server_log(data: ServerLogData):
    entry = {
        "server_type": data.server_type,
        "ip": data.ip,
        "method": data.method,
        "path": data.path,
        "payload": data.payload,
        "timestamp": data.timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    server_logs.append(entry)
    if len(server_logs) > 500:
        server_logs.pop(0)
    await manager.broadcast({"type": "server_log", **entry})
    return {"status": "ok"}

@app.get("/server_logs")
async def get_server_logs():
    return server_logs[-100:]

@app.get("/watchlist")
async def get_watchlist():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM watchlist WHERE active=1 ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/watchlist/add")
async def add_watchlist(data: dict):
    ip = data.get("ip")
    reason = data.get("reason", "auto")
    threat_level = data.get("threat_level", "low")
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO watchlist (ip, reason, threat_level, added_at, active) VALUES (?,?,?,?,1)",
        (ip, reason, threat_level, now)
    )
    conn.commit()
    conn.close()
    return {"status": "added", "ip": ip}

@app.post("/watchlist/remove")
async def remove_watchlist(data: dict):
    ip = data.get("ip")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE watchlist SET active=0 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    return {"status": "removed", "ip": ip}

# SSH_KEY는 파일 상단에서 IPS_SSH_KEY 환경변수 기준으로 정의됨

def ubuntu_ssh(cmd):
    try:
        subprocess.run(
            ['ssh', '-i', SSH_KEY,
             '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
             f'{UBUNTU_USER}@{UBUNTU_HOST}', cmd],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=5
        )
    except Exception as e:
        print(f"⚠️ Ubuntu SSH 실패: {e}")

def ubuntu_clear_ip(ip):
    """해당 IP의 기존 iptables 룰 전부 제거 후 재적용 방지"""
    ubuntu_ssh(f"sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null; true")
    ubuntu_ssh(f"sudo iptables -D FORWARD -s {ip} -j DROP 2>/dev/null; true")
    ubuntu_ssh(f"sudo iptables -D INPUT -s {ip} -p tcp --dport 5000 -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name throttle_{ip.replace('.','_')} -j DROP 2>/dev/null; true")
    ubuntu_ssh(f"sudo iptables -t nat -D PREROUTING -s {ip} -p tcp --dport 5000 -j REDIRECT --to-port 9999 2>/dev/null; true")

# ==================== 위협 레벨 기반 단계적 대응 ====================
# realtime_detect.py의 흐름 기반 탐지(apply_response)와 동일한 임계값/단계를 사용해서
# 공격 종류(흐름 기반 PortScan/DDoS든, 콘텐츠 기반 SQLi/XSS든) 상관없이 같은 기준으로 대응한다.
LEVEL_LOW              = 0.40
LEVEL_MEDIUM           = 0.55
LEVEL_HIGH             = 0.65
LEVEL_CRITICAL         = 0.80
HIGH_TO_CRITICAL_DELAY = 60   # 초 — HIGH 대응 후 이 시간 내에 다시 CRITICAL급이면 바로 완전차단

UBUNTU_REAL_PORT     = 5000
UBUNTU_HONEYPOT_PORT = 9999

high_response_time = {}   # {ip: timestamp} - HIGH 단계를 적용한 시각 (CRITICAL 승격 판단용)

def is_watchlisted(ip: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM watchlist WHERE ip=? AND active=1", (ip,))
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False

def respond_low(ip):
    print(f"  📋 [LOW] {ip} → 로그 기록 및 모니터링")

def respond_medium(ip):
    print(f"  🔶 [MEDIUM] {ip} → 연결 속도 제한 적용")
    try:
        subprocess.run(['sudo', 'pfctl', '-t', 'throttlelist', '-T', 'add', ip], capture_output=True)
        ubuntu_ssh(
            f"sudo iptables -I INPUT -s {ip} -p tcp --dport {UBUNTU_REAL_PORT} "
            f"-m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 "
            f"--hashlimit-mode srcip --hashlimit-name throttle_{ip.replace('.','_')} -j DROP"
        )
    except Exception as e:
        print(f"  ⚠️ [MEDIUM] 속도 제한 실패: {e}")

def respond_high(ip):
    print(f"  🔴 [HIGH] {ip} → 정상서버(포트 {UBUNTU_REAL_PORT}) 트래픽을 허니팟으로 리다이렉트")
    try:
        subprocess.run(['sudo', 'pfctl', '-t', 'highlist', '-T', 'add', ip], capture_output=True)
        ubuntu_ssh(
            f"sudo iptables -I PREROUTING -t nat -s {ip} -p tcp --dport {UBUNTU_REAL_PORT} "
            f"-j REDIRECT --to-port {UBUNTU_HONEYPOT_PORT}"
        )
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO watchlist (ip, reason, threat_level, added_at, active) VALUES (?,?,?,?,1)",
            (ip, "HIGH 레벨 공격 — 허니팟 리다이렉트", "high", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"  ⚠️ [HIGH] 리다이렉트 실패: {e}")

def respond_critical(ip, attack_type):
    print(f"  🚫 [CRITICAL] {ip} → 완전 차단")
    try:
        subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'add', ip], capture_output=True)
        ubuntu_ssh(f"sudo iptables -I INPUT -s {ip} -j DROP")
        ubuntu_ssh(f"sudo iptables -I FORWARD -s {ip} -j DROP")
        unblock_time = datetime.now() + timedelta(minutes=AUTO_UNBLOCK_MINUTES)
        blocked_ips[ip] = unblock_time
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO blocked_ips (ip, attack_type, blocked_at, auto_unblock_at) VALUES (?,?,?,?)",
            (ip, attack_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), unblock_time.strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"  ⚠️ [CRITICAL] 차단 실패: {e}")
        return False

def apply_threat_response(ip: str, conf: float, attack_type: str):
    """신뢰도(conf) 하나만 가지고 LOW/MEDIUM/HIGH/CRITICAL 대응을 실행.
    흐름 기반(PortScan/DDoS)이든 콘텐츠 기반(SQLi/XSS)이든 이 함수 하나로 통일."""
    if ip in WHITELIST:
        return "whitelist", False

    now = time.time()
    watchlisted = is_watchlisted(ip)
    blocked = False

    if conf >= LEVEL_CRITICAL:
        if watchlisted or (ip in high_response_time and (now - high_response_time[ip]) >= HIGH_TO_CRITICAL_DELAY):
            blocked = respond_critical(ip, attack_type)
            level = "critical"
        else:
            respond_high(ip)
            high_response_time[ip] = now - HIGH_TO_CRITICAL_DELAY  # 다음번엔 바로 CRITICAL 발동
            level = "high"
    elif conf >= LEVEL_HIGH:
        respond_high(ip)
        high_response_time[ip] = now
        level = "high"
    elif conf >= LEVEL_MEDIUM:
        respond_medium(ip)
        level = "medium"
    elif conf >= LEVEL_LOW:
        respond_low(ip)
        level = "low"
    else:
        level = "none"
    return level, blocked

def unblock_ip(ip: str):
    """차단 해제: pf/우분투 룰 제거 + DB 갱신 + 메모리 상태 정리"""
    try:
        subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'delete', ip], capture_output=True)
        subprocess.run(['sudo', 'pfctl', '-t', 'highlist', '-T', 'delete', ip], capture_output=True)
        subprocess.run(['sudo', 'pfctl', '-t', 'throttlelist', '-T', 'delete', ip], capture_output=True)
        ubuntu_clear_ip(ip)
        blocked_ips.pop(ip, None)
        high_response_time.pop(ip, None)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE blocked_ips SET unblocked=1, reviewed=1 WHERE ip=? AND unblocked=0",
            (ip,)
        )
        cursor.execute("UPDATE watchlist SET active=0 WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
        print(f"  ✅ [관리자] {ip} 차단 해제 완료")
        return True
    except Exception as e:
        print(f"  ⚠️ [관리자] {ip} 차단 해제 실패: {e}")
        return False

@app.get("/blocked_ips")
async def get_blocked_ips():
    """관리자 대기 화면용 — 현재 차단 중인 IP 목록 (해제 여부 무관, 최신순)"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM blocked_ips WHERE unblocked=0 ORDER BY id DESC"
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

@app.post("/blocked_ips/decide")
async def decide_blocked_ip(data: dict):
    """관리자가 차단 건을 검토하고 내리는 결정: keep_10min / permanent / unblock"""
    ip     = data.get("ip")
    action = data.get("action")
    if not ip or action not in ("keep_10min", "permanent", "unblock"):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="ip와 action(keep_10min/permanent/unblock)이 필요합니다.")

    if action == "unblock":
        ok = unblock_ip(ip)
        await manager.broadcast({"type": "blocked_ip_update", "ip": ip, "action": "unblock", "ok": ok})
        return {"status": "unblocked" if ok else "failed", "ip": ip}

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if action == "permanent":
        cursor.execute(
            "UPDATE blocked_ips SET permanent=1, reviewed=1, auto_unblock_at=? WHERE ip=? AND unblocked=0",
            ("9999-12-31 23:59:59", ip)
        )
    else:  # keep_10min — 타이머 재시작
        new_unblock = (datetime.now() + timedelta(minutes=AUTO_UNBLOCK_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "UPDATE blocked_ips SET permanent=0, reviewed=1, auto_unblock_at=? WHERE ip=? AND unblocked=0",
            (new_unblock, ip)
        )
        blocked_ips[ip] = datetime.now() + timedelta(minutes=AUTO_UNBLOCK_MINUTES)
    conn.commit()
    conn.close()
    await manager.broadcast({"type": "blocked_ip_update", "ip": ip, "action": action, "ok": True})
    return {"status": action, "ip": ip}

async def auto_unblock_loop():
    """10분(또는 설정 시간)이 지난 비영구 차단 IP를 주기적으로 자동 해제"""
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip FROM blocked_ips WHERE unblocked=0 AND permanent=0 AND auto_unblock_at <= ?",
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)
            )
            expired = [r[0] for r in cursor.fetchall()]
            conn.close()
            for ip in expired:
                unblock_ip(ip)
                await manager.broadcast({"type": "blocked_ip_update", "ip": ip, "action": "auto_unblock", "ok": True})
        except Exception as e:
            print(f"  ⚠️ 자동 해제 루프 오류: {e}")
        await asyncio.sleep(30)

@app.on_event("startup")
async def start_background_tasks():
    asyncio.create_task(auto_unblock_loop())

@app.post("/test_response")
async def test_response(data: dict):
    """테스트용 강제 대응 트리거 — 실제 차단 시스템까지 실행"""
    ip    = data.get("ip", "192.168.219.118")
    level = data.get("level", "medium")
    now   = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conf_map = {"low": 0.45, "medium": 0.65, "high": 0.80, "critical": 0.95}
    conf = conf_map.get(level, 0.65)

    # 기존 룰 제거 후 재적용 (중복 방지)
    ubuntu_clear_ip(ip)

    # 실제 차단 시스템 실행
    if level == "medium":
        subprocess.run(['sudo', 'pfctl', '-t', 'throttlelist', '-T', 'add', ip], capture_output=True)
        ubuntu_ssh(
            f"sudo iptables -I INPUT -s {ip} -p tcp --dport 5000 "
            f"-m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 "
            f"--hashlimit-mode srcip --hashlimit-name throttle_{ip.replace('.','_')} -j DROP"
        )
        print(f"  🔶 [TEST MEDIUM] {ip} 속도 제한 적용")

    elif level == "high":
        subprocess.run(['sudo', 'pfctl', '-t', 'highlist', '-T', 'add', ip], capture_output=True)
        ubuntu_ssh(
            f"sudo iptables -I PREROUTING -t nat -s {ip} -p tcp --dport 5000 "
            f"-j REDIRECT --to-port 9999"
        )
        print(f"  🔴 [TEST HIGH] {ip} 허니팟 리다이렉트")

    elif level == "critical":
        subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'add', ip], capture_output=True)
        ubuntu_ssh(f"sudo iptables -I INPUT -s {ip} -j DROP")
        ubuntu_ssh(f"sudo iptables -I FORWARD -s {ip} -j DROP")
        print(f"  🚫 [TEST CRITICAL] {ip} 완전 차단")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attack_logs (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked) VALUES (?,?,?,?,?,?)",
        (f"TEST_{level.upper()}", ip, now, conf, 1, 1 if level == "critical" else 0)
    )
    conn.commit()
    conn.close()

    await manager.broadcast({
        "attack_type": f"TEST_{level.upper()}",
        "attacker_ip": ip,
        "timestamp": now,
        "confidence": conf,
        "is_attack": True,
        "blocked": level == "critical"
    })
    return {"status": "ok", "level": level, "ip": ip}

@app.post("/watchlist/clear")
async def clear_watchlist():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE watchlist SET active=0")
    conn.commit()
    conn.close()
    return {"status": "cleared"}

@app.post("/detect_http")
async def detect_http(data: HttpPayload):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── 이미 차단된 IP → 즉시 거부 (로그 없이 DROP) ──
    if data.attacker_ip in blocked_ips:
        print(f"  🚫 [HTTP] {data.attacker_ip} 이미 차단된 IP — 조용히 거부 (로그 미기록)")
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="차단된 IP입니다. 접근이 거부되었습니다.")

    features = extract_http_features(data.payload)
    X = pd.DataFrame([[features.get(f, 0) for f in http_feature_names]], columns=http_feature_names)
    pred = http_model.predict(X)[0]
    conf = float(http_model.predict_proba(X).max())

    is_attack = pred != 'BENIGN'
    blocked   = False
    level     = "none"

    # ── 흐름 기반 탐지와 동일한 4단계(LOW/MEDIUM/HIGH/CRITICAL) 대응으로 통일 ──
    if is_attack:
        level, blocked = apply_threat_response(data.attacker_ip, conf, pred)
        print(f"  🚨 [HTTP] {pred} 탐지! IP: {data.attacker_ip} "
              f"(신뢰도: {conf:.1%}) → 레벨: {level.upper()}"
              + (" [화이트리스트 제외]" if level == "whitelist" else ""))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attack_logs (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked) VALUES (?,?,?,?,?,?)",
        (pred, data.attacker_ip, now, conf, int(is_attack), int(blocked))
    )
    conn.commit()
    conn.close()

    await manager.broadcast({
        "attack_type": pred,
        "attacker_ip": data.attacker_ip,
        "timestamp": now,
        "confidence": conf,
        "is_attack": is_attack,
        "blocked": blocked,
        "threat_level": level
    })
    return {"attack_type": pred, "confidence": conf, "is_attack": is_attack, "blocked": blocked, "threat_level": level}

@app.post("/predict")
async def predict_flow(flow: Dict[str, Any]):
    try:
        attacker_ip = str(flow.get('src_ip', 'unknown'))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 피처 준비
        X = pd.DataFrame([flow])
        X = X.replace([float('inf'), float('-inf')], 0).fillna(0)
        X_final = pd.DataFrame()
        for feat in feature_names:
            X_final[feat] = X[feat] if feat in X.columns else 0

        pred = model.predict(X_final)[0]
        conf = float(model.predict_proba(X_final).max())

        is_attack = pred != 'BENIGN'
        blocked = False

        if is_attack:
            blocked = block_ip(attacker_ip, pred)
            print(f"🚨 {pred} 탐지! IP: {attacker_ip} (신뢰도: {conf:.1%}) {'→ 차단' if blocked else ''}")

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO attack_logs (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked) VALUES (?,?,?,?,?,?)",
                (pred, attacker_ip, now, conf, 1, int(blocked))
            )
            conn.commit()
            conn.close()

            await manager.broadcast({
                "attack_type": pred,
                "attacker_ip": attacker_ip,
                "timestamp": now,
                "confidence": conf,
                "is_attack": True,
                "blocked": blocked
            })

        return {"attack_type": pred, "is_attack": is_attack, "blocked": blocked}
    except Exception as e:
        return {"error": str(e)}

@app.get("/stats/by_type")
async def get_stats_by_type():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_start:
        cursor.execute(
            "SELECT attack_type, COUNT(*) FROM attack_logs WHERE is_attack=1 AND timestamp >= ? GROUP BY attack_type",
            (session_start,)
        )
    else:
        cursor.execute(
            "SELECT attack_type, COUNT(*) FROM attack_logs WHERE is_attack=1 GROUP BY attack_type"
        )
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}

@app.get("/logs")
async def get_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if session_start:
        cursor.execute("SELECT * FROM attack_logs WHERE timestamp >= ? ORDER BY id DESC LIMIT 50", (session_start,))
    else:
        cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.get("/stats")
async def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_start:
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?", (session_start,))
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE is_attack=1 AND timestamp >= ?", (session_start,))
        attack = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE is_attack=0 AND timestamp >= ?", (session_start,))
        benign = cursor.fetchone()[0]
    else:
        cursor.execute("SELECT COUNT(*) FROM attack_logs")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE is_attack=1")
        attack = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE is_attack=0")
        benign = cursor.fetchone()[0]
    conn.close()
    return {"total": total, "attack": attack, "benign": benign, "status": "실시간 보호 중"}

INTERFACE   = "en0"
_MINIFORGE_ENV = "/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin"
CSV_PATH    = os.path.join(IPS_HOME, "captures", "test.csv")
CIC_PATH    = os.environ.get("IPS_CICFLOWMETER", f"{_MINIFORGE_ENV}/cicflowmeter")
PYTHON_PATH = os.environ.get("IPS_PYTHON", f"{_MINIFORGE_ENV}/python")
DETECT_PATH = os.path.join(IPS_HOME, "realtime_detect.py")
DETECT_LOG  = os.path.join(IPS_HOME, "detect.log")

cic_proc     = None
detect_proc  = None
session_start = None  # 현재 세션 시작 시간

def _kill_ips_subprocesses():
    """cic_proc/detect_proc(둘 다 sudo + setsid로 띄운 독립 세션 프로세스) 강제 종료.
    main.py가 정상 종료(/stop)든, 터미널 닫기/Ctrl+C/kill 등 비정상 종료든
    항상 호출되도록 atexit + SIGTERM/SIGHUP 핸들러에 등록되어 있음.
    이게 없으면 main.py 프로세스가 죽어도 setsid로 분리된 자식들은
    터미널 SIGHUP을 받지 않아 백그라운드에 고아 프로세스로 영원히 남는다.

    중요: cic_proc/detect_proc는 'sudo ...'로 띄워서 root 권한으로 실행됨.
    main.py 자체가 root로 안 돌고 있으면 일반 kill/pkill은 권한 때문에
    조용히 실패한다(except로 삼켜짐) — 이게 지금까지 "/stop 눌러도 백그라운드에
    남는다"의 진짜 원인일 가능성이 높음. 그래서 일반 kill과 sudo kill을 둘 다 시도함.
    sudo가 비밀번호를 요구하면 이 호출도 멈출 수 있으니, main.py를 실행하는 계정에
    'sudo kill', 'sudo pkill' 이 NOPASSWD로 허용돼 있는지 확인 필요 (visudo)."""
    global cic_proc, detect_proc
    for proc in [cic_proc, detect_proc]:
        if proc:
            try:
                pgid = os.getpgid(proc.pid)
            except Exception:
                continue
            try:
                os.killpg(pgid, signal.SIGTERM)
            except Exception:
                pass
            subprocess.run(['sudo', '-n', 'kill', '-TERM', f'-{pgid}'], capture_output=True)
    subprocess.run(['pkill', '-f', 'realtime_detect.py'], capture_output=True)
    subprocess.run(['pkill', '-f', 'cicflowmeter'], capture_output=True)
    subprocess.run(['sudo', '-n', 'pkill', '-f', 'realtime_detect.py'], capture_output=True)
    subprocess.run(['sudo', '-n', 'pkill', '-f', 'cicflowmeter'], capture_output=True)
    cic_proc = None
    detect_proc = None

atexit.register(_kill_ips_subprocesses)

def _handle_terminating_signal(signum, frame):
    _kill_ips_subprocesses()
    raise SystemExit(0)

# SIGTERM: kill 명령/정상 종료 신호, SIGHUP: 터미널 창을 그냥 닫았을 때 전달되는 신호
signal.signal(signal.SIGTERM, _handle_terminating_signal)
signal.signal(signal.SIGHUP, _handle_terminating_signal)

def clear_ubuntu_logs():
    """Ubuntu 허니팟/서버 로그 초기화"""
    try:
        subprocess.run(
            ['ssh', '-i', SSH_KEY,
             '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes',
             f'{UBUNTU_USER}@{UBUNTU_HOST}',
             'truncate -s 0 /tmp/honeypot_log.txt 2>/dev/null; true'],
            capture_output=True, timeout=5
        )
        print("🧹 Ubuntu 허니팟 로그 초기화 완료")
    except Exception as e:
        print(f"⚠️ Ubuntu 로그 초기화 실패: {e}")

@app.post("/start")
async def start_ips():
    global detect_proc, session_start, server_logs
    if detect_proc is not None and detect_proc.poll() is None:
        return {"status": "already_running"}

    session_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    server_logs.clear()   # 메모리 서버 로그 초기화
    clear_ubuntu_logs()   # Ubuntu 허니팟 로그 초기화
    # 감시목록 초기화
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE watchlist SET active=0")
    conn.commit()
    conn.close()

    os.makedirs(os.path.join(IPS_HOME, "captures"), exist_ok=True)
    if os.path.exists(CSV_PATH):
        os.remove(CSV_PATH)

    # realtime_detect.py는 자체 ScapyFlowCollector로 패킷을 직접 캡처하므로
    # cicflowmeter는 필요 없음(과거에 쓰던 CSV_PATH 경로는 이제 안 읽힘).
    # sys.executable로 지금 main.py를 실행 중인 인터프리터를 그대로 재사용해서
    # 예전 conda 환경 경로(IPS_PYTHON)에 더 이상 의존하지 않게 함.
    detect_log_f = open(DETECT_LOG, "w")
    detect_proc = subprocess.Popen(
        ["sudo", sys.executable, "-u", DETECT_PATH],
        stdout=detect_log_f, stderr=detect_log_f,
        preexec_fn=os.setsid
    )
    return {"status": "started"}

@app.post("/stop")
async def stop_ips():
    _kill_ips_subprocesses()
    return {"status": "stopped"}

@app.get("/ips_status")
async def ips_status():
    return {"running": detect_proc is not None and detect_proc.poll() is None}

@app.post("/emergency_reset")
async def emergency_reset():
    # pfctl 테이블 초기화
    for table in ['blocklist', 'highlist', 'throttlelist']:
        subprocess.run(['/sbin/pfctl', '-t', table, '-T', 'flush'], capture_output=True)
    # Ubuntu iptables 초기화
    subprocess.run(
        ['ssh', '-i', SSH_KEY,
         '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
         f'{UBUNTU_USER}@{UBUNTU_HOST}',
         'sudo iptables -F && sudo iptables -F FORWARD && sudo iptables -t nat -F'],
        capture_output=True
    )
    # 메모리 내 차단 목록 + HTTP 카운터 + 에스컬레이션 상태 초기화
    blocked_ips.clear()
    http_attack_counts.clear()
    high_response_time.clear()
    # DB 감시목록/차단목록 초기화
    conn = sqlite3.connect(DB_PATH)
    conn.execute('DELETE FROM watchlist')
    conn.execute('DELETE FROM blocked_ips')
    conn.commit()
    conn.close()
    return {"status": "emergency_reset_done"}

@app.get("/detect_log")
async def get_detect_log():
    try:
        with open(DETECT_LOG, "r") as f:
            lines = f.readlines()
        return {"lines": lines[-100:]}  # 최근 100줄
    except FileNotFoundError:
        return {"lines": []}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)