import os
import signal
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

app = FastAPI()

# 모든 외부 접근 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH    = os.path.expanduser("~/ips_project/ips_logs.db")
MODEL_DIR  = os.path.expanduser("~/ips_project/models")

# 모델 로드
model               = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))
feature_names       = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))
http_model          = joblib.load(os.path.join(MODEL_DIR, 'rf_model_http.pkl'))
http_feature_names  = joblib.load(os.path.join(MODEL_DIR, 'http_feature_names.pkl'))

# 화이트리스트
WHITELIST = ['192.168.100.160', '192.168.64.1', '127.0.0.1', '0.0.0.0', '172.20.10.2']
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
        unblocked       INTEGER DEFAULT 0
    )''')
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
    if client_ip in ('127.0.0.1', '::1', '192.168.64.10', '192.168.64.11'):
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attack_logs (attack_type, attacker_ip, timestamp, confidence, is_attack, blocked) VALUES (?,?,?,?,?,?)",
        (data.attack_type, data.attacker_ip, data.timestamp, data.confidence, int(data.is_attack), int(data.blocked))
    )
    conn.commit()
    conn.close()
    await manager.broadcast({
        "attack_type": data.attack_type,
        "attacker_ip": data.attacker_ip,
        "timestamp": data.timestamp,
        "confidence": data.confidence,
        "is_attack": data.is_attack,
        "blocked": data.blocked
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

SSH_KEY = '/Users/shimyoungjong/.ssh/id_ed25519'

def ubuntu_ssh(cmd):
    try:
        subprocess.run(
            ['ssh', '-i', SSH_KEY,
             '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
             'hisecure@192.168.64.10', cmd],
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
    features = extract_http_features(data.payload)
    X = pd.DataFrame([[features.get(f, 0) for f in http_feature_names]], columns=http_feature_names)
    pred = http_model.predict(X)[0]
    conf = float(http_model.predict_proba(X).max())

    is_attack = pred != 'BENIGN'
    blocked   = False
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── HTTP 공격 탐지 시 PF 자동 차단 로직 ──
    if is_attack and data.attacker_ip not in WHITELIST:
        count = check_http_count(data.attacker_ip)
        print(f"  🚨 [HTTP] {pred} 탐지! IP: {data.attacker_ip} "
              f"(신뢰도: {conf:.1%}) [{count}/{HTTP_BLOCK_THRESHOLD}회]")
        if count >= HTTP_BLOCK_THRESHOLD:
            blocked = block_ip(data.attacker_ip, pred)
            http_attack_counts[data.attacker_ip] = []   # 카운터 초기화
    elif is_attack:
        print(f"  🚨 [HTTP] {pred} 탐지! IP: {data.attacker_ip} "
              f"(신뢰도: {conf:.1%}) [화이트리스트 — 차단 제외]")

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
        "blocked": blocked
    })
    return {"attack_type": pred, "confidence": conf, "is_attack": is_attack, "blocked": blocked}

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
CSV_PATH    = os.path.expanduser("~/ips_project/captures/test.csv")
CIC_PATH    = "/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/cicflowmeter"
PYTHON_PATH = "/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python"
DETECT_PATH = os.path.expanduser("~/ips_project/realtime_detect.py")
DETECT_LOG  = os.path.expanduser("~/ips_project/detect.log")

cic_proc     = None
detect_proc  = None
session_start = None  # 현재 세션 시작 시간

def clear_ubuntu_logs():
    """Ubuntu 허니팟/서버 로그 초기화"""
    try:
        subprocess.run(
            ['ssh', '-i', '/Users/shimyoungjong/.ssh/id_ed25519',
             '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             '-o', 'BatchMode=yes',
             'hisecure@192.168.64.10',
             'truncate -s 0 /tmp/honeypot_log.txt 2>/dev/null; true'],
            capture_output=True, timeout=5
        )
        print("🧹 Ubuntu 허니팟 로그 초기화 완료")
    except Exception as e:
        print(f"⚠️ Ubuntu 로그 초기화 실패: {e}")

@app.post("/start")
async def start_ips():
    global cic_proc, detect_proc, session_start, server_logs
    if cic_proc is not None:
        return {"status": "already_running"}

    session_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    server_logs.clear()   # 메모리 서버 로그 초기화
    clear_ubuntu_logs()   # Ubuntu 허니팟 로그 초기화
    # 감시목록 초기화
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE watchlist SET active=0")
    conn.commit()
    conn.close()

    os.makedirs(os.path.expanduser("~/ips_project/captures"), exist_ok=True)
    if os.path.exists(CSV_PATH):
        os.remove(CSV_PATH)

    cic_proc = subprocess.Popen(
        ["sudo", CIC_PATH, "-i", INTERFACE, "-c", CSV_PATH],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    detect_log_f = open(DETECT_LOG, "w")
    detect_proc = subprocess.Popen(
        ["sudo", PYTHON_PATH, "-u", DETECT_PATH],
        stdout=detect_log_f, stderr=detect_log_f,
        preexec_fn=os.setsid
    )
    return {"status": "started"}

@app.post("/stop")
async def stop_ips():
    global cic_proc, detect_proc
    for proc in [cic_proc, detect_proc]:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
    # 혹시 남은 좀비 프로세스 강제 종료
    subprocess.run(['pkill', '-f', 'realtime_detect.py'], capture_output=True)
    subprocess.run(['pkill', '-f', 'cicflowmeter'], capture_output=True)
    cic_proc = None
    detect_proc = None
    return {"status": "stopped"}

@app.get("/ips_status")
async def ips_status():
    return {"running": cic_proc is not None}

@app.post("/emergency_reset")
async def emergency_reset():
    # pfctl 테이블 초기화
    for table in ['blocklist', 'highlist', 'throttlelist']:
        subprocess.run(['/sbin/pfctl', '-t', table, '-T', 'flush'], capture_output=True)
    # Ubuntu iptables 초기화
    subprocess.run(
        ['ssh', '-i', '/Users/shimyoungjong/.ssh/id_ed25519',
         '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
         'hisecure@192.168.64.10',
         'sudo iptables -F && sudo iptables -F FORWARD && sudo iptables -t nat -F'],
        capture_output=True
    )
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