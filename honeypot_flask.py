# 허니팟 서버 - Ubuntu app.py 완전 클론 (포트 9999)
# 공격자는 진짜 서버인 줄 알고 계속 공격 → 모든 페이로드 로깅
from flask import Flask, request, session
import sqlite3
import requests as req
from datetime import datetime
import threading

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DB_PATH    = '/tmp/honeypot_users.db'
LOG_FILE   = '/tmp/honeypot_log.txt'
MAC_API    = 'http://192.168.64.1:8000/server_log'  # Mac FastAPI (bridge100 고정)

def send_to_mac(ip, method, path, payload=''):
    try:
        req.post(MAC_API, json={
            "server_type": "honeypot",
            "ip": ip,
            "method": method,
            "path": path,
            "payload": payload,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }, timeout=1)
    except:
        pass

def log_request(extra=''):
    now  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip   = request.remote_addr
    line = f"[{now}] {ip} {request.method} {request.path}"
    if extra:
        line += f"\n  └ PAYLOAD: {extra}"
    print(f"\033[93m[허니팟]\033[0m {line}")
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except:
        pass

@app.before_request
def log_all():
    payloads = list(request.args.values()) + list(request.form.values())
    payload_str = ' | '.join(payloads) if payloads else ''
    log_request(payload_str)
    threading.Thread(
        target=send_to_mac,
        args=(request.remote_addr, request.method, request.path, payload_str),
        daemon=True
    ).start()

# ==================== 공통 HTML (원본 그대로) ====================
def base_html(content, title='HiSecure Corp'):
    return f'''
<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: "Segoe UI", sans-serif; background: #f0f2f5; color: #333; }}

        nav {{
            background: #1a237e;
            padding: 0 40px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 64px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }}
        nav .logo {{
            color: white;
            font-size: 20px;
            font-weight: bold;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        nav .logo .badge {{
            background: #1976d2;
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: normal;
            letter-spacing: 1px;
        }}
        nav ul {{ list-style: none; display: flex; gap: 30px; }}
        nav ul li a {{
            color: #90caf9;
            text-decoration: none;
            font-size: 14px;
            transition: color 0.2s;
        }}
        nav ul li a:hover {{ color: white; }}

        .topbar {{
            background: #0d1b6e;
            padding: 6px 40px;
            font-size: 12px;
            color: #90caf9;
            display: flex;
            justify-content: space-between;
        }}

        .container {{ max-width: 960px; margin: 40px auto; padding: 0 20px; }}

        .page-header {{ margin-bottom: 24px; }}
        .page-header h2 {{ font-size: 22px; color: #1a237e; margin-bottom: 4px; }}
        .page-header p {{ font-size: 13px; color: #888; }}

        .card {{
            background: white;
            border-radius: 8px;
            padding: 32px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.07);
            margin-bottom: 24px;
        }}

        .form-group {{ margin-bottom: 18px; }}
        .form-group label {{
            display: block;
            margin-bottom: 6px;
            font-size: 13px;
            font-weight: 600;
            color: #444;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .form-group input,
        .form-group textarea {{
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            outline: none;
            transition: border 0.2s;
            background: #fafafa;
        }}
        .form-group input:focus,
        .form-group textarea:focus {{ border-color: #1976d2; background: white; }}
        .form-group textarea {{ height: 110px; resize: vertical; }}

        .btn {{
            background: #1a237e;
            color: white;
            border: none;
            padding: 10px 28px;
            border-radius: 6px;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: #1976d2; }}

        .alert {{ padding: 10px 16px; border-radius: 6px; margin-bottom: 18px; font-size: 14px; font-weight: 500; }}
        .alert-success {{ background: #e8f5e9; color: #2e7d32; border-left: 4px solid #43a047; }}
        .alert-danger {{ background: #ffebee; color: #c62828; border-left: 4px solid #e53935; }}

        .hero {{
            background: linear-gradient(135deg, #1a237e 0%, #1976d2 100%);
            color: white;
            padding: 60px 40px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .hero .tag {{
            font-size: 11px;
            background: rgba(255,255,255,0.2);
            padding: 4px 10px;
            border-radius: 20px;
            letter-spacing: 1px;
            margin-bottom: 16px;
            display: inline-block;
        }}
        .hero h1 {{ font-size: 30px; margin-bottom: 10px; }}
        .hero p {{ font-size: 15px; opacity: 0.8; margin-bottom: 24px; }}

        .menu-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
        .menu-card {{
            background: white;
            border-radius: 8px;
            padding: 24px;
            text-decoration: none;
            color: #333;
            box-shadow: 0 2px 12px rgba(0,0,0,0.07);
            transition: transform 0.2s, box-shadow 0.2s;
            border-top: 3px solid #1a237e;
        }}
        .menu-card:hover {{ transform: translateY(-3px); box-shadow: 0 6px 20px rgba(0,0,0,0.12); }}
        .menu-card .icon {{ font-size: 32px; margin-bottom: 12px; }}
        .menu-card h3 {{ font-size: 16px; margin-bottom: 6px; color: #1a237e; }}
        .menu-card p {{ font-size: 13px; color: #888; line-height: 1.5; }}

        .result-item {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 14px 18px;
            margin-bottom: 10px;
            border-left: 4px solid #1976d2;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .result-item .avatar {{
            width: 36px; height: 36px;
            background: #1a237e;
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            color: white; font-size: 14px; font-weight: bold;
        }}
        .result-item .info {{ flex: 1; }}
        .result-item .info strong {{ font-size: 14px; color: #1a237e; }}
        .result-item .info span {{ font-size: 12px; color: #aaa; margin-left: 8px; }}

        .post {{ border-bottom: 1px solid #f0f0f0; padding: 18px 0; }}
        .post:last-child {{ border-bottom: none; }}
        .post .post-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }}
        .post h3 {{ font-size: 15px; color: #1a237e; }}
        .post .meta {{ font-size: 12px; color: #bbb; }}
        .post p {{ font-size: 14px; color: #555; line-height: 1.6; }}
        .post .tag-label {{
            font-size: 11px; background: #e3f2fd; color: #1976d2;
            padding: 2px 8px; border-radius: 4px; margin-right: 8px;
        }}

        footer {{ text-align: center; padding: 30px; color: #bbb; font-size: 12px; margin-top: 40px; border-top: 1px solid #e0e0e0; }}
    </style>
</head>
<body>
    <div class="topbar">
        <span>🔒 HiSecure Corp 내부 포털 | 보안등급: 내부용</span>
        <span>📍 Seoul HQ | 운영팀 문의: security@hisecure.corp</span>
    </div>
    <nav>
        <a href="/" class="logo">
            🛡️ HiSecure Corp
            <span class="badge">INTRANET</span>
        </a>
        <ul>
            <li><a href="/">홈</a></li>
            <li><a href="/login">직원 로그인</a></li>
            <li><a href="/search">고객사 검색</a></li>
            <li><a href="/board">공지게시판</a></li>
        </ul>
    </nav>
    {content}
    <footer>
        © 2025 HiSecure Corp. All rights reserved. | 본 시스템은 내부 직원 전용입니다.
    </footer>
</body>
</html>
'''

# ==================== DB 초기화 ====================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS board
                 (id INTEGER PRIMARY KEY, title TEXT, content TEXT,
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'kimcs', 'hello123')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'parkjh', 'qwerty')")
    c.execute("INSERT OR IGNORE INTO board (id, title, content) VALUES (1, '[공지] 2025년 보안 정책 업데이트', '전 직원은 2025년 보안 정책을 숙지하시기 바랍니다. 자세한 내용은 보안팀에 문의하세요.')")
    c.execute("INSERT OR IGNORE INTO board (id, title, content) VALUES (2, '[긴급] 서버 점검 안내', '2025년 1월 15일 새벽 2시부터 4시까지 서버 점검이 예정되어 있습니다.')")
    c.execute("INSERT OR IGNORE INTO board (id, title, content) VALUES (3, '[안내] 사내 보안 교육 일정', '1월 20일 오후 2시 대회의실에서 사내 보안 교육이 진행됩니다. 전 직원 필참 바랍니다.')")
    conn.commit()
    conn.close()

# ==================== 메인 ====================
@app.route('/')
def index():
    content = '''
    <div class="container">
        <div class="hero">
            <div class="tag">🔒 INTERNAL PORTAL</div>
            <h1>HiSecure Corp 직원 포털</h1>
            <p>보안 솔루션 전문기업 HiSecure Corp의 내부 시스템입니다.<br>
               인가된 직원만 접근 가능합니다.</p>
            <a href="/login" class="btn" style="text-decoration:none; display:inline-block; background:white; color:#1a237e;">
                직원 로그인 →
            </a>
        </div>
        <div class="menu-grid">
            <a href="/login" class="menu-card">
                <div class="icon">🔐</div>
                <h3>직원 로그인</h3>
                <p>사원증 계정으로 내부 시스템에 로그인하세요</p>
            </a>
            <a href="/search" class="menu-card">
                <div class="icon">🔍</div>
                <h3>고객사 검색</h3>
                <p>계약 고객사 및 담당자 정보를 검색하세요</p>
            </a>
            <a href="/board" class="menu-card">
                <div class="icon">📋</div>
                <h3>공지게시판</h3>
                <p>사내 공지사항 및 보안 업데이트를 확인하세요</p>
            </a>
        </div>
    </div>
    '''
    return base_html(content, 'HiSecure Corp - 내부 포털')

# ==================== /login ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    alert_class = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user'] = username
            message = f'✅ 로그인 성공! 환영합니다, {username}님!'
            alert_class = 'alert-success'
        else:
            message = '❌ 사원 계정 정보가 올바르지 않습니다. 보안팀에 문의하세요.'
            alert_class = 'alert-danger'

    alert_html = f'<div class="alert {alert_class}">{message}</div>' if message else ''
    content = f'''
    <div class="container">
        <div class="card" style="max-width:460px; margin:40px auto;">
            <div class="page-header">
                <h2>🔐 직원 포털 로그인</h2>
                <p>HiSecure Corp 사원 계정으로 로그인하세요</p>
            </div>
            {alert_html}
            <form method="POST">
                <div class="form-group">
                    <label>사원 ID</label>
                    <input name="username" placeholder="사원 ID를 입력하세요">
                </div>
                <div class="form-group">
                    <label>비밀번호</label>
                    <input name="password" type="password" placeholder="비밀번호를 입력하세요">
                </div>
                <button type="submit" class="btn" style="width:100%;">로그인</button>
            </form>
            <p style="font-size:12px; color:#aaa; text-align:center; margin-top:16px;">
                계정 문의: security@hisecure.corp
            </p>
        </div>
    </div>
    '''
    return base_html(content, 'HiSecure Corp - 로그인')

# ==================== /search (취약한 SQLi 허용) ====================
@app.route('/search', methods=['GET', 'POST'])
def search():
    results = []
    query = ''
    searched = False
    if request.method == 'POST':
        query = request.form.get('query', '')
        searched = True
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(f"SELECT * FROM users WHERE username = '{query}'")
            results = c.fetchall()
        except Exception as e:
            results = [(-1, f'오류: {str(e)}', '')]
        conn.close()

    results_html = ''
    if searched:
        if results:
            for row in results:
                avatar = row[1][0].upper() if row[1] else '?'
                results_html += f'''
                <div class="result-item">
                    <div class="avatar">{avatar}</div>
                    <div class="info">
                        <strong>{row[1]}</strong>
                        <span>ID: {row[0]}</span>
                    </div>
                </div>'''
        else:
            results_html = '<div class="alert alert-danger">검색 결과가 없습니다.</div>'

    results_section = f'<h3 style="margin-top:28px; margin-bottom:14px; font-size:15px; color:#1a237e;">검색 결과</h3>{results_html}' if searched else ''
    content = f'''
    <div class="container">
        <div class="page-header">
            <h2>🔍 고객사 검색</h2>
            <p>계약 고객사 및 담당자 정보를 검색합니다</p>
        </div>
        <div class="card">
            <form method="POST">
                <div class="form-group">
                    <label>고객사 / 담당자명</label>
                    <input name="query" placeholder="검색어를 입력하세요" value="{query}">
                </div>
                <button type="submit" class="btn">검색하기</button>
            </form>
            {results_section}
        </div>
    </div>
    '''
    return base_html(content, 'HiSecure Corp - 고객사 검색')

# ==================== /board (XSS 허용) ====================
@app.route('/board', methods=['GET', 'POST'])
def board():
    if request.method == 'POST':
        title = request.form.get('title', '')
        content_text = request.form.get('content', '')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO board (title, content) VALUES (?, ?)", (title, content_text))
        conn.commit()
        conn.close()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM board ORDER BY id DESC")
    posts = c.fetchall()
    conn.close()

    posts_html = ''
    for post in posts:
        created_at = post[3] if len(post) > 3 else ''
        posts_html += f'''
        <div class="post">
            <div class="post-header">
                <h3><span class="tag-label">공지</span>{post[1]}</h3>
                <span class="meta">📅 {created_at}</span>
            </div>
            <p>{post[2]}</p>
        </div>'''

    content = f'''
    <div class="container">
        <div class="page-header">
            <h2>📋 사내 공지게시판</h2>
            <p>HiSecure Corp 사내 공지사항 및 보안 업데이트</p>
        </div>
        <div class="card">
            <h3 style="font-size:15px; color:#1a237e; margin-bottom:20px;">✏️ 글 작성</h3>
            <form method="POST">
                <div class="form-group">
                    <label>제목</label>
                    <input name="title" placeholder="제목을 입력하세요">
                </div>
                <div class="form-group">
                    <label>내용</label>
                    <textarea name="content" placeholder="내용을 입력하세요"></textarea>
                </div>
                <button type="submit" class="btn">등록하기</button>
            </form>
        </div>
        <div class="card">
            <h3 style="font-size:15px; color:#1a237e; margin-bottom:4px;">📌 공지 목록</h3>
            {posts_html}
        </div>
    </div>
    '''
    return base_html(content, 'HiSecure Corp - 공지게시판')

if __name__ == '__main__':
    init_db()
    print(f"[허니팟] 포트 9999 시작 — 모든 요청 로깅 중")
    print(f"[허니팟] 로그: {LOG_FILE}")
    app.run(host='0.0.0.0', port=9999, debug=False)
