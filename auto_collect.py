#!/usr/bin/env python3
"""
ML 데이터 자동 수집 스크립트 (Scapy 기반)
각 공격 유형별 7만개 플로우 수집 → 라벨링 → 재학습
"""
import subprocess, os, time, glob, sys, csv
from datetime import datetime
sys.path.insert(0, os.path.expanduser("~/ips_project"))
from scapy_flow import ScapyFlowCollector, FLOW_TIMEOUT

PYTHON   = "/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python"
PROJ     = os.path.expanduser("~/ips_project")
CAPTURES = os.path.join(PROJ, "captures")
IFACE      = "en0"
# Ubuntu WiFi IP 자동 감지 (bridge100 SSH 사용)
def _detect_ubuntu_ip():
    try:
        r = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3',
             'hisecure@192.168.64.10',
             "ip -4 addr show | grep 'inet ' | grep -v '192.168.64\\|127.0' | awk '{print $2}' | cut -d/ -f1"],
            capture_output=True, text=True, timeout=5
        )
        ip = r.stdout.strip().split('\n')[0]
        return ip if ip else '192.168.64.10'
    except Exception:
        return '192.168.64.10'   # fallback: bridge100

TARGET = _detect_ubuntu_ip()
print(f"🖥️  타깃 Ubuntu IP: {TARGET}")
FLASK_PORT = 5000
FLASK      = f"http://{TARGET}:{FLASK_PORT}"
TARGET_FLOWS = 70000

os.makedirs(CAPTURES, exist_ok=True)

# 공격 패턴: (명령어, 제한시간초)
PATTERNS = {
    "normal": [
        (f"{PYTHON} {PROJ}/normal_traffic.py",                           70),
        (f"for i in $(seq 1 200); do curl -s {FLASK}/ > /dev/null; sleep 0.2; done",                                          70),
        (f"for i in $(seq 1 150); do curl -s '{FLASK}/search?q=hello' > /dev/null; sleep 0.3; done",                          70),
        (f"for i in $(seq 1 100); do curl -s {FLASK}/board > /dev/null; sleep 0.4; sleep 0.1; done",                          70),
        (f"for i in $(seq 1 80);  do curl -s -X POST {FLASK}/login -d 'username=admin&password=admin123' > /dev/null; sleep 0.5; done", 70),
        (f"for i in $(seq 1 200); do curl -s '{FLASK}/search?q=security' > /dev/null; sleep 0.25; done",                      70),
        (f"{PYTHON} {PROJ}/normal_traffic.py",                           70),
    ],
    "portscan": [
        (f"nmap -sT -p 1-10000 {TARGET} -T4",                            90),
        (f"nmap -sT -p 10001-30000 {TARGET} -T4",                        90),
        (f"nmap -sT -p 30001-65535 {TARGET} -T4",                        90),
        (f"nmap -sT -p 1-65535 {TARGET} -T3",                           180),
        (f"nmap -sV {TARGET}",                                            90),
        (f"nmap -A {TARGET}",                                            120),
        (f"nmap --script=default {TARGET}",                               90),
        (f"sudo nmap -sS -p 1-65535 {TARGET} -T4",                      120),  # SYN 스캔 (Kali 방식)
        (f"sudo nmap -sS -p 1-10000 {TARGET} -T5",                       60),
    ],
    "bruteforce": [
        # HTTP 브루트포스
        (f"hydra -l admin    -P {PROJ}/rockyou.txt -t 16 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l root     -P {PROJ}/rockyou.txt -t 16 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l hisecure -P {PROJ}/rockyou.txt -t 16 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l ubuntu   -P {PROJ}/rockyou.txt -t 12 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l user     -P {PROJ}/rockyou.txt -t 12 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l pi       -P {PROJ}/rockyou.txt -t 12 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l test     -P {PROJ}/rockyou.txt -t 12 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        (f"hydra -l guest    -P {PROJ}/rockyou.txt -t 12 'http-post-form://{TARGET}:{FLASK_PORT}/login:username=^USER^&password=^PASS^:F=alert-danger'", 120),
        # SSH 브루트포스 (다른 포트/패턴으로 다양성 확보)
        (f"hydra -l admin  -P {PROJ}/rockyou.txt -t 4 ssh://{TARGET}",   120),
        (f"hydra -l root   -P {PROJ}/rockyou.txt -t 4 ssh://{TARGET}",   120),
        (f"hydra -l ubuntu -P {PROJ}/rockyou.txt -t 4 ssh://{TARGET}",   120),
        (f"hydra -l pi     -P {PROJ}/rockyou.txt -t 4 ssh://{TARGET}",   120),
    ],
    "ddos": [
        (f"ab -n 10000 -c 100 {FLASK}/",                                  70),
        (f"ab -n 8000  -c 200 '{FLASK}/search?q=test'",                   70),
        (f"ab -n 10000 -c 150 {FLASK}/login",                             70),
        (f"siege -c 150 -t 30S {FLASK}/",                                 35),
        (f"wrk -t4 -c200 -d30s {FLASK}/",                                 35),
        (f"ab -n 12000 -c 100 {FLASK}/board",                             70),
        (f"ab -n 10000 -c 200 '{FLASK}/search?q=admin'",                  70),
    ],
    "sqli": [
        (f"sqlmap -u '{FLASK}/search?q=test' --batch --level=2 --risk=1 --threads=5 --forms", 120),
        (f"sqlmap -u '{FLASK}/login' --data='username=admin&password=test' --batch --level=2 --risk=2 --threads=5", 120),
        (f"sqlmap -u '{FLASK}/board' --batch --level=1 --risk=1 --threads=5 --crawl=2", 120),
        (f"sqlmap -u '{FLASK}/search?q=test' --batch --technique=BEUSTQ --threads=5", 120),
        (f"for i in $(seq 1 500); do curl -s '{FLASK}/search?q=1%27+OR+%271%27%3D%271' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 400); do curl -s '{FLASK}/search?q=1+UNION+SELECT+null,null,null--' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 400); do curl -s \"{FLASK}/search?q=' OR 1=1 --\" > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 300); do curl -s -X POST {FLASK}/login -d \"username=admin'--&password=x\" > /dev/null; sleep 0.15; done", 70),
        (f"sqlmap -u '{FLASK}/search?q=test' --batch --level=3 --risk=1 --threads=8 --dbs", 150),
    ],
    "xss": [
        (f"for i in $(seq 1 500); do curl -s '{FLASK}/search?q=%3Cscript%3Ealert(1)%3C/script%3E' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 400); do curl -s '{FLASK}/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 400); do curl -s '{FLASK}/search?q=%3Csvg+onload%3Dalert(document.cookie)%3E' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 300); do curl -s '{FLASK}/search?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 300); do curl -s '{FLASK}/search?q=javascript:alert(document.cookie)' > /dev/null; sleep 0.15; done", 70),
        (f"xsser -u '{FLASK}/search' -g '?q=XSS' --auto --threads=5 2>/dev/null || for i in $(seq 1 300); do curl -s '{FLASK}/search?q=<script>alert(1)</script>' > /dev/null; sleep 0.1; done", 90),
        (f"for i in $(seq 1 400); do curl -s '{FLASK}/search?q=%3Ciframe+src%3Djavascript:alert(1)%3E' > /dev/null; sleep 0.1; done", 70),
        (f"for i in $(seq 1 300); do curl -s -X POST {FLASK}/login -d 'username=<script>alert(1)</script>&password=x' > /dev/null; sleep 0.15; done", 70),
    ],
}

def count_flows(attack_type):
    total = 0
    for f in glob.glob(os.path.join(CAPTURES, f"{attack_type}_*.csv")):
        try:
            with open(f, 'r', errors='ignore') as fp:
                rows = max(0, sum(1 for _ in fp) - 1)
            total += rows
        except:
            pass
    return total

def run_session(attack_type, cmd, duration):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    capture_file = os.path.join(CAPTURES, f"{attack_type}_{timestamp}.csv")

    print(f"\n  📡 {cmd[:65]}...")
    print(f"  ⏱️  {duration}초")

    # Scapy 플로우 수집기: 완료된 플로우를 리스트에 저장
    collected = []
    def _on_flow(features):
        collected.append(features)

    collector = ScapyFlowCollector(iface=IFACE, callback=_on_flow)
    collector.start()
    time.sleep(1)  # 수집기 안정화 대기

    atk = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for i in range(duration):
        pct = (i + 1) * 100 // duration
        bar = '█' * (pct * 25 // 100)
        print(f"\r    [{bar:<25}] {pct:3d}%", end='', flush=True)
        time.sleep(1)
    print()

    try: atk.terminate()
    except: pass

    # 미완료 플로우가 timeout 되길 대기
    time.sleep(FLOW_TIMEOUT + 2)
    collector.stop()
    time.sleep(1)

    rows = len(collected)
    if rows > 0:
        with open(capture_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(collected[0].keys()))
            writer.writeheader()
            writer.writerows(collected)
    elif os.path.exists(capture_file):
        os.remove(capture_file)

    print(f"    → 이번: {rows:,}개")
    return rows

def collect_type(attack_type):
    print(f"\n{'='*55}")
    print(f"🔥 [{attack_type.upper()}] 목표: {TARGET_FLOWS:,}개")
    print(f"{'='*55}")

    patterns = PATTERNS[attack_type]
    idx = 0

    while True:
        current = count_flows(attack_type)
        remaining = TARGET_FLOWS - current
        print(f"\n  📊 누적: {current:,} / {TARGET_FLOWS:,}개 (남은: {remaining:,}개)")

        if current >= TARGET_FLOWS:
            print(f"  🎉 [{attack_type.upper()}] 목표 달성!")
            break

        cmd, duration = patterns[idx % len(patterns)]
        run_session(attack_type, cmd, duration)
        idx += 1

if __name__ == '__main__':
    types = sys.argv[1:] if len(sys.argv) > 1 else ["normal", "portscan", "bruteforce", "ddos", "sqli", "xss"]

    print("🚀 자동 데이터 수집 시작! (Scapy 기반)")
    print(f"   수집 유형: {types}")
    print(f"   목표: 각 {TARGET_FLOWS:,}개 플로우\n")

    # Flask 서버 확인
    if any(t in types for t in ["normal", "ddos", "sqli", "xss"]):
        try:
            r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                "--connect-timeout", "3", f"{FLASK}/"],
                               capture_output=True, text=True, timeout=5)
            if r.stdout.strip() == "200":
                print(f"✅ Flask 서버 확인됨 ({FLASK})")
            else:
                print(f"⚠️  Flask 서버 응답 없음! Ubuntu에서 Flask 켜주세요.")
                print(f"   ssh hisecure@{TARGET} 'cd ~/vulnerable_server && python3 app.py &'")
        except:
            print(f"⚠️  Flask 서버 확인 실패. Ubuntu 상태 확인 필요.")

    print()

    for t in types:
        collect_type(t)

    print(f"\n{'='*55}")
    print("✅ 수집 완료!")
    print(f"{'='*55}\n")
    print("라벨링/재학습은 수동으로 실행하세요:")
    print(f"  python add_labels.py")
    print(f"  python train_mydata.py")
