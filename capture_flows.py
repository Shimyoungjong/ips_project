#!/usr/bin/env python3
"""
패시브 플로우 캡처 스크립트
칼리에서 공격 → Mac en0에서 Scapy로 수집 → CSV 저장

사용법:
  sudo python3 capture_flows.py <attack_type> [목표개수]
  sudo python3 capture_flows.py normal 70000
  sudo python3 capture_flows.py portscan
  sudo python3 capture_flows.py bruteforce
  sudo python3 capture_flows.py ddos
  sudo python3 capture_flows.py sqli
  sudo python3 capture_flows.py xss

Ctrl+C 로 중지 → 자동 저장
"""
import sys, os, csv, time, signal, glob
from datetime import datetime

IPS_HOME  = os.environ.get("IPS_HOME") or os.path.expanduser("~/ips_project")
sys.path.insert(0, IPS_HOME)
from scapy_flow import ScapyFlowCollector, FLOW_TIMEOUT

CAPTURES  = os.path.join(IPS_HOME, "captures")
IFACE     = "en0"
TARGET_FLOWS = 70000

os.makedirs(CAPTURES, exist_ok=True)

VALID_TYPES = ["normal", "portscan", "bruteforce", "ddos", "sqli", "xss"]

if len(sys.argv) < 2 or sys.argv[1] not in VALID_TYPES:
    print(f"사용법: sudo python3 capture_flows.py <{'|'.join(VALID_TYPES)}> [목표개수]")
    sys.exit(1)

attack_type  = sys.argv[1]
target_flows = int(sys.argv[2]) if len(sys.argv) > 2 else TARGET_FLOWS


def count_existing():
    total = 0
    for f in glob.glob(os.path.join(CAPTURES, f"{attack_type}_*.csv")):
        try:
            with open(f, 'r', errors='ignore') as fp:
                total += max(0, sum(1 for _ in fp) - 1)
        except:
            pass
    return total


timestamp    = datetime.now().strftime('%Y%m%d_%H%M%S')
capture_file = os.path.join(CAPTURES, f"{attack_type}_{timestamp}.csv")

collected = []
writer_file = None
writer_obj  = None
stop_flag   = False


def on_flow(features):
    global writer_file, writer_obj
    collected.append(features)
    # 스트리밍 저장: 수집 즉시 디스크에 기록
    if writer_file is None:
        writer_file = open(capture_file, 'w', newline='')
        writer_obj  = csv.DictWriter(writer_file, fieldnames=list(features.keys()))
        writer_obj.writeheader()
    writer_obj.writerow(features)
    writer_file.flush()


def stop_handler(sig, frame):
    global stop_flag
    stop_flag = True


signal.signal(signal.SIGINT, stop_handler)

existing = count_existing()
remaining = max(0, target_flows - existing)

print(f"\n{'='*55}")
print(f"🎯 [{attack_type.upper()}] 수집 시작")
print(f"   기존 누적: {existing:,}개 / 목표: {target_flows:,}개")
print(f"   이번 목표: {remaining:,}개 더 필요")
print(f"   저장 파일: {os.path.basename(capture_file)}")
print(f"{'='*55}")
print(f"\n⚡ 칼리에서 공격 시작하세요! (Ctrl+C 로 중지)\n")

collector = ScapyFlowCollector(iface=IFACE, callback=on_flow)
collector.start()

last_print = time.time()
start_time = time.time()

while not stop_flag:
    time.sleep(0.5)
    now = time.time()
    if now - last_print >= 5:
        n      = len(collected)
        total  = existing + n
        pct    = min(100, total * 100 // target_flows)
        bar    = '█' * (pct * 20 // 100)
        elapsed = int(now - start_time)
        rate   = n / max(elapsed, 1) * 60
        print(f"\r  [{bar:<20}] {pct:3d}%  이번: {n:,}개  누적: {total:,}/{target_flows:,}  속도: {rate:.0f}개/분  {elapsed//60}분{elapsed%60}초", end='', flush=True)
        last_print = now
        if total >= target_flows:
            print(f"\n\n  🎉 목표 달성! ({total:,}개)")
            stop_flag = True

collector.stop()
time.sleep(FLOW_TIMEOUT + 1)  # 남은 플로우 timeout 대기

if writer_file:
    writer_file.close()

n = len(collected)
print(f"\n\n{'='*55}")
print(f"✅ 수집 완료!")
print(f"   이번 세션: {n:,}개 플로우")
print(f"   저장 위치: {capture_file}")
print(f"   전체 누적: {count_existing():,}개")
print(f"{'='*55}")

if n == 0 and os.path.exists(capture_file):
    os.remove(capture_file)
    print("  (플로우 없음 → 파일 삭제)")
