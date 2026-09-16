#!/usr/bin/env python3
"""
화이트리스트에 안 걸리는 가짜 출발지 IP로 포트스캔 패턴 패킷을 bridge100에 직접 주입.
목적: realtime_detect.py의 Scapy 플로우 수집기가 실제로 캡처해서 RF 모델로 판정하는지 확인.
타겟: 192.168.64.2:20~39 (우분투 VM, 취약서버가 아니라 포트스캔 자체를 보는 것이라 열려있을 필요 없음)

실행 (sudo 필요 - raw socket): sudo /Users/macintosh/Downloads/ips_project/.venv/bin/python simulate_portscan.py
"""
from scapy.all import Ether, IP, TCP, sendp
import time

IFACE   = 'en0'
FAKE_IP = '203.0.113.77'    # 화이트리스트에 없는 가짜 공격자 IP (실존/도달 불가능해도 무관 - 스니퍼는 그냥 지나가는 패킷만 봄)
TARGET  = '203.0.113.2'     # 임의의 목적지 (실제 도달 여부 무관)
BCAST   = 'ff:ff:ff:ff:ff:ff'  # ARP 해석 없이 무조건 인터페이스로 내보내기 위한 목적지 MAC
ports = list(range(20, 40))

print(f'포트스캔 시뮬레이션({IFACE}): {FAKE_IP} -> {TARGET} (포트 {ports[0]}~{ports[-1]})')
for port in ports:
    sport = 40000 + port
    pkt1 = Ether(dst=BCAST) / IP(src=FAKE_IP, dst=TARGET) / TCP(sport=sport, dport=port, flags='S', seq=1000)
    pkt2 = Ether(dst=BCAST) / IP(src=FAKE_IP, dst=TARGET) / TCP(sport=sport, dport=port, flags='A', seq=1001, ack=1)
    sendp(pkt1, verbose=0, iface=IFACE)
    time.sleep(0.05)
    sendp(pkt2, verbose=0, iface=IFACE)
    time.sleep(0.1)
print('전송 완료')
