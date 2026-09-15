#!/usr/bin/env python3
"""
Ubuntu IPS 에이전트
- Ubuntu 네트워크 인터페이스에서 직접 패킷 캡처
- 플로우 집계 + 피처 추출
- Mac IPS로 TCP 소켓 전송 (재연결 자동)

Ubuntu에서 실행:
  sudo python3 ubuntu_agent.py
"""

import json
import socket
import time
import threading
import queue
import sys
import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, UDP

# ==================== 설정 ====================
IPS_HOST = '192.168.64.1'  # Mac bridge100 게이트웨이 IP
IPS_PORT = 9001             # Mac IPS 수신 포트
IFACE    = 'eth0'           # Ubuntu 인터페이스 (ip a 로 확인 후 변경)

FLOW_TIMEOUT = 2.0
MAX_PACKETS  = 1000
MIN_PACKETS  = 2

# 명령줄 인자로 인터페이스 변경 가능
if len(sys.argv) > 1:
    IFACE = sys.argv[1]
if len(sys.argv) > 2:
    IPS_HOST = sys.argv[2]

print(f"[설정] 인터페이스: {IFACE}, IPS 주소: {IPS_HOST}:{IPS_PORT}")


# ==================== FlowRecord ====================
class FlowRecord:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, ts):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto    = proto
        self.start_ts = ts
        self.last_ts  = ts
        self.fwd_pkts = []
        self.bwd_pkts = []
        self.all_ts   = []
        self.init_fwd_win = -1
        self.init_bwd_win = -1

    def add_packet(self, is_fwd, ts, length, flags, header_len, win):
        self.last_ts = ts
        self.all_ts.append(ts)
        info = (ts, length, flags, header_len, win)
        if is_fwd:
            self.fwd_pkts.append(info)
            if self.init_fwd_win < 0:
                self.init_fwd_win = win
        else:
            self.bwd_pkts.append(info)
            if self.init_bwd_win < 0:
                self.init_bwd_win = win

    @property
    def total_pkts(self):
        return len(self.fwd_pkts) + len(self.bwd_pkts)

    def is_expired(self, now):
        return (now - self.last_ts) > FLOW_TIMEOUT or self.total_pkts >= MAX_PACKETS

    def extract_features(self):
        duration = max(self.last_ts - self.start_ts, 1e-9)

        fwd_lens = [p[1] for p in self.fwd_pkts]
        bwd_lens = [p[1] for p in self.bwd_pkts]
        all_lens = fwd_lens + bwd_lens

        fwd_ts = sorted(p[0] for p in self.fwd_pkts)
        bwd_ts = sorted(p[0] for p in self.bwd_pkts)
        all_ts = sorted(self.all_ts)

        tot_fwd    = len(fwd_lens)
        tot_bwd    = len(bwd_lens)
        totlen_fwd = sum(fwd_lens)
        totlen_bwd = sum(bwd_lens)

        def _stats(lst):
            if not lst:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            a = np.array(lst, dtype=float)
            return float(a.max()), float(a.min()), float(a.mean()), float(a.std()), float(a.var())

        def _iat(ts_list):
            if len(ts_list) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            iats = np.diff(ts_list) * 1e6
            return float(iats.sum()), float(iats.mean()), float(iats.std()), float(iats.min()), float(iats.max())

        pkt_max, pkt_min, pkt_mean, pkt_std, pkt_var = _stats(all_lens)
        fwd_max, fwd_min, fwd_mean, fwd_std, _       = _stats(fwd_lens)
        bwd_max, bwd_min, bwd_mean, bwd_std, _       = _stats(bwd_lens)

        _, flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = _iat(all_ts)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_min, _    = _iat(fwd_ts)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_min, _    = _iat(bwd_ts)

        all_flags = [p[2] for p in self.fwd_pkts + self.bwd_pkts]
        fwd_flags = [p[2] for p in self.fwd_pkts]
        bwd_flags = [p[2] for p in self.bwd_pkts]

        syn_cnt = sum(1 for f in all_flags if f & 0x02)
        fin_cnt = sum(1 for f in all_flags if f & 0x01)
        rst_cnt = sum(1 for f in all_flags if f & 0x04)
        psh_cnt = sum(1 for f in all_flags if f & 0x08)
        ack_cnt = sum(1 for f in all_flags if f & 0x10)
        urg_cnt = sum(1 for f in all_flags if f & 0x20)
        ece_cnt = sum(1 for f in all_flags if f & 0x40)

        fwd_header_len = sum(p[3] for p in self.fwd_pkts)
        bwd_header_len = sum(p[3] for p in self.bwd_pkts)

        total       = self.total_pkts
        flow_byts_s = (totlen_fwd + totlen_bwd) / duration
        flow_pkts_s = total / duration
        fwd_pkts_s  = tot_fwd / duration
        bwd_pkts_s  = tot_bwd / duration

        return {
            'src_ip':            self.src_ip,
            'dst_ip':            self.dst_ip,
            'src_port':          self.src_port,
            'dst_port':          self.dst_port,
            'protocol':          self.proto,
            'timestamp':         time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_ts)),
            'flow_duration':     duration * 1e6,
            'flow_byts_s':       flow_byts_s,
            'flow_pkts_s':       flow_pkts_s,
            'fwd_pkts_s':        fwd_pkts_s,
            'bwd_pkts_s':        bwd_pkts_s,
            'tot_fwd_pkts':      tot_fwd,
            'tot_bwd_pkts':      tot_bwd,
            'totlen_fwd_pkts':   totlen_fwd,
            'totlen_bwd_pkts':   totlen_bwd,
            'fwd_pkt_len_max':   fwd_max,
            'fwd_pkt_len_min':   fwd_min,
            'fwd_pkt_len_mean':  fwd_mean,
            'fwd_pkt_len_std':   fwd_std,
            'bwd_pkt_len_max':   bwd_max,
            'bwd_pkt_len_min':   bwd_min,
            'bwd_pkt_len_mean':  bwd_mean,
            'bwd_pkt_len_std':   bwd_std,
            'pkt_len_max':       pkt_max,
            'pkt_len_min':       pkt_min,
            'pkt_len_mean':      pkt_mean,
            'pkt_len_std':       pkt_std,
            'pkt_len_var':       pkt_var,
            'fwd_header_len':    fwd_header_len,
            'bwd_header_len':    bwd_header_len,
            'fwd_seg_size_avg':  fwd_mean,
            'bwd_seg_size_avg':  bwd_mean,
            'fwd_seg_size_min':  fwd_min,
            'fwd_act_data_pkts': sum(1 for p in self.fwd_pkts if p[1] > 0),
            'flow_iat_mean':     flow_iat_mean,
            'flow_iat_std':      flow_iat_std,
            'flow_iat_min':      flow_iat_min,
            'flow_iat_max':      flow_iat_max,
            'fwd_iat_tot':       fwd_iat_tot,
            'fwd_iat_mean':      fwd_iat_mean,
            'fwd_iat_std':       fwd_iat_std,
            'fwd_iat_min':       fwd_iat_min,
            'bwd_iat_tot':       bwd_iat_tot,
            'bwd_iat_mean':      bwd_iat_mean,
            'bwd_iat_std':       bwd_iat_std,
            'bwd_iat_min':       bwd_iat_min,
            'fin_flag_cnt':      fin_cnt,
            'syn_flag_cnt':      syn_cnt,
            'rst_flag_cnt':      rst_cnt,
            'psh_flag_cnt':      psh_cnt,
            'ack_flag_cnt':      ack_cnt,
            'urg_flag_cnt':      urg_cnt,
            'ece_flag_cnt':      ece_cnt,
            'fwd_psh_flags':     sum(1 for f in fwd_flags if f & 0x08),
            'bwd_psh_flags':     sum(1 for f in bwd_flags if f & 0x08),
            'fwd_urg_flags':     sum(1 for f in fwd_flags if f & 0x20),
            'bwd_urg_flags':     sum(1 for f in bwd_flags if f & 0x20),
            'down_up_ratio':     tot_bwd / max(tot_fwd, 1),
            'pkt_size_avg':      pkt_mean,
            'init_fwd_win_byts': max(self.init_fwd_win, 0),
            'init_bwd_win_byts': max(self.init_bwd_win, 0),
            'active_mean':       duration * 1e6 / max(total, 1),
            'active_std':        0.0,
            'idle_mean':         0.0,
            'idle_std':          0.0,
            'fwd_byts_b_avg':    totlen_fwd / max(tot_fwd, 1),
            'fwd_pkts_b_avg':    1.0,
            'bwd_byts_b_avg':    totlen_bwd / max(tot_bwd, 1),
            'bwd_pkts_b_avg':    1.0,
            'fwd_blk_rate_avg':  0.0,
            'bwd_blk_rate_avg':  0.0,
            'subflow_fwd_pkts':  tot_fwd,
            'subflow_bwd_pkts':  tot_bwd,
            'subflow_fwd_byts':  totlen_fwd,
            'subflow_bwd_byts':  totlen_bwd,
            'cwe_flag_count':    0,
            '_source':           'ubuntu_agent',  # Mac IPS에서 중복 처리 방지용
        }


# ==================== 플로우 수집기 ====================
class FlowCollector:
    def __init__(self, iface, callback):
        self.iface    = iface
        self.callback = callback
        self.flows    = {}
        self.lock     = threading.Lock()
        self._running = False

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        if (src_ip, src_port) > (dst_ip, dst_port):
            return (dst_ip, src_ip, dst_port, src_port, proto)
        return (src_ip, dst_ip, src_port, dst_port, proto)

    def _on_packet(self, pkt):
        if IP not in pkt:
            return
        ts      = float(pkt.time)
        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        proto   = pkt[IP].proto
        ip_hlen = pkt[IP].ihl * 4
        src_port = dst_port = flags = win = tcp_hlen = 0
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = int(pkt[TCP].flags)
            win      = pkt[TCP].window
            tcp_hlen = pkt[TCP].dataofs * 4
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        header_len = ip_hlen + tcp_hlen
        pkt_len    = len(pkt[IP])
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        with self.lock:
            if key not in self.flows:
                self.flows[key] = FlowRecord(src_ip, dst_ip, src_port, dst_port, proto, ts)
            flow   = self.flows[key]
            is_fwd = (src_ip == flow.src_ip)
            flow.add_packet(is_fwd, ts, pkt_len, flags, header_len, win)
            if TCP in pkt and (flags & 0x01 or flags & 0x04):
                finished = self.flows.pop(key)
                self._emit(finished)

    def _emit(self, flow):
        if flow.total_pkts >= MIN_PACKETS and self.callback:
            try:
                self.callback(flow.extract_features())
            except Exception:
                pass

    def _expire_loop(self):
        while self._running:
            time.sleep(1.0)
            now = time.time()
            expired_keys = []
            with self.lock:
                for key, flow in self.flows.items():
                    if flow.is_expired(now):
                        expired_keys.append(key)
                for key in expired_keys:
                    self._emit(self.flows.pop(key))

    def start(self):
        self._running = True
        threading.Thread(target=self._expire_loop, daemon=True).start()
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            # 실제 웹서버/허니팟 포트만 캡처 — Mac으로 보내는 alert 웹훅(8000), SSH(22),
            # apt/DNS 등 Ubuntu 자체 관리 트래픽이 플로우로 잡혀서 Mac IP가
            # attacker_ip로 둔갑하는 문제(self-block 원인) 방지
            filter='tcp port 5000 or tcp port 9999',
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        print(f"✅ 패킷 캡처 시작 (인터페이스: {self.iface})")

    def stop(self):
        self._running = False
        if hasattr(self, '_sniffer'):
            try:
                self._sniffer.stop(join=False)
            except Exception:
                pass


# ==================== 소켓 전송 (자동 재연결) ====================
_send_queue = queue.Queue(maxsize=2000)

def sender_thread():
    """Mac IPS로 플로우 데이터 전송. 연결 끊기면 자동 재연결."""
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((IPS_HOST, IPS_PORT))
            sock.settimeout(None)
            print(f"✅ Mac IPS 연결됨 ({IPS_HOST}:{IPS_PORT})")
            while True:
                features = _send_queue.get()
                line = json.dumps(features, ensure_ascii=False) + '\n'
                sock.sendall(line.encode('utf-8'))
        except Exception as e:
            print(f"⚠️ 소켓 오류: {e} — 5초 후 재연결...")
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            time.sleep(5)


def on_flow(features):
    try:
        _send_queue.put_nowait(features)
    except queue.Full:
        pass  # 버퍼 가득 찼으면 해당 플로우 버림 (유실 최소화 우선)


# ==================== 메인 ====================
if __name__ == '__main__':
    threading.Thread(target=sender_thread, daemon=True).start()
    collector = FlowCollector(iface=IFACE, callback=on_flow)
    collector.start()
    print(f"\n{'='*50}")
    print(f"🔍 Ubuntu IPS 에이전트 실행 중")
    print(f"   인터페이스: {IFACE}")
    print(f"   IPS 주소: {IPS_HOST}:{IPS_PORT}")
    print(f"   Ctrl+C 로 종료")
    print(f"{'='*50}\n")
    try:
        while True:
            time.sleep(10)
            qsize = _send_queue.qsize()
            if qsize > 0:
                print(f"  [큐] 대기 중인 플로우: {qsize}개")
    except KeyboardInterrupt:
        collector.stop()
        print("\n에이전트 종료")
