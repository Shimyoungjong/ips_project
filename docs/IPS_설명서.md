# 머신러닝 기반 네트워크 침입 방지 시스템 (IPS)
## 상세 설계 및 동작 설명서

---

## 1. 시스템 개요

### 목적
네트워크 트래픽을 실시간으로 감시하여 공격을 자동 탐지하고, 위협 수준에 따라 단계적으로 대응하는 IPS(Intrusion Prevention System) 구현.

### 핵심 기술 스택
| 구성요소 | 기술 |
|----------|------|
| 패킷 캡처 | Scapy (AsyncSniffer) |
| 플로우 집계 | 자체 구현 FlowRecord |
| 공격 탐지 | Random Forest (scikit-learn) |
| 차단 | macOS pfctl + Ubuntu iptables |
| 허니팟 | Flask (포트 9999) |
| 대시보드 | React + FastAPI |
| DB | SQLite |

---

## 2. 네트워크 구성

```
┌─────────────────────────────────────────────────────────┐
│                    핫스팟 네트워크                        │
│                   (172.20.10.0/24)                       │
│                                                          │
│  [칼리 - 공격자]          [맥북 - IPS 호스트]            │
│   172.20.10.4    ──────▶   172.20.10.2 (en0)             │
│                              │                           │
│                              │ (bridge100: 192.168.64.x) │
│                              ▼                           │
│                         [우분투 VM]                       │
│                       172.20.10.5                        │
│                    Flask 서버 (포트 5000)                 │
│                    허니팟 서버 (포트 9999)                │
└─────────────────────────────────────────────────────────┘
```

### 트래픽 경로
- 칼리 → 우분투로 가는 모든 트래픽이 맥북 en0를 반드시 통과
- 맥북이 중간에서 Scapy로 패킷을 수동(passive) 방식으로 캡처
- 우분투는 맥북 내부 UTM 가상머신으로 bridge100(192.168.64.10)으로 SSH 접속 가능

---

## 3. 전체 동작 흐름

```
①패킷 캡처 → ②플로우 집계 → ③피처 추출 → ④ML 분류 → ⑤임계값 판단 → ⑥단계별 대응
```

---

## 4. ① 패킷 캡처

**파일**: `scapy_flow.py`

```python
AsyncSniffer(iface='en0', filter='ip', prn=_on_packet, store=False)
```

- Scapy의 `AsyncSniffer`로 en0 인터페이스의 모든 IP 패킷을 실시간 캡처
- `filter='ip'`로 IP 패킷만 수신 (ARP 등 제외)
- `store=False`로 메모리에 저장하지 않고 즉시 처리
- TCP / UDP 패킷 모두 처리, ICMP는 포트가 없어 플로우 집계에서 제외

---

## 5. ② 플로우 집계

**파일**: `scapy_flow.py` - `ScapyFlowCollector`, `FlowRecord`

### 플로우 키 (Flow Key)
동일한 통신 세션을 식별하는 5-tuple:
```
(src_ip, dst_ip, src_port, dst_port, protocol)
```
양방향 트래픽을 하나의 플로우로 묶기 위해 IP+포트를 정렬하여 canonical key 생성.

### 방향 판단
- 플로우를 생성한 첫 번째 패킷의 src_ip를 기준으로 forward/backward 구분
- `is_fwd = (src_ip == flow.src_ip)`

### 플로우 완료 조건
| 조건 | 설명 |
|------|------|
| TCP FIN/RST 수신 | 연결 종료 신호 감지 시 즉시 완료 |
| 2초 타임아웃 | 마지막 패킷 후 2초 경과 시 완료 |
| 최대 패킷 수 초과 | 1000개 이상 시 강제 완료 |
| 최소 패킷 미만 | 2개 미만이면 버림 |

---

## 6. ③ 피처 추출

**파일**: `scapy_flow.py` - `FlowRecord.extract_features()`

완료된 플로우에서 총 **65개 피처** 추출:

### 패킷 길이 관련
| 피처 | 설명 |
|------|------|
| fwd_pkt_len_mean/std/max/min | 순방향 패킷 길이 통계 |
| bwd_pkt_len_mean/std/max/min | 역방향 패킷 길이 통계 |
| pkt_len_mean/std/var/max/min | 전체 패킷 길이 통계 |
| totlen_fwd_pkts / totlen_bwd_pkts | 순/역방향 총 바이트 |

### 플로우 속도
| 피처 | 설명 |
|------|------|
| flow_byts_s | 초당 바이트 수 |
| flow_pkts_s | 초당 패킷 수 |
| fwd_pkts_s / bwd_pkts_s | 순/역방향 초당 패킷 수 |

### 패킷 간격 (IAT)
| 피처 | 설명 |
|------|------|
| flow_iat_mean/std/min/max | 전체 패킷 간격 통계 |
| fwd_iat_tot/mean/std/min | 순방향 패킷 간격 통계 |
| bwd_iat_tot/mean/std/min | 역방향 패킷 간격 통계 |

### TCP 플래그
| 피처 | 설명 |
|------|------|
| syn_flag_cnt | SYN 플래그 수 |
| fin_flag_cnt | FIN 플래그 수 |
| rst_flag_cnt | RST 플래그 수 |
| psh_flag_cnt | PSH 플래그 수 |
| ack_flag_cnt | ACK 플래그 수 |

### 파생 피처 (학습 시 추가 계산)
| 피처 | 설명 | 의미 |
|------|------|------|
| win_ratio | init_fwd_win / init_bwd_win | 윈도우 크기 비율 |
| payload_ratio | totlen_fwd / totlen_bwd | 페이로드 비율 |
| fwd_bwd_pkt_ratio | tot_fwd_pkts / tot_bwd_pkts | 패킷 수 비율 |
| syn_ratio | syn_cnt / total_pkts | SYN 비율 |
| rst_ratio | rst_cnt / total_pkts | RST 비율 |
| header_ratio | header_len / total_bytes | 헤더 오버헤드 |
| bytes_per_pkt | flow_byts_s / flow_pkts_s | 패킷당 바이트 |

---

## 7. ④ ML 분류

**파일**: `train_mydata.py`, `models/rf_model.pkl`

### 모델
- **알고리즘**: Random Forest Classifier
- **하이퍼파라미터 튜닝**: RandomizedSearchCV (n_iter=20, cv=3)
- **학습 데이터**: 각 클래스 68,000개 × 6클래스 = 408,000개 플로우

### 학습 데이터 수집 방법
| 공격 유형 | 수집 도구 |
|-----------|-----------|
| DDoS | hping3 --faster, ab (Apache Benchmark) |
| BruteForce | Hydra (HTTP POST, SSH) |
| PortScan | nmap -sT, nmap -sS |
| SQLi | sqlmap, curl (SQL 페이로드) |
| XSS | xsser, dalfox, curl (XSS 페이로드) |
| BENIGN | curl 정상 요청 (sleep 0.2~0.3초 간격) |

### 성능
```
전체 정확도: 98%

클래스별 F1-score:
  BENIGN     : 0.97
  BruteForce : 0.99
  DDoS       : 1.00
  PortScan   : 1.00
  SQLi       : 0.95
  XSS        : 0.95
```

### 출력
- `pred`: 예측 클래스 (BENIGN / DDoS / BruteForce / PortScan / SQLi / XSS)
- `conf`: 예측 신뢰도 (0.0 ~ 1.0)

---

## 8. ⑤ 임계값 판단

**파일**: `realtime_detect.py`

### 탐지 필터
신뢰도가 아래 기준 미만이면 무시:

| 공격 유형 | 최소 신뢰도 |
|-----------|------------|
| PortScan  | 80% |
| BruteForce| 80% |
| DDoS      | 80% |
| XSS       | 85% |
| SQLi      | 85% |

### 누적 카운트
- 같은 IP에서 **5분(300초) 이내** 공격이 탐지될 때마다 카운트 증가
- 공격 유형 관계없이 같은 IP면 누적
- **3회 이상** 누적 시 대응 발동

---

## 9. ⑥ 단계별 대응

**파일**: `realtime_detect.py`

### 대응 레벨 기준
```
신뢰도 50% ~ 60%  →  LOW      (기록)
신뢰도 60% ~ 75%  →  MEDIUM   (속도 제한)
신뢰도 75% ~ 90%  →  HIGH     (허니팟)
신뢰도 90% 이상   →  CRITICAL (차단) ← 감시목록 등록된 IP에 한해
```

### LOW
- SQLite DB에 탐지 기록 저장
- 차단 없음, 모니터링만

### MEDIUM
- Ubuntu iptables hashlimit으로 해당 IP의 포트 5000 접속을 **초당 5개**로 제한
- 맥 pfctl throttlelist에 IP 추가

### HIGH
1. 맥 pfctl `highlist` 테이블에 IP 추가
2. Ubuntu iptables NAT PREROUTING 규칙 추가:
   ```
   iptables --insert PREROUTING -t nat -s {ip} -p tcp --dport 5000 -j REDIRECT --to-port 9999
   ```
3. 공격자의 모든 요청이 허니팟(포트 9999)으로 리다이렉트됨
4. 감시목록(Watchlist)에 등록 + watchlist_cache 즉시 반영

### CRITICAL (감시목록 등록 IP에 한해)
1. 맥 pfctl `blocklist` 테이블에 IP 추가 → 맥 레벨에서 차단
2. Ubuntu iptables INPUT/FORWARD에 DROP 규칙 추가 → 우분투 레벨에서 차단
3. tcpdump로 해당 IP 패킷 캡처 → `evidence/` 폴더에 pcap 파일 저장
4. DB `blocked_ips` 테이블에 기록
5. **10분 후 자동 해제**

---

## 10. 허니팟 상세

**파일**: `honeypot_flask.py` (Ubuntu에서 실행)

- Flask 앱으로 실제 서버(`vulnerable_server/app.py`)와 동일한 UI/엔드포인트 제공
- `/login`, `/board`, `/search` 등 모든 페이지 구현
- 실제 서버와 달리 모든 요청을 `/tmp/honeypot_log.txt`에 기록
- 공격자는 진짜 서버를 공격하는 줄 알고 계속 공격 진행

### 허니팟 리다이렉트 흐름
```
칼리 → 우분투:5000 요청
         ↓ (Ubuntu iptables NAT)
         우분투:9999 (허니팟)으로 내부 리다이렉트
         ↓
         공격자는 200 OK 응답 받음 (계속 공격)
         ↓
         모든 페이로드 로그 기록
```

---

## 11. PortScan 휴리스틱

ML 모델 외에 별도의 규칙 기반 포트스캔 탐지:

- **윈도우**: 5초
- **임계값**: 5초 내에 같은 IP에서 30개 이상의 다른 포트로 접속 시도
- ML 모델보다 빠르게 탐지 가능 (플로우 완료 불필요)

---

## 12. HTTP 페이로드 탐지

Scapy로 포트 5000의 HTTP 패킷 페이로드를 직접 분석:

- URL에 SQL 키워드(`UNION`, `SELECT`, `OR 1=1` 등) 포함 시 SQLi 탐지
- URL에 HTML 태그(`<script>`, `<img onerror>` 등) 포함 시 XSS 탐지
- 별도 RF 모델(`rf_model_http.pkl`)로 분류

---

## 13. 화이트리스트

오탐 방지를 위해 탐지 대상에서 제외하는 IP/대역:

| IP / 대역 | 설명 |
|-----------|------|
| 127.0.0.1 | 루프백 |
| 172.20.10.1 | 핫스팟 게이트웨이 (아이폰) |
| 172.20.10.2 | 맥북 IPS 호스트 |
| 192.168.64.1 | bridge100 게이트웨이 |
| 160.79.104.0/21 | Anthropic (Claude AI) |
| 13.64.0.0/11 | Microsoft VSCode/Azure |
| 20.33.0.0/16 | Microsoft Azure |
| 17.0.0.0/8 | Apple 백그라운드 트래픽 |
| 185.125.188.0/22 | Canonical (Ubuntu apt) |
| 23.32.0.0/11 | Akamai CDN |
| 34.0.0.0/8 | Google Cloud |
| 121.53.93.72 | 드림라인 메일서버 |

화이트리스트 매칭 시 detect.log에 `⬜ [WHITELIST_SKIP]` 표시.

---

## 14. 대시보드

**백엔드**: `pj/model/main.py` (FastAPI, 포트 8000)  
**프론트엔드**: `pj/frontend/` (React, 포트 3000)

### 주요 기능
| 기능 | 설명 |
|------|------|
| ▶ 시작 | realtime_detect.py 실행, 세션 초기화 |
| ■ 중지 | realtime_detect.py 종료 |
| 🚨 긴급 해제 | pfctl/iptables 전체 초기화, 감시목록 삭제 |
| 실시간 로그 | 탐지된 공격 IP, 유형, 신뢰도, 차단 여부 표시 |
| 통계 | 공격 유형별 카운트, 총 탐지 수 |
| 감시목록 | 현재 감시 중인 IP 목록 |

---

## 15. 시연 순서

### 사전 준비 (한 번만)

**Ubuntu 터미널:**
```bash
# Flask 웹서버
cd ~/vulnerable_server && python3 app.py

# 허니팟 서버
python3 ~/honeypot_flask.py
```

**Mac 터미널 1 - 백엔드:**
```bash
cd ~/ips_project
sudo /opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python -m uvicorn pj.model.main:app --host 0.0.0.0 --port 8000
```

**Mac 터미널 2 - 대시보드:**
```bash
cd ~/ips_project/pj/frontend && npm start
```

### 시연 시작
```bash
# 환경 초기화 (매 시연마다)
sudo ~/ips_project/demo_reset.sh
```

1. 브라우저 `http://localhost:3000` → **▶ 시작** 클릭
2. 칼리에서 공격 전송

### 공격 명령어 예시

**DDoS:**
```bash
sudo hping3 -S --faster -p 5000 172.20.10.5
ab -n 20000 -c 200 http://172.20.10.5:5000/
```

**BruteForce:**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 16 \
  http-post-form://172.20.10.5:5000/login:"username=^USER^&password=^PASS^:F=alert-danger"
```

**PortScan:**
```bash
nmap -sT -p 1-10000 172.20.10.5
```

**SQLi:**
```bash
sqlmap -u 'http://172.20.10.5:5000/search?q=test' --batch --level=3 --threads=5
```

**XSS:**
```bash
for i in $(seq 1 100); do
  curl -s 'http://172.20.10.5:5000/search?q=<script>alert(1)</script>' > /dev/null
  sleep 0.1
done
```

### 시연 흐름 확인
```bash
# 탐지 로그 실시간 확인
tail -f ~/ips_project/detect.log

# 허니팟 접속 확인
ssh hisecure@192.168.64.10 "cat /tmp/honeypot_log.txt | tail -10"

# Ubuntu iptables 확인
ssh hisecure@192.168.64.10 "sudo iptables -t nat -L PREROUTING -n"
```

---

## 16. 파일 구조

```
ips_project/
├── realtime_detect.py     # IPS 메인 엔진 (탐지 + 대응)
├── scapy_flow.py          # 패킷 캡처 + 플로우 집계 + 피처 추출
├── train_mydata.py        # RF 모델 학습
├── add_labels.py          # 수집 데이터 라벨링
├── capture_flows.py       # 수동 데이터 수집 (Ctrl+C로 중지)
├── auto_collect.py        # 자동 데이터 수집 (공격 자동화)
├── honeypot_flask.py      # 허니팟 Flask 서버 (Ubuntu에서 실행)
├── demo_reset.sh          # 시연 환경 초기화 스크립트
├── IPS_설명서.md           # 이 문서
├── models/
│   ├── rf_model.pkl           # 학습된 RF 모델
│   ├── feature_names.pkl      # 피처 이름 목록
│   ├── classes.pkl            # 클래스 목록
│   ├── rf_model_http.pkl      # HTTP 페이로드 분류 모델
│   └── confusion_matrix_mydata.png  # 혼동행렬 이미지
├── MachineLearningCSV/    # 라벨링된 학습 데이터
│   ├── benign_labeled.csv
│   ├── ddos_labeled.csv
│   ├── bruteforce_labeled.csv
│   ├── portscan_labeled.csv
│   ├── sqli_labeled.csv
│   └── xss_labeled.csv
├── captures/              # 수집된 raw 플로우 CSV
├── evidence/              # CRITICAL 탐지 시 pcap 증거 파일
└── pj/
    ├── model/main.py      # FastAPI 백엔드 (포트 8000)
    └── frontend/          # React 대시보드 (포트 3000)
```

---

## 17. 주요 설정값 요약

| 설정 | 값 | 설명 |
|------|----|------|
| FLOW_TIMEOUT | 2초 | 플로우 완료 타임아웃 |
| BLOCK_THRESHOLD | 3회 | 대응 발동 임계 횟수 |
| BLOCK_WINDOW_SECONDS | 300초 | 카운트 누적 윈도우 |
| AUTO_UNBLOCK_MINUTES | 10분 | 자동 차단 해제 시간 |
| LEVEL_LOW | 50% | LOW 대응 임계값 |
| LEVEL_MEDIUM | 60% | MEDIUM 대응 임계값 |
| LEVEL_HIGH | 75% | HIGH 대응 임계값 |
| LEVEL_CRITICAL | 90% | CRITICAL 대응 임계값 |
