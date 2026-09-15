# 머신러닝 기반 실시간 네트워크 침입 방지 시스템 (IPS)

네트워크 트래픽을 실시간으로 감시하여 공격을 자동 탐지하고, 위협 수준에 따라
단계적으로 대응(기록 → 속도 제한 → 허니팟 유인 → 차단)하는 IPS 구현체입니다.
Random Forest 분류기로 네트워크 플로우와 HTTP 페이로드를 분석하며, 탐지 결과는
React 대시보드에서 실시간으로 확인할 수 있습니다.

> 이 저장소는 학습/시연용 프로젝트입니다. 격리된 실습 환경(개인 핫스팟 + VM)에서만
> 사용하세요. 실제 운영망이나 타인의 네트워크에 사용하면 안 됩니다.

---

## 1. 주요 기능

- **실시간 플로우 탐지** — Scapy로 패킷을 캡처해 5-tuple 플로우로 집계하고 65개 피처를 추출, RF 모델로 6개 클래스(BENIGN / DDoS / BruteForce / PortScan / SQLi / XSS) 분류
- **HTTP 페이로드 탐지** — SQLi/XSS 페이로드를 별도의 경량 RF 모델(`rf_model_http.pkl`)로 분류
- **단계적 위협 대응** — 신뢰도·누적 횟수에 따라 LOW/MEDIUM/HIGH/CRITICAL 4단계로 대응
- **허니팟 유인** — HIGH 단계에서 공격자를 실제 서버 클론(포트 9999)으로 리다이렉트하여 페이로드 수집
- **자동 차단/해제** — macOS `pfctl` + Ubuntu `iptables`로 차단, 일정 시간 후 자동 해제
- **관제 대시보드** — 실시간 로그, 공격 유형별 통계, 감시목록, 차단 IP 관리 UI (React + FastAPI WebSocket)

---

## 2. 아키텍처

```
┌──────────────────────────────────────────────────────────────┐
│                     실습 네트워크 (예: 핫스팟)                 │
│                                                                │
│   [공격자 VM/호스트]        [Mac — IPS 탐지 서버]              │
│        (Kali 등)   ───────▶   en0 (패킷 통과)                  │
│                                 │                              │
│                                 │  bridge100 (192.168.64.x)    │
│                                 ▼                              │
│                          [Ubuntu VM]                          │
│                     취약 웹서버 (포트 5000)                    │
│                     허니팟 서버   (포트 9999)                  │
│                     ubuntu_agent (패킷 수집 에이전트)         │
└──────────────────────────────────────────────────────────────┘

  패킷 캡처 ─▶ 플로우 집계 ─▶ 피처 추출 ─▶ ML 분류 ─▶ 임계값 판단 ─▶ 단계별 대응
```

- **Ubuntu 에이전트**(`ubuntu_agent.py`) — Ubuntu 인터페이스에서 패킷을 직접 캡처·집계하여 Mac IPS로 TCP 소켓 전송
- **Mac 탐지 서버**(`realtime_detect.py` + `pj/model/main.py`) — 로컬 캡처와 에이전트 수신 플로우를 ML로 분류하고 대응 수행, FastAPI로 대시보드/허니팟 연동
- **대시보드**(`pj/frontend`) — React 앱, 5초 폴링 + WebSocket으로 상태 표시
- **허니팟**(`honeypot_flask.py`) — Ubuntu에서 실행, 모든 요청을 로깅하고 입력값을 Mac의 HTTP ML 탐지기로 전달

전체 상세 설계(피처 목록, 플로우 완료 조건, 대응 단계별 동작 등)는
[`docs/IPS_설명서.md`](docs/IPS_설명서.md)를 참고하세요.

---

## 3. 요구사항

**Mac (탐지 서버 / 대시보드)**
- macOS (pfctl 사용)
- Python 3.10+ 및 패키지: `scapy`, `scikit-learn`, `pandas`, `numpy`, `joblib`, `fastapi`, `uvicorn`, `requests`
- Node.js 18+ / npm (React 대시보드)
- 학습된 모델 파일 (`models/` — 저장소에는 포함되지 않음, 아래 참고)

**Ubuntu (공격 대상 / 에이전트)**
- Python 3, `scapy`, `flask`, `requests`
- 취약 웹서버(`vulnerable_server/app.py`), `honeypot_flask.py`, `ubuntu_agent.py`

> ⚠️ `models/`, `MachineLearningCSV/`, `captures/`, `ips_logs.db`, `evidence/` 등
> 대용량·생성물 파일은 `.gitignore`로 제외되어 있어 저장소 clone만으로는 없습니다.
> 모델은 `train_mydata.py`로 재학습하거나 별도로 전달받아 `models/`에 두어야 합니다.

---

## 4. 설정

경로·호스트·SSH 키 등 환경 의존 값은 환경변수로 분리했습니다. 기본값은 기존 동작과
동일하므로, 동일 환경에서는 별도 설정 없이 그대로 동작합니다. 다른 환경에서는
`.env.example`을 복사해 값을 채우고 셸에 export 하세요.

```bash
cp .env.example .env
# .env 편집 후:
set -a; source .env; set +a
```

| 환경변수 | 기본값 | 설명 |
|----------|--------|------|
| `IPS_HOME` | `~/ips_project` | 프로젝트 루트 (DB·모델·캡처·증거·로그·rules.json 기준 경로) |
| `IPS_SSH_KEY` | `~/.ssh/id_ed25519` | Ubuntu VM 접속용 SSH 개인키 경로 |
| `IPS_UBUNTU_HOST` | `192.168.64.10` | Ubuntu VM 호스트(IP) |
| `IPS_UBUNTU_USER` | `hisecure` | Ubuntu SSH 사용자명 |
| `IPS_PYTHON` | miniforge `ips_env` 파이썬 | 시연 스크립트가 사용할 Python 실행 파일 |

> 실제 SSH 키·비밀값은 저장소에 넣지 마세요. `.env`는 `.gitignore`에 포함되어 있습니다.

탐지 임계값·차단 정책은 코드 수정 없이 [`rules.json`](rules.json)에서 조정합니다
(자세한 내용은 8절 참고).

---

## 5. 설치 및 실행

```bash
# 1) 대시보드 프론트엔드 의존성 설치
cd pj/frontend && npm install && cd ../..

# 2) (필요 시) 모델 재학습 — MachineLearningCSV/ 데이터 필요
python train_mydata.py

# 3) 원클릭 시연 (Ubuntu 서비스 + Mac 백엔드 + 대시보드 자동 기동)
bash start_demo.sh
#   → http://localhost:3000 대시보드에서 ▶ 시작 버튼으로 탐지 시작
```

수동 실행:

```bash
# Ubuntu 측 (VM 안에서)
cd ~/vulnerable_server && python3 app.py       # 취약 웹서버 (5000)
python3 ~/honeypot_flask.py                     # 허니팟 (9999)
sudo python3 ~/ubuntu_agent.py enp0s2           # 패킷 수집 에이전트

# Mac 측
sudo "$IPS_PYTHON" -m uvicorn pj.model.main:app --host 0.0.0.0 --port 8000  # 백엔드
cd pj/frontend && npm start                                                  # 대시보드 (3000)
```

시연마다 환경 초기화:

```bash
sudo bash demo_reset.sh    # pfctl/iptables 초기화, DB·로그·증거 리셋
```

---

## 6. 주요 파일 구조

```
ips_project/
├── realtime_detect.py        # IPS 메인 엔진 (탐지 + 단계별 대응 + 에이전트 수신)
├── scapy_flow.py             # 패킷 캡처 + 플로우 집계 + 피처 추출
├── ubuntu_agent.py           # Ubuntu 측 패킷 수집 에이전트 (Mac으로 TCP 전송)
├── honeypot_flask.py         # 허니팟 Flask 서버 (Ubuntu에서 실행)
├── train_mydata.py           # RF 모델 학습
├── add_labels.py             # 수집 데이터 라벨링
├── capture_flows.py          # 수동 데이터 수집
├── test_model.py / test_http_model.py   # 모델 평가
├── gen_rf_tree.py            # RF 트리 시각화
├── rules.json                # 탐지 임계값·차단 정책 (런타임 로드)
├── .env.example              # 환경변수 샘플
├── demo_reset.sh, start_demo.sh, *.command   # 시연/실행 편의 스크립트
├── pj/
│   ├── model/main.py         # FastAPI 백엔드 (포트 8000)
│   └── frontend/             # React 대시보드 (포트 3000)
├── docs/
│   └── IPS_설명서.md          # 상세 설계 문서
└── (gitignore 대상)
    ├── models/               # 학습된 RF 모델 (.pkl)
    ├── MachineLearningCSV/   # 라벨링된 학습 데이터
    ├── captures/             # 수집된 raw 플로우 CSV
    ├── evidence/             # CRITICAL 탐지 시 pcap 증거
    └── ips_logs.db           # 탐지/차단 로그 (SQLite)
```

---

## 7. 탐지 흐름 요약

1. **캡처** — Scapy `AsyncSniffer`로 IP 패킷 실시간 수신 (`store=False`)
2. **집계** — 5-tuple(src/dst IP·포트·프로토콜)로 양방향 플로우 묶음. FIN/RST 또는 2초 타임아웃, 최대 1000패킷에서 완료
3. **피처 추출** — 패킷 길이·속도·IAT·TCP 플래그 등 65개 피처 + 파생 피처
4. **분류** — RF 모델이 클래스와 신뢰도(0~1) 출력
5. **판단** — 유형별 최소 신뢰도 미달 시 무시, 같은 IP의 공격을 윈도우 내 누적
6. **대응** — 아래 단계에 따라 기록/제한/유인/차단

---

## 8. 탐지 임계값 및 대응 정책 (`rules.json`)

```json
{
  "block_threshold": 1,          // 대응 발동까지 누적 임계 횟수
  "level_low": 0.40,             // LOW  대응 최소 신뢰도
  "level_medium": 0.55,          // MEDIUM
  "level_high": 0.65,            // HIGH
  "level_critical": 0.80,        // CRITICAL
  "high_to_critical_delay": 10,  // HIGH → CRITICAL 승격 지연(초)
  "auto_unblock_minutes": 10,    // 차단 후 자동 해제(분)
  "enable_block": true,          // 차단 기능 on/off
  "detection_threshold": {       // 유형별 최소 탐지 신뢰도
    "PortScan": 0.80, "BruteForce": 0.80, "DDoS": 0.80,
    "XSS": 0.85, "SQLi": 0.85
  },
  "extra_whitelist": []          // 추가 화이트리스트 IP
}
```

| 단계 | 트리거 | 동작 |
|------|--------|------|
| **LOW** | 낮은 신뢰도 | DB 기록만 (모니터링) |
| **MEDIUM** | 중간 신뢰도 | 속도 제한 (iptables hashlimit / pfctl throttle) |
| **HIGH** | 높은 신뢰도 | 허니팟(9999)으로 리다이렉트 + 감시목록 등록 |
| **CRITICAL** | 매우 높은 신뢰도 (감시목록 IP) | pfctl/iptables 차단 + pcap 증거 저장 + 자동 해제 예약 |

`rules.json`은 런타임에 로드되므로 값만 바꾸면 재시작 없이(또는 재시작 시) 정책이 반영됩니다.
화이트리스트, 대응 단계별 상세 동작은 `docs/IPS_설명서.md`를 참고하세요.

---

## 9. 라이선스 / 참고

- 라이선스: [`LICENSE`](LICENSE) 참고
- HTTP 페이로드 데이터셋 원본 설명: [`README.HttpParamsDataset.md`](README.HttpParamsDataset.md)
  (CSIC2010, sqlmap, XSSYA, Vega, FuzzDB 등 공개 소스 기반)
