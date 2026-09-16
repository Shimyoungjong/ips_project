#!/bin/bash
# =========================================
# IPS 시연 환경 시작 스크립트
# 탐지 시작은 대시보드 ▶ 버튼으로
# =========================================

# 환경변수로 재정의 가능(미지정 시 기존 기본값):
#   IPS_UBUNTU_HOST, IPS_UBUNTU_USER, IPS_UBUNTU_IFACE, IPS_SSH_KEY, IPS_PYTHON, IPS_HOME
# IPS_UBUNTU_IFACE(우분투 캡처 인터페이스)는 우분투 버전/설치에 따라 달라지므로,
# 실행 전 우분투에서 `ip a`로 확인 후 필요하면 재정의하세요.
UBUNTU="${IPS_UBUNTU_HOST:-192.168.64.10}"
IPS_UBUNTU_USER="${IPS_UBUNTU_USER:-hisecure}"
IPS_UBUNTU_IFACE="${IPS_UBUNTU_IFACE:-enp0s1}"
IPS_SSH_KEY="${IPS_SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH="ssh -i $IPS_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5 $IPS_UBUNTU_USER@$UBUNTU"
IPS_DIR="${IPS_HOME:-$HOME/ips_project}"
# 백엔드(uvicorn) 실행에 쓸 파이썬 - 기본은 프로젝트 자체 venv.
# (cicflowmeter는 더 이상 안 씀 - ScapyFlowCollector가 패킷을 직접 캡처하므로 불필요)
IPS_PYTHON="${IPS_PYTHON:-$IPS_DIR/.venv/bin/python}"

echo "🔄 환경 초기화 중..."
sudo bash "$IPS_DIR/demo_reset.sh"
echo ""

# ── Ubuntu 서비스 시작 ──────────────────────
echo "🖥️  Ubuntu 서비스 시작 중..."

$SSH "pkill -f 'app.py' 2>/dev/null; pkill -f 'honeypot_flask.py' 2>/dev/null; pkill -f 'ubuntu_agent.py' 2>/dev/null; sleep 1
nohup bash -c 'cd ~/vulnerable_server && python3 app.py' > /tmp/webserver.log 2>&1 &
nohup python3 ~/honeypot_flask.py > /tmp/honeypot.log 2>&1 &
nohup sudo python3 ~/ubuntu_agent.py $IPS_UBUNTU_IFACE > /tmp/agent.log 2>&1 &
echo DONE"

echo "  ✅ 웹서버 / 허니팟 / 에이전트 시작"
echo ""

# ── Mac 백엔드 시작 ─────────────────────────
echo "🔧 FastAPI 백엔드 시작 중..."
pkill -f "uvicorn pj.model.main" 2>/dev/null
sleep 1
nohup sudo -E "$IPS_PYTHON" -m uvicorn pj.model.main:app \
    --host 0.0.0.0 --port 8000 \
    > "$IPS_DIR/backend.log" 2>&1 &
echo "  ✅ 백엔드 시작 (포트 8000)"
echo ""

# ── React 대시보드 시작 ─────────────────────
echo "📊 대시보드 시작 중..."
pkill -f "react-scripts start" 2>/dev/null
sleep 1
nohup bash -c "cd '$IPS_DIR/pj/frontend' && npm start" \
    > "$IPS_DIR/frontend.log" 2>&1 &
echo "  ✅ 대시보드 시작 (포트 3000)"
echo ""

# ── 대기 후 브라우저 열기 ───────────────────
echo "⏳ 서비스 준비 중 (10초)..."
sleep 10
open "http://localhost:3000"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  준비 완료!                               ║"
echo "║  대시보드에서 ▶ 시작 버튼을 누르세요.    ║"
echo "╚══════════════════════════════════════════╝"
