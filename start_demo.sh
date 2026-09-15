#!/bin/bash
# =========================================
# IPS 시연 환경 시작 스크립트
# 탐지 시작은 대시보드 ▶ 버튼으로
# =========================================

UBUNTU="192.168.64.10"
SSH="ssh -i /Users/shimyoungjong/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o ConnectTimeout=5 hisecure@$UBUNTU"
IPS_PYTHON="/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python"
IPS_DIR="$HOME/ips_project"

echo "🔄 환경 초기화 중..."
sudo bash "$IPS_DIR/demo_reset.sh"
echo ""

# ── Ubuntu 서비스 시작 ──────────────────────
echo "🖥️  Ubuntu 서비스 시작 중..."

$SSH "pkill -f 'app.py' 2>/dev/null; pkill -f 'honeypot_flask.py' 2>/dev/null; pkill -f 'ubuntu_agent.py' 2>/dev/null; sleep 1
nohup bash -c 'cd ~/vulnerable_server && python3 app.py' > /tmp/webserver.log 2>&1 &
nohup python3 ~/honeypot_flask.py > /tmp/honeypot.log 2>&1 &
nohup sudo python3 ~/ubuntu_agent.py enp0s2 > /tmp/agent.log 2>&1 &
echo DONE"

echo "  ✅ 웹서버 / 허니팟 / 에이전트 시작"
echo ""

# ── Mac 백엔드 시작 ─────────────────────────
echo "🔧 FastAPI 백엔드 시작 중..."
pkill -f "uvicorn pj.model.main" 2>/dev/null
sleep 1
nohup sudo "$IPS_PYTHON" -m uvicorn pj.model.main:app \
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
