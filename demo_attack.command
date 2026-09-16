#!/bin/bash
# IPS 시연용 공격 스크립트 (화면 녹화 전용)
# 환경변수 IPS_PYTHON / IPS_UBUNTU_HOST 로 재정의 가능(미지정 시 기존 기본값)
PYTHON="${IPS_PYTHON:-$HOME/ips_project/.venv/bin/python}"
BASE_URL="http://localhost:8000"
IP="${IPS_UBUNTU_HOST:-192.168.64.10}"

echo "================================================"
echo "  IPS 시연 공격 스크립트"
echo "================================================"
echo ""
echo "대시보드(http://localhost:3000)에서"
echo "  1. '긴급 해제' 클릭"
echo "  2. '▶ 시작' 클릭"
echo ""
echo "준비 완료되면 Enter ..."
read -r

# 서버 메모리 초기화
echo "[초기화] 서버 상태 초기화 중..."
curl -s -X POST $BASE_URL/emergency_reset > /dev/null
sleep 1
echo "[완료] 초기화 완료. 공격 시작!"
echo ""

# ───────────────────────────────────
# 1단계: SQLi 공격 (3회 → 차단)
# ───────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [SQLi 공격] 3회 누적 → PF 자동 차단"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 1

for i in 1 2 3; do
  PAYLOAD="' OR 1=1 --"
  RES=$(curl -s -X POST $BASE_URL/detect_http \
    -H "Content-Type: application/json" \
    -d "{\"payload\": \"$PAYLOAD\", \"attacker_ip\": \"$IP\"}")
  BLOCKED=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print('✅ 차단됨!' if d.get('blocked') else '⚠️  탐지됨')" 2>/dev/null)
  CONF=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('confidence',0)*100:.1f}%\")" 2>/dev/null)
  echo "  [SQLi $i/3] 신뢰도: $CONF | $BLOCKED"
  sleep 2   # 대시보드에서 볼 수 있도록 2초 대기
done

echo ""
echo "  ★ 192.168.64.10 PF 차단 목록 확인:"
sudo pfctl -t blocklist -T show 2>/dev/null | sed 's/^/    /'
echo ""
sleep 3

# ───────────────────────────────────
# 2단계: 서버 초기화 후 XSS 공격
# ───────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [긴급 해제 → XSS 공격] 3회 → 차단"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  * 대시보드에서 '긴급 해제' 클릭하세요 *"
sleep 3
curl -s -X POST $BASE_URL/emergency_reset > /dev/null
echo "  초기화 완료. XSS 공격 시작..."
echo ""
sleep 1

for i in 1 2 3; do
  PAYLOAD="<script>alert('xss')</script>"
  RES=$(curl -s -X POST $BASE_URL/detect_http \
    -H "Content-Type: application/json" \
    -d "{\"payload\": \"$PAYLOAD\", \"attacker_ip\": \"$IP\"}")
  BLOCKED=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print('✅ 차단됨!' if d.get('blocked') else '⚠️  탐지됨')" 2>/dev/null)
  CONF=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('confidence',0)*100:.1f}%\")" 2>/dev/null)
  echo "  [XSS $i/3] 신뢰도: $CONF | $BLOCKED"
  sleep 2
done

echo ""
echo "  ★ PF 차단 목록 최종 확인:"
sudo pfctl -t blocklist -T show 2>/dev/null | sed 's/^/    /'
echo ""
echo "================================================"
echo "  시연 완료! 녹화를 중지하세요."
echo "================================================"
