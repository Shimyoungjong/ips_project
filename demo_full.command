#!/bin/bash
# =========================================
# IPS 풀 시연 스크립트 (화면 녹화용)
# 네트워크 탐지: LOW → MEDIUM → HIGH → CRITICAL
# HTTP 탐지: SQLi / XSS → PF 차단
# =========================================
PYTHON=/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python
BASE_URL="http://localhost:8000"
UBUNTU="192.168.45.6"   # Ubuntu 취약 서버 (현재 IP)
HTTP_IP="192.168.45.135"  # Mac 공격자 IP (현재 네트워크)

echo "╔══════════════════════════════════════════╗"
echo "║    AI 기반 IPS 시연 (단계별 대응)         ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "사전 확인:"
echo "  ✅ 대시보드 ▶ 시작 눌렀는지 확인"
echo "  ✅ Ubuntu 에이전트 + 웹서버 실행 중 확인"
echo "  ✅ 긴급 해제 버튼 눌러서 초기화"
echo ""
echo "준비되면 Enter ..."
read -r

# 서버 초기화
curl -s -X POST $BASE_URL/emergency_reset > /dev/null
sleep 1

# ═══════════════════════════════════════
# Part 1: 네트워크 공격 탐지 (realtime_detect)
# DDoS성 트래픽 → LOW → MEDIUM → HIGH → CRITICAL
# ═══════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [Part 1] 네트워크 공격 탐지 시연"
echo "  Ubuntu($UBUNTU:5000)로 DDoS 트래픽 전송"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 1
echo ""
echo "  🚀 DDoS 트래픽 발생 중 (대시보드 확인)..."
# 빠른 HTTP 요청으로 DDoS 패턴 생성
for i in $(seq 1 50); do
  curl -s "http://$UBUNTU:5000/" > /dev/null &
done
wait
echo "  → 1차 전송 완료 (LOW/MEDIUM 탐지 기대)"
sleep 3

echo ""
echo "  🚀 2차 DDoS 트래픽 (HIGH 탐지 기대)..."
for i in $(seq 1 100); do
  curl -s "http://$UBUNTU:5000/search?q=test" > /dev/null &
done
wait
echo "  → 2차 전송 완료 (HIGH → 허니팟 리다이렉트 기대)"
sleep 3

echo ""
echo "  ⏳ HIGH→CRITICAL 쿨다운 대기 (10초)..."
for i in $(seq 10 -1 1); do
  echo -ne "  $i초 후 CRITICAL 공격...\r"
  sleep 1
done
echo ""

echo ""
echo "  🚀 3차 공격 (CRITICAL → 완전 차단 기대)..."
for i in $(seq 1 80); do
  curl -s "http://$UBUNTU:5000/" > /dev/null &
done
wait
echo "  → 3차 전송 완료 (CRITICAL 차단 기대)"
sleep 4

# ═══════════════════════════════════════
# Part 2: HTTP 공격 탐지 (SQLi / XSS)
# ═══════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [Part 2] HTTP 공격 탐지 시연 (SQLi/XSS)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  * 대시보드에서 '긴급 해제' 클릭하세요 *"
sleep 4
curl -s -X POST $BASE_URL/emergency_reset > /dev/null
echo "  초기화 완료."
echo ""

SQLI_PAYLOADS=("' OR 1=1 --" "'; DROP TABLE users; --" "' UNION SELECT * FROM users --")
echo "  [SQLi 공격 시작]"
for i in "${!SQLI_PAYLOADS[@]}"; do
  n=$((i+1))
  RES=$(curl -s -X POST $BASE_URL/detect_http \
    -H "Content-Type: application/json" \
    -d "{\"payload\": \"${SQLI_PAYLOADS[$i]}\", \"attacker_ip\": \"$HTTP_IP\"}")
  BLOCKED=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print('🔴 차단됨!' if d.get('blocked') else '⚠️  탐지됨')" 2>/dev/null)
  CONF=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('confidence',0)*100:.1f}%\")" 2>/dev/null)
  echo "  [SQLi $n/3] 신뢰도: $CONF | $BLOCKED"
  sleep 2
done

echo ""
echo "  PF 차단 목록:"
sudo pfctl -t blocklist -T show 2>/dev/null | sed 's/^/    /' || echo "    (없음)"

sleep 3
echo ""
curl -s -X POST $BASE_URL/emergency_reset > /dev/null

XSS_PAYLOADS=("<script>alert('xss')</script>" "<img src=x onerror=alert(1)>" "<svg onload=alert(1)>")
echo "  [XSS 공격 시작]"
for i in "${!XSS_PAYLOADS[@]}"; do
  n=$((i+1))
  RES=$(curl -s -X POST $BASE_URL/detect_http \
    -H "Content-Type: application/json" \
    -d "{\"payload\": \"${XSS_PAYLOADS[$i]}\", \"attacker_ip\": \"$HTTP_IP\"}")
  BLOCKED=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print('🔴 차단됨!' if d.get('blocked') else '⚠️  탐지됨')" 2>/dev/null)
  CONF=$(echo $RES | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('confidence',0)*100:.1f}%\")" 2>/dev/null)
  echo "  [XSS $n/3] 신뢰도: $CONF | $BLOCKED"
  sleep 2
done

echo ""
echo "  PF 차단 목록 최종:"
sudo pfctl -t blocklist -T show 2>/dev/null | sed 's/^/    /' || echo "    (없음)"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  시연 완료! 녹화를 중지하세요.            ║"
echo "╚══════════════════════════════════════════╝"
