#!/bin/bash
# IPS 시연 화면 녹화 스크립트
# 녹화 파일 저장 위치
OUTPUT=~/ips_project/IPS_시연영상_$(date +%Y%m%d_%H%M%S).mov

echo "================================================"
echo "  IPS 시연 화면 녹화"
echo "================================================"
echo ""
echo "저장 위치: $OUTPUT"
echo ""
echo "** 녹화 시작 전 준비 **"
echo "  1. 브라우저에서 http://localhost:3000 열기"
echo "  2. 대시보드 '긴급 해제' 버튼 눌러서 초기화"
echo "  3. '▶ 시작' 버튼 클릭"
echo ""
echo "준비되면 Enter 눌러 녹화를 시작하세요..."
read -r

echo ""
echo "3초 후 녹화 시작..."
sleep 1; echo "3..."
sleep 1; echo "2..."
sleep 1; echo "1..."
echo "🔴 녹화 중! (Ctrl+C 로 중지)"
echo ""

# 화면 녹화 (avfoundation: 화면 + 마이크 없음)
# ffmpeg -f avfoundation -i "1" = 메인 디스플레이 캡처
ffmpeg -f avfoundation \
    -capture_cursor 1 \
    -capture_mouse_clicks 1 \
    -framerate 30 \
    -i "1" \
    -vcodec libx264 \
    -preset ultrafast \
    -pix_fmt yuv420p \
    -crf 23 \
    "$OUTPUT" 2>/dev/null

echo ""
echo "✅ 녹화 완료!"
echo "파일: $OUTPUT"
echo ""
echo "아무 키나 누르세요."
read -n 1
