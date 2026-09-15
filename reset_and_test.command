#!/bin/bash
cd ~/ips_project

echo "=== 서버 메모리 + PF 차단 목록 초기화 ==="
curl -s -X POST http://localhost:8000/emergency_reset | python3 -c "import sys,json; d=json.load(sys.stdin); print('서버 초기화:', d.get('status','?'))"
sudo pfctl -t blocklist -T flush 2>/dev/null && echo "PF 초기화 완료" || echo "PF 초기화 실패"

echo ""
echo "=== 공격 테스트 시작 ==="
/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python run_attack_test.py

echo ""
echo "완료. 아무 키나 누르세요."
read -n 1
