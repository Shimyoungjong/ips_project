#!/bin/bash
echo "🔄 시연 환경 초기화 중..."

# 1. 기존 IPS 프로세스 종료
pkill -f realtime_detect.py 2>/dev/null
echo "✅ IPS 프로세스 종료"

# 2. pfctl 테이블 초기화
/sbin/pfctl -t blocklist -T flush 2>/dev/null
/sbin/pfctl -t highlist -T flush 2>/dev/null
/sbin/pfctl -t throttlelist -T flush 2>/dev/null
echo "✅ pfctl 테이블 초기화"

# 3. Ubuntu iptables 초기화
ssh -i /Users/shimyoungjong/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o ConnectTimeout=3 hisecure@192.168.64.10 \
    "sudo iptables -F && sudo iptables -F FORWARD && sudo iptables -t nat -F" 2>/dev/null
echo "✅ Ubuntu iptables 초기화"

# 4. DB 감시목록/차단목록 초기화
python3 -c "
import sqlite3, os
db = os.path.expanduser('~/ips_project/ips_logs.db')
conn = sqlite3.connect(db)
conn.execute('DELETE FROM watchlist')
conn.execute('DELETE FROM blocked_ips')
conn.execute('DELETE FROM attack_logs')
conn.commit()
conn.close()
print('✅ DB 초기화')
"

# 5. detect.log 초기화
> ~/ips_project/detect.log
echo "✅ detect.log 초기화"

# 6. evidence 초기화
sudo rm -f ~/ips_project/evidence/*.pcap
echo "✅ evidence 초기화"

echo ""
echo "🎯 초기화 완료! 대시보드에서 시작 버튼 누르세요."
