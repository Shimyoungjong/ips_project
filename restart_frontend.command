#!/bin/bash
echo "프론트엔드 재시작 중..."
pkill -f "react-scripts start" 2>/dev/null
pkill -f "node.*3000" 2>/dev/null
sleep 2
cd ~/ips_project/pj/frontend
npm start
