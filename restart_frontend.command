#!/bin/bash
# 환경변수 IPS_HOME 로 재정의 가능(미지정 시 기존 기본값)
IPS_HOME="${IPS_HOME:-$HOME/ips_project}"
echo "프론트엔드 재시작 중..."
pkill -f "react-scripts start" 2>/dev/null
pkill -f "node.*3000" 2>/dev/null
sleep 2
cd "$IPS_HOME/pj/frontend"
npm start
