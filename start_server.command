#!/bin/bash
# 환경변수 IPS_HOME / IPS_PYTHON 로 재정의 가능(미지정 시 기존 기본값)
IPS_HOME="${IPS_HOME:-$HOME/ips_project}"
IPS_PYTHON="${IPS_PYTHON:-$HOME/ips_project/.venv/bin/python}"
cd "$IPS_HOME"
pkill -f "uvicorn pj.model.main" 2>/dev/null
sleep 1
echo "IPS 서버 시작 중..."
"$IPS_PYTHON" -m uvicorn pj.model.main:app --host 0.0.0.0 --port 8000
