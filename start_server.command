#!/bin/bash
cd ~/ips_project
pkill -f "uvicorn pj.model.main" 2>/dev/null
sleep 1
echo "IPS 서버 시작 중..."
/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python -m uvicorn pj.model.main:app --host 0.0.0.0 --port 8000
