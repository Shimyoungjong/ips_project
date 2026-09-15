#!/bin/bash
echo "IPS 실시간 탐지 엔진 시작 중..."
cd ~/ips_project
sudo /opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python realtime_detect.py
