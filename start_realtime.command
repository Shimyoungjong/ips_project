#!/bin/bash
# 환경변수 IPS_HOME / IPS_PYTHON 로 재정의 가능(미지정 시 기존 기본값)
IPS_HOME="${IPS_HOME:-$HOME/ips_project}"
IPS_PYTHON="${IPS_PYTHON:-/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python}"
echo "IPS 실시간 탐지 엔진 시작 중..."
cd "$IPS_HOME"
sudo "$IPS_PYTHON" realtime_detect.py
