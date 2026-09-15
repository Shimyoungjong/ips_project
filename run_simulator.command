#!/bin/bash
# 환경변수 IPS_HOME / IPS_PYTHON 로 재정의 가능(미지정 시 기존 기본값)
IPS_HOME="${IPS_HOME:-$HOME/ips_project}"
IPS_PYTHON="${IPS_PYTHON:-/opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python}"
cd "$IPS_HOME"
sudo "$IPS_PYTHON" attack_simulator.py
echo ""
echo "완료. 아무 키나 누르세요."
read -n 1
