#!/bin/bash
cd ~/ips_project
sudo /opt/homebrew/Caskroom/miniforge/base/envs/ips_env/bin/python attack_simulator.py
echo ""
echo "완료. 아무 키나 누르세요."
read -n 1
