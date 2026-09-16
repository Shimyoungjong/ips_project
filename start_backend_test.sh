#!/bin/bash
# 테스트용: bridge100(Mac<->Ubuntu VM 가상망)을 감시 인터페이스로 사용
cd /Users/macintosh/Downloads/ips_project
source .venv/bin/activate
export IPS_IFACE=bridge100
export IPS_UBUNTU_HOST=192.168.64.2
export IPS_UBUNTU_USER=shim2148
export IPS_SSH_KEY=/Users/macintosh/.ssh/ips_agent_ed25519
echo "IPS_IFACE=$IPS_IFACE 로 시작합니다"
sudo -E .venv/bin/python -m uvicorn pj.model.main:app --host 0.0.0.0 --port 8000
