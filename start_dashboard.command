#!/bin/bash
# 환경변수 IPS_HOME 로 재정의 가능(미지정 시 기존 기본값)
IPS_HOME="${IPS_HOME:-$HOME/ips_project}"
echo "IPS 대시보드 시작 중..."
cd "$IPS_HOME/pj/frontend"
npm start
