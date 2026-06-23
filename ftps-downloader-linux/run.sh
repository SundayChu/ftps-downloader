#!/bin/bash
# FTPS Downloader - Linux 啟動腳本
# 用法: ./run.sh [設定檔路徑]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${1:-$SCRIPT_DIR/config.properties}"

cd "$SCRIPT_DIR"
chmod +x ./ftps-downloader

echo "啟動 FTPS Downloader..."
echo "設定檔: $CONFIG"
./ftps-downloader -config "$CONFIG"
