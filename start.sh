#!/usr/bin/env bash
set -euo pipefail

# 1) 切换到本脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 2) 执行：cd ~/codespeakss/SmartProxy; go build; ./SmartProxy
cd "$HOME/codespeakss/SmartProxy"
echo "Building SmartProxy in $(pwd)..."
go build -o SmartProxy

echo "Starting ./SmartProxy ..."
exec ./SmartProxy
