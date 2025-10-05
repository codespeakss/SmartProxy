#!/usr/bin/env bash
set -euo pipefail

# 1) 切换到本脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 2) 执行：cd ~/codespeakss/SmartProxy; go build; ./SmartProxy
cd "$HOME/codespeakss/SmartProxy"
ARTIFACT="$(pwd)/SmartProxy"

# 定义清理函数：脚本退出（正常或异常）时删除构建产物
cleanup() {
  # 仅在构建产物存在时删除
  if [[ -f "$ARTIFACT" ]]; then
    echo "Cleaning build artifact: $ARTIFACT"
    rm -f "$ARTIFACT" || true
  fi
}

# 将信号转发给子进程，并在退出时清理
child_pid=""
forward_and_wait() {
  if [[ -n "${child_pid}" ]] && kill -0 "${child_pid}" 2>/dev/null; then
    kill -TERM "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
  fi
}
trap forward_and_wait INT TERM
trap cleanup EXIT

echo "Building SmartProxy in $(pwd)..."
go build -o "$ARTIFACT"

echo "Starting ./SmartProxy ..."
./SmartProxy &
child_pid=$!

# 等待 SmartProxy 退出并将其退出码作为脚本退出码
wait "${child_pid}"
exit_code=$?
exit "$exit_code"
