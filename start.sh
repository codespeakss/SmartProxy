#!/usr/bin/env bash
set -euo pipefail

# --- 代理切换脚本（脚本A / 脚本B）---
# 脚本A：将代理切换到 127.0.0.1:7895
run_script_apply() {
  echo -e "\033[31m[Proxy] run_script_apply: set proxies to 127.0.0.1:7895 for 'Wi-Fi'\033[0m"
  networksetup -setsecurewebproxy      "Wi-Fi" 127.0.0.1 7895 || true
  networksetup -setwebproxy            "Wi-Fi" 127.0.0.1 7895 || true
  networksetup -setsocksfirewallproxy  "Wi-Fi" 127.0.0.1 7895 || true
}

# 脚本B：恢复代理到 127.0.0.1:7890
run_script_restore() {
  echo -e "\033[31m[Proxy] run_script_restore: restore proxies to 127.0.0.1:7890 for 'Wi-Fi'\033[0m"
  networksetup -setsecurewebproxy      "Wi-Fi" 127.0.0.1 7890 || true
  networksetup -setwebproxy            "Wi-Fi" 127.0.0.1 7890 || true
  networksetup -setsocksfirewallproxy  "Wi-Fi" 127.0.0.1 7890 || true
}

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
on_exit() {
  # 确保在任何退出路径下恢复代理
  run_script_restore || true
  cleanup
}
trap on_exit EXIT

echo "Building SmartProxy in $(pwd)..."
go build -o "$ARTIFACT"

# 启动 SmartProxy 之前切换代理到 127.0.0.1:7895
run_script_apply || true

echo "Starting ./SmartProxy ..."
./SmartProxy &
child_pid=$!

# 等待 SmartProxy 退出并将其退出码作为脚本退出码
wait "${child_pid}"
exit_code=$?
exit "$exit_code"
