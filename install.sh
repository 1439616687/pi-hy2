#!/usr/bin/env bash
# pihy2 一键安装引导脚本
#   把本项目复制到 /opt/pihy2，创建 pihy2 命令，然后启动交互式部署向导。
# 用法（树莓派上，root）：
#   sudo bash install.sh
# 若被 `sh install.sh`（dash）调用，BASH_SOURCE 与 pipefail 会失效，这里自动切回 bash
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
set -euo pipefail

INSTALL_DIR=/opt/pihy2
BIN=/usr/local/bin/pihy2

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

# 1. root 检查
if [ "$(id -u)" -ne 0 ]; then
  red "请用 root 运行：sudo bash install.sh"
  exit 1
fi

# 2. python3 检查
if ! command -v python3 >/dev/null 2>&1; then
  ylw "未检测到 python3，尝试用 apt 安装…"
  apt-get update -y && apt-get install -y python3 || {
    red "python3 安装失败，请先手动安装 python3 再重试。"; exit 1; }
fi
grn "python3: $(python3 --version 2>&1)"

# 3. 复制项目到 /opt/pihy2
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
grn "安装目录：$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
# 仅复制需要的内容，排除 .git 与测试缓存
for item in pihy2 web README.md docs; do
  [ -e "$SRC_DIR/$item" ] && cp -r "$SRC_DIR/$item" "$INSTALL_DIR/"
done
find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# 4. 创建 pihy2 命令
cat > "$BIN" <<EOF
#!/bin/sh
exec env PYTHONPATH=$INSTALL_DIR python3 -m pihy2 "\$@"
EOF
chmod +x "$BIN"
grn "已创建命令：pihy2（= python3 -m pihy2）"

# 5. 进入部署向导
grn "启动部署向导…"
echo
exec env PYTHONPATH="$INSTALL_DIR" python3 -m pihy2 install
