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
# 最低版本 3.7：代码用了 from __future__ import annotations、f-string、ThreadingHTTPServer（INSTALL-3）
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)'; then
  red "需要 Python 3.7+（当前 $(python3 --version 2>&1)）。请升级 python3 后重试。"; exit 1
fi
grn "python3: $(python3 --version 2>&1)"

# 3. 复制项目到 /opt/pihy2
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
grn "安装目录：$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
DEST_DIR="$(cd "$INSTALL_DIR" && pwd)"
if [ "$SRC_DIR" = "$DEST_DIR" ]; then
  # 直接在 /opt/pihy2 里检出/解压再运行：源即目标，绝不能 rm -rf 自己的源码（INSTALL-1）
  grn "源目录即安装目录，跳过复制。"
else
  # 升级/重装：先删旧的包与 web/docs 子树再复制，避免上个版本里已删除/改名的文件残留被导入或读到
  # （cp -r 是“合并”进已存在目录，不会替换；docs/ 也要一并清，否则旧文档累积，INSTALL-2）
  rm -rf "$INSTALL_DIR/pihy2" "$INSTALL_DIR/web" "$INSTALL_DIR/docs"
  for item in pihy2 web README.md docs; do
    [ -e "$SRC_DIR/$item" ] && cp -r "$SRC_DIR/$item" "$INSTALL_DIR/"
  done
fi
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
