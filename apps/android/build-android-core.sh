#!/usr/bin/env bash
set -euo pipefail

# 构建 Go 核心并生成 app/libs/bind.aar。
# 在 Go 包 chimera/bind 合并到仓库根目录后运行本脚本。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_DIR="$SCRIPT_DIR"
AAR_OUT="$APP_DIR/app/libs/bind.aar"

# 1. 确保 gomobile / gobind 可用
if ! command -v gomobile >/dev/null 2>&1; then
    echo "[1/4] 安装 gomobile ..."
    go install golang.org/x/mobile/cmd/gomobile@latest
fi

if ! command -v gobind >/dev/null 2>&1; then
    echo "[1/4] 安装 gobind ..."
    go install golang.org/x/mobile/cmd/gobind@latest
fi

export PATH="$PATH:$(go env GOPATH)/bin"

if ! command -v gomobile >/dev/null 2>&1; then
    echo "错误：找不到 gomobile，请确认 \$(go env GOPATH)/bin 在 PATH 中" >&2
    exit 1
fi

# 2. 初始化 gomobile 环境
echo "[2/4] 运行 gomobile init ..."
gomobile init

# 3. 从仓库根目录构建 AAR
echo "[3/4] 在 $REPO_ROOT 下运行 gomobile bind ..."
cd "$REPO_ROOT"

mkdir -p app/libs
rm -f app/libs/bind.aar

GOFLAGS=-mod=mod gomobile bind -target=android -o app/libs/bind.aar chimera/bind

# 4. 复制 AAR 到 Android 工程
echo "[4/4] 复制 bind.aar 到 $AAR_OUT"
mkdir -p "$APP_DIR/app/libs"
cp -f app/libs/bind.aar "$AAR_OUT"

echo "完成：$AAR_OUT"
