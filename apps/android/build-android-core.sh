#!/usr/bin/env bash
set -euo pipefail

# 构建 Go 核心并生成 app/libs/bind.aar。
# 在仓库根目录的 Go 模块下运行 gomobile bind。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AAR_OUT="$SCRIPT_DIR/app/libs/bind.aar"

if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
    echo "错误：需要设置 ANDROID_HOME 或 ANDROID_SDK_ROOT" >&2
    exit 1
fi

# 1. 确保 gomobile / gobind 可用
if ! command -v gomobile >/dev/null 2>&1; then
    echo "[1/3] 安装 gomobile ..."
    go install golang.org/x/mobile/cmd/gomobile@latest
fi

if ! command -v gobind >/dev/null 2>&1; then
    echo "[1/3] 安装 gobind ..."
    go install golang.org/x/mobile/cmd/gobind@latest
fi

export PATH="$PATH:$(go env GOPATH)/bin"

if ! command -v gomobile >/dev/null 2>&1; then
    echo "错误：找不到 gomobile，请确认 \$(go env GOPATH)/bin 在 PATH 中" >&2
    exit 1
fi

# 2. 初始化 gomobile 环境
echo "[2/3] 运行 gomobile init ..."
gomobile init

# 3. 从仓库根目录构建 AAR（-androidapi 26 对齐 minSdk，并避开新 NDK 不再提供的 API 16）
echo "[3/3] 在 $REPO_ROOT 下运行 gomobile bind ..."
cd "$REPO_ROOT"

mkdir -p "$(dirname "$AAR_OUT")"
rm -f "$AAR_OUT"

GOFLAGS=-mod=mod gomobile bind \
    -target=android \
    -androidapi 26 \
    -o "$AAR_OUT" \
    chimera/bind

echo "完成：$AAR_OUT"
