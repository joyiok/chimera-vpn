#!/usr/bin/env bash
# Build the Linux server.
set -euo pipefail
cd "$(dirname "$0")/.."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/chimerad-linux-amd64 ./cmd/chimerad
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/chimerac-linux-amd64 ./cmd/chimerac
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/chimera-init-linux-amd64 ./cmd/chimera-init
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/chimerad-linux-arm64 ./cmd/chimerad
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/chimerac-linux-arm64 ./cmd/chimerac
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/chimera-init-linux-arm64 ./cmd/chimera-init
echo "built dist/chimerad-linux-{amd64,arm64} dist/chimerac-linux-{amd64,arm64} dist/chimera-init-linux-{amd64,arm64}"
