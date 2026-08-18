#!/usr/bin/env bash
# Build the gomobile AAR used by the Android client.
#
# Prerequisites:
#   go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
#   (versions pinned as tool directives in go.mod)
#   gomobile init            (downloads Android NDK when Android SDK is set)
#   export ANDROID_HOME=/path/to/android-sdk
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist

export PATH="$(go env GOPATH)/bin:$PATH"
echo "installing gomobile/gobind from go.mod tool versions..."
go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
gomobile init

echo "building Android AAR..."
GOFLAGS=-mod=mod gomobile bind -target=android -androidapi 26 -o dist/chimera-bind.aar chimera/bind
