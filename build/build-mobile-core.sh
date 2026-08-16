#!/usr/bin/env bash
# Build the gomobile artifacts used by the Android and iOS clients.
#
# Prerequisites:
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   gomobile init            (downloads Android NDK when Android SDK is set)
#   export ANDROID_HOME=/path/to/android-sdk   (Android only)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist

if ! command -v gomobile >/dev/null 2>&1; then
  echo "installing gomobile..."
  go install golang.org/x/mobile/cmd/gomobile@latest
  export PATH="$PATH:$(go env GOPATH)/bin"
fi
gomobile init

echo "building Android AAR..."
gomobile bind -target=android -o dist/chimera-bind.aar chimera/bind

echo "building iOS XCFramework (requires macOS + Xcode)..."
gomobile bind -target=ios,iossimulator,macos -iosversion=13.0 -o dist/ChimeraBind.xcframework chimera/bind
