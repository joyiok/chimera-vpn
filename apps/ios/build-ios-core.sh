#!/usr/bin/env bash
set -euo pipefail

# Build the ChimeraBind XCFramework from the Go core and place it where the
# Xcode project expects it. Run this from anywhere; the script locates the
# repository root relative to its own path.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IOS_DIR="$SCRIPT_DIR"
XCODE_DIR="$IOS_DIR/ChimeraVPN"
BUILD_DIR="$IOS_DIR/build"
FRAMEWORK_BUILT="$BUILD_DIR/ChimeraBind.xcframework"
FRAMEWORK_OUT="$XCODE_DIR/ChimeraBind.xcframework"
IOS_VERSION="15.0"
GO_PACKAGE="chimera/bind"

echo "==> Repository root: $REPO_ROOT"
echo "==> Output XCFramework: $FRAMEWORK_OUT"

command -v go >/dev/null 2>&1 || {
  echo "error: go not found in PATH; install Go 1.24+ first" >&2
  exit 1
}

export PATH="$(go env GOPATH)/bin:$PATH"

# Install gomobile / gobind if they are not already available.
if ! command -v gomobile >/dev/null 2>&1; then
  echo "==> gomobile not found; installing golang.org/x/mobile/cmd/gomobile@latest"
  (cd "$REPO_ROOT" && go install golang.org/x/mobile/cmd/gomobile@latest)
fi
if ! command -v gobind >/dev/null 2>&1; then
  echo "==> gobind not found; installing golang.org/x/mobile/cmd/gobind@latest"
  (cd "$REPO_ROOT" && go install golang.org/x/mobile/cmd/gobind@latest)
fi

command -v gomobile >/dev/null 2>&1 || {
  echo "error: gomobile still not found in PATH after install attempt" >&2
  exit 1
}
command -v gobind >/dev/null 2>&1 || {
  echo "error: gobind still not found in PATH after install attempt" >&2
  exit 1
}

# gomobile bind resolves Go package paths from the current module, so run it
# from the repository root.
cd "$REPO_ROOT"

echo "==> Running gomobile init"
gomobile init

echo "==> Building $GO_PACKAGE with gomobile bind"
mkdir -p "$BUILD_DIR" "$XCODE_DIR"
gomobile bind \
  -target=ios,iossimulator,macos \
  -iosversion="$IOS_VERSION" \
  -o "$FRAMEWORK_BUILT" \
  "$GO_PACKAGE"

# Copy the freshly built XCFramework into the location the Xcode project
# expects to link against.
if [ -d "$FRAMEWORK_BUILT" ]; then
  rm -rf "$FRAMEWORK_OUT"
  cp -R "$FRAMEWORK_BUILT" "$FRAMEWORK_OUT"
  echo "==> XCFramework is ready at $FRAMEWORK_OUT"
else
  echo "error: gomobile did not produce $FRAMEWORK_BUILT" >&2
  exit 1
fi

echo "==> Done. Link $FRAMEWORK_OUT into the ChimeraPacketTunnel target in Xcode."
