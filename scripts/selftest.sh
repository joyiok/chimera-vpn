#!/usr/bin/env bash
# Userspace self-test: no root, no TUN. Boots chimerad -no-tun, then
# chimerac -check. Exit 0 means handshake + assigned IP + packet echo worked.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/chimera-selftest.XXXXXX")"
SRV_PID=""
cleanup() {
  if [[ -n "${SRV_PID}" ]] && kill -0 "$SRV_PID" 2>/dev/null; then
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "==> build"
go build -o "$WORKDIR/chimerad" ./cmd/chimerad
go build -o "$WORKDIR/chimerac" ./cmd/chimerac
go build -o "$WORKDIR/chimera-init" ./cmd/chimera-init

echo "==> generate configs"
"$WORKDIR/chimera-init" -dir "$WORKDIR" -dev

echo "==> start chimerad -no-tun"
"$WORKDIR/chimerad" -config "$WORKDIR/server.json" -no-tun -listen 127.0.0.1:0 \
  >"$WORKDIR/srv.log" 2>&1 &
SRV_PID=$!

BOUND=""
for _ in $(seq 1 80); do
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "chimerad exited early:" >&2
    cat "$WORKDIR/srv.log" >&2
    exit 1
  fi
  BOUND="$(sed -n 's/.*bound=\([^ ]*\).*/\1/p' "$WORKDIR/srv.log" | head -1 || true)"
  if [[ -n "$BOUND" ]]; then
    break
  fi
  sleep 0.1
done
if [[ -z "$BOUND" ]]; then
  echo "timed out waiting for bound= in server log:" >&2
  cat "$WORKDIR/srv.log" >&2
  exit 1
fi
echo "    bound=$BOUND"

echo "==> chimerac -check"
set +e
CHECK_OUT="$("$WORKDIR/chimerac" -config "$WORKDIR/client.json" -check -json -server "$BOUND" 2>"$WORKDIR/cli.err")"
CHECK_STATUS=$?
set -e
printf '%s\n' "$CHECK_OUT"
if [[ -s "$WORKDIR/cli.err" ]]; then
  cat "$WORKDIR/cli.err" >&2
fi
if [[ "$CHECK_STATUS" -ne 0 ]]; then
  echo "chimerac -check failed (exit $CHECK_STATUS)" >&2
  echo "--- server log ---" >&2
  cat "$WORKDIR/srv.log" >&2
  exit 1
fi
case "$CHECK_OUT" in
  *'"ok":true'*|*'\"ok\": true'*) ;;
  *)
    echo "check JSON missing ok=true: $CHECK_OUT" >&2
    exit 1
    ;;
esac
case "$CHECK_OUT" in
  *'"probe":"echo"'*|*'"probe": "echo"'*) ;;
  *)
    echo "expected probe=echo: $CHECK_OUT" >&2
    exit 1
    ;;
esac

echo "selftest ok bound=$BOUND"
echo "$CHECK_OUT"
