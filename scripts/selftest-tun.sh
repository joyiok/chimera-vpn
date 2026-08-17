#!/usr/bin/env bash
# Optional root self-test of the real TUN path using two network namespaces.
# Requires: root, /dev/net/tun, ip(8). Not a replacement for scripts/selftest.sh.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "selftest-tun: need root (ip netns + TUN)" >&2
  exit 1
fi
if [[ ! -e /dev/net/tun ]]; then
  echo "selftest-tun: /dev/net/tun missing" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NS_S="chimera-s-$$"
NS_C="chimera-c-$$"
WORKDIR="$(mktemp -d /tmp/chimera-tuntest.XXXXXX)"
SRV_PID=""

cleanup() {
  if [[ -n "${SRV_PID}" ]]; then
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
  fi
  ip netns del "$NS_S" 2>/dev/null || true
  ip netns del "$NS_C" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "==> build"
go build -o "$WORKDIR/chimerad" ./cmd/chimerad
go build -o "$WORKDIR/chimerac" ./cmd/chimerac
go build -o "$WORKDIR/chimera-init" ./cmd/chimera-init

"$WORKDIR/chimera-init" -dir "$WORKDIR" -listen 10.200.0.1:4789 -server 10.200.0.1:4789 -replay-path=

ip netns add "$NS_S"
ip netns add "$NS_C"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_S"
ip link set veth-c netns "$NS_C"
ip netns exec "$NS_S" ip addr add 10.200.0.1/24 dev veth-s
ip netns exec "$NS_C" ip addr add 10.200.0.2/24 dev veth-c
ip netns exec "$NS_S" ip link set veth-s up
ip netns exec "$NS_C" ip link set veth-c up
ip netns exec "$NS_S" ip link set lo up
ip netns exec "$NS_C" ip link set lo up

echo "==> chimerad in $NS_S"
ip netns exec "$NS_S" "$WORKDIR/chimerad" -config "$WORKDIR/server.json" \
  >"$WORKDIR/srv.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 80); do
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "chimerad exited early:" >&2
    cat "$WORKDIR/srv.log" >&2
    exit 1
  fi
  if grep -q 'TUN interface' "$WORKDIR/srv.log" && grep -q 'bound=' "$WORKDIR/srv.log"; then
    break
  fi
  sleep 0.1
done
if ! grep -q 'TUN interface' "$WORKDIR/srv.log"; then
  echo "TUN did not come up:" >&2
  cat "$WORKDIR/srv.log" >&2
  exit 1
fi

echo "==> chimerac -check from $NS_C (expect icmp-reply)"
set +e
CHECK_OUT="$(ip netns exec "$NS_C" "$WORKDIR/chimerac" -config "$WORKDIR/client.json" -check -json -timeout 12s)"
CHECK_STATUS=$?
set -e
printf '%s\n' "$CHECK_OUT"
if [[ "$CHECK_STATUS" -ne 0 ]]; then
  echo "--- server log ---" >&2
  cat "$WORKDIR/srv.log" >&2
  exit 1
fi
case "$CHECK_OUT" in
  *'"probe":"icmp-reply"'*|*'"probe": "icmp-reply"'*) ;;
  *)
    echo "expected probe=icmp-reply through TUN, got: $CHECK_OUT" >&2
    echo "--- server log ---" >&2
    cat "$WORKDIR/srv.log" >&2
    exit 1
    ;;
esac
echo "selftest-tun ok"
