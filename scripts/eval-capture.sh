#!/usr/bin/env bash
# Capture UDP 4789 on the VPN server, then score it with chimera-eval.
# Usage: sudo bash scripts/eval-capture.sh eth0 [seconds]
set -euo pipefail
IFACE="${1:-eth0}"
SECS="${2:-60}"
OUT="${3:-/tmp/chimera-eval.pcap}"

echo "capturing ${SECS}s on ${IFACE} udp/4789 -> ${OUT}"
timeout "$SECS" tcpdump -i "$IFACE" -nn -s 0 -w "$OUT" "udp port 4789" || true
echo "next: chimera-eval -pcap $OUT"
echo "control (QUIC): tcpdump -i $IFACE -nn -s 0 -w /tmp/quic.pcap udp port 443"
echo "then: chimera-eval -pcap /tmp/quic.pcap -port 443"
