#!/usr/bin/env bash
# Enable IP forwarding and masquerade traffic leaving the CHIMERA TUN.
# Usage: sudo ./scripts/setup-nat.sh eth0
set -euo pipefail

OUT_IF="${1:-eth0}"
TUN_CIDR="${2:-10.99.0.0/24}"

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -C POSTROUTING -s "$TUN_CIDR" -o "$OUT_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$TUN_CIDR" -o "$OUT_IF" -j MASQUERADE
iptables -C FORWARD -i chimera0 -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i chimera0 -j ACCEPT
iptables -C FORWARD -o chimera0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -o chimera0 -m state --state RELATED,ESTABLISHED -j ACCEPT
echo "NAT enabled: $TUN_CIDR -> $OUT_IF"
