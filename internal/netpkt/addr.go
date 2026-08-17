// Package netpkt builds and inspects raw IPv4 packets used by the Linux
// CLI client (ICMP connectivity probes) and by route helpers.
package netpkt

import (
	"fmt"
	"net"
)

// GatewayForClient returns the TUN gateway for a client address, matching
// the address-pool convention: host offset 1 of the /24 that contains the
// client (see core/assign.go). Production configs use 10.99.0.0/24.
func GatewayForClient(clientIP string) (string, error) {
	ip := net.ParseIP(clientIP)
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("tun address %q is not IPv4", clientIP)
	}
	mask := net.CIDRMask(24, 32)
	network := v4.Mask(mask)
	gw := make(net.IP, 4)
	copy(gw, network)
	gw[3]++
	return gw.String(), nil
}

// HostFromAddr strips a port if present: "1.2.3.4:443" -> "1.2.3.4",
// "[::1]:443" -> "::1". Bare hosts are returned unchanged.
func HostFromAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// ResolveIPv4 resolves host to one IPv4 address. Literal IPv4 is returned
// as-is; IPv6-only names are rejected (route takeover is IPv4-only).
func ResolveIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("server %s is IPv6; IPv4 is required", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("server %s has no IPv4 address", host)
}

// IPv4HeaderSrcDst returns the source and destination of a raw IPv4 packet.
func IPv4HeaderSrcDst(packet []byte) (src, dst net.IP, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, nil, false
	}
	src = net.IPv4(packet[12], packet[13], packet[14], packet[15])
	dst = net.IPv4(packet[16], packet[17], packet[18], packet[19])
	return src, dst, true
}
