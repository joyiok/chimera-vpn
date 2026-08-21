package bridge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Route takeover: while the tunnel is up, 0.0.0.0/1 and 128.0.0.0/1 point
// through the TUN (both more specific than any real default route, so no
// metric games are needed), and the server endpoint keeps a /32 exception
// on the physical adapter so the encrypted UDP stream does not loop back
// into the tunnel. All routes use store=active: a crash can at worst leave
// the /32 exception until reboot, never a persistent hijack.

const (
	ifTypeLoopback = 24
	ifTypeTunnel   = 131

	tunHalfRouteA = "0.0.0.0/1"
	tunHalfRouteB = "128.0.0.0/1"
)

// privateBypassRoutes are pinned to the physical adapter in split mode so
// LAN and other non-public destinations never enter the tunnel.
var privateBypassRoutes = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// adapterInfo is the subset of OS adapter facts route takeover needs; the
// windows layer fills it from GetAdaptersAddresses.
type adapterInfo struct {
	name        string // FriendlyName, e.g. "Ethernet"
	description string // e.g. "Wintun Userspace Tunnel"
	index       uint32
	metric      uint32 // interface metric, lower wins
	operUp      bool
	ifType      uint32
	gateway     string // IPv4 default gateway, "" if none
	onLink      []net.IPNet
}

// containsIP reports whether ip falls inside one of the adapter's on-link
// prefixes (the local subnet behind that NIC).
func (a adapterInfo) containsIP(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for _, n := range a.onLink {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// isVirtual reports whether the adapter is one of our own or another
// tunnel product's virtual NICs, which must never act as the "physical"
// underlay route.
func (a adapterInfo) isVirtual(tunName string) bool {
	if a.ifType == ifTypeLoopback || a.ifType == ifTypeTunnel {
		return true
	}
	if tunName != "" && strings.EqualFold(a.name, tunName) {
		return true
	}
	return strings.Contains(strings.ToLower(a.description), "wintun")
}

// choosePhysicalAdapter picks the NIC that should carry the server /32
// exception: among adapters whose on-link subnet contains serverIP (direct
// LAN server) the best-metric one, else the up adapter with the best-metric
// IPv4 gateway.
func choosePhysicalAdapter(adapters []adapterInfo, serverIP net.IP, tunName string) (adapterInfo, error) {
	best := -1
	lanBest := -1
	for i := range adapters {
		a := &adapters[i]
		if !a.operUp || a.isVirtual(tunName) {
			continue
		}
		if serverIP != nil && a.containsIP(serverIP) && (lanBest < 0 || a.metric < adapters[lanBest].metric) {
			lanBest = i
		}
		if a.gateway != "" && (best < 0 || a.metric < adapters[best].metric) {
			best = i
		}
	}
	if lanBest >= 0 {
		return adapters[lanBest], nil
	}
	if best >= 0 {
		return adapters[best], nil
	}
	return adapterInfo{}, errors.New("no usable physical IPv4 adapter found (up, non-virtual, with default gateway)")
}

// tunGateway derives the TUN-side next hop from a client address. The
// address pool reserves host offset 1 of the /24 for the server's TUN
// gateway (see core/assign.go), and configureAdapter pins the mask to /24.
func tunGateway(clientIP string) (string, error) {
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

// tunSubnetPrefix returns the /24 the client TUN address lives in, e.g.
// "10.99.0.5" -> "10.99.0.0/24". Split mode must pin this prefix to the
// TUN adapter: it is covered by the 10.0.0.0/8 private bypass, which is
// more specific than the half-default TUN routes and would otherwise
// blackhole all in-tunnel traffic via the physical NIC.
func tunSubnetPrefix(clientIP string) (string, error) {
	ip := net.ParseIP(clientIP)
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("tun address %q is not IPv4", clientIP)
	}
	return v4.Mask(net.CIDRMask(24, 32)).String() + "/24", nil
}

// hostFromAddr strips a port if present: "1.2.3.4:443" -> "1.2.3.4",
// "[::1]:443" -> "::1", "vpn.example.com" unchanged.
func hostFromAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// resolveServerIPv4 resolves the server endpoint to one IPv4 address
// before any route is touched, so the lookup itself rides the physical
// network.
func resolveServerIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("server %s is IPv6; route takeover currently supports IPv4 servers only", host)
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
	return nil, fmt.Errorf("server %s has no IPv4 address; route takeover currently supports IPv4 servers only", host)
}

// routeSpec is one netsh-managed route entry, remembered so Close can
// remove exactly what Install added.
type routeSpec struct {
	prefix  string // "0.0.0.0/1"
	ifIndex uint32
	ifName  string // for logs only
	nexthop string // "" = on-link route
}

// RouteTakeover installs and remembers the takeover routes. Safe for
// concurrent use; Release is idempotent.
type RouteTakeover struct {
	mu    sync.Mutex
	specs []routeSpec
}

// NewRouteTakeover returns an idle takeover manager.
func NewRouteTakeover() *RouteTakeover { return &RouteTakeover{} }

// ipToString is a tiny helper shared by the platform layers for tests.
func ipToString(ip net.IP) string {
	v := binary.BigEndian.Uint32(ip.To4())
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}
