//go:build windows

package bridge

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// chnroutePrefixes parses the embedded APNIC-derived mainland-China CIDR
// list, skipping comments and blank lines.
func chnroutePrefixes() []string {
	var out []string
	for _, line := range strings.Split(chnrouteV4Data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

const (
	gaaFlags = windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_INCLUDE_GATEWAYS
)

// enumerateAdapters walks GetAdaptersAddresses and returns one entry per
// IPv4-capable adapter with its gateway and on-link prefixes.
func enumerateAdapters() ([]adapterInfo, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_INET, gaaFlags, 0, nil, &size)
	if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("GetAdaptersAddresses size probe: %w", err)
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_INET, gaaFlags, 0, aa, &size); err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var out []adapterInfo
	for ; aa != nil; aa = aa.Next {
		info := adapterInfo{
			name:        windows.UTF16PtrToString(aa.FriendlyName),
			description: windows.UTF16PtrToString(aa.Description),
			index:       aa.IfIndex,
			metric:      aa.Ipv4Metric,
			operUp:      aa.OperStatus == windows.IfOperStatusUp,
			ifType:      aa.IfType,
		}
		for gw := aa.FirstGatewayAddress; gw != nil; gw = gw.Next {
			if ip := gw.Address.IP(); ip != nil && ip.To4() != nil && info.gateway == "" {
				info.gateway = ip.String()
			}
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP(); ip != nil && ip.To4() != nil {
				mask := net.CIDRMask(int(ua.OnLinkPrefixLength), 32)
				info.onLink = append(info.onLink, net.IPNet{IP: ip.Mask(mask), Mask: mask})
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// Install adds the default-route takeover. tunName is the Wintun adapter
// name ("Chimera"), tunIP the assigned client address (e.g. 10.99.0.5),
// serverAddr the host[:port] of the UDP/TCP endpoint. serverAddr may be
// empty to install the halves without the server exception (tests /
// loopback). bypassPrivate additionally pins private/loopback/link-local
// destinations to the physical adapter for split routing, and
// geoPrefixes (when non-empty) are mainland-China CIDRs installed the
// same way so 国内直连 works alongside the private bypass.
func (t *RouteTakeover) Install(tunName, tunIP, serverAddr string, bypassPrivate bool, geoPrefixes []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.specs) != 0 {
		return fmt.Errorf("route takeover already active")
	}

	gateway, err := tunGateway(tunIP)
	if err != nil {
		return err
	}

	adapters, err := enumerateAdapters()
	if err != nil {
		return err
	}

	var tunIdx uint32
	found := false
	for _, a := range adapters {
		if strings.EqualFold(a.name, tunName) {
			tunIdx = a.index
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("adapter %q not found", tunName)
	}

	var serverIP net.IP
	if serverAddr != "" {
		serverIP, err = resolveServerIPv4(hostFromAddr(serverAddr))
		if err != nil {
			return err
		}
	}

	installed := 0
	rollback := func() {
		for i := 0; i < installed; i++ {
			s := t.specs[i]
			if err := deleteRoute(s); err != nil {
				log.Printf("[route] rollback: delete %s failed: %v", s.prefix, err)
			}
		}
		t.specs = nil
	}

	var phys adapterInfo
	havePhys := false

	// Server /32 exception first: never route the underlay through itself.
	if serverIP != nil {
		phys, err = choosePhysicalAdapter(adapters, serverIP, tunName)
		if err != nil {
			return err
		}
		havePhys = true
		spec := routeSpec{prefix: fmt.Sprintf("%s/32", serverIP), ifIndex: phys.index, ifName: phys.name, nexthop: phys.gateway}
		if err := addRoute(spec); !isRouteExistsErr(err) {
			rollback()
			return fmt.Errorf("add server exception on %s: %w", phys.name, err)
		}
		t.specs = append(t.specs, spec)
		installed++
		log.Printf("[route] server %s/32 -> %s (gw %s)", serverIP, phys.name, phys.gateway)
	}

	// Split mode: pin private/local ranges to the physical adapter. These
	// are more specific than the half-default TUN routes and keep LAN,
	// printers, loopback, link-local and multicast off the tunnel.
	if bypassPrivate {
		if !havePhys {
			phys, err = choosePhysicalAdapter(adapters, nil, tunName)
			if err != nil {
				rollback()
				return err
			}
			havePhys = true
		}
		// The TUN's own /24 sits inside 10.0.0.0/8; without this more
		// specific route the bypass would send in-tunnel traffic (gateway,
		// peer addresses) out the physical NIC and break the tunnel.
		tunSubnet, err := tunSubnetPrefix(tunIP)
		if err != nil {
			rollback()
			return err
		}
		tunSpec := routeSpec{prefix: tunSubnet, ifIndex: tunIdx, ifName: tunName, nexthop: gateway}
		if err := addRoute(tunSpec); !isRouteExistsErr(err) {
			rollback()
			return fmt.Errorf("add tun subnet %s on %s: %w", tunSubnet, tunName, err)
		}
		t.specs = append(t.specs, tunSpec)
		installed++
		log.Printf("[route] tun subnet %s -> %s (gw %s)", tunSubnet, tunName, gateway)

		for _, prefix := range privateBypassRoutes {
			spec := routeSpec{prefix: prefix, ifIndex: phys.index, ifName: phys.name, nexthop: phys.gateway}
			if err := addRoute(spec); !isRouteExistsErr(err) {
				rollback()
				return fmt.Errorf("add bypass %s on %s: %w", prefix, phys.name, err)
			}
			t.specs = append(t.specs, spec)
			installed++
		}
		log.Printf("[route] split mode: %d private/local bypass routes -> %s", len(privateBypassRoutes), phys.name)

		// Geo split: mainland-China prefixes stay on the physical adapter
		// so domestic destinations bypass the tunnel (国内直连). Sources,
		// in order: caller-supplied mmdb extraction; embedded snapshot.
		prefixes := geoPrefixes
		if len(prefixes) == 0 {
			prefixes = chnroutePrefixes()
		}
		start := time.Now()
		geoSpecs := make([]routeSpec, 0, len(prefixes))
		for _, p := range prefixes {
			geoSpecs = append(geoSpecs, routeSpec{prefix: p, ifIndex: phys.index, ifName: phys.name, nexthop: phys.gateway})
		}
		if err := runNetshBatch(geoSpecs); err != nil {
			// Non-fatal: worst case the geo split is incomplete; rollback
			// of already-installed private routes would break connectivity
			// more than a partial geo list helps.
			log.Printf("[route] geo bypass batch failed (split continues without it): %v", err)
		} else {
			t.specs = append(t.specs, geoSpecs...)
			installed += len(geoSpecs)
			log.Printf("[route] geo split: %d mainland routes -> %s (%s)", len(geoSpecs), phys.name, time.Since(start).Round(time.Millisecond))
		}
	}

	// Then the two half-default routes through the TUN.
	for _, half := range []string{tunHalfRouteA, tunHalfRouteB} {
		spec := routeSpec{prefix: half, ifIndex: tunIdx, ifName: tunName, nexthop: gateway}
		if err := addRoute(spec); err != nil {
			rollback()
			return fmt.Errorf("add %s on %s: %w", half, tunName, err)
		}
		t.specs = append(t.specs, spec)
		installed++
		log.Printf("[route] %s -> %s (gw %s)", half, tunName, gateway)
	}
	return nil
}

// Release removes every route Install added (store=active routes die with
// a reboot anyway; this is the clean path).
func (t *RouteTakeover) Release() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var firstErr error
	for _, s := range t.specs {
		if err := deleteRoute(s); err != nil {
			log.Printf("[route] delete %s: %v", s.prefix, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	t.specs = nil
	return firstErr
}

// isRouteExistsErr treats "route already exists" as success: a stale
// exception from an unclean shutdown should not block a reconnect. netsh
// reports this in the system language, hence the locale fragments.
func isRouteExistsErr(err error) bool {
	if err == nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "已存在")
}

func addRoute(s routeSpec) error { return runNetsh("add", s) }

// runNetshBatch executes one netsh script with an "add route" line per
// spec. netsh -f processes them in-process, which is dramatically faster
// than one process per route at chnroute scale (~5500 prefixes).
func runNetshBatch(specs []routeSpec) error {
	if len(specs) == 0 {
		return nil
	}
	tmp, err := os.CreateTemp("", "chimera-routes-*.netsh")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, s := range specs {
		line := fmt.Sprintf("interface ipv4 add route prefix=%s interface=%d", s.prefix, s.ifIndex)
		if s.nexthop != "" {
			line += " nexthop=" + s.nexthop
		}
		line += " store=active"
		fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	cmd := exec.Command("netsh", "-f", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh -f (%d routes): %v: %s", len(specs), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteRoute(s routeSpec) error { return runNetsh("delete", s) }

func runNetsh(verb string, s routeSpec) error {
	args := []string{
		"interface", "ipv4", verb, "route",
		"prefix=" + s.prefix,
		fmt.Sprintf("interface=%d", s.ifIndex),
		"store=active",
	}
	if s.nexthop != "" {
		args = append(args, "nexthop="+s.nexthop)
	}
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &sysProcAttr
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s route %s: %v: %s", verb, s.prefix, err, strings.TrimSpace(string(out)))
	}
	return nil
}
