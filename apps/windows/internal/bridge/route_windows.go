//go:build windows

package bridge

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
// serverAddr the host[:port] of the UDP endpoint. serverAddr may be empty
// to install the halves without the server exception (tests / loopback).
func (t *RouteTakeover) Install(tunName, tunIP, serverAddr string) error {
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

	// Server /32 exception first: never route the underlay through itself.
	if serverIP != nil {
		phys, err := choosePhysicalAdapter(adapters, serverIP, tunName)
		if err != nil {
			return err
		}
		spec := routeSpec{prefix: fmt.Sprintf("%s/32", serverIP), ifIndex: phys.index, ifName: phys.name, nexthop: phys.gateway}
		if err := addRoute(spec); !isRouteExistsErr(err) {
			rollback()
			return fmt.Errorf("add server exception on %s: %w", phys.name, err)
		}
		t.specs = append(t.specs, spec)
		installed++
		log.Printf("[route] server %s/32 -> %s (gw %s)", serverIP, phys.name, phys.gateway)
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
