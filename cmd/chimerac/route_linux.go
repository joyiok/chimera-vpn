//go:build linux

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"chimera/internal/netpkt"
)

type routeSpec struct {
	args []string // ip route add/del arguments after "route add|del"
	ipv6 bool
}

type linuxRoutes struct {
	specs []routeSpec
}

func installDefaultRoutes(tunName, clientIP, serverAddr string) (*linuxRoutes, error) {
	host := netpkt.HostFromAddr(serverAddr)
	serverIP, err := netpkt.ResolveIPv4(host)
	if err != nil {
		return nil, err
	}
	if serverIP.IsLoopback() || serverIP.IsUnspecified() {
		return nil, fmt.Errorf("refusing default-route takeover for loopback/unspecified server %s", serverIP)
	}

	physDev, physVia, err := lookupUnderlay(serverIP)
	if err != nil {
		return nil, err
	}

	r := &linuxRoutes{}
	except := []string{serverIP.String() + "/32"}
	if physVia != "" {
		except = append(except, "via", physVia)
	}
	except = append(except, "dev", physDev)
	if err := r.add(false, except...); err != nil {
		return nil, err
	}

	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := r.add(false, half, "dev", tunName); err != nil {
			_ = r.release()
			return nil, err
		}
	}
	for _, half := range []string{"::/1", "8000::/1"} {
		if err := r.add(true, half, "dev", tunName); err != nil {
			// IPv6 leak-plug is best-effort: some hosts disable IPv6 on TUN.
			continue
		}
	}
	return r, nil
}

func (r *linuxRoutes) add(ipv6 bool, args ...string) error {
	bin := []string{"route", "replace"}
	cmdName := "ip"
	var cmd *exec.Cmd
	if ipv6 {
		cmd = exec.Command(cmdName, append([]string{"-6"}, append(bin, args...)...)...)
	} else {
		cmd = exec.Command(cmdName, append(bin, args...)...)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip route replace %s: %v: %s", strings.Join(args, " "), err, out)
	}
	r.specs = append(r.specs, routeSpec{args: append([]string(nil), args...), ipv6: ipv6})
	return nil
}

func (r *linuxRoutes) release() error {
	var first error
	for i := len(r.specs) - 1; i >= 0; i-- {
		s := r.specs[i]
		var cmd *exec.Cmd
		if s.ipv6 {
			cmd = exec.Command("ip", append([]string{"-6", "route", "del"}, s.args...)...)
		} else {
			cmd = exec.Command("ip", append([]string{"route", "del"}, s.args...)...)
		}
		if out, err := cmd.CombinedOutput(); err != nil && first == nil {
			first = fmt.Errorf("ip route del %s: %v: %s", strings.Join(s.args, " "), err, out)
		}
	}
	r.specs = nil
	return first
}

// lookupUnderlay parses `ip route get <server>` for the physical device and
// optional next-hop used to reach the VPN server before takeover.
func lookupUnderlay(server net.IP) (dev, via string, err error) {
	out, err := exec.Command("ip", "-4", "route", "get", server.String()).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ip route get %s: %v: %s", server, err, out)
	}
	fields := strings.Fields(string(out))
	dev, via = parseRouteGetFields(fields)
	if dev == "" || dev == "lo" {
		return "", "", fmt.Errorf("no physical device in `ip route get %s`: %s", server, strings.TrimSpace(string(out)))
	}
	return dev, via, nil
}

func parseRouteGetFields(fields []string) (dev, via string) {
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			dev = fields[i+1]
		}
		if f == "via" && i+1 < len(fields) {
			via = fields[i+1]
		}
	}
	return dev, via
}
