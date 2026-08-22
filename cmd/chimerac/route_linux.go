//go:build linux

package main

import (
	_ "embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"chimera/internal/netpkt"
)

//go:embed chnroute_v4.txt
var chnrouteV4 string

// chnrouteCIDRs parses the embedded APNIC-derived mainland-China CIDR
// list, skipping comments and blank lines.
func chnrouteCIDRs() []string {
	var out []string
	for _, line := range strings.Split(chnrouteV4, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

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

// buildIPBatchLines renders one "route replace …" line per spec for
// ip -batch. Exposed for tests.
func buildIPBatchLines(ipv6 bool, specs [][]string) []string {
	fam := "-4"
	if ipv6 {
		fam = "-6"
	}
	lines := make([]string, 0, len(specs))
	for _, args := range specs {
		lines = append(lines, fam+" route replace "+strings.Join(args, " "))
	}
	return lines
}

// addBatch installs many routes with a single `ip -batch` invocation
// (thousands of individual execs would take minutes). The batch stops on
// the first error; callers roll back via release().
func (r *linuxRoutes) addBatch(ipv6 bool, specs [][]string) error {
	if len(specs) == 0 {
		return nil
	}
	tmp, err := os.CreateTemp("", "chimera-routes-*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	for _, line := range buildIPBatchLines(ipv6, specs) {
		if _, err := tmp.WriteString(line + "\n"); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	bin := []string{"-batch", "-force", tmp.Name()}
	if ipv6 {
		bin = append([]string{"-6"}, bin...)
	}
	cmd := exec.Command("ip", bin...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip -batch (%d routes): %v: %s", len(specs), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// installCNDirectRoutes pins mainland-China destinations to the physical
// underlay so domestic traffic bypasses the tunnel even after the
// half-default takeover. Returns the number of routes installed.
func (r *linuxRoutes) installCNDirectRoutes(serverAddr string) (int, error) {
	host := netpkt.HostFromAddr(serverAddr)
	serverIP, err := netpkt.ResolveIPv4(host)
	if err != nil {
		return 0, err
	}
	dev, via, err := lookupUnderlay(serverIP)
	if err != nil {
		return 0, err
	}
	cidrs := chnrouteCIDRs()
	specs := make([][]string, 0, len(cidrs))
	for _, c := range cidrs {
		args := []string{c}
		if via != "" {
			args = append(args, "via", via)
		}
		args = append(args, "dev", dev)
		specs = append(specs, args)
		r.specs = append(r.specs, routeSpec{args: append([]string(nil), args...)})
	}
	if err := r.addBatch(false, specs); err != nil {
		return 0, err
	}
	return len(specs), nil
}
