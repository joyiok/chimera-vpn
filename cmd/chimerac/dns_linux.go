//go:build linux

package main

import (
	"log"
	"net"
	"os/exec"
	"strings"
)

// dnsOverride records a systemd-resolved push onto the TUN so release can
// call `resolvectl revert` instead of leaving ~. as the default domain.
type dnsOverride struct {
	tunName string
	applied bool
}

// defaultDNSServers are used when the config leaves dns empty.
var defaultDNSServers = []string{"1.1.1.1", "8.8.8.8"}

func pushTUNDNS(tunName string, servers []string) *dnsOverride {
	d := &dnsOverride{tunName: tunName}
	if tunName == "" {
		return d
	}
	if len(servers) == 0 {
		servers = defaultDNSServers
	}
	// Drop anything that is not a literal IP: resolvectl would accept
	// garbage and silently produce a broken resolver.
	var ips []string
	for _, s := range servers {
		if net.ParseIP(strings.TrimSpace(s)) != nil {
			ips = append(ips, strings.TrimSpace(s))
		} else if s != "" {
			log.Printf("DNS: ignoring non-IP resolver %q", s)
		}
	}
	if len(ips) == 0 {
		log.Printf("DNS: no valid resolvers configured; not changing resolver")
		return d
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		log.Printf("DNS: resolvectl not found; not changing resolver")
		return d
	}
	args := append([]string{"dns", tunName}, ips...)
	if out, err := exec.Command("resolvectl", args...).CombinedOutput(); err != nil {
		log.Printf("resolvectl dns %s: %v: %s", tunName, err, strings.TrimSpace(string(out)))
		return d
	}
	if out, err := exec.Command("resolvectl", "domain", tunName, "~.").CombinedOutput(); err != nil {
		log.Printf("resolvectl domain %s ~.: %v: %s", tunName, err, strings.TrimSpace(string(out)))
	}
	d.applied = true
	log.Printf("DNS via %s: %s (domain ~.)", tunName, strings.Join(ips, " "))
	return d
}

func (d *dnsOverride) revert() {
	if d == nil || !d.applied {
		return
	}
	if out, err := exec.Command("resolvectl", "revert", d.tunName).CombinedOutput(); err != nil {
		log.Printf("resolvectl revert %s: %v: %s", d.tunName, err, strings.TrimSpace(string(out)))
		return
	}
	d.applied = false
}
