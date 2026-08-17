//go:build linux

package main

import (
	"log"
	"os/exec"
	"strings"
)

// dnsOverride records a systemd-resolved push onto the TUN so release can
// call `resolvectl revert` instead of leaving ~. as the default domain.
type dnsOverride struct {
	tunName string
	applied bool
}

func pushTUNDNS(tunName string) *dnsOverride {
	d := &dnsOverride{tunName: tunName}
	if tunName == "" {
		return d
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		log.Printf("DNS: resolvectl not found; not changing resolver")
		return d
	}
	if out, err := exec.Command("resolvectl", "dns", tunName, "1.1.1.1", "8.8.8.8").CombinedOutput(); err != nil {
		log.Printf("resolvectl dns %s: %v: %s", tunName, err, strings.TrimSpace(string(out)))
		return d
	}
	if out, err := exec.Command("resolvectl", "domain", tunName, "~.").CombinedOutput(); err != nil {
		log.Printf("resolvectl domain %s ~.: %v: %s", tunName, err, strings.TrimSpace(string(out)))
	}
	d.applied = true
	log.Printf("DNS via %s: 1.1.1.1 8.8.8.8 (domain ~.)", tunName)
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
