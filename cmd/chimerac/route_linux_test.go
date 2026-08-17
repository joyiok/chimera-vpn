//go:build linux

package main

import "testing"

func TestParseRouteGetFields(t *testing.T) {
	dev, via := parseRouteGetFields([]string{"8.8.8.8", "via", "192.168.1.1", "dev", "eth0", "src", "192.168.1.10"})
	if dev != "eth0" || via != "192.168.1.1" {
		t.Fatalf("dev=%s via=%s", dev, via)
	}
	dev, via = parseRouteGetFields([]string{"10.0.0.5", "dev", "eth1", "src", "10.0.0.9", "uid", "0"})
	if dev != "eth1" || via != "" {
		t.Fatalf("on-link dev=%s via=%q", dev, via)
	}
}
