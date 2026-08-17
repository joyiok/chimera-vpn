//go:build linux

package main

import "testing"

func TestDNSOverrideRevertNoop(t *testing.T) {
	var d *dnsOverride
	d.revert()
	(&dnsOverride{tunName: "chimerac0"}).revert()
}

func TestPushTUNDNSEmptyName(t *testing.T) {
	d := pushTUNDNS("")
	if d.applied {
		t.Fatal("empty tun name must not change resolver")
	}
}
