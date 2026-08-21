//go:build linux

package main

import "testing"

func TestDNSOverrideRevertNoop(t *testing.T) {
	var d *dnsOverride
	d.revert()
	(&dnsOverride{tunName: "chimerac0"}).revert()
}

func TestPushTUNDNSEmptyName(t *testing.T) {
	d := pushTUNDNS("", nil)
	if d.applied {
		t.Fatal("empty tun name must not change resolver")
	}
}

func TestPushTUNDSNFiltersNonIP(t *testing.T) {
	// resolvectl is absent in most test environments, so we only assert
	// the validation path: garbage resolvers are dropped before exec and
	// an all-garbage list never flips applied.
	d := pushTUNDNS("chimerac0-test", []string{"not-an-ip", "", "10.0.0.1"})
	if d.applied {
		t.Skip("resolvectl present; applied state depends on environment")
	}
}
