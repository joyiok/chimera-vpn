//go:build linux

package main

import "testing"

func TestConfigureClientTUN6Empty(t *testing.T) {
	if err := configureClientTUN6("", clientTUN6); err != nil {
		t.Fatal(err)
	}
	if err := configureClientTUN6("chimerac0", ""); err != nil {
		t.Fatal(err)
	}
}
