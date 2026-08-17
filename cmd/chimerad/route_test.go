package main

import (
	"net"
	"testing"

	"chimera/core"
)

func TestPacketIP(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[12:16], net.IPv4(10, 99, 0, 2).To4())
	copy(v4[16:20], net.IPv4(1, 2, 3, 4).To4())
	if got := packetIP(v4, false); got != "10.99.0.2" {
		t.Fatalf("src=%s", got)
	}
	if got := packetIP(v4, true); got != "1.2.3.4" {
		t.Fatalf("dst=%s", got)
	}
}

func TestClientRouteDisplace(t *testing.T) {
	r := newClientRoute()
	a := &core.Conn{}
	b := &core.Conn{}
	if d := r.register(a, "10.99.0.2"); d != nil {
		t.Fatal("first register displaced")
	}
	if r.lookup("10.99.0.2") != a {
		t.Fatal("lookup")
	}
	if d := r.register(b, "10.99.0.2"); d != a {
		t.Fatal("expected displace of a")
	}
	r.remove(b)
	if r.lookup("10.99.0.2") != nil {
		t.Fatal("remove left mapping")
	}
}
