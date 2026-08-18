package main

import (
	"net"
	"testing"
	"time"

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

func TestClientRouteSnapshotSorted(t *testing.T) {
	r := newClientRoute()
	a := &core.Conn{}
	b := &core.Conn{}
	r.register(a, "10.99.0.3")
	r.register(b, "10.99.0.2")
	got := r.snapshot()
	if len(got) != 2 || got[0].IP != "10.99.0.2" || got[1].IP != "10.99.0.3" {
		t.Fatalf("%+v", got)
	}
}

func TestFormatSessionSnap(t *testing.T) {
	got := formatSessionSnap(sessionSnap{IP: "10.99.0.2", Remote: "1.2.3.4:9", Generation: 2, Idle: time.Second})
	if got != "client 1.2.3.4:9 tun=10.99.0.2 gen=2 idle=1s" {
		t.Fatalf("got %q", got)
	}
}
