package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestHopPortsDeterministicAndDistinct(t *testing.T) {
	base := freeLocalPort(t)
	cfg := testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(base)), "udp")
	cfg.PortHopCount = 5
	cfg.PortHopSpread = 2048

	a, err := hopPortsForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hopPortsForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 5 || len(b) != 5 {
		t.Fatalf("ports = %v / %v", a, b)
	}
	seen := map[int]bool{}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("sequence not deterministic: %v vs %v", a, b)
		}
		if a[i] < 1 || a[i] > 65535 || seen[a[i]] {
			t.Fatalf("bad port sequence %v", a)
		}
		seen[a[i]] = true
	}
	if a[0] != base {
		t.Fatalf("first port %d, want base %d", a[0], base)
	}
}

func portsAllFree(t *testing.T, transport string, ports []int) bool {
	t.Helper()
	for _, port := range ports {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		if transport == "udp" {
			c, err := net.ListenPacket("udp", addr)
			if err != nil {
				return false
			}
			_ = c.Close()
		} else {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return false
			}
			_ = ln.Close()
		}
	}
	return true
}

func runPortHopServerRoundTrip(t *testing.T, transport string) {
	t.Helper()
	var cfg Config
	for attempt := 0; attempt < 20; attempt++ {
		base := freeLocalPort(t)
		cfg = testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(base)), transport)
		cfg.PortHopCount = 3
		cfg.PortHopSpread = 2048
		ports, err := hopPortsForConfig(cfg)
		if err == nil && portsAllFree(t, transport, ports) {
			break
		}
	}
	if cfg.ServerAddr == "" {
		t.Fatal("could not find a free port-hop set")
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ports, err := hopPortsForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 {
		t.Fatalf("ports = %v", ports)
	}
	target := ports[2]

	clientCfg := testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(target)), transport)
	clientCfg.PortHopCount = 1
	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("connect to derived port %d: %v", target, err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SendPacket([]byte("derived-port")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "derived-port" {
		t.Fatalf("got %q", got)
	}
	if conn.RemoteAddr().String() == "" {
		t.Fatal("missing remote address")
	}
}

func TestUDPPortHopServerListensOnDerivedPorts(t *testing.T) {
	runPortHopServerRoundTrip(t, "udp")
}

func TestTCPPortHopServerListensOnDerivedPorts(t *testing.T) {
	runPortHopServerRoundTrip(t, "tcp")
}

func TestPortHopClientWalksSequence(t *testing.T) {
	// Configure a client whose base port is closed. startSession must walk
	// to the derived port and complete the handshake there.
	base := freeLocalPort(t)
	derived, err := hopPortsForConfig(Config{
		ServerAddr:    net.JoinHostPort("127.0.0.1", strconv.Itoa(base)),
		SeedHex:       testConfig("", "udp").SeedHex,
		Generation:    testConfig("", "udp").Generation,
		PortHopCount:  3,
		PortHopSpread: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(derived[1])), "tcp")
	serverCfg.PortHopCount = 1
	srv, err := NewServer(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	clientCfg := testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(base)), "tcp")
	clientCfg.PortHopCount = 3
	clientCfg.PortHopSpread = 2048
	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("client did not fall through to derived port: %v", err)
	}
	defer cli.Close()
	fmt.Println("walk sequence ok")
}
