package core

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestMultiTransportServeAndProbe verifies multi-transport mode end to
// end: one server starts UDP and TCP listeners together, and a client
// probing [tcp, udp] connects over its first choice.
func TestMultiTransportServeAndProbe(t *testing.T) {
	// Both transports must share one port number, so pick a fixed free
	// port instead of letting each listener bind its own :0.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freeLocalPort(t)))
	srvCfg := testConfig(addr, "udp")
	srvCfg.Transports = []string{"udp", "tcp"}
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cliCfg := testConfig(srv.LocalAddr().String(), "udp")
	cliCfg.Transports = []string{"tcp", "udp"}
	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if got := cli.WorkingTransport(); got != "tcp" {
		t.Fatalf("working transport = %q, want tcp (first in probe list)", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SendPacket([]byte("multi-echo")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "multi-echo" {
		t.Fatalf("got %q", got)
	}
}
