package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestWebSocketRoundTrip(t *testing.T) {
	srv, err := NewServer(testConfig("127.0.0.1:0", "websocket"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// A scanner that cannot guess the seed-derived path sees a normal 404.
	resp, err := http.Get("http://" + srv.LocalAddr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || len(body) == 0 {
		t.Fatalf("decoy page: status=%d body=%q", resp.StatusCode, body)
	}

	cli, err := NewClient(testConfig(srv.LocalAddr().String(), "websocket"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SendPacket([]byte("ws-echo")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ws-echo" {
		t.Fatalf("got %q", got)
	}
	if conn.RemoteAddr().String() == "" {
		t.Fatal("websocket session has no remote address")
	}
}

func TestWebSocketPortHopDerivedPort(t *testing.T) {
	base := freeLocalPort(t)
	addr := net.JoinHostPort("127.0.0.1", itoa(base))
	cfg := testConfig(addr, "websocket")
	cfg.PortHopCount = 3
	cfg.PortHopSpread = 2048
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
	target := net.JoinHostPort("127.0.0.1", itoa(ports[2]))
	cli, err := NewClient(testConfig(target, "websocket"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("connect to derived ws port: %v", err)
	}
	defer cli.Close()
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
