package core

import (
	"context"
	"testing"
	"time"
)

func testConfig(addr, transport string) Config {
	return Config{
		SeedHex:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		PSKHex:     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		ServerAddr: addr,
		Transport:  transport,
	}
}

func TestClientServerOverTCP(t *testing.T) {
	srv, err := NewServer(testConfig("127.0.0.1:0", "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli, err := NewClient(testConfig(srv.LocalAddr().String(), "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	want := []byte("hello over tcp")
	if err := conn.SendPacket(want); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("client got %q, want %q", got, want)
	}

	echo := []byte("echo from client")
	if err := cli.SendPacket(echo); err != nil {
		t.Fatal(err)
	}
	got, err = conn.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(echo) {
		t.Fatalf("server got %q, want %q", got, echo)
	}
	if conn.RemoteAddr() == nil || conn.RemoteAddr().String() == "" {
		t.Fatal("tcp session has no remote address")
	}
}

func TestClientOverTCPGenerationWindow(t *testing.T) {
	cfg := testConfig("127.0.0.1:0", "tcp")
	cfg.GenerationWindow = 1
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	clientCfg := testConfig(srv.LocalAddr().String(), "tcp")
	clientCfg.Generation = 1
	clientCfg.GenerationWindow = 1
	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.Generation() != 1 {
		t.Fatalf("accepted generation = %d, want 1", conn.Generation())
	}
}
