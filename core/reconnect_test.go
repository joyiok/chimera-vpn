package core

import (
	"context"
	"testing"
	"time"
)

func TestClientIdleForOneSidedKeepalive(t *testing.T) {
	addr := freeUDPAddr(t)
	serverCfg := Config{
		SeedHex:           hex32(201),
		PSKHex:            hex32(202),
		ServerAddr:        addr,
		ClientCIDR:        "10.99.0.0/24",
		DisableDecoy:      true,
		KeepaliveInterval: -1, // server silent
	}
	server, err := NewServer(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	clientCfg := serverCfg
	clientCfg.KeepaliveInterval = 80 * time.Millisecond
	client, err := NewClient(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	time.Sleep(350 * time.Millisecond)
	if idle := client.IdleFor(); idle < 250*time.Millisecond {
		t.Fatalf("client IdleFor=%s; own keepalives must not count as inbound", idle)
	}
}

func TestReconnectAfterServerRestart(t *testing.T) {
	addr := freeUDPAddr(t)
	cfg := Config{
		SeedHex:      hex32(211),
		PSKHex:       hex32(212),
		ServerAddr:   addr,
		ClientCIDR:   "10.99.0.0/24",
		DisableDecoy: true,
	}

	start := func() *Server {
		s, err := NewServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
		return s
	}

	server := start()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := server.Accept(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	server.Close()

	server = start()
	t.Cleanup(func() { server.Close() })

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("handshake after server restart: %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err = server.Accept(ctx)
	if err != nil {
		t.Fatalf("accept after restart: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if ip := conn.AssignedIP(); ip == "" {
		t.Fatal("expected assigned IP after reconnect")
	}
}
