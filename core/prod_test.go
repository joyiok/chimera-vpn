package core

import (
	"context"
	"testing"
	"time"
)

// runPair boots a server and one client with the given config overrides and
// returns the accepted server-side conn plus the started client.
func runPair(t *testing.T, mutate func(*Config)) (*Server, *Client, *Conn) {
	t.Helper()
	cfg := Config{
		SeedHex:    hex32(50),
		Generation: 0,
		PSKHex:     hex32(51),
		ServerAddr: freeUDPAddr(t),
	}
	if mutate != nil {
		mutate(&cfg)
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	client, err := NewClient(cfg)
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
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return server, client, conn
}

// TestChaChaEndToEnd drives the full client-server stack with the ChaCha
// cipher override configured identically on both ends.
func TestChaChaEndToEnd(t *testing.T) {
	mutate := func(c *Config) { c.Cipher = "chacha20-poly1305" }
	_, client, conn := runPair(t, mutate)

	recv := make(chan []byte, 1)
	go func() { p, _ := conn.ReceivePacket(); recv <- p }()
	if err := client.SendPacket([]byte{0x45, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-recv:
		if p[0] != 0x45 {
			t.Fatalf("payload mismatch: %v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet over the ChaCha tunnel")
	}
}

// TestCipherConfigValidation: unknown cipher names must fail up front, and
// endpoints with mismatched ciphers must fail to establish.
func TestCipherConfigValidation(t *testing.T) {
	if _, err := NewClient(Config{SeedHex: hex32(60), PSKHex: hex32(61), ServerAddr: "127.0.0.1:1", Cipher: "rot13"}); err == nil {
		t.Fatal("unknown cipher accepted")
	}

	// Server on ChaCha, client on the genome default: the handshake keys
	// bind the cipher choice, so the session must not establish.
	serverCfg := Config{SeedHex: hex32(62), PSKHex: hex32(63), ServerAddr: freeUDPAddr(t), Cipher: "chacha20-poly1305"}
	server, err := NewServer(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientCfg := serverCfg
	clientCfg.Cipher = ""
	client, err := NewClient(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err == nil {
		client.Close()
		t.Fatal("mismatched cipher handshake unexpectedly succeeded")
	}
}

// TestKeepaliveConfigWiring: an explicit keepalive interval on the client
// config must reach the tunnel pump (short interval -> server sees frames
// while the app stays idle).
func TestKeepaliveConfigWiring(t *testing.T) {
	mutate := func(c *Config) { c.KeepaliveInterval = 200 * time.Millisecond }
	_, client, conn := runPair(t, mutate)

	_ = client
	// Server side: the session must stay warm purely from client
	// keepalives; idleFor staying small proves the pump runs.
	time.Sleep(700 * time.Millisecond)
	if conn.t.IdleFor() > 500*time.Millisecond {
		t.Fatalf("client keepalive config not wired: idle %v", conn.t.IdleFor())
	}
}

// TestIdleReapConfigWiring: a short server IdleTimeout must close the
// session once the client goes silent.
func TestIdleReapConfigWiring(t *testing.T) {
	mutate := func(c *Config) {
		c.IdleTimeout = 300 * time.Millisecond
		c.KeepaliveInterval = -1 // server keepalives off; reap must still see silence
	}
	server, client, conn := runPair(t, mutate)
	_ = server
	_ = client

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := server.Accept(ctx)
		cancel()
		if err == nil {
			t.Fatal("unexpected extra client accepted")
		}
		if _, rerr := conn.ReceivePacket(); rerr != nil {
			return // session reaped: ReceivePacket reports closure
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idle session was never reaped via core config")
}

func TestUDPFileDescriptor(t *testing.T) {
	_, client, _ := runPair(t, nil)
	fd, err := client.UDPFileDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if fd < 0 {
		t.Fatalf("fd=%d", fd)
	}
}

func TestMaxSessionsConfigWiring(t *testing.T) {
	addr := freeUDPAddr(t)
	cfg := Config{
		SeedHex:      hex32(80),
		PSKHex:       hex32(81),
		ServerAddr:   addr,
		MaxSessions:  1,
		DisableDecoy: true,
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	first, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := server.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	second, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(); err == nil {
		second.Close()
		t.Fatal("second client connected despite MaxSessions=1")
	}
}
