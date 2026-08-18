package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"
)

func hex32(i int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("core-test-%d", i)))
	return fmt.Sprintf("%x", h[:])
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

func TestMultiClientServer(t *testing.T) {
	addr := freeUDPAddr(t)
	cfg := Config{SeedHex: hex32(1), Generation: 0, PSKHex: hex32(2), ServerAddr: addr}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	const clients = 3
	clientErrs := make(chan error, clients)
	cs := make([]*Client, clients)
	for i := 0; i < clients; i++ {
		go func(i int) {
			c, err := NewClient(cfg)
			if err == nil {
				cs[i] = c
				err = c.Start()
			}
			clientErrs <- err
		}(i)
	}
	for i := 0; i < clients; i++ {
		if err := <-clientErrs; err != nil {
			t.Fatalf("client %d failed: %v", i, err)
		}
	}
	defer func() {
		for _, c := range cs {
			if c != nil {
				c.Close()
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conns := make([]*Conn, 0, clients)
	for i := 0; i < clients; i++ {
		conn, err := server.Accept(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		conns = append(conns, conn)
		defer conn.Close()
	}

	// Each client sends a marker; match it to a server Conn.
	type rx struct {
		conn *Conn
		pkt  []byte
		err  error
	}
	got := make(chan rx, clients)
	for _, conn := range conns {
		go func(c *Conn) {
			p, err := c.ReceivePacket()
			got <- rx{c, p, err}
		}(conn)
	}
	for i := 0; i < clients; i++ {
		if err := cs[i].SendPacket([]byte(fmt.Sprintf("marker-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	byMarker := map[string]*Conn{}
	for i := 0; i < clients; i++ {
		select {
		case r := <-got:
			if r.err != nil {
				t.Fatal(r.err)
			}
			byMarker[string(r.pkt)] = r.conn
		case <-time.After(3 * time.Second):
			t.Fatal("server did not receive all markers")
		}
	}

	// Reply through the matched connection and verify the right client.
	for i := 0; i < clients; i++ {
		marker := fmt.Sprintf("marker-%d", i)
		conn := byMarker[marker]
		if conn == nil {
			t.Fatalf("marker %s missing", marker)
		}
		reply := []byte("reply-" + marker)
		recv := make(chan []byte, 1)
		go func(i int) { p, _ := cs[i].ReceivePacket(); recv <- p }(i)
		if err := conn.SendPacket(reply); err != nil {
			t.Fatal(err)
		}
		select {
		case p := <-recv:
			if string(p) != string(reply) {
				t.Fatalf("client %d got %q, want %q", i, p, reply)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("client %d did not receive reply", i)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := NewClient(Config{SeedHex: "zz", PSKHex: hex32(2), ServerAddr: "x:1"}); err == nil {
		t.Fatal("bad seed accepted")
	}
	if _, err := NewClient(Config{SeedHex: hex32(1), PSKHex: hex32(2), ServerAddr: ""}); err == nil {
		t.Fatal("empty server accepted")
	}
}

func TestNilConnAccessors(t *testing.T) {
	var c *Conn
	if c.RemoteAddr() != nil || c.IdleFor() != 0 {
		t.Fatal("nil Conn")
	}
	empty := &Conn{}
	if empty.RemoteAddr() != nil || empty.IdleFor() != 0 {
		t.Fatal("empty Conn")
	}
}
