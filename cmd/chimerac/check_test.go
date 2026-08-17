package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"

	"chimera/core"
)

func hex32n(i int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("chimerac-check-%d", i)))
	return fmt.Sprintf("%x", h[:])
}

func TestRunCheckUserspaceEcho(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()

	cfg := core.Config{
		SeedHex:      hex32n(1),
		PSKHex:       hex32n(2),
		ServerAddr:   addr,
		ClientCIDR:   "10.99.0.0/24",
		DisableDecoy: true,
	}
	server, err := core.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := server.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			pkt, err := conn.ReceivePacket()
			if err != nil {
				return
			}
			if err := conn.SendPacket(pkt); err != nil {
				return
			}
		}
	}()

	res := runCheck(clientConfig{
		ServerAddr: addr,
		SeedHex:    cfg.SeedHex,
		PSKHex:     cfg.PSKHex,
	}, 12*time.Second)
	if !res.OK {
		t.Fatalf("check failed: %+v", res)
	}
	if res.Probe != "echo" {
		t.Fatalf("probe=%s want echo", res.Probe)
	}
	if res.Assigned == "" {
		t.Fatal("missing assigned IP")
	}
}
