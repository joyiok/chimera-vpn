package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func withNoise(cfg Config) Config {
	cfg.DecoyEvery = 1
	cfg.DecoyMaxPerSec = 10000
	return cfg
}

func roundTripWithNoise(t *testing.T, transport string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv, err := NewServer(withNoise(testConfig("127.0.0.1:0", transport)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli, err := NewClient(withNoise(testConfig(srv.LocalAddr().String(), transport)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const n = 24
	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf("s2c-%02d", i))
		if err := conn.SendPacket(payload); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		want := []byte(fmt.Sprintf("s2c-%02d", i))
		got, err := cli.ReceivePacket()
		if err != nil {
			t.Fatalf("client recv %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("client got %q, want %q", got, want)
		}
	}
	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf("c2s-%02d", i))
		if err := cli.SendPacket(payload); err != nil {
			t.Fatalf("client send %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		want := []byte(fmt.Sprintf("c2s-%02d", i))
		got, err := conn.ReceivePacket()
		if err != nil {
			t.Fatalf("server recv %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("server got %q, want %q", got, want)
		}
	}
}

func TestUDPNoiseMaskDeliversAllFrames(t *testing.T) {
	roundTripWithNoise(t, "udp")
}

func TestTCPNoiseMaskDeliversAllFrames(t *testing.T) {
	roundTripWithNoise(t, "tcp")
}
