package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

func TestAllowDecoySize(t *testing.T) {
	if allowDecoySize(10, 40) {
		t.Fatal("3x amplification must be rejected")
	}
	if allowDecoySize(100, maxDecoyBytes+1) {
		t.Fatal("oversize decoy must be rejected")
	}
	if !allowDecoySize(400, 200) {
		t.Fatal("smaller-than-probe decoy must be allowed")
	}
}

func TestDecoyRepliesToClientFirstProbe(t *testing.T) {
	g, seed, psk, cp := clientFirstProtocol(t, 7000)
	dcp := compileDecoy(t, seed, psk, 0)

	frame, err := encodeDecoyFrame(dcp)
	if err != nil {
		t.Fatal(err)
	}
	probe := make([]byte, 512)
	for i := range probe {
		probe[i] = 0x41
	}
	if !allowDecoySize(len(probe), len(frame)) {
		t.Fatalf("decoy frame %d bytes too large for 512-byte probe; pick another seed", len(frame))
	}

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk).WithDecoy(dcp)
	go mux.Run(ctx)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	if _, err := clientConn.WriteTo(probe, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := clientConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected decoy reply: %v", err)
	}
	if n == 0 {
		t.Fatal("empty decoy")
	}

	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.RecvStep(buf[:n]); err == nil {
		t.Fatalf("decoy decoded as live protocol %s", g.HandshakePattern)
	}

	// Same address, inside the 1s creation gap: no second reply.
	if _, err := clientConn.WriteTo(probe, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := clientConn.ReadFrom(buf); err == nil {
		t.Fatal("second probe within 1s should stay silent")
	}

	if mux.Stats().Decoys != 1 {
		t.Fatalf("decoys=%d want 1", mux.Stats().Decoys)
	}
}

func TestMaxSessionsDropsExtraClients(t *testing.T) {
	g, err := genome.Generate(seedFor(7100), 0)
	if err != nil {
		t.Fatal(err)
	}
	psk := pskFor(7100)
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk).WithMaxSessions(1)
	go mux.Run(ctx)

	first, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	h1, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientHandshake(first, serverConn.LocalAddr(), h1); err != nil {
		t.Fatalf("first client: %v", err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatalf("accept first: %v", err)
	}
	defer st.Close()

	second, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	h2, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientHandshake(second, serverConn.LocalAddr(), h2); err == nil {
		t.Fatal("second client connected despite maxSessions=1")
	}
}

func clientFirstProtocol(t *testing.T, start int) (*genome.ProtocolGenome, []byte, []byte, *compiler.CompiledProtocol) {
	t.Helper()
	for i := start; i < start+40; i++ {
		seed := seedFor(i)
		g, err := genome.Generate(seed, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Handshake) == 0 || g.Handshake[0].Direction != genome.DirClient {
			continue
		}
		psk := pskFor(i)
		cp, err := compiler.Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}
		return g, seed, psk, cp
	}
	t.Fatal("no client-first genome in seed range")
	return nil, nil, nil, nil
}

func compileDecoy(t *testing.T, seed, psk []byte, generation uint64) *compiler.CompiledProtocol {
	t.Helper()
	g, err := genome.Generate(seed, DecoyGeneration(generation))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}
