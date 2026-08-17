package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

func compileClientFirstWindow(t *testing.T) (*compiler.CompiledProtocol, *compiler.CompiledProtocol, []byte) {
	t.Helper()
	for i := 0; i < 2500; i++ {
		seed := seedFor(91000 + i)
		psk := pskFor(91000 + i)
		g0, err := genome.Generate(seed, 0)
		if err != nil {
			t.Fatal(err)
		}
		g1, err := genome.Generate(seed, 1)
		if err != nil {
			t.Fatal(err)
		}
		if g0.Handshake[0].Direction != genome.DirClient || g1.Handshake[0].Direction != genome.DirClient {
			continue
		}
		cp0, err := compiler.Compile(g0, psk)
		if err != nil {
			t.Fatal(err)
		}
		cp1, err := compiler.Compile(g1, psk)
		if err != nil {
			t.Fatal(err)
		}
		return cp0, cp1, psk
	}
	t.Fatal("no seed where generations 0 and 1 are both client-first")
	return nil, nil, nil
}

func TestServerMuxAcceptsRotatedGeneration(t *testing.T) {
	cp0, cp1, psk := compileClientFirstWindow(t)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp0, psk).WithProtocols([]*compiler.CompiledProtocol{cp0, cp1})
	go mux.Run(ctx)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	h, err := compiler.NewHandshake(cp1, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ClientHandshake(clientConn, serverConn.LocalAddr(), h)
	if err != nil {
		t.Fatalf("client gen+1 handshake: %v", err)
	}
	ct := NewPacketTunnel(clientConn, serverConn.LocalAddr(), sess)
	defer ct.Close()

	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Generation() != 1 {
		t.Fatalf("matched generation %d, want 1", st.Generation())
	}

	recv := make(chan []byte, 1)
	go func() {
		p, err := st.ReceivePacket()
		if err != nil {
			return
		}
		recv <- p
	}()
	if err := ct.SendPacket([]byte{0x45, 9, 9, 9}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-recv:
		if p[0] != 0x45 {
			t.Fatalf("payload %v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet after rotated-generation handshake")
	}
}
