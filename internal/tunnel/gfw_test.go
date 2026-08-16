package tunnel

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

type recordingConn struct {
	net.PacketConn
	mu    sync.Mutex
	sends [][]byte
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sends = append(c.sends, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *recordingConn) first() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sends) == 0 {
		return nil
	}
	return append([]byte(nil), c.sends[0]...)
}

func TestHandshakeFirstDatagramExemptFromFEP(t *testing.T) {
	// Wu et al., USENIX Security 2023 Algorithm 1: first payload of a flow.
	for i := 0; i < 50; i++ {
		g, err := genome.Generate(seedFor(12000+i), uint64(i%6))
		if err != nil {
			t.Fatal(err)
		}
		psk := pskFor(12000 + i)
		cp, err := compiler.Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}
		h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := h.CurrentSpec()
		if err != nil {
			t.Fatal(err)
		}
		var wire []byte
		if spec.Direction == genome.DirClient {
			frame, _, err := h.EncodeStep()
			if err != nil {
				t.Fatal(err)
			}
			wire = h.WrapDatagram(frame)
		} else {
			knock, err := h.EncodeKnock()
			if err != nil {
				t.Fatal(err)
			}
			wire = h.WrapDatagram(knock)
		}
		exempt, rule := compiler.FEPExemption(wire)
		if !exempt {
			t.Fatalf("seed %d pattern %s first datagram blocked by inferred FEP detector", i, g.HandshakePattern)
		}
		// Wu et al. evaluate Ex1 (popcount) before Ex2/Ex4. A printable
		// cover can still trip Ex1 first; that is still an exemption. Reject
		// only Ex5 (TLS/HTTP DPI) and require the cover prefix we emit.
		if rule == "ex5" {
			t.Fatalf("seed %d exempt via Ex5 TLS/HTTP fingerprint", i)
		}
		if len(wire) < 6 {
			t.Fatalf("seed %d first datagram %d bytes, shorter than Ex2 prefix", i, len(wire))
		}
		for _, b := range wire[:6] {
			if b < 0x20 || b > 0x7e {
				t.Fatalf("seed %d first 6 bytes not printable ASCII (rule %s)", i, rule)
			}
		}
		if spec.Direction == genome.DirClient && len(wire) >= 160 && len(wire) <= 700 {
			t.Fatalf("seed %d client-first wire %d still in IMC 2020 160-700 band", i, len(wire))
		}
	}
}

func TestReplayOfFirstDatagramDoesNotCreateSession(t *testing.T) {
	// Alice et al., IMC 2020: identical replay of the first data-carrying
	// packet must not complete a second handshake.
	_, _, psk, cp := clientFirstProtocol(t, 13000)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rec := &recordingConn{PacketConn: raw}

	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientHandshake(rec, serverConn.LocalAddr(), h); err != nil {
		t.Fatalf("legitimate handshake: %v", err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first := rec.first()
	if len(first) == 0 {
		t.Fatal("did not capture first datagram")
	}

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(first, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	replayCtx, replayCancel := context.WithTimeout(ctx, time.Second)
	defer replayCancel()
	if st2, err := mux.Accept(replayCtx); err == nil {
		st2.Close()
		t.Fatal("replay of first datagram created a second session")
	}
	if mux.Stats().Established != 1 {
		t.Fatalf("established=%d want 1", mux.Stats().Established)
	}
}

func TestPatchedReplayDoesNotCreateSession(t *testing.T) {
	_, _, psk, cp := clientFirstProtocol(t, 13100)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rec := &recordingConn{PacketConn: raw}
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientHandshake(rec, serverConn.LocalAddr(), h); err != nil {
		t.Fatal(err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	patched := rec.first()
	if len(patched) < 8 {
		t.Fatal("short first datagram")
	}
	patched[len(patched)-1] ^= 0x01

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(patched, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	replayCtx, replayCancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer replayCancel()
	if st2, err := mux.Accept(replayCtx); err == nil {
		st2.Close()
		t.Fatal("patched replay created a session")
	}
}

func TestRandomProbeDoesNotCreateSession(t *testing.T) {
	_, _, psk, cp := clientFirstProtocol(t, 13200)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	junk := make([]byte, 400)
	for i := range junk {
		junk[i] = byte(i)
	}
	if _, err := probe.WriteTo(junk, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer probeCancel()
	if st, err := mux.Accept(probeCtx); err == nil {
		st.Close()
		t.Fatal("random probe created a session")
	}
}

func TestUnauthenticatedKnockDoesNotElicitRealHello(t *testing.T) {
	g, psk, cp := serverFirstProtocol(t, 14000)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	junk := make([]byte, 80)
	for i := range junk {
		junk[i] = 0x41
	}
	if _, err := probe.WriteTo(junk, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = probe.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	n, _, err := probe.ReadFrom(buf)
	if err == nil {
		h, herr := compiler.NewHandshake(cp, genome.DirClient, psk)
		if herr != nil {
			t.Fatal(herr)
		}
		inner, uerr := h.UnwrapDatagram(buf[:n])
		if uerr == nil && h.RecvStep(inner) == nil {
			t.Fatalf("unauthenticated knock decoded as live %s hello", g.HandshakePattern)
		}
	}
}

func TestKnockReplayDoesNotCreateSecondSession(t *testing.T) {
	_, psk, cp := serverFirstProtocol(t, 14100)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rec := &recordingConn{PacketConn: raw}
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientHandshake(rec, serverConn.LocalAddr(), h); err != nil {
		t.Fatalf("legitimate server-first handshake: %v", err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	knock := rec.first()
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(knock, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	replayCtx, replayCancel := context.WithTimeout(ctx, time.Second)
	defer replayCancel()
	if st2, err := mux.Accept(replayCtx); err == nil {
		st2.Close()
		t.Fatal("replayed knock created a second session")
	}
}

func serverFirstProtocol(t *testing.T, start int) (*genome.ProtocolGenome, []byte, *compiler.CompiledProtocol) {
	t.Helper()
	for i := start; i < start+80; i++ {
		seed := seedFor(i)
		g, err := genome.Generate(seed, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Handshake) == 0 || g.Handshake[0].Direction != genome.DirServer {
			continue
		}
		psk := pskFor(i)
		cp, err := compiler.Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}
		return g, psk, cp
	}
	t.Fatal("no server-first genome in seed range")
	return nil, nil, nil
}
