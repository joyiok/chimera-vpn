package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

// awaitTrue polls cond until true or the deadline passes.
func awaitTrue(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestServerKeepaliveOnIdle: a client that goes silent must still receive
// periodic encrypted frames from the server (NAT refresh), and the session
// must not be reaped while keepalives flow.
func TestServerKeepaliveOnIdle(t *testing.T) {
	cp, psk := compileFor(t, 7100)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr()

	keepalive := 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk).
		WithKeepalive(keepalive).
		WithIdleTimeout(2 * time.Second) // far beyond test duration
	go mux.Run(ctx)

	// Real client completes the handshake, then stops reading entirely.
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ClientHandshake(clientConn, serverAddr, h)
	if err != nil {
		t.Fatal(err)
	}
	ct := NewPacketTunnel(clientConn, serverAddr, sess)
	defer ct.Close()

	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}

	// Count datagrams that authenticate as session keepalive frames (raw
	// counting would also see leftover handshake retransmits).
	received := 0
	awaitTrue(t, 2*time.Second, func() bool {
		received += keepaliveProbe(ct)
		return received >= 2
	}, "server sent no keepalives while idle")

	select {
	case <-st.closed:
		t.Fatal("session was reaped despite keepalive flow")
	default:
	}
}

// keepaliveProbe drains the client socket and returns how many datagrams
// authenticated as session frames carrying ControlKeepalive.
func keepaliveProbe(ct *PacketTunnel) int {
	total := 0
	buf := make([]byte, maxDatagram)
	for {
		_ = ct.conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, _, err := ct.conn.ReadFrom(buf)
		if err != nil {
			return total
		}
		ct.sessMu.Lock()
		msg, derr := ct.sess.Decode(buf[:n])
		ct.sessMu.Unlock()
		if derr != nil {
			continue // stale handshake retransmit or probe junk
		}
		if len(msg.Payload) == 1 && msg.Payload[0] == ControlKeepalive {
			total++
		}
	}
}

// TestIdleReaping: with reaping enabled and keepalives disabled server-side,
// a silent client's session must be closed and dropped from the mux.
func TestIdleReaping(t *testing.T) {
	cp, psk := compileFor(t, 7101)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk).
		WithKeepalive(-1).
		WithIdleTimeout(400 * time.Millisecond)
	go mux.Run(ctx)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ClientHandshake(clientConn, serverConn.LocalAddr(), h)
	if err != nil {
		t.Fatal(err)
	}
	ct := NewPacketTunnel(clientConn, serverConn.LocalAddr(), sess)
	defer ct.Close()
	// Client stays completely silent: no SetKeepalive, no data.

	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}

	awaitTrue(t, 3*time.Second, func() bool {
		select {
		case <-st.closed:
			return true
		default:
			return false
		}
	}, "idle session was not reaped")

	// And it is gone from the established table.
	mux.mu.Lock()
	left := len(mux.established)
	mux.mu.Unlock()
	if left != 0 {
		t.Fatalf("established table still has %d sessions after reap", left)
	}
}

// TestClientKeepalivePump: the client-side SetKeepalive pump must emit
// frames when idle and stay quiet while data flows.
func TestClientKeepalivePump(t *testing.T) {
	cp, psk := compileFor(t, 7102)
	ct, st, _, teardown := handshakePair(t, cp, psk)
	defer teardown()

	ct.SetKeepalive(200 * time.Millisecond)
	defer ct.SetKeepalive(-1)

	// Server sees keepalive frames arrive: its decode path touches
	// lastActive, so idleFor stays near zero while the pump runs.
	time.Sleep(700 * time.Millisecond)
	if st.idleFor() > 500*time.Millisecond {
		t.Fatalf("server saw no client keepalives: idle %v", st.idleFor())
	}
}

// TestRateLimitDropsBurst: with a tiny token bucket, most of a large burst
// of client datagrams must be dropped server-side.
func TestRateLimitDropsBurst(t *testing.T) {
	cp, psk := compileFor(t, 7103)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 4 KiB/s with a 4 KiB burst: frames are ~1450 B on the wire, so the
	// budget admits ~2 of a 64-frame burst and drops the rest.
	mux := NewServerMux(serverConn, cp, psk).
		WithRateLimit(4096)
	go mux.Run(ctx)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ClientHandshake(clientConn, serverConn.LocalAddr(), h)
	if err != nil {
		t.Fatal(err)
	}
	ct := NewPacketTunnel(clientConn, serverConn.LocalAddr(), sess)
	defer ct.Close()

	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 1400)
	payload[0] = 0x45
	sent, delivered := 0, 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			pkt, err := st.ReceivePacket()
			if err != nil {
				return
			}
			_ = pkt
			delivered++
		}
	}()
	for i := 0; i < 64; i++ {
		if err := ct.SendPacket(payload); err != nil {
			t.Fatal(err)
		}
		sent++
	}
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	// The 4 KiB burst budget admits at most ~2 frames of ~1450 B; the
	// remaining 60+ must be dropped.
	if delivered > 3 {
		t.Fatalf("rate limit ineffective: %d/%d frames delivered", delivered, sent)
	}
	if delivered == 0 {
		t.Fatal("burst budget admitted nothing; limiter misconfigured")
	}
}

func TestTokenBucketUnit(t *testing.T) {
	if !(*tokenBucket)(nil).take(1000) {
		t.Error("nil bucket must be unlimited")
	}

	b := newTokenBucket(1000, 1000) // 1000 B/s, 1000 B burst
	for i := 0; i < 10; i++ {
		if !b.take(100) {
			t.Fatalf("frame %d should fit the burst budget", i)
		}
	}
	if b.take(1) {
		t.Error("burst exhausted; next frame must be dropped")
	}
	time.Sleep(30 * time.Millisecond) // ~30 tokens refill
	if !b.take(20) {
		t.Error("refill did not credit tokens")
	}
}

// TestIdleReapDespiteServerKeepalive: server-originated keepalives must not
// reset lastActive, otherwise a vanished client is never reaped.
func TestIdleReapDespiteServerKeepalive(t *testing.T) {
	cp, psk := compileFor(t, 7103)

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk).
		WithKeepalive(40 * time.Millisecond).
		WithIdleTimeout(350 * time.Millisecond)
	go mux.Run(ctx)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ClientHandshake(clientConn, serverConn.LocalAddr(), h)
	if err != nil {
		t.Fatal(err)
	}
	ct := NewPacketTunnel(clientConn, serverConn.LocalAddr(), sess)
	defer ct.Close()

	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}

	awaitTrue(t, 3*time.Second, func() bool {
		select {
		case <-st.closed:
			return true
		default:
			return false
		}
	}, "idle session was not reaped while server keepalives were running")
}
