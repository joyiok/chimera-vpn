package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

// compileFor builds a compiled protocol from deterministic seeds.
func compileFor(t *testing.T, seedIdx int) (*compiler.CompiledProtocol, []byte) {
	t.Helper()
	g, err := genome.Generate(seedFor(seedIdx), 0)
	if err != nil {
		t.Fatal(err)
	}
	psk := pskFor(seedIdx)
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}
	return cp, psk
}

// handshakePair runs one client/server handshake over loopback UDP sockets
// and returns both established tunnels.
func handshakePair(t *testing.T, cp *compiler.CompiledProtocol, psk []byte) (*PacketTunnel, *ServerTunnel, *ServerMux, func()) {
	t.Helper()
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := serverConn.LocalAddr()

	ctx, cancel := context.WithCancel(t.Context())
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		cancel()
		serverConn.Close()
		t.Fatal(err)
	}
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	type cres struct {
		tun *PacketTunnel
		err error
	}
	done := make(chan cres, 1)
	go func() {
		sess, err := ClientHandshake(clientConn, serverAddr, h)
		if err != nil {
			done <- cres{err: err}
			return
		}
		done <- cres{tun: NewPacketTunnel(clientConn, serverAddr, sess)}
	}()

	acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
	defer acceptCancel()
	st, err := mux.Accept(acceptCtx)
	if err != nil {
		cancel()
		t.Fatalf("server accept: %v", err)
	}
	cr := <-done
	if cr.err != nil {
		cancel()
		t.Fatalf("client handshake: %v", cr.err)
	}

	teardown := func() {
		cr.tun.Close()
		st.Close()
		serverConn.Close()
		clientConn.Close()
		cancel()
	}
	return cr.tun, st, mux, teardown
}

func TestAckPayloadCodec(t *testing.T) {
	for _, base := range []uint64{0, 1, 42, 1 << 40} {
		kind, v, err := decodeAckPayload(encodeAckPayload(base))
		if err != nil || kind != ControlAck || v != base {
			t.Fatalf("ack roundtrip %d: kind=%d v=%d err=%v", base, kind, v, err)
		}
		kind, v, err = decodeAckPayload(encodeSkipPayload(base))
		if err != nil || kind != ControlSkip || v != base {
			t.Fatalf("skip roundtrip %d: kind=%d v=%d err=%v", base, kind, v, err)
		}
	}
	for _, bad := range [][]byte{nil, {0x02}, {0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {0x09, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, _, err := decodeAckPayload(bad); err == nil {
			t.Errorf("payload %v should be rejected", bad)
		}
	}
}

func TestAdvanceBaseSkipsLostFrames(t *testing.T) {
	cp, psk := compileFor(t, 7000)
	ct, st, _, teardown := handshakePair(t, cp, psk)
	defer teardown()

	// Frames 0..15; the receiver consumes everything except sequence 3.
	sender := ct.sess
	receiver := st.sess
	var frames [][]byte
	for i := 0; i < 16; i++ {
		f, err := sender.Encode([]byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	for i := 0; i < 16; i++ {
		if i == 3 {
			continue // dropped forever
		}
		if _, err := receiver.Decode(frames[i]); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}

	// Base is wedged at 3 by the permanent hole.
	if got := receiver.PacketBase(); got != 3 {
		t.Fatalf("base after hole = %d, want 3", got)
	}

	// Advance past the hole; the duplicate of a pre-skip frame must no
	// longer authenticate (window cleared), and fresh frames keep flowing.
	if err := receiver.AdvanceBaseTo(16); err != nil {
		t.Fatal(err)
	}
	if got := receiver.PacketBase(); got != 16 {
		t.Fatalf("base after skip = %d, want 16", got)
	}
	if _, err := receiver.Decode(frames[5]); err == nil {
		t.Fatal("stale pre-skip duplicate must not authenticate")
	}
	f, err := sender.Encode([]byte("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := receiver.Decode(f)
	if err != nil {
		t.Fatalf("fresh frame after skip: %v", err)
	}
	if string(msg.Payload) != "fresh" {
		t.Fatalf("payload %q", msg.Payload)
	}
}

func TestAdvanceBaseRejectsBadTargets(t *testing.T) {
	cp, psk := compileFor(t, 7001)
	ct, st, _, teardown := handshakePair(t, cp, psk)
	defer teardown()

	sender := ct.sess
	receiver := st.sess
	for i := 0; i < 4; i++ {
		f, err := sender.Encode([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.Decode(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := receiver.AdvanceBaseTo(0); err != nil {
		t.Errorf("advance to current base should be a no-op, got %v", err)
	}
	if err := receiver.AdvanceBaseTo(receiver.PacketBase() + compiler.PacketWindow + 1); err == nil {
		t.Error("advance beyond window must be rejected")
	}
}

// TestLossRecoveryEndToEnd wedges the server's receive base with a dropped
// run, then keeps sending until the client's skip control frame frees it.
func TestLossRecoveryEndToEnd(t *testing.T) {
	cp, psk := compileFor(t, 7002)
	ct, st, _, teardown := handshakePair(t, cp, psk)
	defer teardown()

	// Consume the handshake-era sequence on the server side by pulling one
	// packet through each direction first.
	startRecv := make(chan []byte, 1)
	go func() { p, _ := ct.ReceivePacket(); startRecv <- p }()
	if err := st.SendPacket([]byte{0x45, 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-startRecv:
	case <-time.After(3 * time.Second):
		t.Fatal("no start packet")
	}

	// Send far more than skipSpan frames. The receiver never reads them
	// here; the point is that the sender-side tracker fires a SKIP once
	// the span crosses the threshold, and the server applies it.
	before := st.ackBaseSnapshot()
	deadline := time.Now().Add(10 * time.Second)
	applied := false
	for i := 0; i < compiler.PacketWindow+64 && time.Now().Before(deadline); i++ {
		if err := ct.SendPacket([]byte{0x45, byte(i)}); err != nil {
			t.Fatal(err)
		}
		// The server must process incoming frames for the skip to land;
		// drain non-blocking so we do not block the sender loop.
		for {
			pkt, err := st.TryReceive()
			if err != nil || pkt == nil {
				break
			}
		}
		if st.ackBaseSnapshot() > before {
			applied = true
			break
		}
		if i%256 == 0 {
			// Give the skip frame a moment to arrive and be applied.
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !applied {
		t.Fatal("server receive base never advanced despite a skip-worthy span")
	}
}

func TestAckControlRidesData(t *testing.T) {
	cp, psk := compileFor(t, 7003)
	ct, st, _, teardown := handshakePair(t, cp, psk)
	defer teardown()

	// ackEvery data frames client->server; the server's periodic ACK must
	// come back and lift the client's peerBase view.
	recvDone := make(chan int, 1)
	go func() {
		n := 0
		for n < ackEvery {
			pkt, err := st.ReceivePacket()
			if err != nil {
				recvDone <- -1
				return
			}
			if len(pkt) == 9 && (pkt[0] == ControlAck || pkt[0] == ControlSkip) {
				continue // control frames pass through ReceivePacket too
			}
			n++
		}
		recvDone <- n
	}()
	for i := 0; i < ackEvery; i++ {
		if err := ct.SendPacket([]byte{0x45, byte(i % 250)}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case n := <-recvDone:
		if n != ackEvery {
			t.Fatalf("server received %d data frames, want %d", n, ackEvery)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the data burst")
	}

	// The ACK of our receive position was sent after the 32nd decode; the
	// client should observe it on its next receive cycle. Poll briefly.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ct.ack.peerBase > 0 {
			return
		}
		buf := make([]byte, maxDatagram)
		_ = ct.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := ct.conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		ct.sessMu.Lock()
		msg, err := ct.sess.Decode(buf[:n])
		if err != nil {
			ct.sessMu.Unlock()
			continue
		}
		ct.handleLossControl(append([]byte(nil), msg.Payload...))
		ct.sessMu.Unlock()
	}
	t.Fatal("client never observed the server ACK")
}

func TestBinaryBigEndianAckLayout(t *testing.T) {
	// Wire compatibility guard: ACK payloads must stay 1+8 bytes BE.
	p := encodeAckPayload(0xDEADBEEF)
	want := []byte{ControlAck, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF}
	if len(p) != 9 || p[0] != want[0] || binary.BigEndian.Uint64(p[1:]) != 0xDEADBEEF {
		t.Fatalf("ack wire layout drifted: %v", p)
	}
	_ = fmt.Sprintf("%x", want)
}
