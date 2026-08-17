package tunnel

import (
	"testing"
	"time"
)

// TestIdleForIgnoresOwnSends: client keepalives and data must not look like
// inbound liveness. Otherwise a dead server never trips the watchdog.
func TestIdleForIgnoresOwnSends(t *testing.T) {
	cp, psk := compileFor(t, 8200)
	ct, st, mux, teardown := handshakePair(t, cp, psk)
	defer teardown()
	_, _ = st, mux

	ct.SetKeepalive(80 * time.Millisecond)
	defer ct.SetKeepalive(-1)

	if err := ct.SendPacket([]byte{0x45, 0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)
	idle := ct.IdleFor()
	if idle < 250*time.Millisecond {
		t.Fatalf("own sends reset IdleFor: %s", idle)
	}
}

// TestIdleForResetsOnPeerFrame: an authenticated inbound frame (here a
// server data packet the client actually reads) must clear inbound idle.
func TestIdleForResetsOnPeerFrame(t *testing.T) {
	cp, psk := compileFor(t, 8201)
	ct, st, mux, teardown := handshakePair(t, cp, psk)
	defer teardown()
	_ = mux

	time.Sleep(200 * time.Millisecond)
	if ct.IdleFor() < 150*time.Millisecond {
		t.Fatalf("pre-inbound idle too small: %s", ct.IdleFor())
	}

	recv := make(chan error, 1)
	go func() {
		_, err := ct.ReceivePacket()
		recv <- err
	}()
	if err := st.SendPacket([]byte{0x45, 9, 9, 9}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-recv:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive server packet")
	}
	if ct.IdleFor() > 150*time.Millisecond {
		t.Fatalf("inbound frame did not reset IdleFor: %s", ct.IdleFor())
	}
}
