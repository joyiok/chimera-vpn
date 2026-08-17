package tunnel

import "testing"

func TestBytesCountIPPayloads(t *testing.T) {
	cp, psk := compileFor(t, 8210)
	ct, st, mux, teardown := handshakePair(t, cp, psk)
	defer teardown()
	_ = mux

	payload := []byte{0x45, 0, 1, 2, 3, 4, 5, 6}
	done := make(chan []byte, 1)
	go func() {
		pkt, err := st.ReceivePacket()
		if err != nil {
			t.Error(err)
			close(done)
			return
		}
		done <- pkt
	}()
	if err := ct.SendPacket(payload); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	sent, _ := ct.Bytes()
	if sent != uint64(len(payload)) {
		t.Fatalf("client sent=%d want %d", sent, len(payload))
	}
}
