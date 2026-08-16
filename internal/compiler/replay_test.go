package compiler

import (
	"testing"

	"chimera/internal/genome"
)

// streamPair builds two strict stream codecs sharing a key.
func streamPair(t *testing.T) (send, recv *MessageCodec) {
	t.Helper()
	g, err := genome.Generate(packetSeed(88), 0)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := Compile(g, packetSeed(188))
	if err != nil {
		t.Fatal(err)
	}
	spec := cp.Handshake[0]
	send, err = NewMessageCodec(spec, cp.Bootstrap.C2S)
	if err != nil {
		t.Fatal(err)
	}
	recv, err = NewMessageCodec(spec, cp.Bootstrap.C2S)
	if err != nil {
		t.Fatal(err)
	}
	return send, recv
}

func TestStreamDecodeRejectsReplay(t *testing.T) {
	send, recv := streamPair(t)

	f0, _, err := send.Encode(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f1, _, err := send.Encode(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := recv.Decode(f0); err != nil {
		t.Fatalf("in-order frame 0: %v", err)
	}
	// Immediate replay of the just-accepted frame must be rejected.
	if _, err := recv.Decode(f0); err == nil {
		t.Fatal("replay of frame 0 accepted")
	}
	// Reordering within the 64 window works.
	if _, err := recv.Decode(f1); err != nil {
		t.Fatalf("frame 1 after replay attempt: %v", err)
	}
	// And a replay of frame 1 is still rejected.
	if _, err := recv.Decode(f1); err == nil {
		t.Fatal("replay of frame 1 accepted")
	}
}

func TestStreamDecodeRejectsOldReplay(t *testing.T) {
	send, recv := streamPair(t)

	var frames [][]byte
	for i := 0; i < 70; i++ {
		f, _, err := send.Encode(nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	// Deliver 0..63 in order; the window advances past them.
	for i := 0; i < 64; i++ {
		if _, err := recv.Decode(frames[i]); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	// A recorded frame from far before the window must not authenticate.
	if _, err := recv.Decode(frames[0]); err == nil {
		t.Fatal("ancient replay accepted")
	}
	if _, err := recv.Decode(frames[69]); err != nil {
		t.Fatalf("fresh frame after ancient replay: %v", err)
	}
}

func TestSeenWindowUnit(t *testing.T) {
	var w seenWindow
	if !w.observe(0) {
		t.Fatal("seq 0 must be fresh")
	}
	if w.observe(0) {
		t.Fatal("seq 0 duplicate must be rejected")
	}
	// Jump far ahead: window advances, everything skipped is dead.
	if !w.observe(100) {
		t.Fatal("seq 100 must be fresh")
	}
	if w.observe(50) {
		t.Fatal("seq 50 fell inside the skipped run; must be dead")
	}
	if !w.observe(101) {
		t.Fatal("seq 101 must be fresh")
	}
}
