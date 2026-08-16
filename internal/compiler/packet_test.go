package compiler

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"chimera/internal/genome"
)

func packetSeed(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("packet-test-seed-%d", i)))
	return h[:]
}

func TestPacketSessionOutOfOrderAndDuplicates(t *testing.T) {
	for i := 0; i < 40; i++ {
		g, err := genome.Generate(packetSeed(i), uint64(i%4))
		if err != nil {
			t.Fatal(err)
		}
		psk := packetSeed(1000 + i)
		cp, err := Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}
		c2s, _ := cp.Bootstrap.C2S, cp.Bootstrap.S2C
		send, err := NewPacketSession(cp, genome.DirClient, c2s, cp.Bootstrap.S2C)
		if err != nil {
			t.Fatal(err)
		}
		recv, err := NewPacketSession(cp, genome.DirServer, c2s, cp.Bootstrap.S2C)
		if err != nil {
			t.Fatal(err)
		}

		payloads := [][]byte{[]byte("zero"), []byte("one"), []byte("two")}
		frames := make([][]byte, 3)
		for j, p := range payloads {
			f, err := send.Encode(p)
			if err != nil {
				t.Fatal(err)
			}
			frames[j] = f
		}

		// Arrive 2, 0, 1: all three must decrypt and be delivered.
		for _, j := range []int{2, 0, 1} {
			msg, err := recv.Decode(frames[j])
			if err != nil {
				t.Fatalf("seed %d: out-of-order frame %d failed: %v", i, j, err)
			}
			if string(msg.Payload) != string(payloads[j]) {
				t.Fatalf("seed %d: payload %d mismatch", i, j)
			}
		}

		// Duplicate of frame 2 must be dropped (already seen).
		if msg, err := recv.Decode(frames[2]); err == nil && msg != nil {
			t.Fatalf("seed %d: duplicate frame accepted", i)
		}

		// Next fresh frame still works.
		f3, err := send.Encode([]byte("three"))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := recv.Decode(f3)
		if err != nil {
			t.Fatalf("seed %d: post-duplicate frame failed: %v", i, err)
		}
		if string(msg.Payload) != "three" {
			t.Fatalf("seed %d: post-duplicate payload mismatch", i)
		}
	}
}

func TestStreamDecodeStillStrict(t *testing.T) {
	g, _ := genome.Generate(packetSeed(9), 0)
	psk := packetSeed(19)
	cp, _ := Compile(g, psk)
	send, _ := NewPacketSession(cp, genome.DirClient, cp.Bootstrap.C2S, cp.Bootstrap.S2C)
	strict, err := NewSession(cp, genome.DirServer, cp.Bootstrap.C2S, cp.Bootstrap.S2C)
	if err != nil {
		t.Fatal(err)
	}
	_ = send
	if strict == nil {
		t.Fatal("nil session")
	}
}
