package compiler

import (
	"testing"

	"chimera/internal/genome"
)

// compileChaCha builds a compiled protocol with the ChaCha override.
func compileChaCha(t *testing.T) *CompiledProtocol {
	t.Helper()
	seed := packetSeed(77)
	g, err := genome.GenerateWithCipher(seed, 0, genome.CipherChaCha20P1305)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := Compile(g, packetSeed(177))
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestChaChaPacketSessionRoundTrip(t *testing.T) {
	cp := compileChaCha(t)
	client, err := NewPacketSession(cp, genome.DirClient, cp.Bootstrap.C2S, cp.Bootstrap.S2C)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPacketSession(cp, genome.DirServer, cp.Bootstrap.C2S, cp.Bootstrap.S2C)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 8; i++ {
		payload := []byte{0x45, byte(i), byte(len(payloadMarker(i)))}
		frame, err := client.Encode(append(payload, payloadMarker(i)...))
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		msg, err := server.Decode(frame)
		if err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if msg.Payload[0] != payload[0] {
			t.Fatalf("payload %d mismatch", i)
		}
	}

	// Out of order + duplicate still behave identically under ChaCha.
	f1, _ := client.Encode([]byte("x1"))
	f2, _ := client.Encode([]byte("x2"))
	if _, err := server.Decode(f2); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Decode(f1); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Decode(f2); err == nil {
		t.Fatal("duplicate accepted under ChaCha")
	}
}

func payloadMarker(i int) string {
	return "payload-" + string(rune('a'+i))
}
