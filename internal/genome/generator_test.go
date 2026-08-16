package genome

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func seedFor(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("chimera-test-seed-%d", i)))
	return h[:]
}

func TestSameSeedSameGenome(t *testing.T) {
	a, err := Generate(seedFor(1), 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(seedFor(1), 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.ProtocolFingerprint != b.ProtocolFingerprint {
		t.Fatalf("same seed produced different fingerprints:\n%x\n%x", a.ProtocolFingerprint, b.ProtocolFingerprint)
	}
}

func TestMutationChangesDesign(t *testing.T) {
	a, _ := Generate(seedFor(2), 0)
	b, _ := Generate(seedFor(2), 1)
	c, _ := Generate(seedFor(3), 0)
	if a.ProtocolFingerprint == b.ProtocolFingerprint {
		t.Fatal("generation change did not mutate the protocol")
	}
	if a.ProtocolFingerprint == c.ProtocolFingerprint {
		t.Fatal("different seeds collided")
	}
}

func TestEntropyIsReported(t *testing.T) {
	g, err := Generate(seedFor(4), 0)
	if err != nil {
		t.Fatal(err)
	}
	if g.EstimatedEntropyBits < 60 {
		t.Fatalf("suspiciously low entropy estimate: %f bits", g.EstimatedEntropyBits)
	}
}

func TestPatternDiversity(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 400; i++ {
		g, err := Generate(seedFor(1000+i), uint64(i%3))
		if err != nil {
			t.Fatal(err)
		}
		seen[g.HandshakePattern]++
	}
	if len(seen) < 6 {
		t.Fatalf("expected all 6 handshake patterns over 400 samples, saw %d: %v", len(seen), seen)
	}
}

func TestHandshakeCoversBothKeys(t *testing.T) {
	for i := 0; i < 200; i++ {
		g, err := Generate(seedFor(2000+i), 0)
		if err != nil {
			t.Fatal(err)
		}
		clientKey, serverKey := false, false
		for _, m := range g.Handshake {
			for _, f := range m.EncryptedFields {
				if f.Kind == FieldKey {
					if m.Direction == DirClient {
						clientKey = true
					} else {
						serverKey = true
					}
				}
			}
		}
		if !clientKey || !serverKey {
			t.Fatalf("seed %d pattern %s does not exchange both ephemeral keys", i, g.HandshakePattern)
		}
	}
}
