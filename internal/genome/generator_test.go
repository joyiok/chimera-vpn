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

// TestHandshakeHasCleartextLengthField: UPGen (Wails et al., USENIX
// Security 2025) always places a length field in the clear so generated
// protocols look like structured encrypted designs, not fully-encrypted
// protocols that GFW-style classifiers already block.
func TestHandshakeHasCleartextLengthField(t *testing.T) {
	for i := 0; i < 80; i++ {
		g, err := Generate(seedFor(3000+i), 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range g.Handshake {
			if m.LengthFieldIndex < 0 {
				t.Fatalf("seed %d pattern %s message %s has no plaintext length field", i, g.HandshakePattern, m.Name)
			}
			if m.LengthFieldIndex >= len(m.PlainFields) {
				t.Fatalf("length field index %d out of range on %s", m.LengthFieldIndex, m.Name)
			}
			if m.PlainFields[m.LengthFieldIndex].Kind != FieldLength {
				t.Fatalf("length index does not point at a length field")
			}
		}
	}
}

func TestDefaultCipherStaysAESFamily(t *testing.T) {
	// ChaCha is GenerateWithCipher only: adding it to the lottery would
	// re-key every existing (seed, generation) deployment.
	for i := 0; i < 60; i++ {
		g, err := Generate(seedFor(4000+i), 0)
		if err != nil {
			t.Fatal(err)
		}
		switch g.AppRecord.Cipher {
		case CipherAES128GCM, CipherAES192GCM, CipherAES256GCM:
		default:
			t.Fatalf("default cipher %s; want AES-GCM family", g.AppRecord.Cipher)
		}
	}
}

func TestMaxIntValueU32FitsInt64(t *testing.T) {
	// EncU32's max must not be typed as 32-bit int: gomobile android/armeabi-v7a
	// rejects `1<<32 - 1` as int (overflows).
	if got, want := maxIntValue(EncU32), int64(1<<32-1); got != want {
		t.Fatalf("maxIntValue(EncU32)=%d want %d", got, want)
	}
	if maxIntValue(EncU8) < 16 {
		t.Fatal("u8 max too small for a 16-byte handshake field")
	}
}
