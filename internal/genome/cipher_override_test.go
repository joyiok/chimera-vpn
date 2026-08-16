package genome

import "testing"

func TestGenerateWithCipherOverride(t *testing.T) {
	seed := []byte("cipher-override-seed-0")

	base, err := Generate(seed, 0)
	if err != nil {
		t.Fatal(err)
	}

	cha, err := GenerateWithCipher(seed, 0, CipherChaCha20P1305)
	if err != nil {
		t.Fatal(err)
	}

	// Forced cipher applies everywhere.
	if cha.AppRecord.Cipher != CipherChaCha20P1305 {
		t.Fatalf("app record cipher = %s", cha.AppRecord.Cipher)
	}
	for i, m := range cha.Handshake {
		if m.Cipher != CipherChaCha20P1305 {
			t.Fatalf("handshake %d cipher = %s", i, m.Cipher)
		}
	}

	// Everything except the cipher itself (and the fingerprint over it) is
	// identical: the cipher draw is consumed either way.
	if cha.HandshakePattern != base.HandshakePattern {
		t.Error("override changed the handshake pattern")
	}
	if len(cha.Handshake) != len(base.Handshake) {
		t.Fatal("override changed the message count")
	}
	for i := range cha.Handshake {
		a, b := cha.Handshake[i], base.Handshake[i]
		if a.Name != b.Name || a.Direction != b.Direction ||
			len(a.PlainFields) != len(b.PlainFields) || len(a.EncryptedFields) != len(b.EncryptedFields) ||
			a.LengthFieldIndex != b.LengthFieldIndex || a.Padding != b.Padding {
			t.Errorf("override changed handshake message %d layout", i)
		}
	}

	// Unknown cipher is rejected; empty falls back to the drawn default.
	if _, err := GenerateWithCipher(seed, 0, "rc4"); err == nil {
		t.Error("unknown cipher must be rejected")
	}
	fb, err := GenerateWithCipher(seed, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if fb.ProtocolFingerprint != base.ProtocolFingerprint {
		t.Error("empty override must be identical to Generate")
	}
}
