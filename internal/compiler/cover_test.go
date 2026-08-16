package compiler

import (
	"bytes"
	"crypto/rand"
	"testing"

	"chimera/internal/genome"
)

func TestCoverLenStableAndInRange(t *testing.T) {
	seen := map[int]int{}
	for i := 0; i < 80; i++ {
		g, err := genome.Generate(testSeed(9000+i), uint64(i%4))
		if err != nil {
			t.Fatal(err)
		}
		n := CoverLen(g)
		if n < CoverLenMin || n > CoverLenMax {
			t.Fatalf("cover len %d out of [%d,%d]", n, CoverLenMin, CoverLenMax)
		}
		g2, err := genome.Generate(testSeed(9000+i), uint64(i%4))
		if err != nil {
			t.Fatal(err)
		}
		if CoverLen(g2) != n {
			t.Fatal("cover length not stable for the same genome")
		}
		seen[n]++
	}
	if len(seen) < 3 {
		t.Fatalf("cover lengths not diverse enough: %v", seen)
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	g, err := genome.Generate(testSeed(42), 0)
	if err != nil {
		t.Fatal(err)
	}
	inner := []byte("inner-handshake-frame")
	wire := WrapHandshakeDatagram(g, inner)
	if bytes.Equal(wire, inner) {
		t.Fatal("wrap did not change the datagram")
	}
	got, err := UnwrapHandshakeDatagram(g, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("unwrap mismatch: %q", got)
	}
	if _, err := UnwrapHandshakeDatagram(g, wire[:CoverLen(g)-1]); err == nil {
		t.Fatal("short datagram accepted")
	}
}

func TestWrappedDatagramExemptFromFEP(t *testing.T) {
	g, err := genome.Generate(testSeed(7), 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		inner := make([]byte, 180)
		if _, err := rand.Read(inner); err != nil {
			t.Fatal(err)
		}
		copy(inner[:6], []byte{0, 1, 2, 3, 4, 5})
		wire := WrapHandshakeDatagram(g, inner)
		exempt, rule := FEPExemption(wire)
		if !exempt {
			t.Fatalf("wrapped datagram not exempt (rule empty)")
		}
		if rule != "ex2" && rule != "ex4" {
			t.Fatalf("wrapped datagram exempt via %s, want ex2 or ex4", rule)
		}
		if looksLikeHTTP(wire) || looksLikeTLS(wire) {
			t.Fatalf("cover collided with TLS/HTTP fingerprint: %q", wire[:8])
		}
		for _, b := range wire[:CoverLen(g)] {
			if !printableASCII(b) {
				t.Fatalf("cover byte 0x%02x not printable", b)
			}
		}
	}
}

func TestCoverIsNotGlobalMagic(t *testing.T) {
	// Two species must not share a cover length AND produce identical
	// prefixes; prefixes are random, so we only require length diversity
	// across many seeds plus distinct unwrapped inner frames.
	lengths := map[int]int{}
	for i := 0; i < 60; i++ {
		g, err := genome.Generate(testSeed(11000+i), 0)
		if err != nil {
			t.Fatal(err)
		}
		lengths[CoverLen(g)]++
	}
	if len(lengths) < 4 {
		t.Fatalf("cover lengths too concentrated: %v", lengths)
	}
}
