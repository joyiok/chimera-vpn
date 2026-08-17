package compiler

import (
	"testing"
)

func TestFEPExemptionRandomHighEntropy(t *testing.T) {
	// 0x0f is 4 set bits and not printable, so Ex1 stays near 4 bits/byte
	// and Ex2–Ex4 cannot fire. This is the payload class Wu et al. inferred
	// the GFW blocks as fully encrypted.
	pkt := make([]byte, 256)
	for i := range pkt {
		pkt[i] = 0x0f
	}
	exempt, rule := FEPExemption(pkt)
	if exempt {
		t.Fatalf("uniform 0x0f payload should be blocked, got rule %s", rule)
	}
}

func TestFEPExemptionEx2Prefix(t *testing.T) {
	pkt := make([]byte, 200)
	for i := range pkt {
		pkt[i] = 0x0f
	}
	copy(pkt[:6], []byte("ABCDEF"))
	exempt, rule := FEPExemption(pkt)
	if !exempt || rule != "ex2" {
		t.Fatalf("printable prefix: exempt=%v rule=%s", exempt, rule)
	}
}

func TestFEPExemptionEx4Contiguous(t *testing.T) {
	pkt := make([]byte, 80)
	for i := range pkt {
		pkt[i] = 0x0f
	}
	for i := 6; i < 27; i++ {
		pkt[i] = 'A'
	}
	exempt, rule := FEPExemption(pkt)
	if !exempt || rule != "ex4" {
		t.Fatalf("21 contiguous printable: exempt=%v rule=%s", exempt, rule)
	}
}

func TestFEPExemptionEx5TLSAndHTTP(t *testing.T) {
	tls := make([]byte, 64)
	for i := range tls {
		tls[i] = 0x0f
	}
	tls[0], tls[1], tls[2] = 0x16, 0x03, 0x01
	exempt, rule := FEPExemption(tls)
	if !exempt || rule != "ex5" {
		t.Fatalf("TLS fingerprint: exempt=%v rule=%s", exempt, rule)
	}
	// HTTP methods are printable, so Ex2 fires first in our evaluation
	// order; the packet is still exempt (the GFW does not specify order).
	http := []byte("GET /index HTTP/1.1\r\n")
	exempt, rule = FEPExemption(http)
	if !exempt {
		t.Fatalf("HTTP fingerprint blocked, rule=%s", rule)
	}
}
