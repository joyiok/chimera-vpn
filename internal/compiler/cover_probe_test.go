package compiler

// Tests for the opt-in probe mark: a deployment-identifying tag written
// over the head of handshake covers. Safety invariants under test:
// default deployments are unchanged; marks stay inside the printable
// prefix; handshakes and FEP exemption keep working with a mark set.

import (
	"bytes"
	"testing"

	"chimera/internal/genome"
)

func probeSeed(i int) []byte {
	b := make([]byte, 32)
	for j := range b {
		b[j] = byte(i + j)
	}
	return b
}

func probePSK(i int) []byte {
	b := make([]byte, 32)
	for j := range b {
		b[j] = byte(0x80 + i + j)
	}
	return b
}

func TestProbeMarkEmbedsTagInCover(t *testing.T) {
	g, err := genome.Generate(probeSeed(9001), 0)
	if err != nil {
		t.Fatal(err)
	}
	const mark = "PROBE-TAG-01"
	if err := SetProbeMark(mark); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetProbeMark("") })

	wire := WrapHandshakeDatagram(g, []byte("inner-frame"))
	if !bytes.HasPrefix(wire, []byte(mark)) {
		t.Fatalf("wire does not start with mark: %q", wire[:20])
	}
	// The rest of the cover stays printable and the inner frame is intact.
	if !bytes.HasSuffix(wire, []byte("inner-frame")) {
		t.Fatal("inner frame corrupted by mark")
	}
	// Repeated wraps re-apply the mark (retransmissions included).
	for i := 0; i < 5; i++ {
		w := WrapHandshakeDatagram(g, []byte("x"))
		if !bytes.HasPrefix(w, []byte(mark)) {
			t.Fatalf("retransmission %d lost the mark", i)
		}
	}
}

func TestProbeMarkHandshakeStillWorks(t *testing.T) {
	g, err := genome.Generate(probeSeed(9002), 0)
	if err != nil {
		t.Fatal(err)
	}
	psk := probePSK(9002)
	cp, err := Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetProbeMark("MARK-MARK"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetProbeMark("") })

	// Client-first: the client's wrapped first datagram carries the mark,
	// yet the server-side handshake must still accept it.
	ch, err := NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := ch.EncodeStep()
	if err != nil {
		t.Fatal(err)
	}
	wire := ch.WrapDatagram(frame)
	if !bytes.HasPrefix(wire, []byte("MARK-MARK")) {
		t.Fatalf("mark missing from client wire: %q", wire[:16])
	}

	sh, err := NewHandshake(cp, genome.DirServer, psk)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := sh.UnwrapDatagram(wire)
	if err != nil {
		t.Fatalf("unwrap with mark set: %v", err)
	}
	spec, err := sh.CurrentSpec()
	if err != nil {
		t.Fatal(err)
	}
	trimmed, err := DeclaredFrame(spec, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.RecvStep(trimmed); err != nil {
		t.Fatalf("server rejected marked client first datagram: %v", err)
	}
}

func TestProbeMarkKeepsFEPExemption(t *testing.T) {
	g, err := genome.Generate(probeSeed(9003), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetProbeMark("MEASURE-7"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetProbeMark("") })

	for i := 0; i < 8; i++ {
		wire := WrapHandshakeDatagram(g, []byte("payload"))
		if exempt, rule := FEPExemption(wire); !exempt {
			t.Fatalf("marked cover lost FEP exemption (rule=%s) on wrap %d", rule, i)
		}
	}
}

func TestProbeMarkValidationAndReset(t *testing.T) {
	for _, bad := range []string{"has space", "tab\t", longerThan(17)} {
		if err := SetProbeMark(bad); err == nil {
			t.Fatalf("mark %q accepted", bad)
		}
	}
	// An explicitly empty mark is the documented reset (and the default).
	if err := SetProbeMark(""); err != nil {
		t.Fatal(err)
	}
	g, err := genome.Generate(probeSeed(9004), 0)
	if err != nil {
		t.Fatal(err)
	}
	wire := WrapHandshakeDatagram(g, []byte("x"))
	if bytes.HasPrefix(wire, []byte("MARK")) {
		t.Fatal("mark survived reset")
	}
}

func longerThan(n int) string {
	b := make([]byte, n+1)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
