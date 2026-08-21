package main

// Red-team gate: every generated protocol species' first wire datagram
// must classify as exempt under the gfw.report / Wu 2023 FEP heuristics.
// A genome, cover, or shaping change that degrades cover effectiveness
// fails CI here instead of in the field.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

func TestRedTeamGeneratedFirstDatagramsPassFEP(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	checked := 0
	for i := 0; i < 60; i++ {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		g, err := genome.GenerateWithCipher(seed, uint64(i%4), "")
		if err != nil {
			t.Fatal(err)
		}
		cp, err := compiler.Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}
		h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := h.CurrentSpec()
		if err != nil {
			t.Fatal(err)
		}
		if spec.Direction != genome.DirClient {
			// Server-first species: the client's first datagram is a
			// PSK-MAC knock, which is deliberately high entropy. FEP
			// exemption does not apply to knocks.
			continue
		}
		frame, _, err := h.EncodeStep()
		if err != nil {
			t.Fatal(err)
		}
		wire := h.WrapDatagram(frame)
		exempt, rule := compiler.FEPExemption(wire)
		if !exempt {
			t.Fatalf("species fingerprint %.8s (generation %d): first datagram flagged by FEP heuristics (rule=%s) — cover regression",
				g.ProtocolFingerprint, i%4, rule)
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("only %d client-first species sampled; expected broader coverage", checked)
	}
}
