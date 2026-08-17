package compiler

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"chimera/internal/genome"
)

const (
	// CoverLenMin/Max bound the per-species printable prefix prepended to
	// datagram-mode handshake frames. 24..32 is long enough for Wu et al.
	// USENIX Security 2023 Ex2 (first 6 printable) and Ex4 (>20 contiguous
	// printable) without being a global magic length.
	CoverLenMin = 24
	CoverLenMax = 32

	// HandshakeMinWire / HandshakeMaxWire bound optional printable tail
	// padding. Alice et al., IMC 2020: the GFW's Shadowsocks replay trigger
	// concentrated on first payloads of 160–700 bytes. Handshake datagrams
	// that land in that band are padded up to a species-derived size in
	// [HandshakeMinWire, HandshakeMaxWire].
	HandshakeMinWire = 701
	HandshakeMaxWire = 1200
)

// CoverLen is the printable prefix length for one protocol species. It is
// derived from ProtocolFingerprint so every (seed, generation) pair has its
// own length; the genome generator lottery is not consumed.
func CoverLen(g *genome.ProtocolGenome) int {
	if g == nil {
		return CoverLenMin
	}
	sum := sha256.Sum256([]byte("chimera-pgc/0/cover-len\x00" + g.ProtocolFingerprint))
	span := CoverLenMax - CoverLenMin + 1
	return CoverLenMin + int(sum[0])%span
}

// WrapHandshakeDatagram prepends a fresh random printable ASCII cover of
// CoverLen(g) bytes. Retransmissions wrap again so the on-wire prefix is not
// a static per-server magic. The inner frame (AEAD transcript) is unchanged.
func WrapHandshakeDatagram(g *genome.ProtocolGenome, frame []byte) []byte {
	n := CoverLen(g)
	cover := randomPrintable(n, rand.Reader)
	out := make([]byte, 0, n+len(frame)+64)
	out = append(out, cover...)
	out = append(out, frame...)
	return padHandshakeWire(g, out)
}

// UnwrapHandshakeDatagram strips the species cover. The prefix itself is not
// authenticated; authentication is the inner AEAD. A truncated datagram is
// rejected so RecvStep never sees a short slice that could be confused with
// a well-formed frame.
func UnwrapHandshakeDatagram(g *genome.ProtocolGenome, wire []byte) ([]byte, error) {
	n := CoverLen(g)
	if len(wire) < n {
		return nil, fmt.Errorf("handshake datagram %d shorter than cover %d", len(wire), n)
	}
	return wire[n:], nil
}

// WrapDatagram is Handshake.WrapHandshakeDatagram using this endpoint's genome.
func (h *Handshake) WrapDatagram(frame []byte) []byte {
	if h == nil || h.cp == nil {
		return append([]byte(nil), frame...)
	}
	return WrapHandshakeDatagram(h.cp.Genome, frame)
}

// UnwrapDatagram strips this endpoint's species cover.
func (h *Handshake) UnwrapDatagram(wire []byte) ([]byte, error) {
	if h == nil || h.cp == nil {
		return nil, errors.New("nil handshake")
	}
	return UnwrapHandshakeDatagram(h.cp.Genome, wire)
}

func handshakePadTarget(g *genome.ProtocolGenome) int {
	label := "chimera-pgc/0/hs-pad\x00"
	if g != nil {
		label += g.ProtocolFingerprint
	}
	sum := sha256.Sum256([]byte(label))
	span := HandshakeMaxWire - HandshakeMinWire + 1
	return HandshakeMinWire + int(sum[0])%span
}

func padHandshakeWire(g *genome.ProtocolGenome, wire []byte) []byte {
	if len(wire) < 160 || len(wire) > 700 {
		return wire
	}
	target := handshakePadTarget(g)
	if target < HandshakeMinWire {
		target = HandshakeMinWire
	}
	if target > HandshakeMaxWire {
		target = HandshakeMaxWire
	}
	if target <= len(wire) {
		target = HandshakeMinWire
	}
	if target <= len(wire) {
		return wire
	}
	return append(wire, randomPrintable(target-len(wire), rand.Reader)...)
}

func randomPrintable(n int, rnd io.Reader) []byte {
	if n <= 0 {
		return nil
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	buf := make([]byte, n)
	scratch := make([]byte, n)
	for tries := 0; tries < 32; tries++ {
		if _, err := io.ReadFull(rnd, scratch); err != nil {
			// Extremely unlikely; fall back to a non-HTTP constant so the
			// packet still hits Ex2/Ex4 rather than failing the send.
			for i := 0; i < n; i++ {
				buf[i] = 0x41 + byte(i%26)
			}
			return buf
		}
		for i := 0; i < n; i++ {
			buf[i] = 0x20 + scratch[i]%95
		}
		if !looksLikeHTTP(buf) && !looksLikeTLS(buf) {
			return buf
		}
	}
	for i := 0; i < n; i++ {
		buf[i] = 0x61 + byte(i%26) // 'a'.. repeating
	}
	return buf
}
