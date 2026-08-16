// Package drbg implements the deterministic randomness source used by the
// protocol genome compiler.
//
// It is an HMAC-DRBG (NIST SP 800-90A) built on HMAC-SHA256. Every choice in
// a generated protocol must be reproducible from (seed, generation), so the
// compiler never consults crypto/rand. Runtime frame fields (nonces, padding,
// certificate blobs) use crypto/rand instead; only the *design* is derived.
package drbg

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// Rand is a deterministic byte source with child-stream derivation.
type Rand struct {
	k [32]byte
	v [32]byte
	// buf holds unused bytes from the previous block generation.
	buf []byte
}

const blockLen = 32

func newHMAC(key []byte) hash.Hash {
	h := hmac.New(sha256.New, key)
	return h
}

// New creates an HMAC-DRBG instance from arbitrary seed material.
func New(seed []byte, label string) *Rand {
	r := &Rand{}
	// Instantiate: K = 0x00^32, V = 0x01^32.
	for i := range r.v {
		r.v[i] = 0x01
	}
	// update(seed_material) with domain separation label.
	r.update(append([]byte(label+"\x00"), seed...))
	return r
}

func (r *Rand) update(provided []byte) {
	h := newHMAC(r.k[:])
	h.Write(r.v[:])
	h.Write([]byte{0x00})
	h.Write(provided)
	copy(r.k[:], h.Sum(nil))

	h = newHMAC(r.k[:])
	h.Write(r.v[:])
	copy(r.v[:], h.Sum(nil))
}

// block generates and buffers one 32-byte block.
func (r *Rand) block() {
	h := newHMAC(r.k[:])
	h.Write(r.v[:])
	copy(r.v[:], h.Sum(nil))
	out := make([]byte, blockLen)
	copy(out, r.v[:])
	r.update(nil)
	r.buf = append(r.buf, out...)
}

// Read fills p with deterministic bytes.
func (r *Rand) Read(p []byte) (int, error) {
	for len(r.buf) < len(p) {
		r.block()
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Uint64 returns a uniformly distributed 64-bit value.
func (r *Rand) Uint64() uint64 {
	var b [8]byte
	if _, err := r.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(b[:])
}

// Intn returns a uniform value in [0,n). n must be positive.
//
// It deliberately uses masked rejection sampling: a little slower than
// Lemire-style multiplication, but trivially and visibly unbiased. Speed is
// irrelevant here because the generator makes only a few hundred choices.
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		panic("drbg: Intn with non-positive bound")
	}
	mask := uint64(1)
	for mask < uint64(n)-1 {
		mask = mask<<1 | 1
	}
	for {
		x := r.Uint64() & mask
		if x < uint64(n) {
			return int(x)
		}
	}
}

// Perm returns a random permutation of [0,n).
func (r *Rand) Perm(n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// PickWeighted selects an index according to the supplied weights.
func (r *Rand) PickWeighted(weights []int) int {
	total := 0
	for _, w := range weights {
		total += w
	}
	x := r.Intn(total)
	for i, w := range weights {
		if x < w {
			return i
		}
		x -= w
	}
	panic("drbg: unreachable")
}

// Bytes returns n deterministic bytes.
func (r *Rand) Bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := r.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Child derives an independent stream, e.g. one per generation.
func (r *Rand) Child(label string) *Rand {
	seed := r.Bytes(blockLen)
	return New(seed, label)
}
