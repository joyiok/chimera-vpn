package compiler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const (
	knockNonceLen = 32
	knockMACLen   = 16
	// KnockInnerLen is the unwrapped server-first knock: 32-byte nonce +
	// 16-byte truncated HMAC-SHA256 under the PSK. Wu et al. / Alice IMC
	// 2020: the server must not speak a real first frame to an unauthenticated
	// probe; obfs4 proves the shared secret before answering.
	KnockInnerLen = knockNonceLen + knockMACLen
)

var knockInfo = []byte("chimera-pgc/0/knock")

// EncodeKnock builds an authenticated server-first knock. The datagram
// layer still wraps this with WrapHandshakeDatagram so the first bytes on
// the wire are printable ASCII (FEP Ex2/Ex4).
func EncodeKnock(psk []byte) ([]byte, error) {
	return encodeKnock(psk, rand.Reader)
}

func encodeKnock(psk []byte, rnd io.Reader) ([]byte, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("empty pre-shared key")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	out := make([]byte, KnockInnerLen)
	if _, err := io.ReadFull(rnd, out[:knockNonceLen]); err != nil {
		return nil, err
	}
	copy(out[knockNonceLen:], knockMAC(psk, out[:knockNonceLen]))
	return out, nil
}

// VerifyKnock reports whether inner is a well-formed knock under psk.
func VerifyKnock(psk, inner []byte) bool {
	if len(psk) == 0 || len(inner) < KnockInnerLen {
		return false
	}
	want := knockMAC(psk, inner[:knockNonceLen])
	return hmac.Equal(inner[knockNonceLen:KnockInnerLen], want)
}

// KnockReplayKey is the prefix stored in the handshake replay table.
func KnockReplayKey(inner []byte) []byte {
	if len(inner) < KnockInnerLen {
		return inner
	}
	return inner[:KnockInnerLen]
}

func knockMAC(psk, nonce []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write(knockInfo)
	_, _ = mac.Write(nonce)
	sum := mac.Sum(nil)
	return sum[:knockMACLen]
}

// EncodeKnock builds a knock under this handshake's PSK.
func (h *Handshake) EncodeKnock() ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("nil handshake")
	}
	return EncodeKnock(h.psk)
}

// VerifyKnock checks a knock under this handshake's PSK.
func (h *Handshake) VerifyKnock(inner []byte) bool {
	if h == nil {
		return false
	}
	return VerifyKnock(h.psk, inner)
}
