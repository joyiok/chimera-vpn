package tunnel

import (
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// TxMask wraps a PacketConn and may emit additional traffic while writing.
// Masks are send-side only: the peer's decoder already drops frames that do
// not authenticate, so no shared state or handshake extension is required.
type TxMask func(net.PacketConn) net.PacketConn

type noiseMaskConn struct {
	net.PacketConn
	every     uint64
	maxPerSec int
	ladder    []int

	written atomic.Uint64
	mu      sync.Mutex
	last    time.Time
}

// NewNoiseTxMask returns a mask that, on average, emits one high-entropy
// decoy frame every `every` real writes, capped at maxPerSec decoys per
// second. Decoy lengths are drawn from ladder (typically the species shape
// ladder) and payloads are crypto-random, so an observer cannot separate
// them from encrypted records by entropy or size.
//
// every <= 0 or maxPerSec <= 0 returns an identity mask (decoy disabled).
func NewNoiseTxMask(every, maxPerSec int, ladder []int) TxMask {
	if every <= 0 || maxPerSec <= 0 {
		return func(conn net.PacketConn) net.PacketConn { return conn }
	}
	lengths := append([]int(nil), ladder...)
	if len(lengths) == 0 {
		lengths = []int{96, 192, 384, 768, 1152}
	}
	return func(conn net.PacketConn) net.PacketConn {
		return &noiseMaskConn{
			PacketConn: conn,
			every:      uint64(every),
			maxPerSec:  maxPerSec,
			ladder:     lengths,
		}
	}
}

func (c *noiseMaskConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err != nil {
		return n, err
	}
	if c.written.Add(1)%c.every == 0 && c.decoyAllowed() {
		if decoy, ok := randomDecoy(c.ladder); ok {
			// Best effort: a dropped decoy must never break the data path.
			_, _ = c.PacketConn.WriteTo(decoy, addr)
		}
	}
	return n, err
}

func (c *noiseMaskConn) decoyAllowed() bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	minGap := time.Second / time.Duration(c.maxPerSec)
	if now.Sub(c.last) < minGap {
		return false
	}
	c.last = now
	return true
}

func randomDecoy(ladder []int) ([]byte, bool) {
	if len(ladder) == 0 {
		return nil, false
	}
	idx := make([]byte, 1)
	if _, err := rand.Read(idx); err != nil {
		return nil, false
	}
	size := ladder[int(idx[0])%len(ladder)]
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, false
	}
	return out, true
}

// SyscallConn lets Android VpnService.protect still reach the real socket
// through the mask wrapper.
func (c *noiseMaskConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, net.ErrClosed
}
