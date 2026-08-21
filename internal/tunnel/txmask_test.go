package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"
)

type txRecordingConn struct {
	mu     sync.Mutex
	writes int
	sizes  []int
}

func (c *txRecordingConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *txRecordingConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	c.sizes = append(c.sizes, len(p))
	c.mu.Unlock()
	return len(p), nil
}
func (c *txRecordingConn) Close() error                     { return nil }
func (c *txRecordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *txRecordingConn) SetDeadline(time.Time) error      { return nil }
func (c *txRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *txRecordingConn) SetWriteDeadline(time.Time) error { return nil }

func TestNoiseTxMaskEmitsDecoy(t *testing.T) {
	raw := &txRecordingConn{}
	masked := NewNoiseTxMask(1, 1_000_000, []int{64, 128})(raw)
	if _, err := masked.WriteTo([]byte("real"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if raw.writes != 2 {
		t.Fatalf("writes = %d, want real+decoy=2", raw.writes)
	}
	if raw.sizes[0] != 4 {
		t.Fatalf("first write size = %d, want real payload 4", raw.sizes[0])
	}
	if raw.sizes[1] != 64 && raw.sizes[1] != 128 {
		t.Fatalf("decoy size = %d, want ladder member", raw.sizes[1])
	}
}

func TestNoiseTxMaskHonorsRateCap(t *testing.T) {
	raw := &txRecordingConn{}
	masked := NewNoiseTxMask(1, 1, []int{32})(raw)
	peer := &net.UDPAddr{}
	// Two writes inside one second: only the first may carry a decoy.
	_, _ = masked.WriteTo([]byte("a"), peer)
	_, _ = masked.WriteTo([]byte("b"), peer)
	if raw.writes != 3 {
		t.Fatalf("writes = %d, want 3 (2 real + 1 decoy)", raw.writes)
	}
}

func TestNoiseTxMaskDisabledIdentity(t *testing.T) {
	raw := &txRecordingConn{}
	masked := NewNoiseTxMask(0, 0, nil)(raw)
	if _, err := masked.WriteTo([]byte("x"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if raw.writes != 1 {
		t.Fatalf("identity mask must not emit decoys, writes=%d", raw.writes)
	}
}
