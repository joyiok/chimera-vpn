package tunnel

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"time"
)

// DefaultJitterMax is the production send-side timing smear. Uniform delay
// in [0, DefaultJitterMax] on every datagram makes inter-packet gaps less
// of a constant fingerprint. Tests and library callers leave JitterMax at
// 0 (off) unless they opt in; chimerad enables this by default.
const DefaultJitterMax = 20 * time.Millisecond

// MaxJitterMax rejects misconfiguration that would stall the data plane.
const MaxJitterMax = time.Second

// jitterSleep holds the delay function so tests can observe jitter without
// waiting. Store a func(time.Duration). Nil means time.Sleep.
var jitterSleep atomic.Value // func(time.Duration)

func applyJitter(max time.Duration) {
	d := jitterDelay(max)
	if d <= 0 {
		return
	}
	if fn, ok := jitterSleep.Load().(func(time.Duration)); ok && fn != nil {
		fn(d)
		return
	}
	time.Sleep(d)
}

// jitterDelay returns a uniformly random duration in [0, max].
func jitterDelay(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// writeDatagram smears timing then sends one UDP payload. The caller must
// not hold session locks across this call.
func writeDatagram(conn net.PacketConn, addr net.Addr, frame []byte, jitter time.Duration) error {
	if len(frame) > maxDatagram {
		return fmt.Errorf("encrypted frame too large: %d", len(frame))
	}
	applyJitter(jitter)
	_, err := conn.WriteTo(frame, addr)
	return err
}

// writeDatagramAsync is for best-effort control (ACK/keepalive/decoy) so
// the mux read loop is not stalled by jitter.
func writeDatagramAsync(conn net.PacketConn, addr net.Addr, frame []byte, jitter time.Duration) {
	if conn == nil || addr == nil || len(frame) == 0 || len(frame) > maxDatagram {
		return
	}
	cp := append([]byte(nil), frame...)
	go func() {
		applyJitter(jitter)
		_, _ = conn.WriteTo(cp, addr)
	}()
}
