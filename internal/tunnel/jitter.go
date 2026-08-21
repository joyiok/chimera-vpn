package tunnel

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"net"
	"sync/atomic"
	"time"
)

// DefaultJitterMax is the production send-side timing smear. Inter-arrival
// delays are a truncated exponential in (0, DefaultJitterMax], matching the
// obfs4/ScrambleSuit lesson that a *uniform* IAT is itself a classifier
// feature (Wang et al., CCS 2015; Fifield, FOCI 2020). Tests and library
// callers leave JitterMax at 0 (off) unless they opt in; chimerad enables
// this by default.
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

// jitterDelay samples a truncated-exponential inter-arrival delay in
// (0, max]. Mean is max/3 so most gaps stay short with a long tail.
// A zero draw is replaced by 1ns so applyJitter actually runs when
// jitter is enabled (uniform-inclusive-zero used to skip the sleeper).
func jitterDelay(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return max / 3
	}
	u := float64(n.Int64()+1) / float64(int64(1)<<53)
	d := -math.Log(u) * float64(max) / 3
	if d > float64(max) {
		d = float64(max)
	}
	if d < 1 {
		d = 1
	}
	return time.Duration(d)
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
// the mux read loop is not stalled by jitter. With jitter disabled it
// writes synchronously: a goroutine per frame both spikes scheduling and
// lets frames arrive out of order, which data-plane ordering tests (and
// real ACK bookkeeping) should not have to tolerate.
func writeDatagramAsync(conn net.PacketConn, addr net.Addr, frame []byte, jitter time.Duration) {
	if conn == nil || addr == nil || len(frame) == 0 || len(frame) > maxDatagram {
		return
	}
	if jitter <= 0 {
		_, _ = conn.WriteTo(frame, addr)
		return
	}
	cp := append([]byte(nil), frame...)
	go func() {
		applyJitter(jitter)
		_, _ = conn.WriteTo(cp, addr)
	}()
}
