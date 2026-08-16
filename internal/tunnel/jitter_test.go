package tunnel

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestJitterDelayRange(t *testing.T) {
	if d := jitterDelay(0); d != 0 {
		t.Fatalf("zero max produced %v", d)
	}
	max := 40 * time.Millisecond
	var sawPositive atomic.Bool
	for i := 0; i < 64; i++ {
		d := jitterDelay(max)
		if d < 0 || d > max {
			t.Fatalf("delay %v outside [0, %v]", d, max)
		}
		if d > 0 {
			sawPositive.Store(true)
		}
	}
	if !sawPositive.Load() {
		t.Fatal("never drew a positive delay")
	}
}

func TestWriteDatagramAppliesJitter(t *testing.T) {
	var calls atomic.Int64
	jitterSleep.Store(func(time.Duration) { calls.Add(1) })
	t.Cleanup(func() {
		jitterSleep.Store(func(d time.Duration) { time.Sleep(d) })
	})

	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	for i := 0; i < 32 && calls.Load() == 0; i++ {
		if err := writeDatagram(a, b.LocalAddr(), []byte("hi"), 8*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() == 0 {
		t.Fatal("jitter sleeper was never invoked")
	}
}
