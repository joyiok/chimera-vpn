package tunnel

import (
	"crypto/sha256"
	"sync"
	"time"
)

const (
	replayCacheMax = 65536
	replayCacheTTL = time.Hour
)

// replayCache remembers recently authenticated handshake first-datagrams
// and server-first knocks. Alice et al., IMC 2020: the GFW records the first
// data-carrying packet of a genuine session and replays it (sometimes with
// byte patches) from other addresses. AEAD rejects patched copies; identical
// copies would otherwise complete a fresh handshake at seq 0.
type replayCache struct {
	mu sync.Mutex
	m  map[string]int64 // key -> expiry unix nano
}

func newReplayCache() *replayCache {
	return &replayCache{m: make(map[string]int64)}
}

func replayKey(inner []byte) string {
	sum := sha256.Sum256(inner)
	return string(sum[:])
}

// seen reports whether inner was already recorded. A new inner is stored
// and seen returns false. Call only after AEAD/knock authentication so
// probes cannot fill the table.
func (c *replayCache) seen(inner []byte) bool {
	if c == nil || len(inner) == 0 {
		return false
	}
	key := replayKey(inner)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.m[key]; ok && now.UnixNano() < exp {
		return true
	}
	if len(c.m) >= replayCacheMax {
		c.sweepLocked(now)
	}
	if len(c.m) >= replayCacheMax {
		return false // fail-open: PSK holders can fill the table
	}
	c.m[key] = now.Add(replayCacheTTL).UnixNano()
	return false
}

func (c *replayCache) sweepLocked(now time.Time) {
	ns := now.UnixNano()
	for k, exp := range c.m {
		if ns >= exp {
			delete(c.m, k)
		}
	}
}
