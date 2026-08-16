package tunnel

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	replayCacheMax = 65536
	replayCacheTTL = time.Hour
	replayFileVer  = "chimera-pgc/0/replay-v1"
)

// replayCache remembers recently authenticated handshake first-datagrams
// and server-first knocks. Alice et al., IMC 2020: the GFW records the first
// data-carrying packet of a genuine session and replays it (sometimes with
// byte patches) from other addresses. AEAD rejects patched copies; identical
// copies would otherwise complete a fresh handshake at seq 0.
//
// When path is set, entries are loaded at start and rewritten on insert so
// a process restart does not reopen the IMC 2020 delayed-replay window.
type replayCache struct {
	mu   sync.Mutex
	m    map[string]int64 // key -> expiry unix nano
	path string
}

func newReplayCache() *replayCache {
	return &replayCache{m: make(map[string]int64)}
}

func loadReplayCache(path string) *replayCache {
	c := newReplayCache()
	c.path = path
	if path == "" {
		return c
	}
	f, err := os.Open(path)
	if err != nil {
		return c
	}
	defer f.Close()
	now := time.Now().UnixNano()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return c
	}
	if strings.TrimSpace(sc.Text()) != replayFileVer {
		return c
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, exp, ok := parseReplayLine(line)
		if !ok || exp <= now {
			continue
		}
		c.m[k] = exp
		if len(c.m) >= replayCacheMax {
			break
		}
	}
	return c
}

func parseReplayLine(line string) (string, int64, bool) {
	hexKey, rest, ok := strings.Cut(line, " ")
	if !ok {
		return "", 0, false
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != sha256.Size {
		return "", 0, false
	}
	exp, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		return "", 0, false
	}
	return string(raw), exp, true
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
	c.persistLocked()
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

func (c *replayCache) persistLocked() {
	if c.path == "" {
		return
	}
	dir := filepath.Dir(c.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return
		}
	}
	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintln(f, replayFileVer); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	for k, exp := range c.m {
		if _, err := fmt.Fprintf(f, "%s %d\n", hex.EncodeToString([]byte(k)), exp); err != nil {
			f.Close()
			os.Remove(tmp)
			return
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, c.path); err != nil {
		os.Remove(tmp)
	}
}
