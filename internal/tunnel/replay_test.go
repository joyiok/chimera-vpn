package tunnel

import (
	"testing"
)

func TestReplayCacheDetectsDuplicate(t *testing.T) {
	c := newReplayCache()
	inner := []byte("authenticated-first-frame")
	if c.seen(inner) {
		t.Fatal("first observation must be fresh")
	}
	if !c.seen(inner) {
		t.Fatal("second observation must be a replay")
	}
	other := []byte("another-authenticated-frame")
	if c.seen(other) {
		t.Fatal("distinct inner must be fresh")
	}
}

func TestReplayCacheIgnoresEmpty(t *testing.T) {
	c := newReplayCache()
	if c.seen(nil) || c.seen([]byte{}) {
		t.Fatal("empty inner must not count as replay")
	}
}

func TestReplayCachePersistsAcrossLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/handshake.replay"
	c := loadReplayCache(path)
	inner := []byte("authenticated-first-frame-persist")
	if c.seen(inner) {
		t.Fatal("first observation must be fresh")
	}
	c2 := loadReplayCache(path)
	if !c2.seen(inner) {
		t.Fatal("reloaded cache missed persisted replay")
	}
}
