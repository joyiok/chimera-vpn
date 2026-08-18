package main

import (
	"testing"
	"time"
)

func TestNextBackoff(t *testing.T) {
	if got := nextBackoff(0); got != time.Second {
		t.Fatalf("zero: %s", got)
	}
	if got := nextBackoff(time.Second); got != 2*time.Second {
		t.Fatalf("1s: %s", got)
	}
	if got := nextBackoff(20 * time.Second); got != 30*time.Second {
		t.Fatalf("capped: %s", got)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[uint64]string{
		0:                      "0 B",
		512:                    "512 B",
		1536:                   "1.5 KB",
		2 * 1024 * 1024:        "2.00 MB",
		3 * 1024 * 1024 * 1024: "3.00 GB",
	}
	for n, want := range cases {
		if got := formatBytes(n); got != want {
			t.Fatalf("%d: got %q want %q", n, got, want)
		}
	}
}

func TestFormatLinkStats(t *testing.T) {
	got := formatLinkStats("10.99.0.2", 90*time.Second, 2048, 4096)
	if got != "link assigned=10.99.0.2 idle=1m30s sent=2.0 KB recv=4.0 KB" {
		t.Fatalf("got %q", got)
	}
}

func TestWatchdogTick(t *testing.T) {
	if got := watchdogTick(90 * time.Second); got != 5*time.Second {
		t.Fatalf("90s: %s", got)
	}
	if got := watchdogTick(400 * time.Millisecond); got != 100*time.Millisecond {
		t.Fatalf("400ms: %s", got)
	}
	if got := watchdogTick(10 * time.Millisecond); got != 50*time.Millisecond {
		t.Fatalf("floor: %s", got)
	}
}
