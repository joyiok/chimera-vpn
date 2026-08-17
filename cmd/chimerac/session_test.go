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
