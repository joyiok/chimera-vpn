package core

import (
	"net"
	"reflect"
	"testing"
	"time"

	"chimera/internal/tunnel"
)

// TestShapeBucketsOverride verifies the config-level ladder override:
// NormalizeConfig sorts and validates the entries, and a running mux uses
// the override instead of the genome-selected ladder.
func TestShapeBucketsOverride(t *testing.T) {
	cfg := testConfig("127.0.0.1:0", "udp")
	cfg.ShapeBuckets = []int{300, 100, 200} // deliberately unsorted
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.cfg.ShapeBuckets; !reflect.DeepEqual(got, []int{100, 200, 300}) {
		t.Fatalf("NormalizeConfig did not sort buckets: %v", got)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if len(srv.muxes) == 0 {
		t.Fatal("no mux started")
	}
	if got := srv.muxes[0].ShapeBuckets(); !reflect.DeepEqual(got, []int{100, 200, 300}) {
		t.Fatalf("mux ladder = %v, want override", got)
	}

	for _, bad := range [][]int{{10}, {2000}, {100, 100}} {
		badCfg := testConfig("127.0.0.1:0", "udp")
		badCfg.ShapeBuckets = bad
		if _, err := NewServer(badCfg); err == nil {
			t.Fatalf("ShapeBuckets %v accepted", bad)
		}
	}
}

// TestResolveShapeLadder pins the preference order: explicit override wins
// over the genome ladder; empty falls back.
func TestResolveShapeLadder(t *testing.T) {
	cfg := Config{ShapeBuckets: []int{128}}
	if got := cfg.resolveShapeLadder([]int{999}); !reflect.DeepEqual(got, []int{128}) {
		t.Fatalf("override ignored: %v", got)
	}
	empty := Config{}
	if got := empty.resolveShapeLadder([]int{999}); !reflect.DeepEqual(got, []int{999}) {
		t.Fatalf("fallback broken: %v", got)
	}
}

// TestGenerationRotationPush verifies the full rotation loop: the server
// advances its base on schedule, the connected client receives the
// ControlGeneration push and adopts it, and a fresh client configured with
// the pre-rotation generation can still connect through window probing.
func TestGenerationRotationPush(t *testing.T) {
	srvCfg := testConfig("127.0.0.1:0", "udp")
	// 500ms: fast enough to observe several rotations, slow enough that a
	// loopback handshake (with jitter) fits comfortably inside one window.
	// Production intervals are minutes/hours.
	srvCfg.GenerationRotation = 500 * time.Millisecond
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	base := srv.BaseGeneration()

	cliCfg := testConfig(srv.LocalAddr().String(), "udp")
	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	// Generation pushes are decoded by the receive path; drain frames like
	// a real client pump would so the push is observed.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			if _, err := cli.ReceivePacket(); err != nil {
				return
			}
		}
	}()
	defer func() { cli.Close(); <-drainDone }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.BaseGeneration() > base && cli.BaseGeneration() > base {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.BaseGeneration() <= base {
		t.Fatalf("server did not rotate: base still %d", srv.BaseGeneration())
	}
	if got := cli.BaseGeneration(); got <= base {
		t.Fatalf("client did not adopt pushed generation: %d", got)
	}

	// A client only one rotation behind must still connect immediately:
	// rotateGeneration keeps the outgoing base in the accepted window for
	// one interval (backward-compat slot).
	oneUp := base + 1
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.BaseGeneration() >= oneUp {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.BaseGeneration() < oneUp {
		t.Fatalf("server never reached generation %d", oneUp)
	}
	oldCli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer oldCli.Close()
	oldCliStart := make(chan error, 1)
	go func() { oldCliStart <- oldCli.Start() }()
	select {
	case err := <-oldCliStart:
		if err != nil {
			t.Fatalf("one-rotation-behind client could not reconnect (server base=%d probes=%d decoys=%d hands=%d): %v",
				srv.BaseGeneration(), srv.teleProbes.Load(), srv.teleDecoys.Load(), srv.teleHands.Load(), err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("one-rotation-behind client handshake timed out")
	}
	// Connecting at the compat generation (base) is the expected outcome;
	// the next reconnect adopts the pushed base via its receive pump.
}

// TestImmuneEscalation drives the threat evaluator directly: junk TCP
// probes must raise the threat level and escalate the first-frame defense
// from silent to tls.
func TestImmuneEscalation(t *testing.T) {
	srvCfg := testConfig("127.0.0.1:0", "tcp")
	srvCfg.StreamDecoyMode = tunnel.StreamProbeSilent
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if got := srv.ProbeMode(); got != tunnel.StreamProbeSilent {
		t.Fatalf("initial probe mode = %s, want silent", got)
	}

	for i := 0; i < 10; i++ {
		c, err := net.Dial("tcp", srv.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("garbage probe frame"))
		_ = c.Close()
	}
	time.Sleep(300 * time.Millisecond) // let handshake goroutines count

	level := srv.evaluateThreat()
	if level < ThreatElevated {
		t.Fatalf("threat level = %d, want >= elevated after %d probes", level, 10)
	}
	if srv.ThreatLevel() != level {
		t.Fatalf("threat not stored: %d vs %d", srv.ThreatLevel(), level)
	}
	if got := srv.ProbeMode(); got != tunnel.StreamProbeTLS {
		t.Fatalf("probe mode = %s, want escalated to tls", got)
	}
}
