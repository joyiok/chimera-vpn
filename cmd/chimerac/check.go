package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"chimera/core"
	"chimera/internal/netpkt"
)

type checkResult struct {
	OK         bool   `json:"ok"`
	Assigned   string `json:"assigned,omitempty"`
	Generation uint64 `json:"generation"`
	Probe      string `json:"probe,omitempty"`
	RTTMillis  int64  `json:"rtt_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

func runCheck(cfg clientConfig, timeout time.Duration) checkResult {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	client, err := core.NewClient(clientCoreConfig(cfg))
	if err != nil {
		return checkResult{Error: err.Error()}
	}
	defer client.Close()

	if err := client.Start(); err != nil {
		return checkResult{Error: fmt.Sprintf("handshake: %v", err)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	assigned, err := client.AssignedIP(ctx)
	if err != nil {
		return checkResult{Error: fmt.Sprintf("assigned IP: %v", err)}
	}
	gw, err := netpkt.GatewayForClient(assigned)
	if err != nil {
		return checkResult{Assigned: assigned, Generation: client.Generation(), Error: err.Error()}
	}

	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return checkResult{Assigned: assigned, Generation: client.Generation(), Error: err.Error()}
	}
	id := binary.BigEndian.Uint16(rnd[:2])
	seq := binary.BigEndian.Uint16(rnd[2:])
	src := net.ParseIP(assigned)
	dst := net.ParseIP(gw)
	pkt, err := netpkt.EchoRequest(src, dst, id, seq, []byte(netpkt.ProbeMagic))
	if err != nil {
		return checkResult{Assigned: assigned, Generation: client.Generation(), Error: err.Error()}
	}

	start := time.Now()
	if err := client.SendPacket(pkt); err != nil {
		return checkResult{Assigned: assigned, Generation: client.Generation(), Error: fmt.Sprintf("send probe: %v", err)}
	}

	got, err := recvWithDeadline(client, timeout)
	if err != nil {
		return checkResult{Assigned: assigned, Generation: client.Generation(), Error: fmt.Sprintf("probe: %v", err)}
	}
	kind, ok := netpkt.MatchProbe(pkt, got, src, dst, id, seq)
	if !ok {
		return checkResult{
			Assigned:   assigned,
			Generation: client.Generation(),
			Error:      fmt.Sprintf("unexpected probe reply (%d bytes)", len(got)),
		}
	}
	return checkResult{
		OK:         true,
		Assigned:   assigned,
		Generation: client.Generation(),
		Probe:      string(kind),
		RTTMillis:  time.Since(start).Milliseconds(),
	}
}

func recvWithDeadline(client *core.Client, d time.Duration) ([]byte, error) {
	type result struct {
		pkt []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := client.ReceivePacket()
		ch <- result{p, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.pkt, r.err
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for probe reply")
	}
}
