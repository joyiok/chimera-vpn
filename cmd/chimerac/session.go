package main

import (
	"context"
	"fmt"
	"time"

	"chimera/core"
	"chimera/internal/tunnel"
)

const defaultLinkLostAfter = 90 * time.Second

type vpnOptions struct {
	takeRoute  bool
	lostAfter  time.Duration
	statsEvery time.Duration
}

func clientCoreConfig(cfg clientConfig) core.Config {
	return core.Config{
		SeedHex:               cfg.SeedHex,
		Generation:            cfg.Generation,
		GenerationWindow:      2,
		JitterMax:             tunnel.DefaultJitterMax,
		PSKHex:                cfg.PSKHex,
		ServerAddr:            cfg.ServerAddr,
		Transport:             cfg.Transport,
		PortHopCount:          cfg.PortHopCount,
		PortHopSpread:         cfg.PortHopSpread,
		TLSCAFile:             cfg.TLSCAFile,
		TLSInsecureSkipVerify: cfg.TLSInsecure,
		Cipher:                cfg.Cipher,
		ShapeBuckets:          cfg.ShapeBuckets,
		ProbeMark:             cfg.ProbeMark,
		Transports:            cfg.Transports,
		KeepaliveInterval:     25 * time.Second,
	}
}

func startClient(ctx context.Context, cfg clientConfig, timeout time.Duration) (*core.Client, string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := core.NewClient(clientCoreConfig(cfg))
	if err != nil {
		return nil, "", err
	}
	if err := c.StartContext(ctx); err != nil {
		_ = c.Close()
		return nil, "", fmt.Errorf("handshake: %w", err)
	}
	ipCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ip, err := c.AssignedIP(ipCtx)
	if err != nil {
		_ = c.Close()
		return nil, "", fmt.Errorf("assigned IP: %w", err)
	}
	return c, ip, nil
}

func nextBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	d *= 2
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

func formatBytes(n uint64) string {
	const (
		kb = 1024
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	switch {
	case n < kb:
		return fmt.Sprintf("%d B", n)
	case n < mb:
		return fmt.Sprintf("%.1f KB", float64(n)/kb)
	case n < gb:
		return fmt.Sprintf("%.2f MB", float64(n)/mb)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/gb)
	}
}

func formatLinkStats(assigned string, idle time.Duration, sent, recv uint64) string {
	if assigned == "" {
		assigned = "?"
	}
	return fmt.Sprintf("link assigned=%s idle=%s sent=%s recv=%s",
		assigned, idle.Truncate(time.Second), formatBytes(sent), formatBytes(recv))
}

func watchdogTick(lostAfter time.Duration) time.Duration {
	if lostAfter <= 0 {
		return 5 * time.Second
	}
	t := lostAfter / 4
	if t > 5*time.Second {
		t = 5 * time.Second
	}
	if t < 50*time.Millisecond {
		t = 50 * time.Millisecond
	}
	return t
}
