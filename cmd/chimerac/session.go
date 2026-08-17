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
	takeRoute bool
	lostAfter time.Duration
}

func clientCoreConfig(cfg clientConfig) core.Config {
	return core.Config{
		SeedHex:           cfg.SeedHex,
		Generation:        cfg.Generation,
		GenerationWindow:  2,
		JitterMax:         tunnel.DefaultJitterMax,
		PSKHex:            cfg.PSKHex,
		ServerAddr:        cfg.ServerAddr,
		Cipher:            cfg.Cipher,
		KeepaliveInterval: 25 * time.Second,
	}
}

func startClient(cfg clientConfig, timeout time.Duration) (*core.Client, string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := core.NewClient(clientCoreConfig(cfg))
	if err != nil {
		return nil, "", err
	}
	if err := c.Start(); err != nil {
		_ = c.Close()
		return nil, "", fmt.Errorf("handshake: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ip, err := c.AssignedIP(ctx)
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
