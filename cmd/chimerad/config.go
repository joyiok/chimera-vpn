package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"chimera/core"
	"chimera/internal/tunnel"
)

type tunConfig struct {
	Name    string `json:"name"`
	Address string `json:"address"` // CIDR, e.g. 10.99.0.1/24
	MTU     int    `json:"mtu"`
}

type serverConfig struct {
	Listen     string    `json:"listen"`
	SeedHex    string    `json:"seed_hex"`
	Generation uint64    `json:"generation"`
	PSKHex     string    `json:"psk_hex"`
	ClientCIDR string    `json:"client_cidr"`
	Tun        tunConfig `json:"tun"`

	// Cipher overrides the genome cipher draw ("" = default). Both
	// endpoints must agree; e.g. "chacha20-poly1305".
	Cipher string `json:"cipher"`

	// KeepaliveSec refreshes NAT mappings on idle links (0 = default 25s,
	// negative = disable).
	KeepaliveSec int `json:"keepalive_sec"`
	// IdleTimeoutSec reaps sessions quiet for that long (0 = disable).
	IdleTimeoutSec int `json:"idle_timeout_sec"`
	// RateLimitKBps caps each client's inbound rate in KiB/s (0 = off).
	RateLimitKBps int `json:"rate_limit_kbps"`
	// MaxSessions caps established clients (0 = default 256).
	MaxSessions int `json:"max_sessions"`
	// DisableDecoy turns off anti-probe decoy replies (default: decoys on).
	DisableDecoy bool `json:"disable_decoy"`
	// DisableShape turns off datagram length shaping (default: on).
	DisableShape bool `json:"disable_shape"`
	// JitterMS is the max send-side timing smear in milliseconds
	// (omitted or 0 = 20ms, negative = disable).
	JitterMS int `json:"jitter_ms"`
	// GenerationWindow extra generations the server accepts beyond
	// Generation so key rotation does not drop old clients. nil/omitted
	// defaults to 2; 0 means only the configured generation.
	GenerationWindow *int `json:"generation_window"`
	// ReplayPath persists handshake/knock hashes across restarts.
	// Omitted defaults to /var/lib/chimera/handshake.replay; empty string
	// keeps the table in memory only.
	ReplayPath *string `json:"replay_path"`
}

func defaultConfig() serverConfig {
	replay := "/var/lib/chimera/handshake.replay"
	return serverConfig{
		Listen:         "0.0.0.0:4789",
		ClientCIDR:     "10.99.0.0/24",
		KeepaliveSec:   25,
		IdleTimeoutSec: 180,
		MaxSessions:    256,
		JitterMS:       20,
		ReplayPath:     &replay,
		Tun:            tunConfig{Name: "chimera0", Address: "10.99.0.1/24", MTU: 1400},
	}
}

func loadServerConfig(path string) (serverConfig, error) {
	cfg := defaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "chimera0"
	}
	if cfg.Tun.Address == "" {
		cfg.Tun.Address = "10.99.0.1/24"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1400
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 256
	}
	return cfg, nil
}

func configFilePermWarning(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := info.Mode().Perm()
	if !isWorldReadable(perm) {
		return ""
	}
	return fmt.Sprintf("%s mode %04o is readable by group/other; PSK lives in this file", path, perm)
}

func toCoreConfig(cfg serverConfig) (core.Config, error) {
	jitter := time.Duration(cfg.JitterMS) * time.Millisecond
	if cfg.JitterMS == 0 {
		jitter = tunnel.DefaultJitterMax
	}
	if cfg.JitterMS < 0 {
		jitter = 0
	}
	window := uint64(2)
	if cfg.GenerationWindow != nil {
		if *cfg.GenerationWindow < 0 {
			return core.Config{}, errors.New("generation_window must be >= 0")
		}
		window = uint64(*cfg.GenerationWindow)
	}
	replay := "/var/lib/chimera/handshake.replay"
	if cfg.ReplayPath != nil {
		replay = *cfg.ReplayPath
	}
	return core.Config{
		SeedHex:              cfg.SeedHex,
		Generation:           cfg.Generation,
		GenerationWindow:     window,
		PSKHex:               cfg.PSKHex,
		ServerAddr:           cfg.Listen,
		ClientCIDR:           cfg.ClientCIDR,
		Cipher:               cfg.Cipher,
		KeepaliveInterval:    time.Duration(cfg.KeepaliveSec) * time.Second,
		IdleTimeout:          time.Duration(cfg.IdleTimeoutSec) * time.Second,
		RateLimitBytesPerSec: cfg.RateLimitKBps * 1024,
		MaxSessions:          cfg.MaxSessions,
		DisableDecoy:         cfg.DisableDecoy,
		DisableShape:         cfg.DisableShape,
		JitterMax:            jitter,
		ReplayPath:           replay,
	}, nil
}

func isWorldReadable(mode fs.FileMode) bool {
	return mode.Perm()&0077 != 0
}
