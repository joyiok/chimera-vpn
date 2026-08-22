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
	Listen    string `json:"listen"`
	Transport string `json:"transport"`
	// StreamDecoyMode applies only to TCP listeners: close, silent, tls.
	StreamDecoyMode string `json:"stream_decoy_mode"`
	// StreamDecoyTimeoutSec bounds one silent decoy connection.
	StreamDecoyTimeoutSec int `json:"stream_decoy_timeout_sec"`
	// StreamDecoyMaxPending caps concurrent unauthenticated TCP conns.
	StreamDecoyMaxPending int `json:"stream_decoy_max_pending"`
	// DecoyEvery emits one high-entropy noise frame every N real writes
	// on established sessions (0 = default 48, negative = disable).
	DecoyEvery int `json:"decoy_every"`
	// DecoyMaxPerSec caps noise frames per second per session direction.
	DecoyMaxPerSec int `json:"decoy_max_per_sec"`
	// PortHopCount derives additional listen ports from seed+generation
	// (1 disables hopping; clients must use the same count).
	PortHopCount int `json:"port_hop_count"`
	// PortHopSpread bounds derived port offsets from the listen port.
	PortHopSpread int `json:"port_hop_spread"`
	// GenerationRotationSec > 0 enables scheduled base-generation rotation:
	// every interval the server advances one generation, swaps the accepted
	// protocol window live, and pushes the new base to connected clients.
	// 0 disables rotation.
	GenerationRotationSec int `json:"generation_rotation_sec"`
	// ShapeBuckets overrides the genome-selected packet-length ladder.
	// Derive one from a real-traffic capture with:
	// chimera-eval -pcap real.pcap -ladder
	ShapeBuckets []int `json:"shape_buckets"`
	// ProbeMark embeds a visible deployment tag in handshake covers,
	// making THIS server identifiable on the wire. Opt-in measurement /
	// politeness feature — never enable it on a server whose users need
	// undetectability. Empty (default) = random covers.
	ProbeMark string `json:"probe_mark"`
	// Transports starts every listed underlay at once (udp, tcp,
	// websocket, wss, http, https); clients may arrive over any of them.
	// Empty = [transport].
	Transports []string `json:"transports"`
	// TLSCertFile / TLSKeyFile enable transport=wss.
	TLSCertFile string    `json:"tls_cert_file"`
	TLSKeyFile  string    `json:"tls_key_file"`
	SeedHex     string    `json:"seed_hex"`
	Generation  uint64    `json:"generation"`
	PSKHex      string    `json:"psk_hex"`
	ClientCIDR  string    `json:"client_cidr"`
	Tun         tunConfig `json:"tun"`

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
		Listen:                "0.0.0.0:4789",
		Transport:             "udp",
		StreamDecoyMode:       "silent",
		StreamDecoyTimeoutSec: 5,
		StreamDecoyMaxPending: 256,
		DecoyEvery:            48,
		DecoyMaxPerSec:        2,
		PortHopCount:          1,
		PortHopSpread:         0,
		ClientCIDR:            "10.99.0.0/24",
		KeepaliveSec:          25,
		IdleTimeoutSec:        180,
		MaxSessions:           256,
		JitterMS:              20,
		ReplayPath:            &replay,
		Tun:                   tunConfig{Name: "chimera0", Address: "10.99.0.1/24", MTU: 1400},
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
		SeedHex:               cfg.SeedHex,
		Generation:            cfg.Generation,
		GenerationWindow:      window,
		PSKHex:                cfg.PSKHex,
		ServerAddr:            cfg.Listen,
		Transport:             cfg.Transport,
		StreamDecoyMode:       tunnel.StreamProbeMode(cfg.StreamDecoyMode),
		StreamDecoyTimeout:    time.Duration(cfg.StreamDecoyTimeoutSec) * time.Second,
		StreamDecoyMaxPending: cfg.StreamDecoyMaxPending,
		DecoyEvery:            cfg.DecoyEvery,
		DecoyMaxPerSec:        cfg.DecoyMaxPerSec,
		PortHopCount:          cfg.PortHopCount,
		PortHopSpread:         cfg.PortHopSpread,
		GenerationRotation:    time.Duration(cfg.GenerationRotationSec) * time.Second,
		ShapeBuckets:          cfg.ShapeBuckets,
		ProbeMark:             cfg.ProbeMark,
		Transports:            cfg.Transports,
		TLSCertFile:           cfg.TLSCertFile,
		TLSKeyFile:            cfg.TLSKeyFile,
		ClientCIDR:            cfg.ClientCIDR,
		Cipher:                cfg.Cipher,
		KeepaliveInterval:     time.Duration(cfg.KeepaliveSec) * time.Second,
		IdleTimeout:           time.Duration(cfg.IdleTimeoutSec) * time.Second,
		RateLimitBytesPerSec:  cfg.RateLimitKBps * 1024,
		MaxSessions:           cfg.MaxSessions,
		DisableDecoy:          cfg.DisableDecoy,
		DisableShape:          cfg.DisableShape,
		JitterMax:             jitter,
		ReplayPath:            replay,
	}, nil
}

func isWorldReadable(mode fs.FileMode) bool {
	return mode.Perm()&0077 != 0
}
